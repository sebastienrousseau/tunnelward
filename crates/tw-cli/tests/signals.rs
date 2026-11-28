// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Stopping on SIGTERM (FR-7, G7): the gateway stops accepting, lets the
//! request in flight finish and exits 0; the connector does the same.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

mod common;

use common::procs::{
    Lines, bound, connector_file, expect, gateway_file, spawn_connector, spawn_gateway_lines,
};
use common::{Res, Running, pki_dir};

/// A local service that answers each request with `slow` after `delay`.
fn slow_service(delay: Duration) -> Res<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut request = [0_u8; 4096];
                let _read = stream.read(&mut request);
                std::thread::sleep(delay);
                let _sent = stream.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\nslow",
                );
            });
        }
    });
    Ok(addr)
}

/// A gateway and a connector in front of `target`, and what each prints:
/// kept, so neither process writes to a closed pipe.
struct Pair {
    gateway: Running,
    gateway_out: Lines,
    connector: Running,
    connector_out: Lines,
    ingress: String,
}

/// [`Pair`] from files in `dir`, once the connector has registered.
fn start(dir: &Path, target: &str) -> Res<Pair> {
    let (gateway, out, _) = spawn_gateway_lines(&gateway_file(dir, "127.0.0.1:0", "127.0.0.1:0")?)?;
    let started = expect(&out, "connectors on")?;
    let (connectors, ingress) = (bound(&started, "connectors")?, bound(&started, "agents")?);
    let file = connector_file(dir, &connectors, &format!("http://{target}"), "\"mcp\"")?;
    let (connector, connector_out) = spawn_connector(&file)?;
    expect(&connector_out, "Registered")?;
    Ok(Pair {
        gateway,
        gateway_out: out,
        connector,
        connector_out,
        ingress,
    })
}

fn terminate(child: &Running) -> Res<()> {
    let sent = Command::new("kill")
        .args(["-TERM", &child.0.id().to_string()])
        .status()?;
    Ok(sent.success().then_some(()).ok_or("kill -TERM failed")?)
}

/// An agent's GET through `ingress`, on its own thread: the raw answer.
fn ask_later(ingress: String) -> std::thread::JoinHandle<Result<String, String>> {
    std::thread::spawn(move || ask(&ingress).map_err(|e| e.to_string()))
}

fn ask(ingress: &str) -> Res<String> {
    let mut agent = TcpStream::connect(ingress)?;
    agent.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        agent,
        "GET /mcp/x HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n"
    )?;
    let mut answer = String::new();
    agent.read_to_string(&mut answer)?;
    Ok(answer)
}

/// The agent's request was answered by the slow service.
fn served(answer: std::thread::JoinHandle<Result<String, String>>) -> Res<()> {
    let answer = answer.join().map_err(|_| "the agent thread panicked")??;
    assert!(
        answer.starts_with("HTTP/1.1 200") && answer.ends_with("slow"),
        "{answer}"
    );
    Ok(())
}

#[test]
fn a_terminated_gateway_finishes_the_request_in_flight_and_exits_0() -> Res<()> {
    let dir = pki_dir("signal-gateway")?;
    let mut pair = start(&dir, &slow_service(Duration::from_secs(1))?)?;
    let answer = ask_later(pair.ingress.clone());
    std::thread::sleep(Duration::from_millis(300));
    terminate(&pair.gateway)?;
    expect(&pair.gateway_out, "stopping, draining")?;
    served(answer)?;
    // The connector keeps two connections: both drain, neither is reset.
    let report = expect(&pair.gateway_out, "stopped;")?;
    assert!(
        report.contains("2 drained, 2 finished, 0 reset"),
        "{report}"
    );
    assert!(pair.gateway.0.wait()?.success(), "exit status");
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_terminated_connector_stops_cleanly_and_exits_0() -> Res<()> {
    let dir = pki_dir("signal-connector")?;
    let mut pair = start(&dir, &slow_service(Duration::ZERO)?)?;
    terminate(&pair.connector)?;
    expect(&pair.connector_out, "stopped; every request finished: true")?;
    assert!(pair.connector.0.wait()?.success(), "exit status");
    Ok(std::fs::remove_dir_all(dir)?)
}
