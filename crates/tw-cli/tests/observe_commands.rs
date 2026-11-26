// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway file's `[risk]` and `[telemetry]`: checked by `config
//! check`, and a running gateway exporting a span to a collector on
//! loopback.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use common::{Res, pki_dir, text, tunnelward, write_config};

/// Kills the child when dropped.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _reaped = self.0.wait();
    }
}

fn check(dir: &std::path::Path, extra: &str) -> Res<(Option<i32>, String)> {
    let path = write_config(dir, extra)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    Ok((out.status.code(), text(&out.stderr)))
}

#[test]
fn risk_and_telemetry_check_ok_or_list_their_problems() -> Res<()> {
    let dir = pki_dir("observe-check")?;
    let good = "[risk]\nper_tool = 30\ncanary_tools = [\"export_all\"]\n\n\
                [telemetry]\notlp_endpoint = \"http://127.0.0.1:4318\"\nevery_ms = 100\n";
    let (code, errors) = check(&dir, good)?;
    assert_eq!(code, Some(0), "{errors}");
    let bad = "[risk]\nwindow_secs = 0\nalert_at = 0\ncanary_records = [\" \"]\nmax_subjects = 0\n\n\
               [telemetry]\notlp_endpoint = \"http://otel.example.org:4318\"\nbatch = 0\n";
    let (code, errors) = check(&dir, bad)?;
    assert_eq!(code, Some(1));
    for expected in [
        "[risk] window_secs 0: give at least 1",
        "[risk]: weights are 0 to 100, alert_at 1 to 100",
        "[risk]: a canary cannot be empty",
        "[risk]: max_steps, max_subjects and max_blocked are at least 1",
        "[telemetry] endpoint \"http://otel.example.org:4318\": give https://, or http:// to a loopback address",
        "[telemetry]: queue, batch and every_ms are at least 1",
    ] {
        assert!(
            errors.contains(expected),
            "{expected} missing from: {errors}"
        );
    }
    Ok(std::fs::remove_dir_all(dir)?)
}

/// A collector on loopback needs no CA bundle: `config check` passes on
/// a machine without one, as Windows runners are.
#[test]
fn a_loopback_collector_needs_no_ca_bundle() -> Res<()> {
    let dir = pki_dir("observe-no-bundle")?;
    let path = write_config(
        &dir,
        "[telemetry]\notlp_endpoint = \"http://127.0.0.1:4318\"\n",
    )?;
    let out = Command::new(env!("CARGO_BIN_EXE_tunnelward"))
        .args(["config", "check", &path.to_string_lossy()])
        .env("SSL_CERT_FILE", dir.join("no-such-bundle.pem"))
        .output()?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    Ok(std::fs::remove_dir_all(dir)?)
}

/// A collector that answers 200 and sends each request body on.
fn collector() -> Res<(String, mpsc::Receiver<String>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let (sent, received) = mpsc::channel();
    std::thread::spawn(move || {
        for mut tcp in listener.incoming().flatten() {
            if let Ok(body) = read_request(&mut tcp) {
                let _ok = tcp.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}");
                let _sent = sent.send(body);
            }
        }
    });
    Ok((endpoint, received))
}

/// One HTTP/1.1 request's request line and body.
fn read_request(tcp: &mut TcpStream) -> Res<String> {
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(tcp);
    let (mut head, mut length) = (String::new(), 0);
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = n.trim().parse()?;
        }
        if line == "\r\n" || line.is_empty() {
            break;
        }
        head.push_str(&line);
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(format!(
        "{}\n{}",
        head.lines().next().unwrap_or_default(),
        String::from_utf8(body)?
    ))
}

/// `tunnelward gateway` on `path`, and its ingress address once bound.
fn spawn_gateway(path: &std::path::Path) -> Res<(Running, String)> {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(["gateway", "--config", &path.to_string_lossy()])
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let mut started = String::new();
    BufReader::new(child.0.stdout.take().ok_or("no stdout")?).read_line(&mut started)?;
    let agents = (started.split("agents on ").nth(1))
        .and_then(|rest| rest.split([',', ' ', '\n']).next())
        .ok_or_else(|| format!("no ingress address in {started:?}"))?;
    Ok((child, agents.to_owned()))
}

/// An agent's GET for `path` at `ingress`.
fn ask(ingress: &str, path: &str) -> Res<String> {
    let mut agent = TcpStream::connect(ingress)?;
    write!(
        agent,
        "GET {path} HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n"
    )?;
    let mut answer = String::new();
    agent.read_to_string(&mut answer)?;
    Ok(answer)
}

#[test]
fn a_running_gateway_exports_a_span_per_request() -> Res<()> {
    let dir = pki_dir("observe-run")?;
    let (endpoint, received) = collector()?;
    let extra = format!("[risk]\n\n[telemetry]\notlp_endpoint = \"{endpoint}\"\nevery_ms = 50\n");
    let (child, agents) = spawn_gateway(&write_config(&dir, &extra)?)?;
    ask(&agents, "/mcp/x")?;
    let exported = received.recv_timeout(Duration::from_secs(10))?;
    assert!(
        exported.starts_with("POST /v1/traces HTTP/1.1"),
        "{exported}"
    );
    assert!(
        exported.contains("\"spanId\"") && exported.contains("/mcp/x"),
        "{exported}"
    );
    drop(child);
    Ok(std::fs::remove_dir_all(dir)?)
}
