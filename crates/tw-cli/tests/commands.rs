// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The `config check`, `doctor` and `dev` commands, run as a user would.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

mod common;

use common::procs::{
    Lines, bound, connector_file, expect, gateway_file, spawn_connector, spawn_gateway_lines,
};
use common::{Res, Running, pki_dir, text, tunnelward, write_config};
use tunnelward_testpki as pki;

#[test]
fn a_good_config_checks_ok() -> Res<()> {
    let dir = pki_dir("good")?;
    let owners = "[[connectors.owners]]\nroute = \"mcp\"\n\
                  identities = [\"spiffe://example.org/connector\"]\n";
    let path = write_config(&dir, owners)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).ends_with(": ok\n"));
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_bad_config_lists_every_problem() -> Res<()> {
    let dir = pki_dir("bad")?;
    let extra = "[ingress]\ncert = \"gateway.crt\"\ntrusted_proxies = [\"10.0.0.0/33\"]\n\
                 [[ingress.cors]]\npath = \"mcp\"\norigins = [\"https://app.example/x\"]\n\
                 [connectors]\nallow = [\"nonsense\"]\n\
                 [[connectors.owners]]\nroute = \"/bad/\"\nidentities = [\"nobody\"]\n\
                 [[connectors.owners]]\nroute = \"/bad/\"\nidentities = []\n";
    let path = write_config(&dir, extra)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert_eq!(out.status.code(), Some(1));
    let errors = text(&out.stderr);
    for expected in [
        "give both cert and key",
        "10.0.0.0/33",
        "nonsense",
        "start it with /",
        "give scheme://host",
        "[[connectors.owners]] route \"/bad/\" is not a route",
        "\"nobody\" is not a SPIFFE ID",
        "\"/bad/\" is listed twice",
        "name at least one identity",
    ] {
        assert!(
            errors.contains(expected),
            "{expected} missing from: {errors}"
        );
    }
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn an_unknown_key_names_its_line() -> Res<()> {
    let dir = pki_dir("unknown")?;
    let path = write_config(&dir, "[admin]\ntoken = \"inline\"\n")?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert_eq!(out.status.code(), Some(1));
    let errors = text(&out.stderr);
    assert!(
        errors.contains("line 10") && errors.contains("token"),
        "{errors}"
    );
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn doctor_checks_the_machine_and_the_file() -> Res<()> {
    let dir = pki_dir("doctor")?;
    let path = write_config(&dir, "")?;
    let out = tunnelward(&["doctor", "--config", &path.to_string_lossy()])?;
    let report = text(&out.stdout);
    assert!(out.status.success(), "{report}{}", text(&out.stderr));
    assert!(
        report.contains("ok   TLS offers X25519MLKEM768 first"),
        "{report}"
    );
    assert!(report.contains("passes every check"), "{report}");
    Ok(std::fs::remove_dir_all(dir)?)
}

/// A local service answering every request with `hello`.
fn hello_service() -> Res<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut request = [0_u8; 4096];
            let _read = stream.read(&mut request);
            let _sent = stream.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
            );
        }
    });
    Ok(addr)
}

#[test]
fn dev_puts_a_tunnel_in_front_of_a_local_service() -> Res<()> {
    let service = hello_service()?;
    let to = format!("http://{service}");
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(["dev", "--to", &to, "--listen", "127.0.0.1:0"])
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let stdout = child.0.stdout.take().ok_or("no stdout")?;
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line)?;
    assert!(line.starts_with("tunnelward dev: ready."), "{line}");
    let listen = line
        .split("http://")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .ok_or("no address in the ready line")?;
    let answer = ask(listen, "/anything")?;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.ends_with("hello"), "{answer}");
    Ok(())
}

#[test]
fn dev_refuses_a_public_listener() -> Res<()> {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(["dev", "--to", "http://127.0.0.1:1", "--listen", "0.0.0.0:0"])
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if std::time::Instant::now() > deadline {
            return Err("dev kept running on a public address".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut errors = String::new();
    child
        .0
        .stderr
        .take()
        .ok_or("no stderr")?
        .read_to_string(&mut errors)?;
    assert_eq!(status.code(), Some(1));
    assert!(errors.contains("loopback only"), "{errors}");
    Ok(())
}

#[test]
fn the_gateway_reloads_renewed_certificates_and_keeps_good_ones() -> Res<()> {
    let dir = pki_dir("reload")?;
    let path = write_config(&dir, "reload_secs = 1\n")?;
    let (child, out, err) = spawn_gateway_lines(&path)?;
    expect(&out, "tunnelward gateway: connectors on")?;

    std::fs::write(dir.join("gateway.key"), "not a key")?;
    expect(&err, "not reloaded, keeping the running certificates")?;
    std::fs::write(
        dir.join("gateway.key"),
        pki::pem("PRIVATE KEY", pki::GATEWAY.1),
    )?;
    expect(&out, "certificates and policy reloaded")?;
    drop(child);
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_connector_file_checks_ok_or_lists_its_problems() -> Res<()> {
    let dir = pki_dir("connector-check")?;
    let good = connector_file(&dir, "127.0.0.1:7443", "http://127.0.0.1:8080", "\"mcp\"")?;
    let out = tunnelward(&["config", "check", &good.to_string_lossy()])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let bad = connector_file(&dir, "nowhere", "ftp://x", "\"/bad/\"")?;
    let out = tunnelward(&["config", "check", &bad.to_string_lossy()])?;
    let errors = text(&out.stderr);
    for expected in ["is not a route", "give host:port", "give http://host:port"] {
        assert!(
            errors.contains(expected),
            "{expected} missing from: {errors}"
        );
    }
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_connector_file_must_claim_its_certificates_identity() -> Res<()> {
    let dir = pki_dir("connector-identity")?;
    let path = connector_file(&dir, "127.0.0.1:7443", "http://127.0.0.1:8080", "\"mcp\"")?;
    let claimed = std::fs::read_to_string(&path)?.replace(
        "spiffe://example.org/connector",
        "spiffe://example.org/someone-else",
    );
    std::fs::write(&path, claimed)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    let errors = text(&out.stderr);
    assert!(!out.status.success(), "a borrowed identity passed");
    assert!(
        errors.contains("spiffe://example.org/connector"),
        "the certificate's identity missing from: {errors}"
    );
    Ok(std::fs::remove_dir_all(dir)?)
}

/// [`gateway_file`] on loopback ports with `extra` appended.
fn gateway_file_with(dir: &Path, extra: &str) -> Res<PathBuf> {
    let path = gateway_file(dir, "127.0.0.1:0", "127.0.0.1:0")?;
    let text = std::fs::read_to_string(&path)? + extra;
    std::fs::write(&path, text)?;
    Ok(path)
}

/// An agent's GET for `path` at `ingress`, and the whole raw answer.
fn ask(ingress: &str, path: &str) -> Res<String> {
    let mut agent = TcpStream::connect(ingress)?;
    agent.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        agent,
        "GET {path} HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n"
    )?;
    let mut answer = String::new();
    agent.read_to_string(&mut answer)?;
    Ok(answer)
}

/// A gateway and a connector from their files in `dir`, in front of a
/// local service; returns both processes and the ingress address once
/// the connector has registered.
fn start_pair(dir: &Path) -> Res<(Running, Running, String)> {
    let (gateway, connector, ingress, _) = start_pair_with(dir, "")?;
    Ok((gateway, connector, ingress))
}

/// [`start_pair`] with `extra` appended to the gateway file (after its
/// `[tls]` table); also returns the gateway's stdout lines.
fn start_pair_with(dir: &Path, extra: &str) -> Res<(Running, Running, String, Lines)> {
    let service = hello_service()?;
    let (gateway, gateway_out, _) = spawn_gateway_lines(&gateway_file_with(dir, extra)?)?;
    let started = expect(&gateway_out, "connectors on")?;
    let (connectors, ingress) = (bound(&started, "connectors")?, bound(&started, "agents")?);
    let target = format!("http://{service}");
    let file = connector_file(dir, &connectors, &target, "\"mcp\"")?;
    let (connector, connector_out) = spawn_connector(&file)?;
    expect(&connector_out, "Registered")?;
    Ok((gateway, connector, ingress, gateway_out))
}

#[test]
fn a_changed_policy_file_applies_without_a_restart() -> Res<()> {
    let dir = pki_dir("policy-reload")?;
    let open = "default = \"allow\"\nbaseline = false\n";
    std::fs::write(dir.join("policy.toml"), open)?;
    let extra = "reload_secs = 1\n\n[policy]\nfile = \"policy.toml\"\n";
    let (gateway, connector, ingress, out) = start_pair_with(&dir, extra)?;
    let answer = ask(&ingress, "/mcp/x")?;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let closed = format!("{open}[[rules]]\neffect = \"forbid\"\nmethods = [\"http:GET\"]\n");
    std::fs::write(dir.join("policy.toml"), closed)?;
    expect(&out, "certificates and policy reloaded")?;
    let answer = ask(&ingress, "/mcp/x")?;
    assert!(
        answer.starts_with("HTTP/1.1 403") && answer.contains("TW-P001"),
        "{answer}"
    );
    drop((connector, gateway));
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_gateway_and_a_connector_from_their_files_serve_a_request() -> Res<()> {
    let dir = pki_dir("pair")?;
    let (gateway, connector, ingress) = start_pair(&dir)?;
    let answer = ask(&ingress, "/mcp/x")?;
    assert!(
        answer.starts_with("HTTP/1.1 200") && answer.ends_with("hello"),
        "{answer}"
    );
    drop((connector, gateway));
    Ok(std::fs::remove_dir_all(dir)?)
}
