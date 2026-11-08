// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The `config check`, `doctor` and `dev` commands, run as a user would.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use tunnelward_testpki as pki;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn tunnelward(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_tunnelward"))
        .args(args)
        .output()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Standard base64, as PEM needs it.
fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0_u32, |acc, b| acc << 8 | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            let sextet = (n >> (18 - 6 * i)) & 63;
            out.push(if i <= chunk.len() {
                char::from(ABC[sextet as usize])
            } else {
                '='
            });
        }
    }
    out
}

fn pem(label: &str, der: &[u8]) -> String {
    let body = base64(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// A fresh directory holding the test PKI as PEM files.
fn pki_dir(name: &str) -> Res<PathBuf> {
    let dir = std::env::temp_dir().join(format!("tunnelward-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("gateway.crt"), pem("CERTIFICATE", pki::GATEWAY.0))?;
    std::fs::write(dir.join("gateway.key"), pem("PRIVATE KEY", pki::GATEWAY.1))?;
    std::fs::write(dir.join("ca.crt"), pem("CERTIFICATE", pki::CA))?;
    Ok(dir)
}

fn write_config(dir: &Path, extra: &str) -> Res<PathBuf> {
    let path = dir.join("tunnelward.toml");
    std::fs::write(
        &path,
        format!(
            "[listen]\nconnectors = \"127.0.0.1:0\"\ningress = \"127.0.0.1:0\"\n\n\
             [tls]\ncert = \"gateway.crt\"\nkey = \"gateway.key\"\nclient_ca = \"ca.crt\"\n{extra}"
        ),
    )?;
    Ok(path)
}

#[test]
fn a_good_config_checks_ok() -> Res<()> {
    let dir = pki_dir("good")?;
    let path = write_config(&dir, "")?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).ends_with(": ok\n"));
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_bad_config_lists_every_problem() -> Res<()> {
    let dir = pki_dir("bad")?;
    let extra = "[ingress]\ncert = \"gateway.crt\"\ntrusted_proxies = [\"10.0.0.0/33\"]\n\
                 [connectors]\nallow = [\"nonsense\"]\n";
    let path = write_config(&dir, extra)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert_eq!(out.status.code(), Some(1));
    let errors = text(&out.stderr);
    for expected in ["give both cert and key", "10.0.0.0/33", "nonsense"] {
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

fn free_port() -> Res<String> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.to_string())
}

/// Stops the child when the test ends, pass or fail.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _reaped = self.0.wait();
    }
}

#[test]
fn dev_puts_a_tunnel_in_front_of_a_local_service() -> Res<()> {
    let (service, listen) = (hello_service()?, free_port()?);
    let to = format!("http://{service}");
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(["dev", "--to", &to, "--listen", &listen])
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let stdout = child.0.stdout.take().ok_or("no stdout")?;
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line)?;
    assert!(line.starts_with("tunnelward dev: ready."), "{line}");

    let mut agent = TcpStream::connect(&listen)?;
    agent.set_read_timeout(Some(Duration::from_secs(5)))?;
    agent.write_all(b"GET /anything HTTP/1.1\r\nhost: dev\r\nconnection: close\r\n\r\n")?;
    let mut answer = String::new();
    agent.read_to_string(&mut answer)?;
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
