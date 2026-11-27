// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward crypto report`: the TLS each live connector connection
//! negotiated, read from a running gateway's admin API.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

use common::{Res, Running, text, tunnelward};

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

/// A loopback port free a moment ago.
fn free_port() -> Res<String> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.to_string())
}

#[test]
fn crypto_report_lists_the_tls_each_connector_negotiated() -> Res<()> {
    let to = format!("http://{}", hello_service()?);
    let admin = free_port()?;
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args([
                "dev",
                "--to",
                &to,
                "--listen",
                "127.0.0.1:0",
                "--admin",
                &admin,
            ])
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let mut line = String::new();
    BufReader::new(child.0.stdout.take().ok_or("no stdout")?).read_line(&mut line)?;
    assert!(line.starts_with("tunnelward dev: ready."), "{line}");
    let out = tunnelward(&["crypto", "report", "--admin", &admin])?;
    let report = text(&out.stdout);
    assert!(out.status.success(), "{report}{}", text(&out.stderr));
    let row = report.lines().nth(1).unwrap_or_default();
    for want in ["TLSv1_3", "X25519MLKEM768", "TLS13_", "ECDSA P-256"] {
        assert!(row.contains(want), "{want}: {report}");
    }
    // dev's connector keeps two connections to its gateway.
    assert!(
        report.ends_with("connections 2, hybrid post-quantum 2, classical 0\n"),
        "{report}"
    );
    let refused = tunnelward(&["crypto", "report", "--admin", &free_port()?])?;
    assert_eq!(refused.status.code(), Some(1));
    Ok(())
}
