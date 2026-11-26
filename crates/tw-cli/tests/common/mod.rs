// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Helpers the command tests share: running the binary and writing the
//! test PKI and a gateway file to a temporary directory.

#![allow(dead_code, unreachable_pub)] // each test file uses a different subset

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use tunnelward_testpki as pki;

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

pub fn tunnelward(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_tunnelward"))
        .args(args)
        .output()
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A fresh directory holding the test PKI as PEM files.
pub fn pki_dir(name: &str) -> Res<PathBuf> {
    let dir = std::env::temp_dir().join(format!("tunnelward-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("gateway.crt"),
        pki::pem("CERTIFICATE", pki::GATEWAY.0),
    )?;
    std::fs::write(
        dir.join("gateway.key"),
        pki::pem("PRIVATE KEY", pki::GATEWAY.1),
    )?;
    std::fs::write(dir.join("ca.crt"), pki::pem("CERTIFICATE", pki::CA))?;
    std::fs::write(
        dir.join("connector.crt"),
        pki::pem("CERTIFICATE", pki::CONNECTOR.0),
    )?;
    std::fs::write(
        dir.join("connector.key"),
        pki::pem("PRIVATE KEY", pki::CONNECTOR.1),
    )?;
    Ok(dir)
}

pub fn write_config(dir: &Path, extra: &str) -> Res<PathBuf> {
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

/// Kills the child when dropped.
pub struct Running(pub Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _reaped = self.0.wait();
    }
}

/// `tunnelward gateway` on `path`, and its connector and ingress
/// addresses once bound.
pub fn spawn_gateway_at(path: &Path) -> Res<(Running, String, String)> {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(["gateway", "--config", &path.to_string_lossy()])
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let mut started = String::new();
    BufReader::new(child.0.stdout.take().ok_or("no stdout")?).read_line(&mut started)?;
    let after = |label: &str| {
        (started.split(label).nth(1))
            .and_then(|rest| rest.split([',', ' ', '\n']).next())
            .map(str::to_owned)
            .ok_or_else(|| format!("no {label:?} address in {started:?}"))
    };
    let connectors = after("connectors on ")?;
    let agents = after("agents on ")?;
    Ok((child, connectors, agents))
}

/// [`spawn_gateway_at`], with only the ingress address.
pub fn spawn_gateway(path: &Path) -> Res<(Running, String)> {
    let (child, _connectors, agents) = spawn_gateway_at(path)?;
    Ok((child, agents))
}
