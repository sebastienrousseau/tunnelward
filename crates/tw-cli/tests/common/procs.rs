// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Running the gateway and the connector from their files, and reading
//! what they print, for the tests that drive both.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use tunnelward_testpki as pki;

use super::{Res, Running};

/// Lines a child prints.
pub type Lines = std::sync::mpsc::Receiver<String>;

/// The address after `<label> on ` in a startup line.
pub fn bound(line: &str, label: &str) -> Res<String> {
    let rest = line
        .split(&format!("{label} on "))
        .nth(1)
        .ok_or_else(|| format!("no {label} address in {line:?}"))?;
    Ok(rest.split([',', ' ']).next().unwrap_or_default().to_owned())
}

/// Lines a child prints, on a channel, so a test can wait for one.
pub fn lines(stream: impl Read + Send + 'static) -> Lines {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// Waits for a line containing `wanted`, and returns it.
pub fn expect(rx: &Lines, wanted: &str) -> Res<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        let line = rx.recv_timeout(left)?;
        if line.contains(wanted) {
            return Ok(line);
        }
    }
    Err(format!("no line containing {wanted:?}").into())
}

/// `tunnelward gateway` on `config`, with its stdout and stderr lines.
pub fn spawn_gateway_lines(config: &Path) -> Res<(Running, Lines, Lines)> {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(["gateway", "--config", &config.to_string_lossy()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let out = lines(child.0.stdout.take().ok_or("no stdout")?);
    let err = lines(child.0.stderr.take().ok_or("no stderr")?);
    Ok((child, out, err))
}

pub fn connector_file(dir: &Path, gateway: &str, target: &str, routes: &str) -> Res<PathBuf> {
    let path = dir.join("connector.toml");
    std::fs::write(
        &path,
        format!(
            "[gateway]\naddress = \"{gateway}\"\nserver_name = \"{}\"\nca = \"ca.crt\"\n\n\
             [identity]\ncert = \"connector.crt\"\nkey = \"connector.key\"\n\
             spiffe_id = \"spiffe://example.org/connector\"\n\n\
             [register]\nroutes = [{routes}]\n\n[target]\nurl = \"{target}\"\n",
            pki::GATEWAY_NAME
        ),
    )?;
    Ok(path)
}

pub fn gateway_file(dir: &Path, connectors: &str, ingress: &str) -> Res<PathBuf> {
    let path = dir.join("tunnelward.toml");
    std::fs::write(
        &path,
        format!(
            "[listen]\nconnectors = \"{connectors}\"\ningress = \"{ingress}\"\n\n\
             [tls]\ncert = \"gateway.crt\"\nkey = \"gateway.key\"\nclient_ca = \"ca.crt\"\n"
        ),
    )?;
    Ok(path)
}

/// `tunnelward connector` on `config`, with its stdout lines.
pub fn spawn_connector(config: &Path) -> Res<(Running, Lines)> {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(["connector", "--config", &config.to_string_lossy()])
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let out = lines(child.0.stdout.take().ok_or("no stdout")?);
    Ok((child, out))
}
