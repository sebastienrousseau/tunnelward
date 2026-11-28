// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! A stdio MCP server through the tunnel, from the gateway's and the
//! connector's files: the bridge (FR-6), and the server descriptor and
//! tool guard (ADR 0017).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod common;

use common::procs::{
    bound, connector_file, expect, gateway_file, spawn_connector, spawn_gateway_lines,
};
use common::{Res, Running, pki_dir, text, tunnelward};

/// tunnelward-connector's `stdio-echo` example, which a workspace
/// `cargo test` builds into the profile directory's `examples`. The test
/// binary sits in `deps` below that directory, or deeper in Cargo's newer
/// build layout (`build/<package>/<hash>/out`), so every ancestor is
/// tried.
fn stdio_echo() -> Res<PathBuf> {
    let exe = std::env::current_exe()?;
    let name = format!("stdio-echo{}", std::env::consts::EXE_SUFFIX);
    exe.ancestors()
        .map(|dir| dir.join("examples").join(&name))
        .find(|path| path.is_file())
        .ok_or_else(|| "the stdio-echo example is not built: run `cargo test --workspace`".into())
}

/// Sends `request` to `ingress` and reads until `until` appears.
fn read_until(ingress: &str, request: &str, until: &str) -> Res<String> {
    let mut agent = TcpStream::connect(ingress)?;
    agent.set_read_timeout(Some(Duration::from_secs(10)))?;
    agent.write_all(request.as_bytes())?;
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 4096];
    while !String::from_utf8_lossy(&seen).contains(until) {
        let n = agent.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        seen.extend_from_slice(&chunk[..n]);
    }
    Ok(String::from_utf8_lossy(&seen).into_owned())
}

/// A JSON-RPC POST to `/mcp/`, in `session` when given.
fn mcp_post(body: &str, session: Option<&str>) -> String {
    let session = session.map_or(String::new(), |s| format!("mcp-session-id: {s}\r\n"));
    format!(
        "POST /mcp/ HTTP/1.1\r\nhost: h\r\ncontent-type: application/json\r\n{session}\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A connector file in `dir` for `gateway` whose target is the stdio
/// example.
fn stdio_connector_file(dir: &Path, gateway: &str) -> Res<PathBuf> {
    let file = connector_file(dir, gateway, "unused", "\"mcp\"")?;
    let stdio = format!("stdio = ['{}']", stdio_echo()?.display());
    let text = std::fs::read_to_string(&file)?.replace("url = \"unused\"", &stdio);
    std::fs::write(&file, text)?;
    Ok(file)
}

/// A gateway and a connector bridging to the stdio example, in `dir`:
/// both processes and the ingress address, once registered.
fn start_stdio_pair(dir: &Path) -> Res<(Running, Running, String)> {
    start_stdio_pair_with(dir, "", "Registered")
}

/// [`start_stdio_pair`] with `extra` appended to the connector's file,
/// once the connector has printed `first` and then registered.
fn start_stdio_pair_with(dir: &Path, extra: &str, first: &str) -> Res<(Running, Running, String)> {
    let (gateway, connectors, ingress) = start_gateway(dir)?;
    let file = stdio_connector_file(dir, &connectors)?;
    std::fs::write(&file, std::fs::read_to_string(&file)? + extra)?;
    let (connector, connector_out) = spawn_connector(&file)?;
    expect(&connector_out, first)?;
    expect(&connector_out, "Registered")?;
    Ok((gateway, connector, ingress))
}

/// A gateway on loopback ports in `dir`: the process, its connector
/// address and its ingress address.
fn start_gateway(dir: &Path) -> Res<(Running, String, String)> {
    let (gateway, out, _) = spawn_gateway_lines(&gateway_file(dir, "127.0.0.1:0", "127.0.0.1:0")?)?;
    let started = expect(&out, "connectors on")?;
    Ok((
        gateway,
        bound(&started, "connectors")?,
        bound(&started, "agents")?,
    ))
}

/// Initialises an MCP session through `ingress`; its id.
fn initialise(ingress: &str) -> Res<String> {
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;
    let answer = read_until(ingress, &mcp_post(init, None), "stdio-echo")?;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let id = answer
        .lines()
        .find_map(|l| l.strip_prefix("mcp-session-id: "))
        .ok_or("no session id")?;
    Ok(id.trim().to_owned())
}

#[test]
fn a_stdio_mcp_server_is_served_through_the_tunnel() -> Res<()> {
    let dir = pki_dir("stdio-bridge")?;
    let (gateway, connector, ingress) = start_stdio_pair(&dir)?;
    let session = initialise(&ingress)?;
    let call = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"through the tunnel"}}}"#;
    let answer = read_until(
        &ingress,
        &mcp_post(call, Some(&session)),
        "through the tunnel",
    )?;
    assert!(
        answer.contains(r#""text":"through the tunnel""#),
        "{answer}"
    );
    let stream = format!(
        "GET /mcp/ HTTP/1.1\r\nhost: h\r\naccept: text/event-stream\r\nmcp-session-id: {session}\r\n\r\n"
    );
    let events = read_until(&ingress, &stream, "echoing through the tunnel")?;
    assert!(events.contains("id: 1\n"), "{events}");
    drop((connector, gateway));
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_described_stdio_server_registers_with_its_name_and_serves_its_tools() -> Res<()> {
    let dir = pki_dir("stdio-described")?;
    let describe = "\n[register.describe]\non_change = \"block\"\n";
    let (gateway, connector, ingress) =
        start_stdio_pair_with(&dir, describe, "serving stdio-echo 1.0.0")?;
    let session = initialise(&ingress)?;
    let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
    let answer = read_until(&ingress, &mcp_post(list, Some(&session)), "inputSchema")?;
    assert!(answer.contains(r#""name":"echo""#), "{answer}");
    drop((connector, gateway));
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_describe_path_must_be_a_path() -> Res<()> {
    let dir = pki_dir("describe-check")?;
    let file = connector_file(&dir, "127.0.0.1:7443", "http://127.0.0.1:8080", "\"mcp\"")?;
    let mut toml = std::fs::read_to_string(&file)?;
    toml.push_str("\n[register.describe]\npath = \"mcp\"\n");
    std::fs::write(&file, toml)?;
    let out = tunnelward(&["config", "check", &file.to_string_lossy()])?;
    let errors = text(&out.stderr);
    assert!(
        errors.contains("[register.describe] path \"mcp\": give a path starting with /"),
        "{errors}"
    );
    Ok(std::fs::remove_dir_all(dir)?)
}
