// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! passmcp, the Satellion suite's MCP validator, against an MCP server
//! served through the whole tunnel: the gateway's ingress, a connector
//! and its stdio bridge in front of the `stdio-echo` example. The run
//! must find nothing failing. Ignored by default: it needs `passmcp` on
//! the PATH and the example built; scripts/passmcp-check.sh runs it.

mod common;

use std::path::PathBuf;
use std::process::Command;

use tunnelward_connector::{StdioBridge, StdioConfig, register};

use common::ingress::{ingress_config, start_ingress};
use common::{Res, connector_config, registration};

/// The `stdio-echo` example (see tunnelward-connector's tests/stdio.rs).
fn echo_server() -> Res<PathBuf> {
    let exe = std::env::current_exe()?;
    let name = format!("stdio-echo{}", std::env::consts::EXE_SUFFIX);
    exe.ancestors()
        .map(|dir| dir.join("examples").join(&name))
        .find(|path| path.is_file())
        .ok_or_else(|| {
            "build it first: cargo build -p tunnelward-connector --example stdio-echo".into()
        })
}

/// passmcp's JSON report on `url`, and whether it exited 0.
fn passmcp(url: &str) -> Res<(serde_json::Value, bool)> {
    let out = Command::new("passmcp")
        .args(["check", url, "--output", "json"])
        .output()?;
    Ok((serde_json::from_slice(&out.stdout)?, out.status.success()))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs passmcp on the PATH: scripts/passmcp-check.sh"]
async fn passmcp_finds_nothing_failing_through_the_tunnel() -> Res<()> {
    let (_gateway, connectors, ingress) = start_ingress(ingress_config(|_| {})?).await?;
    let bridge = StdioBridge::new(StdioConfig::new(
        echo_server()?.to_string_lossy(),
        Vec::new(),
    ));
    let session = register(&connector_config(
        &connectors,
        registration(1, &["mcp"], &[]),
    )?)
    .await?;
    tokio::spawn(async move {
        let _ended = session.serve(bridge).await;
    });
    let url = format!("http://{ingress}/mcp");
    let (report, passed) = tokio::task::spawn_blocking(move || passmcp(&url)).await??;
    let counts = &report["counts"];
    println!(
        "passmcp through the tunnel: {counts}, grade {}",
        report["score"]["grade"]
    );
    assert_eq!(counts["fail"], 0, "{report:#}");
    assert!(passed, "passmcp exited non-zero");
    Ok(())
}
