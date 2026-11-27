// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward conformance` against a running `tunnelward gateway`.

mod common;

use common::{Res, pki_dir, spawn_gateway_at, text, tunnelward, write_config};
use tunnelward_testpki as pki;

/// The kit's arguments for the test PKI in `dir`, against `gateway`.
fn kit_args(dir: &std::path::Path, gateway: &str) -> Vec<String> {
    let file = |name: &str| dir.join(name).to_string_lossy().into_owned();
    [
        "conformance",
        "--gateway",
        gateway,
        "--server-name",
        pki::GATEWAY_NAME,
        "--ca",
        &file("ca.crt"),
        "--cert",
        &file("connector.crt"),
        "--key",
        &file("connector.key"),
        "--timeout-secs",
        "2",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn run(args: &[String]) -> Res<std::process::Output> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    Ok(tunnelward(&args)?)
}

#[test]
fn a_running_gateway_passes_the_kit() -> Res<()> {
    let dir = pki_dir("conformance-pass")?;
    let (_gateway, connectors, _agents) = spawn_gateway_at(&write_config(&dir, "")?)?;
    let out = run(&kit_args(&dir, &connectors))?;
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("6 of 6 checks passed"), "{stdout}");
    let mut json = kit_args(&dir, &connectors);
    json.extend(["--format".into(), "json".into()]);
    let out = run(&json)?;
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(report["kit"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["outcomes"].as_array().map(Vec::len), Some(6));
    Ok(())
}

#[test]
fn nothing_listening_fails_with_every_check_named() -> Res<()> {
    let dir = pki_dir("conformance-fail")?;
    let closed = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .to_string();
    let out = run(&kit_args(&dir, &closed))?;
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("FAIL register"), "{stdout}");
    assert!(text(&out.stderr).contains("a check failed"));
    Ok(())
}

#[test]
fn a_missing_flag_or_format_is_a_usage_error() -> Res<()> {
    let out = tunnelward(&["conformance", "--gateway", "127.0.0.1:1"])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("--server-name"));
    let dir = pki_dir("conformance-usage")?;
    let mut args = kit_args(&dir, "127.0.0.1:1");
    args.extend(["--format".into(), "xml".into()]);
    assert_eq!(run(&args)?.status.code(), Some(2));
    Ok(())
}
