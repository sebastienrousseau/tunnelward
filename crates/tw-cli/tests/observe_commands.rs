// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway file's `[risk]` and `[telemetry]`: checked by `config
//! check`, and a running gateway exporting a span to a collector on
//! loopback.

mod common;

use std::process::Command;
use std::time::Duration;

use common::{Res, ask, collector, pki_dir, spawn_gateway, text, tunnelward, write_config};

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
