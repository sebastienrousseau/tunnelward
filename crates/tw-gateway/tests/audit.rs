// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The audit log at the ingress (FR-15, FR-18, G12, G14): every request
//! and admin action is recorded with digests and pseudonyms, the log
//! verifies offline, and a receipt verifies offline and breaks when any
//! field changes.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use serde_json::Value;
use tunnelward_audit::{Settings, Sink, receipt};
use tunnelward_crypto::composite::SigningKey;
use tunnelward_gateway::{AdminConfig, Gateway};
use tunnelward_policy::{Effect, Policy, Rule};

use common::ingress::{h1, ingress_config, start_ingress};
use common::{Res, registration, start_connector};

const CALL: &str = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"pay","arguments":{"amount":"12.50","iban":"GB00TEST0000"}}}"#;

struct Logged {
    gateway: Gateway,
    ingress: String,
    sink: Arc<Sink>,
    path: PathBuf,
    _connector: tokio::task::JoinHandle<()>,
}

/// A gateway with an audit log (receipts on) and a connector for `mcp`,
/// denying the tool `blocked`.
async fn logged(name: &str) -> Res<Logged> {
    let dir = std::env::temp_dir().join(format!(
        "tw-gw-audit-{name}-{}-{}",
        std::process::id(),
        tunnelward_audit::now_ms()
    ));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("audit.jsonl");
    let (key, _) = SigningKey::generate()?;
    let mut settings = Settings::new(path.clone(), key, [9; 32]);
    settings.receipts = true;
    let sink = Arc::new(Sink::open(settings)?);
    let policy = Policy {
        rules: vec![
            Rule::any(Effect::Permit),
            Rule {
                tools: vec!["blocked".into()],
                ..Rule::any(Effect::Forbid)
            },
        ],
        baseline: false,
        ..Policy::deny_by_default()
    };
    let mut config = ingress_config(|i| {
        i.policy = Some(Arc::new(policy) as Arc<dyn tunnelward_gateway::PolicyEngine>);
    })?;
    config.audit = Some(sink.clone());
    let (gateway, connectors, ingress) = start_ingress(config).await?;
    let connector = start_connector(&connectors, "echo", registration(1, &["mcp"], &[])).await?;
    Ok(Logged {
        gateway,
        ingress,
        sink,
        path,
        _connector: connector,
    })
}

async fn post(ingress: &str, body: &str) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    let request = Request::post("/mcp?ref=query-only")
        .header("host", "mcp.example.org")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_owned())))?;
    h1(ingress, request).await
}

/// The log's entries, once the sink has written and closed it.
fn entries(logged: &Logged) -> Res<(String, Vec<Value>)> {
    logged.sink.close();
    let text = std::fs::read_to_string(&logged.path)?;
    let lines = text
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((text, lines))
}

/// The receipt in `headers`, checked against `sink`'s key and `id`.
fn forwarded_receipt(sink: &Sink, headers: &hyper::HeaderMap, id: &str) -> Res<String> {
    let text = headers.get("tw-receipt").ok_or("no receipt")?.to_str()?;
    let got = receipt::verify(&sink.public_key(), text)?;
    assert_eq!(got.decision, "forwarded");
    assert_eq!(got.status, 200);
    assert_eq!(got.path, "/mcp");
    assert_eq!(got.calls[0].tool.as_deref(), Some("pay"));
    assert_eq!(got.request_id, id);
    Ok(text.to_owned())
}

/// The entry for request `id`, with the digests of what was sent.
fn forwarded_entry(entry: &Value, id: &str, body: &str, receipt: &str) {
    assert_eq!(entry["request_id"], id);
    assert_eq!(entry["host"], "mcp.example.org", "from the Host header");
    assert_eq!(entry["decision"], "forwarded");
    assert_eq!(entry["status"], 200);
    assert_eq!(
        entry["result_digest"],
        tunnelward_audit::digest(body.as_bytes())
    );
    assert_eq!(
        entry["request_digest"],
        tunnelward_audit::digest(CALL.as_bytes())
    );
    assert_eq!(
        entry["receipt"],
        tunnelward_audit::digest(receipt.as_bytes())
    );
    assert_eq!(entry["calls"][0]["tool"], "pay");
}

#[tokio::test]
async fn a_forwarded_call_is_logged_with_digests_and_a_receipt_that_verifies() -> Res<()> {
    let logged = logged("forward").await?;
    let (status, headers, body) = post(&logged.ingress, CALL).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = headers.get("tw-request-id").ok_or("no id")?.to_str()?;
    let text = forwarded_receipt(&logged.sink, &headers, id)?;
    let public = logged.sink.public_key();
    let (raw, lines) = entries(&logged)?;
    let entry = lines
        .iter()
        .find(|l| l["kind"] == "request")
        .ok_or("no entry")?;
    forwarded_entry(entry, id, &body, &text);
    clean_and_signed(&raw, public)
}

/// The log `raw` holds no raw value and verifies, signed to its end.
fn clean_and_signed(raw: &str, public: Vec<u8>) -> Res<()> {
    // Fixtures that must never reach the log: an argument value, the
    // query string and the client address.
    let absent = ["GB00TEST0000", "12.50", "query-only", "127.0.0.1"];
    for (i, value) in absent.iter().enumerate() {
        assert!(!raw.contains(value), "fixture {i} is in the log");
    }
    let report = tunnelward_audit::verify::verify(raw.as_bytes(), &[public])?;
    assert!(report.ok(), "{report:?}");
    assert_eq!(report.unsigned, 0);
    Ok(())
}

#[tokio::test]
async fn a_denied_call_is_logged_as_refused_with_its_receipt() -> Res<()> {
    let logged = logged("deny").await?;
    let blocked = CALL.replace("\"pay\"", "\"blocked\"");
    let (_, headers, _) = post(&logged.ingress, &blocked).await?;
    let text = headers.get("tw-receipt").ok_or("no receipt")?.to_str()?;
    let got = receipt::verify(&logged.sink.public_key(), text)?;
    assert_eq!(got.decision, "refused");
    assert!(got.error.is_some());
    let (_, lines) = entries(&logged)?;
    let entry = lines
        .iter()
        .find(|l| l["kind"] == "request")
        .ok_or("no entry")?;
    assert_eq!(entry["decision"], "refused");
    assert_eq!(entry["calls"][0]["tool"], "blocked");
    Ok(())
}

#[tokio::test]
async fn admin_dark_actions_are_logged_without_raw_addresses() -> Res<()> {
    let logged = logged("admin").await?;
    let peer = "127.0.0.1:9".parse()?;
    let request = Request::post("/dark?peer=192.0.2.44&on=true").body(())?;
    let answer = logged
        .gateway
        .admin(&AdminConfig::default(), peer, &request)
        .await;
    assert_eq!(answer.status(), StatusCode::OK);
    let (raw, lines) = entries(&logged)?;
    let entry = lines
        .iter()
        .find(|l| l["kind"] == "admin")
        .ok_or("no entry")?;
    assert_eq!(entry["action"], "dark");
    assert_eq!(entry["changed"], true);
    assert!(
        entry["target"]
            .as_str()
            .is_some_and(|t| t.starts_with("peer:"))
    );
    assert!(!raw.contains("192.0.2.44") && !raw.contains("127.0.0.1"));
    Ok(())
}
