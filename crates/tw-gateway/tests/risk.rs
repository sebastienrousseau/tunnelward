// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The risk score at the ingress (FR-16, ADR 0011): FR-16's acceptance
//! run, a scripted search-then-bulk-export, is refused by a policy that
//! forbids risky calls once it crosses the threshold, and observers are
//! alerted; a canary call is refused, ends its session, and alerts.

mod common;

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tunnelward_connector::register;
use tunnelward_gateway::{Config, ProxyObserver, RequestInfo};
use tunnelward_policy::{Effect, Policy, Rule};
use tunnelward_risk::{Risk, Settings};

use common::ingress::{h1, ingress_config, start_ingress};
use common::{Res, connector_config, registration};

/// Every alert, as `(score, signals)`.
#[derive(Debug, Default)]
struct Alerts(Mutex<Vec<(u8, Vec<String>)>>);

impl ProxyObserver for Alerts {
    fn on_alert(&self, info: &RequestInfo) {
        let risk = info.risk.as_ref().map(|r| {
            let signals = r.signals.iter().map(ToString::to_string).collect();
            (r.score, signals)
        });
        if let Some(alert) = risk {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(alert);
        }
    }
}

impl Alerts {
    fn taken(&self) -> Vec<(u8, Vec<String>)> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Permit everything, forbid a score of 70 or more.
fn policy() -> Policy {
    Policy {
        rules: vec![
            Rule::any(Effect::Permit),
            Rule {
                risk: Some(70),
                ..Rule::any(Effect::Forbid)
            },
        ],
        baseline: false,
        ..Policy::deny_by_default()
    }
}

/// A gateway scoring with `settings` and the [`policy`], its alerts,
/// and a connector on `mcp` counting what reaches it.
async fn gateway(settings: Settings) -> Res<(String, Arc<Alerts>, Arc<AtomicUsize>)> {
    gateway_audited(settings, None).await
}

/// [`gateway`], writing to the audit log `audit` when given.
async fn gateway_audited(
    settings: Settings,
    audit: Option<Arc<tunnelward_audit::Sink>>,
) -> Res<(String, Arc<Alerts>, Arc<AtomicUsize>)> {
    let alerts = Arc::new(Alerts::default());
    let observer: Arc<dyn ProxyObserver> = alerts.clone();
    let mut config: Config = ingress_config(|i| {
        i.risk = Some(Arc::new(Risk::new(settings)));
        i.policy = Some(Arc::new(policy()));
        i.observers = vec![observer];
    })?;
    config.audit = audit;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    let session = register(&connector_config(
        &connectors,
        registration(1, &["mcp"], &[]),
    )?)
    .await?;
    let reached = Arc::new(AtomicUsize::new(0));
    let counter = reached.clone();
    tokio::spawn(async move {
        let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
            counter.fetch_add(1, Ordering::SeqCst);
            let ok = Full::new(Bytes::from(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#));
            std::future::ready(Ok::<_, Infallible>(Response::new(ok)))
        });
        let _ended = session.serve(service).await;
    });
    Ok((ingress, alerts, reached))
}

/// Calls `tool` with `arguments` in MCP session `session`.
async fn call(
    ingress: &str,
    session: &str,
    tool: &str,
    arguments: &str,
) -> Res<(StatusCode, String)> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments}}}}}"#
    );
    let request = Request::post("/mcp")
        .header("host", "mcp.example.org")
        .header("content-type", "application/json")
        .header("mcp-session-id", session)
        .body(Full::new(Bytes::from(body)))?;
    let (status, _, body) = h1(ingress, request).await?;
    Ok((status, body))
}

#[tokio::test]
async fn a_scripted_search_then_bulk_export_is_refused_once_it_crosses() -> Res<()> {
    let (ingress, alerts, reached) = gateway(Settings {
        per_subject: 40,
        per_tool: 30,
        ..Settings::default()
    })
    .await?;
    for _ in 0..25 {
        let (status, body) = call(&ingress, "s1", "search", "{}").await?;
        assert!(
            status == StatusCode::OK && body.contains("\"result\""),
            "{body}"
        );
    }
    assert!(
        alerts.taken().is_empty(),
        "25 searches stay under the alert"
    );
    let mut refused_at = None;
    for n in 1..=40 {
        let (_, body) = call(&ingress, "s1", "export", "{}").await?;
        if body.contains("TW-P001") {
            refused_at = Some(n);
            break;
        }
    }
    let n = refused_at.ok_or("the bulk export was never refused")?;
    assert_eq!(
        reached.load(Ordering::SeqCst),
        25 + n - 1,
        "refused calls never reach it"
    );
    let alert = alerts.taken().first().cloned().ok_or("no alert")?;
    assert!(alert.0 >= 70, "{alert:?}");
    assert!(alert.1.iter().any(|s| s.starts_with("drift:")), "{alert:?}");
    Ok(())
}

#[tokio::test]
async fn a_canary_call_is_refused_ends_its_session_and_alerts() -> Res<()> {
    let (ingress, alerts, reached) = gateway(Settings {
        canary_tools: vec!["export_all_customers".into()],
        canary_records: vec!["CANARY-4417".into()],
        ..Settings::default()
    })
    .await?;
    let (status, _) = call(&ingress, "s1", "search", "{}").await?;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = call(&ingress, "s1", "export_all_customers", "{}").await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.contains("TW-I013") || body.contains("canary"),
        "{body}"
    );
    let (status, _) = call(&ingress, "s1", "search", "{}").await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "the session stays ended");
    assert_eq!(reached.load(Ordering::SeqCst), 1);
    assert_eq!(
        alerts.taken(),
        [(100, vec!["canary-tool:export_all_customers".to_owned()])]
    );
    Ok(())
}

#[tokio::test]
async fn a_canary_record_in_the_arguments_ends_the_session_too() -> Res<()> {
    let (ingress, alerts, _) = gateway(Settings {
        canary_records: vec!["CANARY-4417".into()],
        ..Settings::default()
    })
    .await?;
    let (status, _) = call(&ingress, "s2", "lookup", r#"{"account":"CANARY-4417"}"#).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(alerts.taken(), [(100, vec!["canary-record".to_owned()])]);
    Ok(())
}

#[tokio::test]
async fn the_score_and_its_signals_are_in_the_audit_entry() -> Res<()> {
    let dir = std::env::temp_dir().join(format!(
        "tw-gw-risk-audit-{}-{}",
        std::process::id(),
        tunnelward_audit::now_ms()
    ));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("audit.jsonl");
    let (key, _) = tunnelward_crypto::composite::SigningKey::generate()?;
    let sink = Arc::new(tunnelward_audit::Sink::open(
        tunnelward_audit::Settings::new(path.clone(), key, [9; 32]),
    )?);
    let settings = Settings {
        canary_tools: vec!["export_all_customers".into()],
        ..Settings::default()
    };
    let (ingress, _, _) = gateway_audited(settings, Some(sink.clone())).await?;
    call(&ingress, "s3", "search", "{}").await?;
    call(&ingress, "s3", "export_all_customers", "{}").await?;
    sink.close();
    let entries: Vec<serde_json::Value> = (std::fs::read_to_string(&path)?.lines())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let requests: Vec<_> = entries.iter().filter(|e| e["kind"] == "request").collect();
    assert_eq!(requests.len(), 2, "{entries:?}");
    assert_eq!(requests[0]["risk"], 0);
    assert_eq!(requests[1]["risk"], 100);
    assert_eq!(
        requests[1]["risk_signals"][0],
        "canary-tool:export_all_customers"
    );
    assert_eq!(requests[1]["error"], "TW-I013");
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
