// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Mismatches between claims and evidence (FR-14): a request whose
//! `User-Agent` or `clientInfo` names a provider the gateway did not see
//! is recorded as declared, with a mismatch, and policy can act on it.

mod common;

use std::sync::{Arc, Mutex};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use tunnelward_gateway::{ClaimSource, Mismatch, Providers, ProxyObserver, RequestInfo};
use tunnelward_policy::{Effect, Evidence, Policy, Rule};

use common::ingress::{h1, ingress_config, start_ingress};
use common::{Res, registration, start_connector};

/// What the gateway recorded about each request.
#[derive(Debug, Default)]
struct Seen(Mutex<Vec<(Evidence, Vec<Mismatch>)>>);

impl ProxyObserver for Seen {
    fn on_response(&self, info: &RequestInfo, _: StatusCode, _: std::time::Duration) {
        if let Ok(mut seen) = self.0.lock() {
            seen.push((info.evidence, info.mismatches.clone()));
        }
    }
}

/// Loopback tagged as `provider`.
fn loopback_as(provider: &str) -> Res<Providers> {
    let key = Ed25519KeyPair::generate().map_err(|_| "key generation")?;
    let snap = format!(
        r#"{{"version":1,"providers":[{{"provider":"{provider}","agent":"test","ranges":["127.0.0.0/8"]}}]}}"#
    );
    let providers = Providers::new(vec![key.public_key().as_ref().to_vec()]);
    providers.load(snap.as_bytes(), key.sign(snap.as_bytes()).as_ref())?;
    Ok(providers)
}

/// A gateway seeing loopback as `provider` (none when `None`), with an
/// optional policy; returns its ingress and what it recorded.
async fn gateway(provider: Option<&str>, policy: Option<Policy>) -> Res<(String, Arc<Seen>)> {
    let seen = Arc::new(Seen::default());
    let observer = seen.clone();
    let providers = provider.map(loopback_as).transpose()?.map(Arc::new);
    let config = ingress_config(|i| {
        i.observers.push(observer);
        i.providers = providers;
        i.policy = policy.map(|p| Arc::new(p) as Arc<dyn tunnelward_gateway::PolicyEngine>);
    })?;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    let _connector = start_connector(&connectors, "echo", registration(1, &["mcp"], &[])).await?;
    Ok((ingress, seen))
}

async fn post(ingress: &str, user_agent: &str, body: &str) -> Res<(StatusCode, String)> {
    let request = Request::post("/mcp")
        .header("host", "mcp.example.org")
        .header("user-agent", user_agent)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_owned())))?;
    let (status, _, body) = h1(ingress, request).await?;
    Ok((status, body))
}

const PING: &str = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;

fn last(seen: &Seen) -> Option<(Evidence, Vec<Mismatch>)> {
    seen.0.lock().ok()?.last().cloned()
}

#[tokio::test]
async fn a_claude_request_from_outside_the_ranges_is_declared_with_a_mismatch() -> Res<()> {
    let (ingress, seen) = gateway(None, None).await?;
    post(&ingress, "Claude-User/1.0", PING).await?;
    let (evidence, mismatches) = last(&seen).ok_or("nothing recorded")?;
    assert_eq!(evidence, Evidence::Declared);
    let expected = Mismatch {
        source: ClaimSource::UserAgent,
        claimed: "anthropic",
        seen: None,
    };
    assert_eq!(mismatches, [expected]);
    Ok(())
}

#[tokio::test]
async fn a_claim_the_ranges_back_is_no_mismatch_and_another_provider_is() -> Res<()> {
    let (ingress, seen) = gateway(Some("anthropic"), None).await?;
    post(&ingress, "Claude-User/1.0", PING).await?;
    assert_eq!(last(&seen), Some((Evidence::Network, Vec::new())));
    let (ingress, seen) = gateway(Some("openai"), None).await?;
    post(&ingress, "Claude-User/1.0", PING).await?;
    let (_, mismatches) = last(&seen).ok_or("nothing recorded")?;
    assert_eq!(
        mismatches.first().map(|m| m.seen.clone()),
        Some(Some("openai".into()))
    );
    Ok(())
}

#[tokio::test]
async fn a_client_info_claim_is_checked_too() -> Res<()> {
    let (ingress, seen) = gateway(None, None).await?;
    let initialize = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"claude-ai","version":"1.0"}}}"#;
    post(&ingress, "curl/8.7.1", initialize).await?;
    let (_, mismatches) = last(&seen).ok_or("nothing recorded")?;
    assert_eq!(mismatches.len(), 1, "{mismatches:?}");
    assert_eq!(mismatches[0].source, ClaimSource::ClientInfo);
    post(&ingress, "curl/8.7.1", PING).await?;
    assert_eq!(
        last(&seen).map(|s| s.1),
        Some(Vec::new()),
        "no claim, no mismatch"
    );
    Ok(())
}

#[tokio::test]
async fn policy_can_forbid_calls_whose_claims_do_not_hold() -> Res<()> {
    let policy = Policy {
        rules: vec![
            Rule::any(Effect::Permit),
            Rule {
                mismatch: Some(true),
                ..Rule::any(Effect::Forbid)
            },
        ],
        baseline: false,
        ..Policy::deny_by_default()
    };
    let (ingress, _) = gateway(None, Some(policy)).await?;
    let (_, body) = post(&ingress, "Claude-User/1.0", PING).await?;
    assert!(
        body.contains("-32001"),
        "a dressed-up claim is denied: {body}"
    );
    let (_, body) = post(&ingress, "curl/8.7.1", PING).await?;
    assert!(!body.contains("-32001"), "an honest one is not: {body}");
    Ok(())
}
