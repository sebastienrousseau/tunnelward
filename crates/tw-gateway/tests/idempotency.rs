// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Idempotency keys on high-impact tools (FR-13) and the D6 evidence
//! they need: a repeated key returns the first answer and the tool does
//! not run twice, here or at another gateway sharing the store.

mod common;

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tunnelward_connector::register;
use tunnelward_gateway::{AgentAuth, InMemory, Issuer, KeySet, SharedState};
use tunnelward_policy::{Effect, Policy, Rule};

use common::agent::{Agent, ISSUER, RESOURCE, agent, transfer};
use common::ingress::{ingress_config, start_ingress};
use common::jwt::Signer;
use common::{Res, connector_config, registration};

/// A gateway sharing `state`, permitting every tool with `transfer`
/// marked high impact; its connector counts runs into `runs`.
async fn gateway(
    agent: &Agent,
    state: Arc<dyn SharedState>,
    runs: Arc<AtomicUsize>,
) -> Res<String> {
    let keys = KeySet::from_jwks(Signer::jwks(&[&agent.issuer]).as_bytes())?;
    let auth = AgentAuth::new(
        RESOURCE,
        vec![Issuer {
            issuer: ISSUER.into(),
            keys: Arc::new(keys),
        }],
    );
    let policy = Policy {
        rules: vec![Rule::any(Effect::Permit)],
        high_impact: vec!["transfer".into()],
        ..Policy::deny_by_default()
    };
    let mut config = ingress_config(|i| {
        i.agent_auth = Some(auth);
        i.policy = Some(Arc::new(policy));
    })?;
    config.state = state;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    let session = register(&connector_config(
        &connectors,
        registration(1, &["mcp"], &[]),
    )?)
    .await?;
    tokio::spawn(async move {
        let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
            let run = runs.fetch_add(1, Ordering::SeqCst) + 1;
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"run":{run}}}}}"#);
            std::future::ready(Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                body,
            )))))
        });
        let _ended = session.serve(service).await;
    });
    Ok(ingress)
}

#[tokio::test]
async fn a_repeated_key_returns_the_first_answer_without_a_second_run() -> Res<()> {
    let (agent, runs) = (agent()?, Arc::new(AtomicUsize::new(0)));
    let ingress = gateway(&agent, Arc::new(InMemory::default()), runs.clone()).await?;
    let (status, _, first) = transfer(&ingress, &agent, (100, Some("k1")), true).await?;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert!(first.contains(r#""run":1"#), "{first}");
    let (status, headers, again) = transfer(&ingress, &agent, (100, Some("k1")), true).await?;
    assert_eq!((status, again.as_str()), (StatusCode::OK, first.as_str()));
    assert!(headers.contains_key("tw-idempotent-replay"));
    assert_eq!(runs.load(Ordering::SeqCst), 1, "the tool ran once");
    Ok(())
}

#[tokio::test]
async fn a_high_impact_call_needs_a_key_and_the_same_request_for_it() -> Res<()> {
    let (agent, runs) = (agent()?, Arc::new(AtomicUsize::new(0)));
    let ingress = gateway(&agent, Arc::new(InMemory::default()), runs.clone()).await?;
    let (status, _, body) = transfer(&ingress, &agent, (100, None), true).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("TW-P002"), "{body}");
    assert_eq!(
        transfer(&ingress, &agent, (100, Some("k2")), true).await?.0,
        StatusCode::OK
    );
    let (status, _, body) = transfer(&ingress, &agent, (999, Some("k2")), true).await?;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the key, another amount"
    );
    assert!(body.contains("TW-P004"), "{body}");
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn a_high_impact_call_needs_cryptographic_evidence() -> Res<()> {
    let (agent, runs) = (agent()?, Arc::new(AtomicUsize::new(0)));
    let ingress = gateway(&agent, Arc::new(InMemory::default()), runs.clone()).await?;
    let (status, _, body) = transfer(&ingress, &agent, (100, Some("k3")), false).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("-32001") && body.contains("cryptographic"),
        "{body}"
    );
    assert_eq!(
        runs.load(Ordering::SeqCst),
        0,
        "a plain token is not enough (D6)"
    );
    Ok(())
}

#[tokio::test]
async fn a_key_in_use_at_another_gateway_is_refused_and_then_replayed() -> Res<()> {
    let (agent, runs) = (agent()?, Arc::new(AtomicUsize::new(0)));
    let shared: Arc<dyn SharedState> = Arc::new(InMemory::default());
    let first = gateway(&agent, shared.clone(), runs.clone()).await?;
    let second = gateway(&agent, shared.clone(), runs.clone()).await?;
    // Another gateway is running a call with k4 right now.
    let held = "idem:agent:/mcp:k4";
    shared.claim(held, Duration::from_secs(60)).await?;
    let (status, headers, body) = transfer(&first, &agent, (100, Some("k4")), true).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(headers.contains_key("retry-after"));
    shared.release(held).await?;
    assert_eq!(
        transfer(&first, &agent, (100, Some("k5")), true).await?.0,
        StatusCode::OK
    );
    let (status, _, body) = transfer(&second, &agent, (100, Some("k5")), true).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(runs.load(Ordering::SeqCst), 1, "once across both gateways");
    Ok(())
}
