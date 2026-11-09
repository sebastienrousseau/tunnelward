// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Tool policy at the ingress (FR-4, FR-14): a denied call is answered by
//! the gateway with a JSON-RPC error and never reaches the connector; a
//! body the policy cannot read is refused; the policy can be replaced at
//! runtime; and a rule demanding cryptographic evidence denies the same
//! call from a client known only by its network.

mod common;

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tunnelward_connector::register;
use tunnelward_gateway::{Config, Gateway, Providers};
use tunnelward_policy::{Effect, Evidence, Policy, Rule};

use common::ingress::{h1, ingress_config, start_ingress};
use common::{Res, connector_config, registration};

/// Rules: read_* allowed, delete_* forbidden, plain GETs allowed; deny
/// by default; no D6 baseline (these tests have no tokens).
fn tools_policy() -> Policy {
    let list = |items: &[&str]| items.iter().map(|i| (*i).to_owned()).collect();
    Policy {
        rules: vec![
            Rule {
                tools: list(&["read_*"]),
                ..Rule::any(Effect::Permit)
            },
            Rule {
                methods: list(&["initialize", "tools/list", "http:GET"]),
                ..Rule::any(Effect::Permit)
            },
            Rule {
                tools: list(&["delete_*"]),
                ..Rule::any(Effect::Forbid)
            },
        ],
        baseline: false,
        ..Policy::deny_by_default()
    }
}

/// A gateway with `config` and a connector on `mcp` that counts what
/// reaches it: (gateway, ingress address, count).
async fn gateway(config: Config) -> Res<(Gateway, String, Arc<AtomicUsize>)> {
    let (gateway, connectors, ingress) = start_ingress(config).await?;
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
            let ok = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
            std::future::ready(Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                ok,
            )))))
        });
        let _ended = session.serve(service).await;
    });
    Ok((gateway, ingress, reached))
}

async fn with_policy(policy: Policy) -> Res<(Gateway, String, Arc<AtomicUsize>)> {
    gateway(ingress_config(|i| i.policy = Some(Arc::new(policy)))?).await
}

async fn post(ingress: &str, body: &str) -> Res<(StatusCode, String)> {
    let request = Request::post("/mcp")
        .header("host", "mcp.example.org")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_owned())))?;
    let (status, _, body) = h1(ingress, request).await?;
    Ok((status, body))
}

fn tool_call(id: u32, tool: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}"}}}}"#)
}

#[tokio::test]
async fn a_permitted_call_reaches_the_connector() -> Res<()> {
    let (_g, ingress, reached) = with_policy(tools_policy()).await?;
    let (status, body) = post(&ingress, &tool_call(1, "read_balance")).await?;
    assert_eq!(
        (status, body.contains("\"result\"")),
        (StatusCode::OK, true)
    );
    assert_eq!(reached.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn a_denied_call_gets_a_json_rpc_error_and_never_reaches_the_connector() -> Res<()> {
    let (_g, ingress, reached) = with_policy(tools_policy()).await?;
    for tool in ["delete_account", "transfer"] {
        let (status, body) = post(&ingress, &tool_call(7, tool)).await?;
        assert_eq!(status, StatusCode::OK, "a JSON-RPC answer");
        let answer: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(answer["id"], 7);
        assert_eq!(answer["error"]["code"], -32001);
        assert_eq!(answer["error"]["data"]["tw_error"], "TW-P001");
    }
    assert_eq!(
        reached.load(Ordering::SeqCst),
        0,
        "nothing reached the connector"
    );
    Ok(())
}

#[tokio::test]
async fn one_denied_call_in_a_batch_holds_back_the_whole_batch() -> Res<()> {
    let (_g, ingress, reached) = with_policy(tools_policy()).await?;
    let batch = format!(
        "[{},{}]",
        tool_call(1, "read_balance"),
        tool_call(2, "delete_account")
    );
    let (status, body) = post(&ingress, &batch).await?;
    assert_eq!(status, StatusCode::OK);
    let answers: Vec<serde_json::Value> = serde_json::from_str(&body)?;
    let ids: Vec<_> = answers.iter().map(|a| a["id"].clone()).collect();
    assert_eq!(ids, [serde_json::json!(1), serde_json::json!(2)]);
    assert_eq!(reached.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn json_the_policy_cannot_read_is_refused() -> Res<()> {
    let (_g, ingress, reached) = with_policy(tools_policy()).await?;
    let hidden = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":42}}"#;
    for body in [r#"{"not":"json-rpc"}"#, hidden, "[]"] {
        let (status, text) = post(&ingress, body).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(text.contains("TW-P001"), "{text}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn the_policy_can_be_replaced_at_runtime() -> Res<()> {
    let (gateway, ingress, reached) = with_policy(Policy {
        default: Effect::Permit,
        ..tools_policy()
    })
    .await?;
    assert_eq!(
        post(&ingress, &tool_call(1, "transfer")).await?.0,
        StatusCode::OK
    );
    assert_eq!(reached.load(Ordering::SeqCst), 1);
    gateway.set_policy(Some(Arc::new(tools_policy())));
    let (_, body) = post(&ingress, &tool_call(2, "transfer")).await?;
    assert!(body.contains("-32001"), "now denied: {body}");
    gateway.set_policy(None);
    assert_eq!(
        post(&ingress, &tool_call(3, "delete_account")).await?.0,
        StatusCode::OK
    );
    assert_eq!(reached.load(Ordering::SeqCst), 2, "no policy, no decision");
    Ok(())
}

/// Loopback tagged as provider `test` at network level.
fn loopback_provider() -> Res<Providers> {
    let key = Ed25519KeyPair::generate().map_err(|_| "key generation")?;
    let snap = br#"{"version":1,"created":"2026-11-09T00:00:00Z","providers":[
        {"provider":"test","agent":"loopback","source":"test","ranges":["127.0.0.0/8"]}]}"#;
    let providers = Providers::new(vec![key.public_key().as_ref().to_vec()]);
    providers.load(snap, key.sign(snap).as_ref())?;
    Ok(providers)
}

#[tokio::test]
async fn a_rule_demanding_cryptographic_evidence_denies_a_network_verified_client() -> Res<()> {
    let strict = Policy {
        rules: vec![Rule {
            tools: vec!["transfer".into()],
            evidence: Some(Evidence::Cryptographic),
            ..Rule::any(Effect::Permit)
        }],
        ..Policy::deny_by_default()
    };
    let providers = Arc::new(loopback_provider()?);
    let config = ingress_config(|i| {
        i.policy = Some(Arc::new(strict));
        i.providers = Some(providers);
    })?;
    let (_g, ingress, reached) = gateway(config).await?;
    let (status, body) = post(&ingress, &tool_call(1, "transfer")).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("-32001"),
        "network evidence is not enough: {body}"
    );
    assert_eq!(reached.load(Ordering::SeqCst), 0);
    Ok(())
}
