// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Token replay defences (FR-13): DPoP-bound tokens (RFC 9449) work
//! only with a proof by their key; paths can demand bound tokens and
//! single use; a proof or a single-use token replayed to another gateway
//! sharing the store is refused.

mod common;

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tunnelward_connector::register;
use tunnelward_gateway::{AgentAuth, InMemory, Issuer, KeySet, SharedState, TokenRule};

use common::ingress::{h1, ingress_config, start_ingress};
use common::jwt::{Signer, now};
use common::{Res, connector_config, registration};

const ISSUER: &str = "https://as.example.org";
const RESOURCE: &str = "https://mcp.example.org";
const PAY: &str = "/mcp/pay";
const READ: &str = "/mcp/read";

/// A gateway trusting `issuer`, demanding bound single-use tokens on
/// `/mcp/pay`, sharing `state`; its connector answers whether it saw a
/// `DPoP` header.
async fn gateway(issuer: &Signer, state: Arc<dyn SharedState>) -> Res<String> {
    let keys = KeySet::from_jwks(Signer::jwks(&[issuer]).as_bytes())?;
    let mut auth = AgentAuth::new(
        RESOURCE,
        vec![Issuer {
            issuer: ISSUER.into(),
            keys: Arc::new(keys),
        }],
    );
    auth.token_rules = vec![TokenRule {
        path: PAY.into(),
        sender_constrained: true,
        single_use: true,
    }];
    let mut config = ingress_config(|i| i.agent_auth = Some(auth))?;
    config.state = state;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    let session = register(&connector_config(
        &connectors,
        registration(1, &["mcp"], &[]),
    )?)
    .await?;
    tokio::spawn(async move {
        let service = service_fn(|req: Request<hyper::body::Incoming>| {
            let text = format!("dpop seen: {}", req.headers().contains_key("dpop"));
            std::future::ready(Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                text,
            )))))
        });
        let _ended = session.serve(service).await;
    });
    Ok(ingress)
}

/// A token from the issuer: bound to `holder` when given, with `jti`.
fn token(issuer: &Signer, holder: Option<&Signer>, jti: &str) -> Res<String> {
    let t = now();
    let cnf = holder.map_or(String::new(), |h| {
        format!(r#","cnf":{{"jkt":"{}"}}"#, h.thumbprint())
    });
    issuer.token(&format!(
        r#"{{"iss":"{ISSUER}","aud":"{RESOURCE}","exp":{},"jti":"{jti}"{cnf}}}"#,
        t + 600
    ))
}

/// GET `path` with `Authorization: <scheme> <token>` and, when given, a
/// `DPoP` proof.
async fn call(
    ingress: &str,
    path: &str,
    (scheme, token): (&str, &str),
    proof: Option<&str>,
) -> Res<(StatusCode, String, String)> {
    let mut request = Request::get(path)
        .header("host", "mcp.example.org")
        .header("authorization", format!("{scheme} {token}"));
    if let Some(p) = proof {
        request = request.header("dpop", p);
    }
    let (status, headers, body) = h1(ingress, request.body(Full::new(Bytes::new()))?).await?;
    let challenge = headers
        .get(hyper::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    Ok((status, challenge, body))
}

fn url(path: &str) -> String {
    format!("{RESOURCE}{path}")
}

#[tokio::test]
async fn a_bound_token_works_with_its_proof_once() -> Res<()> {
    let (issuer, client) = (Signer::es256("as")?, Signer::eddsa("client")?);
    let ingress = gateway(&issuer, Arc::new(InMemory::default())).await?;
    let t = token(&issuer, Some(&client), "t1")?;
    let proof = client.proof("GET", &url(PAY), &t, now(), "p1")?;
    let (status, _, body) = call(&ingress, PAY, ("DPoP", &t), Some(&proof)).await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "dpop seen: false")
    );
    let (status, _, _) = call(&ingress, PAY, ("DPoP", &t), Some(&proof)).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the same proof again");
    Ok(())
}

#[tokio::test]
async fn a_copied_token_fails_from_another_client() -> Res<()> {
    let issuer = Signer::es256("as")?;
    let (client, thief) = (Signer::eddsa("client")?, Signer::es256("thief")?);
    let ingress = gateway(&issuer, Arc::new(InMemory::default())).await?;
    let t = token(&issuer, Some(&client), "t1")?;
    let proof = thief.proof("GET", &url(READ), &t, now(), "p1")?;
    let (status, challenge, _) = call(&ingress, READ, ("DPoP", &t), Some(&proof)).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        challenge.starts_with("DPoP error=\"invalid_dpop_proof\""),
        "{challenge}"
    );
    assert!(challenge.contains("not the token's"), "{challenge}");
    Ok(())
}

/// Proofs by `client` for anything but a GET of `/mcp/read` with `t`
/// now, and the check each must fail.
fn mismatched(client: &Signer, t: &str, other: &str) -> Res<Vec<(String, &'static str)>> {
    Ok(vec![
        (
            client.proof("POST", &url(READ), t, now(), "a")?,
            "another method",
        ),
        (
            client.proof("GET", &url("/elsewhere"), t, now(), "b")?,
            "another URL",
        ),
        (
            client.proof("GET", &url(READ), other, now(), "c")?,
            "another access token",
        ),
        (
            client.proof("GET", &url(READ), t, now() - 600, "d")?,
            "too old",
        ),
    ])
}

#[tokio::test]
async fn proofs_for_something_else_are_refused() -> Res<()> {
    let (issuer, client) = (Signer::es256("as")?, Signer::es256("client")?);
    let ingress = gateway(&issuer, Arc::new(InMemory::default())).await?;
    let t = token(&issuer, Some(&client), "t1")?;
    let other = token(&issuer, Some(&client), "t2")?;
    let cases = mismatched(&client, &t, &other)?;
    for (proof, why) in cases {
        let (status, challenge, _) = call(&ingress, READ, ("DPoP", &t), Some(&proof)).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{why}");
        assert!(challenge.contains(why), "{why}: {challenge}");
    }
    Ok(())
}

#[tokio::test]
async fn a_forged_or_mistyped_proof_is_refused() -> Res<()> {
    let issuer = Signer::es256("as")?;
    let (client, thief) = (Signer::es256("client")?, Signer::es256("thief")?);
    let ingress = gateway(&issuer, Arc::new(InMemory::default())).await?;
    let t = token(&issuer, Some(&client), "t1")?;
    let request = ("GET", url(READ));
    let parts = (request.0, request.1.as_str(), t.as_str());
    let forged = thief.forged_proof("dpop+jwt", &client, parts, (now(), "f"))?;
    let (status, challenge, _) = call(&ingress, READ, ("DPoP", &t), Some(&forged)).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        challenge.contains("signature does not verify"),
        "{challenge}"
    );
    let mistyped = client.forged_proof("jwt", &client, parts, (now(), "m"))?;
    let (status, challenge, _) = call(&ingress, READ, ("DPoP", &t), Some(&mistyped)).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(challenge.contains("typ is not dpop+jwt"), "{challenge}");
    Ok(())
}

#[tokio::test]
async fn a_bound_token_needs_a_proof_and_the_dpop_scheme() -> Res<()> {
    let (issuer, client) = (Signer::es256("as")?, Signer::es256("client")?);
    let ingress = gateway(&issuer, Arc::new(InMemory::default())).await?;
    let t = token(&issuer, Some(&client), "t1")?;
    let (status, _, _) = call(&ingress, READ, ("DPoP", &t), None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no proof at all");
    let (status, _, _) = call(&ingress, READ, ("Bearer", &t), None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a bound token as Bearer");
    Ok(())
}

#[tokio::test]
async fn a_path_can_demand_bound_tokens() -> Res<()> {
    let issuer = Signer::es256("as")?;
    let ingress = gateway(&issuer, Arc::new(InMemory::default())).await?;
    let plain = token(&issuer, None, "plain")?;
    let (status, _, _) = call(&ingress, READ, ("Bearer", &plain), None).await?;
    assert_eq!(status, StatusCode::OK, "no rule on /mcp/read");
    let (status, challenge, _) = call(&ingress, PAY, ("Bearer", &plain), None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(challenge.contains("needs a token bound"), "{challenge}");
    Ok(())
}

#[tokio::test]
async fn a_path_can_demand_single_use_tokens() -> Res<()> {
    let (issuer, client) = (Signer::es256("as")?, Signer::eddsa("client")?);
    let ingress = gateway(&issuer, Arc::new(InMemory::default())).await?;
    let t = token(&issuer, Some(&client), "once")?;
    let first = client.proof("GET", &url(PAY), &t, now(), "p1")?;
    assert_eq!(
        call(&ingress, PAY, ("DPoP", &t), Some(&first)).await?.0,
        StatusCode::OK
    );
    let second = client.proof("GET", &url(PAY), &t, now(), "p2")?;
    let (status, challenge, _) = call(&ingress, PAY, ("DPoP", &t), Some(&second)).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the token's second use");
    assert!(challenge.contains("used before"), "{challenge}");
    Ok(())
}

#[tokio::test]
async fn a_replay_to_another_gateway_sharing_the_store_is_refused() -> Res<()> {
    let (issuer, client) = (Signer::es256("as")?, Signer::eddsa("client")?);
    let shared: Arc<dyn SharedState> = Arc::new(InMemory::default());
    let first = gateway(&issuer, shared.clone()).await?;
    let second = gateway(&issuer, shared).await?;
    let t = token(&issuer, Some(&client), "t1")?;
    let proof = client.proof("GET", &url(READ), &t, now(), "p1")?;
    assert_eq!(
        call(&first, READ, ("DPoP", &t), Some(&proof)).await?.0,
        StatusCode::OK
    );
    let (status, _, _) = call(&second, READ, ("DPoP", &t), Some(&proof)).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "replayed to the other gateway"
    );
    Ok(())
}

#[tokio::test]
async fn a_store_that_cannot_answer_refuses_with_503() -> Res<()> {
    let (issuer, client) = (Signer::es256("as")?, Signer::eddsa("client")?);
    let ingress = gateway(&issuer, Arc::new(InMemory::with_capacity(0))).await?;
    let t = token(&issuer, Some(&client), "t1")?;
    let proof = client.proof("GET", &url(READ), &t, now(), "p1")?;
    let (status, _, body) = call(&ingress, READ, ("DPoP", &t), Some(&proof)).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("TW-I012"), "{body}");
    Ok(())
}
