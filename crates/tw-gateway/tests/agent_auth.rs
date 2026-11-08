// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Agent-side authorisation (MCP authorisation spec): bearer JWTs from a
//! trusted issuer, for this resource, in date, with the scopes asked for;
//! the protected-resource metadata (RFC 9728); no token passthrough.

mod common;

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tunnelward_connector::register;
use tunnelward_gateway::{AgentAuth, Issuer, KeySet, ProxyObserver, RequestInfo};

use common::ingress::{get, h1, ingress_config, start_ingress};
use common::jwt::{Signer, claims, now};
use common::{Res, connector_config, registration};

const ISSUER: &str = "https://as.example.org";
const RESOURCE: &str = "https://mcp.example.org";

/// Records each request's client id as the gateway reports it.
#[derive(Debug, Default)]
struct Clients(Mutex<Vec<Option<String>>>);

impl ProxyObserver for Clients {
    fn on_response(&self, info: &RequestInfo, _: StatusCode, _: std::time::Duration) {
        if let Ok(mut seen) = self.0.lock() {
            seen.push(info.client_id.clone());
        }
    }
}

/// A gateway trusting `signers` for ISSUER, requiring `scopes`, with a
/// connector on `mcp` that answers whether it saw an Authorization header.
async fn gateway(signers: &[&Signer], scopes: &[&str]) -> Res<(String, Arc<Clients>)> {
    let keys = KeySet::from_jwks(Signer::jwks(signers).as_bytes())?;
    let mut auth = AgentAuth::new(
        RESOURCE,
        vec![Issuer {
            issuer: ISSUER.into(),
            keys: Arc::new(keys),
        }],
    );
    auth.scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
    let clients = Arc::new(Clients::default());
    let observer = clients.clone();
    let config = ingress_config(|i| {
        i.agent_auth = Some(auth);
        i.observers.push(observer);
    })?;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    let session = register(&connector_config(
        &connectors,
        registration(1, &["mcp"], &[]),
    )?)
    .await?;
    tokio::spawn(async move {
        let service = service_fn(|req: Request<hyper::body::Incoming>| {
            let seen = req.headers().contains_key(hyper::header::AUTHORIZATION);
            let text = format!("authorization seen: {seen}");
            std::future::ready(Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                text,
            )))))
        });
        let _ended = session.serve(service).await;
    });
    Ok((ingress, clients))
}

async fn call(ingress: &str, token: Option<&str>) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    let mut request = get("/mcp")?;
    if let Some(t) = token {
        request
            .headers_mut()
            .insert(hyper::header::AUTHORIZATION, format!("Bearer {t}").parse()?);
    }
    h1(ingress, request).await
}

fn challenge(headers: &hyper::HeaderMap) -> String {
    headers
        .get(hyper::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn a_request_without_a_token_is_told_where_to_get_one() -> Res<()> {
    let key = Signer::es256("k1")?;
    let (ingress, _) = gateway(&[&key], &[]).await?;
    let (status, headers, _) = call(&ingress, None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers
            .get("tw-error")
            .map(hyper::header::HeaderValue::as_bytes),
        Some(&b"TW-I008"[..])
    );
    let expected =
        format!("Bearer resource_metadata=\"{RESOURCE}/.well-known/oauth-protected-resource\"");
    assert_eq!(challenge(&headers), expected);
    Ok(())
}

#[tokio::test]
async fn a_valid_token_reaches_the_service_without_itself() -> Res<()> {
    for key in [Signer::es256("ec")?, Signer::eddsa("ed")?] {
        let (ingress, clients) = gateway(&[&key], &[]).await?;
        let token = key.token(&claims(ISSUER, RESOURCE, "mcp"))?;
        let (status, _, body) = call(&ingress, Some(&token)).await?;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, "authorization seen: false")
        );
        let seen = clients.0.lock().map(|s| s.clone()).unwrap_or_default();
        assert_eq!(seen, [Some("claude".to_owned())], "client_id recorded");
    }
    Ok(())
}

#[tokio::test]
async fn tokens_that_fail_a_check_are_refused() -> Res<()> {
    let key = Signer::es256("k1")?;
    let stranger = Signer::es256("k1")?;
    let (ingress, _) = gateway(&[&key], &[]).await?;
    let t = now();
    let expired = format!(
        r#"{{"iss":"{ISSUER}","aud":"{RESOURCE}","exp":{}}}"#,
        t - 3600
    );
    let early = format!(
        r#"{{"iss":"{ISSUER}","aud":"{RESOURCE}","exp":{},"nbf":{}}}"#,
        t + 7200,
        t + 3600
    );
    let good = key.token(&claims(ISSUER, RESOURCE, ""))?;
    let tampered = format!("{}x", &good[..good.len() - 1]);
    let other = claims(ISSUER, "https://other.example.org", "");
    let evil = claims("https://evil.example.org", RESOURCE, "");
    let signed = [
        (&key, expired.as_str(), "expired"),
        (&key, early.as_str(), "not valid yet"),
        (&key, other.as_str(), "not for this resource"),
        (&key, evil.as_str(), "issuer is not trusted"),
        (&stranger, &claims(ISSUER, RESOURCE, ""), "signature"),
    ];
    let mut cases = vec![(tampered, "signature"), ("not.a.jwt".to_owned(), "header")];
    for (signer, body, why) in signed {
        cases.push((signer.token(body)?, why));
    }
    for (token, why) in cases {
        let (status, headers, _) = call(&ingress, Some(&token)).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{why}");
        let c = challenge(&headers);
        assert!(
            c.contains("error=\"invalid_token\"") && c.contains(why),
            "{why}: {c}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_token_without_the_scopes_is_forbidden() -> Res<()> {
    let key = Signer::es256("k1")?;
    let (ingress, _) = gateway(&[&key], &["mcp", "tools"]).await?;
    let narrow = key.token(&claims(ISSUER, RESOURCE, "mcp"))?;
    let (status, headers, _) = call(&ingress, Some(&narrow)).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        headers
            .get("tw-error")
            .map(hyper::header::HeaderValue::as_bytes),
        Some(&b"TW-I009"[..])
    );
    assert!(challenge(&headers).contains("error=\"insufficient_scope\", scope=\"mcp tools\""));
    let wide = key.token(&claims(ISSUER, RESOURCE, "tools mcp extra"))?;
    assert_eq!(call(&ingress, Some(&wide)).await?.0, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn the_protected_resource_metadata_is_public() -> Res<()> {
    let key = Signer::es256("k1")?;
    let (ingress, _) = gateway(&[&key], &["mcp"]).await?;
    let (status, headers, body) =
        h1(&ingress, get("/.well-known/oauth-protected-resource")?).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(hyper::header::CONTENT_TYPE)
            .map(hyper::header::HeaderValue::as_bytes),
        Some(&b"application/json"[..])
    );
    let doc: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(doc["resource"], RESOURCE);
    assert_eq!(doc["authorization_servers"], serde_json::json!([ISSUER]));
    assert_eq!(doc["scopes_supported"], serde_json::json!(["mcp"]));
    Ok(())
}
