// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Certificate-bound tokens (RFC 8705): with `ClientAuth::AnyHolder` on
//! the ingress, a token naming a client certificate (`cnf.x5t#S256`)
//! works only on a connection that presented that certificate. Any
//! certificate will do, even one no CA vouches for: it proves only that
//! the caller holds the key the token was issued to.

mod common;

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use tunnelward_crypto::{ClientAuth, KeyExchange, server_config};
use tunnelward_gateway::{AgentAuth, Issuer, KeySet};
use tunnelward_testpki as pki;

use common::ingress::{h1_over_tls_as, ingress_config, start_ingress};
use common::jwt::{Signer, b64, now};
use common::{Res, registration, start_connector};

const ISSUER: &str = "https://as.example.org";
const RESOURCE: &str = "https://mcp.example.org";

async fn gateway(issuer: &Signer) -> Res<String> {
    let keys = KeySet::from_jwks(Signer::jwks(&[issuer]).as_bytes())?;
    let mut auth = AgentAuth::new(
        RESOURCE,
        vec![Issuer {
            issuer: ISSUER.into(),
            keys: Arc::new(keys),
        }],
    );
    auth.certificate_bound = true;
    let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let tls = server_config(
        pki::identity(pki::GATEWAY),
        ClientAuth::AnyHolder,
        KeyExchange::default(),
        &alpn,
    )?;
    let config = ingress_config(|i| {
        i.agent_auth = Some(auth);
        i.tls = Some(Arc::new(tls));
    })?;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    let _connector = start_connector(&connectors, "echo", registration(1, &["mcp"], &[])).await?;
    Ok(ingress)
}

/// A token bound to `cert` (DER).
fn bound_to(issuer: &Signer, cert: &[u8]) -> Res<String> {
    let thumb = b64(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, cert).as_ref());
    issuer.token(&format!(
        r#"{{"iss":"{ISSUER}","aud":"{RESOURCE}","exp":{},"cnf":{{"x5t#S256":"{thumb}"}}}}"#,
        now() + 600
    ))
}

async fn call(ingress: &str, token: &str, client: Option<pki::Pair>) -> Res<StatusCode> {
    let request = Request::get("/mcp")
        .header("host", "mcp.example.org")
        .header("authorization", format!("Bearer {token}"))
        .body(Full::new(Bytes::new()))?;
    Ok(h1_over_tls_as(ingress, request, client).await?.0)
}

#[tokio::test]
async fn a_certificate_bound_token_works_only_with_its_certificate() -> Res<()> {
    let issuer = Signer::es256("as")?;
    let ingress = gateway(&issuer).await?;
    let token = bound_to(&issuer, pki::CONNECTOR.0)?;
    assert_eq!(
        call(&ingress, &token, Some(pki::CONNECTOR)).await?,
        StatusCode::OK
    );
    assert_eq!(
        call(&ingress, &token, None).await?,
        StatusCode::UNAUTHORIZED,
        "no certificate"
    );
    assert_eq!(
        call(&ingress, &token, Some(pki::RIVAL)).await?,
        StatusCode::UNAUTHORIZED,
        "another certificate"
    );
    Ok(())
}

#[tokio::test]
async fn any_certificate_proves_its_holder_and_plain_tokens_still_work() -> Res<()> {
    let issuer = Signer::es256("as")?;
    let ingress = gateway(&issuer).await?;
    let token = bound_to(&issuer, pki::INTRUDER.0)?;
    assert_eq!(
        call(&ingress, &token, Some(pki::INTRUDER)).await?,
        StatusCode::OK,
        "a certificate from a CA nothing trusts still proves its key"
    );
    let plain = issuer.token(&format!(
        r#"{{"iss":"{ISSUER}","aud":"{RESOURCE}","exp":{}}}"#,
        now() + 600
    ))?;
    assert_eq!(call(&ingress, &plain, None).await?, StatusCode::OK);
    assert_eq!(
        call(&ingress, &plain, Some(pki::RIVAL)).await?,
        StatusCode::OK
    );
    Ok(())
}
