// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Enrolment: a one-time token buys an SVID that the connector listener
//! accepts; renewal needs a current SVID and its key; revocation stops
//! renewal.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use tunnelward_connector::register;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_crypto::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tunnelward_crypto::{ClientAuth, Identity, KeyExchange, client_config, server_config};
use tunnelward_gateway::{Config, Enrolment, Tokens};
use tunnelward_identity::enrol::{self, Ca};
use tunnelward_proto::ALPN;
use tunnelward_testpki as pki;

use common::ingress::{h1, start_ingress};
use common::jwt::b64;
use common::{Res, connector_config, registration};

const ID: &str = "spiffe://example.org/connector";

fn unb64(text: &str) -> Res<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0_u32, 0);
    for c in text.bytes() {
        let v = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or("not base64url")?;
        acc = acc << 6 | u32::try_from(v)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits & 0xff)?);
        }
    }
    Ok(out)
}

/// A gateway whose ingress enrols from a fresh CA and whose connector
/// listener trusts that CA: (tokens, connector address, ingress address).
async fn gateway(name: &str) -> Res<(Tokens, String, String)> {
    let (cert, key) = Ca::generate(
        "Enrolment test CA",
        Duration::from_secs(86_400),
        SystemTime::now(),
    )?;
    let ca = Ca::load(&cert, &key)?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert))?;
    let tls = server_config(
        pki::identity(pki::GATEWAY),
        ClientAuth::Required(Arc::new(roots)),
        KeyExchange::default(),
        &[ALPN],
    )?;
    let dir = std::env::temp_dir().join(format!("tw-enrol-{name}-{}", std::process::id()));
    let _fresh = std::fs::remove_dir_all(&dir);
    let tokens = Tokens::new(dir);
    let mut config = Config::new(Arc::new(tls));
    config.ingress.enrolment = Some(Arc::new(Enrolment::new(
        ca,
        tokens.clone(),
        Duration::from_secs(600),
    )?));
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    Ok((tokens, connectors, ingress))
}

async fn post(ingress: &str, path: &str, json: String) -> Res<(StatusCode, String)> {
    let request = Request::post(path)
        .header("host", "gateway.test")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json)))?;
    let (status, _, body) = h1(ingress, request).await?;
    Ok((status, body))
}

/// The SVID (DER) in an answer.
fn svid(body: &str) -> Res<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_str(body)?;
    unb64(value["svid"].as_str().ok_or("no svid")?)
}

async fn enrol_with(ingress: &str, token: &str, key: &[u8]) -> Res<(StatusCode, String)> {
    let csr = b64(&enrol::request(key)?);
    post(
        ingress,
        "/.well-known/tunnelward/enrol",
        format!(r#"{{"token":"{token}","csr":"{csr}"}}"#),
    )
    .await
}

/// Renews `svid` with a new key; `prover` signs the proof.
async fn renew_with(
    ingress: &str,
    svid: &[u8],
    prover: &[u8],
    key: &[u8],
) -> Res<(StatusCode, String)> {
    let csr = enrol::request(key)?;
    let proof = enrol::sign(prover, &csr)?;
    let json = format!(
        r#"{{"svid":"{}","csr":"{}","proof":"{}"}}"#,
        b64(svid),
        b64(&csr),
        b64(&proof)
    );
    post(ingress, "/.well-known/tunnelward/renew", json).await
}

/// Registers over mutual TLS as `svid` with `key`.
async fn registers(connectors: &str, svid: Vec<u8>, key: &[u8]) -> Res<bool> {
    let mut config = connector_config(connectors, registration(1, &["mcp"], &[]))?;
    let identity = Identity {
        chain: vec![CertificateDer::from(svid)],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
    };
    config.tls = Arc::new(client_config(
        pki::roots(pki::CA)?,
        Some(identity),
        KeyExchange::default(),
        &[ALPN],
    )?);
    Ok(register(&config).await.is_ok())
}

#[tokio::test]
async fn a_token_enrols_once_and_the_svid_registers() -> Res<()> {
    let (tokens, connectors, ingress) = gateway("once").await?;
    let token = tokens.issue(ID, Duration::from_secs(60), SystemTime::now())?;
    let key = enrol::new_key()?;
    let (status, body) = enrol_with(&ingress, &token, &key).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let svid = svid(&body)?;
    assert_eq!(tunnelward_identity::spiffe_id(&svid)?, ID);
    assert!(
        registers(&connectors, svid, &key).await?,
        "the listener accepts it"
    );
    let (again, body) = enrol_with(&ingress, &token, &enrol::new_key()?).await?;
    assert_eq!(again, StatusCode::FORBIDDEN);
    assert!(
        body.contains("TW-I011") && body.contains("already used"),
        "{body}"
    );
    Ok(())
}

#[tokio::test]
async fn a_certificate_from_elsewhere_does_not_register() -> Res<()> {
    let (_tokens, connectors, _ingress) = gateway("elsewhere").await?;
    let (cert, key) = pki::CONNECTOR;
    assert!(!registers(&connectors, cert.to_vec(), key).await?);
    Ok(())
}

/// A gateway and one SVID enrolled from it: (tokens, connector address,
/// ingress address, SVID, key).
async fn enrolled(name: &str) -> Res<(Tokens, String, String, Vec<u8>, Vec<u8>)> {
    let (tokens, connectors, ingress) = gateway(name).await?;
    let token = tokens.issue(ID, Duration::from_secs(60), SystemTime::now())?;
    let key = enrol::new_key()?;
    let svid = svid(&enrol_with(&ingress, &token, &key).await?.1)?;
    Ok((tokens, connectors, ingress, svid, key))
}

#[tokio::test]
async fn renewal_needs_the_current_key_and_gives_a_new_one() -> Res<()> {
    let (_tokens, connectors, ingress, first, first_key) = enrolled("renew").await?;
    let next_key = enrol::new_key()?;
    let (status, body) = renew_with(&ingress, &first, &next_key, &next_key).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "proof by the new key alone");
    assert!(body.contains("proof"), "{body}");
    let (status, body) = renew_with(&ingress, &first, &first_key, &next_key).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let next = svid(&body)?;
    assert_eq!(tunnelward_identity::spiffe_id(&next)?, ID);
    assert_ne!(enrol::public_key(&next), enrol::public_key(&first));
    assert!(registers(&connectors, next, &next_key).await?);
    Ok(())
}

#[tokio::test]
async fn a_revoked_identity_does_not_renew() -> Res<()> {
    let (tokens, _connectors, ingress, svid, key) = enrolled("revoked").await?;
    assert!(tokens.revoke(ID)?);
    let (status, body) = renew_with(&ingress, &svid, &key, &enrol::new_key()?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("revoked"), "{body}");
    Ok(())
}

#[tokio::test]
async fn an_svid_from_another_ca_does_not_renew() -> Res<()> {
    let (_tokens, _connectors, ingress) = gateway("foreign").await?;
    let (cert, key) = pki::CONNECTOR;
    let (status, body) = renew_with(&ingress, cert, key, &enrol::new_key()?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("not a current one"), "{body}");
    Ok(())
}

#[tokio::test]
async fn bad_requests_are_refused_plainly() -> Res<()> {
    let (_tokens, _connectors, ingress) = gateway("bad").await?;
    let get = Request::get("/.well-known/tunnelward/enrol")
        .header("host", "gateway.test")
        .body(Full::new(Bytes::new()))?;
    assert_eq!(h1(&ingress, get).await?.0, StatusCode::METHOD_NOT_ALLOWED);
    let (status, _) = post(&ingress, "/.well-known/tunnelward/enrol", "{}".into()).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = enrol_with(&ingress, "twe1_guess", &enrol::new_key()?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    Ok(())
}
