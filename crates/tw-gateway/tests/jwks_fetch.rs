// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! An issuer's keys fetched from its `jwks_uri` over HTTPS, refreshed,
//! and kept when a refresh fails.

mod common;

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tunnelward_crypto::{ClientAuth, KeyExchange, server_config};
use tunnelward_gateway::{KeyError, KeySet};
use tunnelward_testpki as pki;

use common::Res;
use common::jwt::Signer;

/// How the test server answers.
const UP: u8 = 0;
const DOWN: u8 = 1;
const GARBAGE: u8 = 2;

/// An HTTPS server on 127.0.0.1 answering every GET with `jwks`, a 503,
/// or a 200 that is not a JWK Set, as `mode` says. Returns its URL.
async fn jwks_server(jwks: String, mode: Arc<AtomicU8>) -> Res<String> {
    let tls = server_config(
        pki::identity(pki::GATEWAY),
        ClientAuth::None,
        KeyExchange::default(),
        &[b"http/1.1"],
    )?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("https://{}/.well-known/jwks.json", listener.local_addr()?);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, jwks, mode) = (acceptor.clone(), jwks.clone(), mode.clone());
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |_req| {
                    let now = mode.load(Ordering::SeqCst);
                    let body = if now == GARBAGE {
                        "<html>"
                    } else {
                        jwks.as_str()
                    };
                    let mut response = Response::new(Full::new(Bytes::from(body.to_owned())));
                    if now == DOWN {
                        *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                    }
                    std::future::ready(Ok::<_, Infallible>(response))
                });
                let conn = hyper::server::conn::http1::Builder::new();
                let _done = conn.serve_connection(TokioIo::new(stream), service).await;
            });
        }
    });
    Ok(url)
}

#[tokio::test]
async fn keys_are_fetched_over_https_and_kept_when_a_refresh_fails() -> Res<()> {
    let (a, b) = (Signer::es256("a")?, Signer::eddsa("b")?);
    let mode = Arc::new(AtomicU8::new(UP));
    let url = jwks_server(Signer::jwks(&[&a, &b]), mode.clone()).await?;
    let keys = KeySet::from_url(&url, pki::roots(pki::CA)?)?;
    assert!(keys.is_empty(), "nothing before the first fetch");
    assert_eq!(keys.refresh().await, Ok(2));
    mode.store(DOWN, Ordering::SeqCst);
    assert!(matches!(keys.refresh().await, Err(KeyError::Fetch(_))));
    assert_eq!(keys.len(), 2, "a failed refresh keeps the old keys");
    mode.store(GARBAGE, Ordering::SeqCst);
    assert_eq!(keys.refresh().await, Err(KeyError::NotAJwkSet));
    assert_eq!(keys.len(), 2, "so does a document that is not a JWK Set");
    Ok(())
}

#[tokio::test]
async fn a_server_the_roots_do_not_trust_is_refused() -> Res<()> {
    let a = Signer::es256("a")?;
    let url = jwks_server(Signer::jwks(&[&a]), Arc::default()).await?;
    let keys = KeySet::from_url(&url, pki::roots(pki::OTHER_CA)?)?;
    assert!(matches!(keys.refresh().await, Err(KeyError::Fetch(why)) if why.starts_with("TLS")));
    Ok(())
}

#[test]
fn only_https_urls_are_accepted() -> Res<()> {
    let roots = pki::roots(pki::CA)?;
    for url in ["http://as.example.org/jwks", "https:///jwks", "not a url"] {
        assert!(
            matches!(KeySet::from_url(url, roots.clone()), Err(KeyError::Url(_))),
            "{url}"
        );
    }
    Ok(())
}
