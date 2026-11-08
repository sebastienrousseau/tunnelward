// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! A plain HTTPS GET (HTTP/1.1 over TLS 1.3) for the public documents a
//! gateway reads: issuers' JWK Sets and providers' published ranges.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::Uri;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{KeyExchange, client_config};

/// Longest a fetch may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// GETs the `https://` URL `url`, trusting `roots`, and returns a body of
/// at most `limit` bytes.
///
/// # Errors
///
/// A sentence naming the step that failed: the URL, connecting, TLS,
/// HTTP, a status other than 200, a body over `limit`, or the 10 s
/// timeout.
pub async fn https_get(
    url: &str,
    roots: Arc<RootCertStore>,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let uri: Uri = url.parse().map_err(|e| format!("URL {url:?}: {e}"))?;
    if uri.scheme_str() != Some("https") || uri.host().is_none() {
        return Err(format!("URL {url:?}: not an https:// URL"));
    }
    tokio::time::timeout(TIMEOUT, fetch(&uri, roots, limit))
        .await
        .map_err(|_| "timed out".to_owned())?
}

fn fail(what: &str, e: &dyn std::fmt::Display) -> String {
    format!("{what}: {e}")
}

async fn fetch(uri: &Uri, roots: Arc<RootCertStore>, limit: usize) -> Result<Vec<u8>, String> {
    let mut sender = connect(uri, roots).await?;
    let host = uri.host().unwrap_or_default();
    let authority = uri.authority().map_or(host, http::uri::Authority::as_str);
    let request = Request::get(uri.path_and_query().map_or("/", |p| p.as_str()))
        .header(http::header::HOST, authority)
        .header(http::header::ACCEPT, "application/json")
        .body(Full::new(Bytes::new()))
        .map_err(|e| fail("request", &e))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| fail("HTTP", &e))?;
    if response.status() != http::StatusCode::OK {
        return Err(format!("status {}", response.status()));
    }
    let body = Limited::new(response.into_body(), limit)
        .collect()
        .await
        .map_err(|e| fail("body", &*e))?;
    Ok(body.to_bytes().to_vec())
}

/// An HTTP/1.1 connection to `uri`'s host over TLS 1.3, trusting `roots`.
async fn connect(
    uri: &Uri,
    roots: Arc<RootCertStore>,
) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>, String> {
    let stream = tls(uri, roots).await?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| fail("HTTP", &e))?;
    tokio::spawn(conn);
    Ok(sender)
}

/// A TLS 1.3 stream to `uri`'s host and port, trusting `roots`.
async fn tls(
    uri: &Uri,
    roots: Arc<RootCertStore>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let host = uri.host().unwrap_or_default().trim_matches(['[', ']']);
    let config = client_config(roots, None, KeyExchange::default(), &[b"http/1.1"])
        .map_err(|e| fail("TLS", &e))?;
    let name = ServerName::try_from(host.to_owned()).map_err(|e| fail("host", &e))?;
    let tcp = TcpStream::connect((host, uri.port_u16().unwrap_or(443)))
        .await
        .map_err(|e| fail("connect", &e))?;
    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| fail("TLS", &e))
}
