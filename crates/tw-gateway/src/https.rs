// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Plain HTTPS (HTTP/1.1 over TLS 1.3): a GET for the public documents a
//! gateway reads, issuers' JWK Sets and providers' published ranges, and
//! a JSON POST for a connector's enrolment.

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
    let uri = https_uri(url)?;
    let request = Request::get(uri.path_and_query().map_or("/", |p| p.as_str()))
        .header(http::header::ACCEPT, "application/json")
        .body(Full::new(Bytes::new()))
        .map_err(|e| fail("request", &e))?;
    tokio::time::timeout(TIMEOUT, fetch(&uri, request, roots, limit))
        .await
        .map_err(|_| "timed out".to_owned())?
}

/// POSTs the JSON `body` to the `https://` URL `url`, trusting `roots`,
/// and returns a body of at most `limit` bytes.
///
/// # Errors
///
/// As [`https_get`]; a status other than 200 comes with the start of
/// the answer, which names the reason.
pub async fn https_post(
    url: &str,
    body: Vec<u8>,
    roots: Arc<RootCertStore>,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let uri = https_uri(url)?;
    let request = Request::post(uri.path_and_query().map_or("/", |p| p.as_str()))
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::ACCEPT, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| fail("request", &e))?;
    tokio::time::timeout(TIMEOUT, fetch(&uri, request, roots, limit))
        .await
        .map_err(|_| "timed out".to_owned())?
}

fn https_uri(url: &str) -> Result<Uri, String> {
    let uri: Uri = url.parse().map_err(|e| format!("URL {url:?}: {e}"))?;
    if uri.scheme_str() != Some("https") || uri.host().is_none() {
        return Err(format!("URL {url:?}: not an https:// URL"));
    }
    Ok(uri)
}

fn fail(what: &str, e: &dyn std::fmt::Display) -> String {
    format!("{what}: {e}")
}

async fn fetch(
    uri: &Uri,
    mut request: Request<Full<Bytes>>,
    roots: Arc<RootCertStore>,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let mut sender = connect(uri, roots).await?;
    let host = uri.host().unwrap_or_default();
    let authority = uri.authority().map_or(host, http::uri::Authority::as_str);
    let value = http::HeaderValue::from_str(authority).map_err(|e| fail("host", &e))?;
    request.headers_mut().insert(http::header::HOST, value);
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| fail("HTTP", &e))?;
    let status = response.status();
    let body = Limited::new(response.into_body(), limit)
        .collect()
        .await
        .map_err(|e| fail("body", &*e))?
        .to_bytes();
    if status != http::StatusCode::OK {
        let text = String::from_utf8_lossy(&body[..body.len().min(300)]);
        return Err(format!("status {status}: {}", text.trim()));
    }
    Ok(body.to_vec())
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
