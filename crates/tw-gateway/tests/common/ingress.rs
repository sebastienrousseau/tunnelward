// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Ingress helpers: a gateway with its agent-facing listener, and HTTP/1.1
//! and HTTP/2 clients for it.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{KeyExchange, client_config};
use tunnelward_gateway::{Config, Gateway, IngressConfig};
use tunnelward_testpki as pki;

use super::{Res, WAIT, gateway_config, start};

/// A gateway with its ingress on a loopback port: (gateway, connector address, ingress address).
pub async fn start_ingress(config: Config) -> Res<(Gateway, String, String)> {
    let (gateway, connectors) = start(config).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let ingress = listener.local_addr()?.to_string();
    let serving = gateway.clone();
    tokio::spawn(async move { serving.serve_ingress(listener).await });
    Ok((gateway, connectors, ingress))
}

/// 127.0.0.0/8, where the tests' clients connect from.
pub fn loopback() -> tunnelward_gateway::Cidr {
    "127.0.0.0/8"
        .parse()
        .unwrap_or_else(|_| unreachable!("a valid range"))
}

pub fn ingress_config(change: impl FnOnce(&mut IngressConfig)) -> Res<Config> {
    let mut config = gateway_config()?;
    config.max_wait = Duration::from_millis(100);
    change(&mut config.ingress);
    Ok(config)
}

/// One HTTP/1.1 request over plain TCP.
pub async fn h1(
    addr: &str,
    request: Request<Full<Bytes>>,
) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    let tcp = TcpStream::connect(addr).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(conn);
    read(tokio::time::timeout(WAIT, sender.send_request(request)).await??).await
}

pub async fn read(response: Response<Incoming>) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    let (parts, body) = response.into_parts();
    let bytes = tokio::time::timeout(WAIT, body.collect())
        .await??
        .to_bytes();
    Ok((
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

pub fn get(path: &str) -> Res<Request<Full<Bytes>>> {
    Ok(Request::get(path)
        .header("host", "mcp.example.org")
        .body(Full::new(Bytes::new()))?)
}

pub async fn tls_stream(
    ingress: &str,
    alpn: &[u8],
) -> Res<tokio_rustls::client::TlsStream<TcpStream>> {
    tls_stream_as(ingress, alpn, None).await
}

/// A TLS stream to `ingress`, presenting `client`'s certificate if the
/// server asks.
pub async fn tls_stream_as(
    ingress: &str,
    alpn: &[u8],
    client: Option<pki::Pair>,
) -> Res<tokio_rustls::client::TlsStream<TcpStream>> {
    let id = client.map(pki::identity);
    let tls = client_config(pki::roots(pki::CA)?, id, KeyExchange::default(), &[alpn])?;
    let tcp = TcpStream::connect(ingress).await?;
    let name = ServerName::try_from(pki::GATEWAY_NAME)?.to_owned();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await?)
}

pub async fn h2_over_tls(
    ingress: &str,
    request: Request<Full<Bytes>>,
) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    let stream = tls_stream(ingress, b"h2").await?;
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await?;
    tokio::spawn(conn);
    read(sender.send_request(request).await?).await
}

pub async fn h1_over_tls(
    ingress: &str,
    request: Request<Full<Bytes>>,
) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    h1_over_tls_as(ingress, request, None).await
}

/// [`h1_over_tls`], presenting `client`'s certificate if asked.
pub async fn h1_over_tls_as(
    ingress: &str,
    request: Request<Full<Bytes>>,
    client: Option<pki::Pair>,
) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    let stream = tls_stream_as(ingress, b"http/1.1", client).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(conn);
    read(sender.send_request(request).await?).await
}
