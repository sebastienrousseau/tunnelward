// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! What every benchmark stands on: an MCP service answering with 1 KiB,
//! a gateway on loopback, connectors registering with it, and a client
//! connection.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tunnelward_connector::{Config as ConnectorConfig, register};
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{ClientAuth, KeyExchange, client_config, server_config};
use tunnelward_gateway::{Config, Gateway, RateLimit};
use tunnelward_proto::{ALPN, ConnectorId, Limits, PROTOCOL_VERSION, Register};
use tunnelward_testpki as pki;

pub(crate) type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// A JSON-RPC body of `size` bytes: a `tools/call` padded with text.
pub(crate) fn mcp_body(size: usize, request: bool) -> Bytes {
    let head = if request {
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{"text":""#
    } else {
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":""#
    };
    let tail = if request { r#""}}}"# } else { r#""}]}}"# };
    let pad = size.saturating_sub(head.len() + tail.len());
    Bytes::from(format!("{head}{}{tail}", "x".repeat(pad)))
}

/// The service under test: reads the request and answers 1 KiB of MCP
/// result, after `hold` (zero for the latency benchmark).
pub(crate) async fn answer(
    request: Request<Incoming>,
    hold: Duration,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let _body = request.into_body().collect().await;
    if !hold.is_zero() {
        tokio::time::sleep(hold).await;
    }
    Ok(Response::new(Full::new(mcp_body(1024, false))))
}

/// The service on a loopback port, without any gateway: the baseline.
pub(crate) async fn direct() -> Res<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let service = service_fn(|r| answer(r, Duration::ZERO));
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service),
            );
        }
    });
    Ok(addr)
}

/// A gateway on loopback with the rate limits off: (connector address,
/// ingress address).
pub(crate) async fn gateway() -> Res<(String, String)> {
    let tls = server_config(
        pki::identity(pki::GATEWAY),
        ClientAuth::Required(pki::roots(pki::CA)?),
        KeyExchange::default(),
        &[ALPN],
    )?;
    let mut config = Config::new(Arc::new(tls));
    config.ingress.rate_limit = RateLimit {
        per_second: 0.0,
        ..RateLimit::default()
    };
    // Every connector and client comes from loopback.
    config.limits.registrations_per_minute = 0;
    let gateway = Gateway::new(config);
    let connectors = TcpListener::bind("127.0.0.1:0").await?;
    let ingress = TcpListener::bind("127.0.0.1:0").await?;
    let addrs = (
        connectors.local_addr()?.to_string(),
        ingress.local_addr()?.to_string(),
    );
    let serving = gateway.clone();
    tokio::spawn(async move { serving.serve_connectors(connectors).await });
    tokio::spawn(async move { gateway.serve_ingress(ingress).await });
    Ok(addrs)
}

/// Registers connector `n` with the gateway at `addr` for route `mcp`
/// and serves it, each request held for `hold`.
pub(crate) async fn connector(addr: &str, n: u16, hold: Duration) -> Res<()> {
    let mut id = [0_u8; 16];
    id[..2].copy_from_slice(&n.to_be_bytes());
    let config = ConnectorConfig {
        gateway: addr.to_owned(),
        server_name: ServerName::try_from(pki::GATEWAY_NAME)?.to_owned(),
        tls: Arc::new(client_config(
            pki::roots(pki::CA)?,
            Some(pki::identity(pki::CONNECTOR)),
            KeyExchange::default(),
            &[ALPN],
        )?),
        register: Register {
            version: PROTOCOL_VERSION,
            connector_id: ConnectorId(id),
            spiffe_id: pki::CONNECTOR_ID.into(),
            routes: vec!["mcp".into()],
            domains: Vec::new(),
            mcp: None,
            attestation: None,
            capacity: 256,
        },
        limits: Limits::default(),
        handshake_timeout: Duration::from_secs(10),
    };
    let session = register(&config).await?;
    tokio::spawn(async move {
        let _ended = session.serve(service_fn(move |r| answer(r, hold))).await;
    });
    Ok(())
}

/// A keep-alive HTTP/1.1 client connection to `addr`.
pub(crate) async fn client(
    addr: &str,
) -> Res<hyper::client::conn::http1::SendRequest<Full<Bytes>>> {
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(conn);
    Ok(sender)
}

/// One 1 KiB MCP POST on `sender`, its whole answer read.
pub(crate) async fn call(
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
) -> Res<()> {
    sender.ready().await?;
    let request = Request::post("/mcp")
        .header("host", "bench")
        .header("content-type", "application/json")
        .body(Full::new(mcp_body(1024, true)))?;
    let response = sender.send_request(request).await?;
    if !response.status().is_success() {
        return Err(format!("status {}", response.status()).into());
    }
    let _body = response.into_body().collect().await?;
    Ok(())
}
