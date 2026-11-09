// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Helpers shared by the gateway's loopback tests.

#![allow(dead_code, unreachable_pub)] // each test file uses a different subset

pub mod ingress;
pub mod jwt;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tunnelward_connector::{
    Config as ConnectorConfig, ConnectorConfig as SupervisedConfig, Gateways, register,
};
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{ClientAuth, KeyExchange, client_config, server_config};
use tunnelward_gateway::{Config, Gateway};
use tunnelward_proto::{ALPN, ConnectorId, Limits, PROTOCOL_VERSION, Register};
use tunnelward_testpki as pki;

pub type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const WAIT: Duration = Duration::from_secs(5);

/// The gateway's default configuration over the test PKI.
pub fn gateway_config() -> Res<Config> {
    let tls = server_config(
        pki::identity(pki::GATEWAY),
        ClientAuth::Required(pki::roots(pki::CA)?),
        KeyExchange::default(),
        &[ALPN],
    )?;
    Ok(Config::new(Arc::new(tls)))
}

/// Starts `config`'s gateway on a loopback port.
pub async fn start(config: Config) -> Res<(Gateway, String)> {
    let gateway = Gateway::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    let serving = gateway.clone();
    tokio::spawn(async move { serving.serve_connectors(listener).await });
    Ok((gateway, addr))
}

pub fn tls_client(alpn: &[&[u8]]) -> Res<Arc<tunnelward_crypto::rustls::ClientConfig>> {
    tls_client_as(pki::CONNECTOR, alpn)
}

/// A client presenting `pair`'s certificate.
pub fn tls_client_as(
    pair: pki::Pair,
    alpn: &[&[u8]],
) -> Res<Arc<tunnelward_crypto::rustls::ClientConfig>> {
    let id = Some(pki::identity(pair));
    Ok(Arc::new(client_config(
        pki::roots(pki::CA)?,
        id,
        KeyExchange::default(),
        alpn,
    )?))
}

pub fn registration(id: u8, routes: &[&str], domains: &[&str]) -> Register {
    Register {
        version: PROTOCOL_VERSION,
        connector_id: ConnectorId([id; 16]),
        spiffe_id: "spiffe://example.org/connector".into(),
        routes: routes.iter().map(|s| (*s).to_owned()).collect(),
        domains: domains.iter().map(|s| (*s).to_owned()).collect(),
        mcp: None,
        attestation: None,
        capacity: 16,
    }
}

pub fn connector_config(addr: &str, register: Register) -> Res<ConnectorConfig> {
    Ok(ConnectorConfig {
        gateway: addr.to_owned(),
        server_name: ServerName::try_from(pki::GATEWAY_NAME)?.to_owned(),
        tls: tls_client(&[ALPN])?,
        register,
        limits: Limits::default(),
        handshake_timeout: WAIT,
    })
}

/// [`connector_config`] presenting `pair`'s certificate.
pub fn connector_config_as(
    addr: &str,
    register: Register,
    pair: pki::Pair,
) -> Res<ConnectorConfig> {
    let mut config = connector_config(addr, register)?;
    config.tls = tls_client_as(pair, &[ALPN])?;
    Ok(config)
}

/// Answers every request with `<name> <method> <path>`.
pub fn echo(name: &str, req: &Request<Incoming>) -> Response<Full<Bytes>> {
    let text = format!("{name} {} {}", req.method(), req.uri().path());
    Response::new(Full::new(Bytes::from(text)))
}

/// Registers a connector that echoes as `name`, serving on its own task.
pub async fn start_connector(
    addr: &str,
    name: &'static str,
    register_as: Register,
) -> Res<tokio::task::JoinHandle<()>> {
    let session = register(&connector_config(addr, register_as)?).await?;
    Ok(tokio::spawn(async move {
        let service =
            service_fn(move |req| std::future::ready(Ok::<_, Infallible>(echo(name, &req))));
        let _ended = session.serve(service).await;
    }))
}

/// Registers a connector whose every request waits for a permit from
/// `gate` before answering, so a test controls how long requests stay in
/// flight.
pub async fn start_gated_connector(
    addr: &str,
    name: &'static str,
    register_as: Register,
    gate: Arc<Semaphore>,
) -> Res<tokio::task::JoinHandle<()>> {
    let session = register(&connector_config(addr, register_as)?).await?;
    Ok(tokio::spawn(async move {
        let service = service_fn(move |req| {
            let gate = gate.clone();
            async move {
                let permit = gate.acquire_owned().await;
                drop(permit);
                Ok::<_, Infallible>(echo(name, &req))
            }
        });
        let _ended = session.serve(service).await;
    }))
}

pub fn get_request(uri: &str) -> Res<Request<Full<Bytes>>> {
    Ok(Request::get(uri).body(Full::new(Bytes::new()))?)
}

/// Sends a GET and reads the whole answer, failing after [`WAIT`] so a
/// request stuck on the wrong connector fails the test instead of hanging.
pub async fn get(gateway: &Gateway, uri: &str) -> Res<(StatusCode, String)> {
    let exchange = async {
        let response = gateway.send(get_request(uri)?).await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
            status,
            String::from_utf8(body.to_vec())?,
        ))
    };
    tokio::time::timeout(WAIT, exchange)
        .await
        .map_err(|_| format!("GET {uri} timed out"))?
}

/// Sends a GET without reading the body, failing after [`WAIT`] instead of
/// hanging, and hands back the gateway's own result.
pub async fn send(
    gateway: &Gateway,
    uri: &str,
) -> Res<Result<Response<tunnelward_gateway::ResponseBody>, tunnelward_gateway::SendError>> {
    let sent = tokio::time::timeout(WAIT, gateway.send(get_request(uri)?)).await;
    sent.map_err(|_| format!("send {uri} timed out").into())
}

/// Polls `check` every 10 ms until it holds or [`WAIT`] passes.
pub async fn eventually(what: &str, check: impl Fn() -> bool) -> Res<()> {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !check() {
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("timed out waiting for {what}").into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

/// A service whose every request waits for a permit from `gate`.
pub fn gated_service(
    gate: Arc<Semaphore>,
) -> impl hyper::service::Service<
    Request<Incoming>,
    Response = Response<Full<Bytes>>,
    Error = Infallible,
    Future: Send,
> + Clone
+ Send
+ Sync
+ 'static {
    service_fn(move |req: Request<Incoming>| {
        let gate = gate.clone();
        async move {
            drop(gate.acquire_owned().await);
            Ok::<_, Infallible>(echo("c", &req))
        }
    })
}

/// A supervised connector's configuration with a short backoff, so tests
/// see reconnects quickly.
pub fn supervised(gateways: Gateways, any_addr: &str) -> Res<SupervisedConfig> {
    let mut config = SupervisedConfig::new(
        gateways,
        connector_config(any_addr, registration(1, &["mcp"], &[]))?,
    );
    config.backoff_base = Duration::from_millis(50);
    config.backoff_cap = Duration::from_millis(200);
    Ok(config)
}

pub fn addr(text: &str) -> Res<std::net::SocketAddr> {
    Ok(text.parse()?)
}
