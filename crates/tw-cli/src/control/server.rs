// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The running control: its state, its two listeners, and the fleet
//! listener's one request (ADR 0012).

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tunnelward_audit::Sink;
use tunnelward_gateway::AgentAuth;

use super::roles::Roles;
use super::store::Store;

/// Longest a client may take to send its request head.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) type Answer = Response<Full<Bytes>>;

/// What the fleet listener last saw from a gateway.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Seen {
    pub(crate) gateway: String,
    /// The version the gateway said it runs.
    pub(crate) version: u64,
    pub(crate) at_ms: u64,
}

pub(crate) struct Control {
    pub(crate) store: Store,
    pub(crate) auth: AgentAuth,
    pub(crate) roles: Roles,
    pub(crate) gateways: Vec<String>,
    pub(crate) audit: Option<Arc<Sink>>,
    pub(crate) fleet: Mutex<BTreeMap<String, Seen>>,
}

impl Control {
    /// Every gateway seen, by SPIFFE ID.
    pub(crate) fn fleet(&self) -> Vec<Seen> {
        let fleet = self.fleet.lock().unwrap_or_else(PoisonError::into_inner);
        fleet.values().cloned().collect()
    }

    fn saw(&self, gateway: &str, version: u64) {
        let seen = Seen {
            gateway: gateway.to_owned(),
            version,
            at_ms: tunnelward_audit::now_ms(),
        };
        let mut fleet = self.fleet.lock().unwrap_or_else(PoisonError::into_inner);
        fleet.insert(gateway.to_owned(), seen);
    }
}

pub(crate) fn text(status: StatusCode, body: impl Into<String>) -> Answer {
    let mut response = Response::new(Full::new(Bytes::from(body.into())));
    *response.status_mut() = status;
    response
}

pub(crate) fn json(status: StatusCode, value: &impl Serialize) -> Answer {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut response = Response::new(Full::new(Bytes::from(body)));
            *response.status_mut() = status;
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "encoding failed\n"),
    }
}

/// Serves gateways on `listener`: only certificates whose SPIFFE ID is
/// allowed get past the handshake.
pub(crate) async fn serve_fleet(
    control: Arc<Control>,
    listener: TcpListener,
    tls: TlsAcceptor,
) -> std::io::Result<()> {
    loop {
        let (tcp, _peer) = listener.accept().await?;
        let (control, tls) = (control.clone(), tls.clone());
        tokio::spawn(async move {
            let Ok(stream) = tls.accept(tcp).await else {
                return;
            };
            let cert = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(<[_]>::first);
            let Some(Ok(id)) = cert.map(|c| tunnelward_identity::spiffe_id(c.as_ref())) else {
                return;
            };
            if !super::file::allowed(&control.gateways, &id) {
                return;
            }
            let service = service_fn(move |request| {
                let answer = fleet_request(&control, &id, &request);
                std::future::ready(Ok::<_, Infallible>(answer))
            });
            let _ended = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

/// `GET /v1/bundle?have=<version>`: the newest envelope, noting the
/// version the gateway runs.
fn fleet_request<B>(control: &Control, gateway: &str, request: &Request<B>) -> Answer {
    if request.method() != hyper::Method::GET || request.uri().path() != "/v1/bundle" {
        return text(StatusCode::NOT_FOUND, "not found\n");
    }
    let have = request
        .uri()
        .query()
        .and_then(|q| q.strip_prefix("have="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    control.saw(gateway, have);
    match control.store.latest() {
        Some((_, envelope)) => {
            let mut response = text(StatusCode::OK, envelope.to_string());
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            response
        }
        None => text(StatusCode::NOT_FOUND, "no bundle published yet\n"),
    }
}

/// Serves operators on `listener`, each connection on its own task.
pub(crate) async fn serve_api(
    control: Arc<Control>,
    listener: TcpListener,
    tls: TlsAcceptor,
) -> std::io::Result<()> {
    loop {
        let (tcp, peer) = listener.accept().await?;
        let (control, tls) = (control.clone(), tls.clone());
        tokio::spawn(async move {
            let Ok(stream) = tls.accept(tcp).await else {
                return;
            };
            let service = service_fn(move |request| {
                let control = control.clone();
                async move { Ok::<_, Infallible>(super::api::answer(&control, peer, request).await) }
            });
            let _ended = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

/// Binds `addr`, naming it in the error.
pub(crate) async fn bind(addr: SocketAddr) -> Result<TcpListener, String> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot listen on {addr}: {e}"))
}
