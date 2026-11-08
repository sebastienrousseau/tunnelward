// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The admin API (FR-9) on its own listener: health, readiness, the
//! inventory, Prometheus counters and drain.
//!
//! | Method | Path | Answer |
//! | :--- | :--- | :--- |
//! | GET | `/healthz` | 200 while the process runs |
//! | GET | `/readyz` | 200 once connectors can register, else 503 |
//! | GET | `/inventory[?redaction=internal]` | the [`Inventory`] as JSON |
//! | GET | `/metrics` | the inventory's counters, Prometheus text |
//! | POST | `/drain?connector=<hex>\|route=<r>\|peer=<ip>[&deadline_ms=<n>]` | the [`DrainReport`](crate::DrainReport) as JSON |
//!
//! Every request needs `Authorization: Bearer <token>` when
//! [`AdminConfig::token`] is set; without a token only loopback clients
//! are served. Anything else gets 401.

mod inventory;

pub use inventory::{Connection, Inventory, Redaction};

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use tokio::net::TcpListener;
use tunnelward_proto::ConnectorId;

use crate::{DrainTarget, Gateway};

/// How long a drain gets when the request names no deadline.
const DEFAULT_DRAIN: Duration = Duration::from_secs(30);
/// The longest drain the API accepts.
const MAX_DRAIN: Duration = Duration::from_secs(600);
/// Longest a client may take to send its request head.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// How the admin API checks its callers.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct AdminConfig {
    /// The bearer token every request must carry. `None` serves loopback
    /// clients only.
    pub token: Option<String>,
}

impl AdminConfig {
    /// Requires `token` on every request.
    #[must_use]
    pub fn with_token(token: impl Into<String>) -> Self {
        Self {
            token: Some(token.into()),
        }
    }
}

impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = self.token.as_ref().map(|_| "<redacted>");
        f.debug_struct("AdminConfig")
            .field("token", &token)
            .finish()
    }
}

type Answer = Response<Full<Bytes>>;

fn text(status: StatusCode, body: &'static str) -> Answer {
    let mut response = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *response.status_mut() = status;
    response
}

fn json(value: &impl Serialize) -> Answer {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut response = Response::new(Full::new(Bytes::from(body)));
            response.headers_mut().insert(
                CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "encoding failed\n"),
    }
}

/// Compares in time that depends only on the lengths.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn authorized<B>(admin: &AdminConfig, peer: IpAddr, request: &Request<B>) -> bool {
    let Some(token) = &admin.token else {
        return peer.is_loopback();
    };
    let given = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.as_bytes().strip_prefix(b"Bearer "));
    given.is_some_and(|given| same(given, token.as_bytes()))
}

/// The value of `key` in `query`, undecoded.
fn param<'q>(query: &'q str, key: &str) -> Option<&'q str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(k, v)| (k == key).then_some(v))
}

fn connector_id(text: &str) -> Option<ConnectorId> {
    if text.len() != 32 || !text.is_ascii() {
        return None;
    }
    let mut id = [0_u8; 16];
    for (byte, pair) in id.iter_mut().zip(text.as_bytes().chunks(2)) {
        let digits = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(digits, 16).ok()?;
    }
    Some(ConnectorId(id))
}

fn drain_target(query: &str) -> Option<DrainTarget> {
    if let Some(id) = param(query, "connector") {
        return connector_id(id).map(DrainTarget::Connector);
    }
    if let Some(route) = param(query, "route") {
        return Some(DrainTarget::Route(route.to_owned()));
    }
    param(query, "peer")?.parse().ok().map(DrainTarget::Peer)
}

fn drain_deadline(query: &str) -> Option<Duration> {
    match param(query, "deadline_ms") {
        None => Some(DEFAULT_DRAIN),
        Some(ms) => {
            let deadline = Duration::from_millis(ms.parse().ok()?);
            (deadline <= MAX_DRAIN).then_some(deadline)
        }
    }
}

impl Gateway {
    /// Marks whether connectors can register, for `/readyz`.
    /// [`Gateway::serve_connectors`] sets it when it starts; embedders that
    /// accept connections themselves set it.
    pub fn set_ready(&self, ready: bool) {
        self.inner.ready.store(ready, Ordering::Release);
    }

    /// Serves the admin API on `listener` until it fails, each connection
    /// on its own task, over HTTP/1.1.
    ///
    /// # Errors
    ///
    /// The listener's accept error.
    pub async fn serve_admin(
        &self,
        listener: TcpListener,
        admin: AdminConfig,
    ) -> std::io::Result<()> {
        let admin = Arc::new(admin);
        loop {
            let (tcp, peer) = listener.accept().await?;
            let (gateway, admin) = (self.clone(), admin.clone());
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let (gateway, admin) = (gateway.clone(), admin.clone());
                    async move { Ok::<_, Infallible>(gateway.admin(&admin, peer, &request).await) }
                });
                let _ended = http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(HEADER_TIMEOUT)
                    .serve_connection(TokioIo::new(tcp), service)
                    .await;
            });
        }
    }

    /// Answers one admin request from `peer`. [`Gateway::serve_admin`] calls
    /// it; embedders can mount it in their own server.
    pub async fn admin<B>(
        &self,
        admin: &AdminConfig,
        peer: SocketAddr,
        request: &Request<B>,
    ) -> Answer {
        if !authorized(admin, peer.ip(), request) {
            return text(StatusCode::UNAUTHORIZED, "unauthorized\n");
        }
        let query = request.uri().query().unwrap_or("");
        match (request.method(), request.uri().path()) {
            (&Method::GET, "/healthz") => text(StatusCode::OK, "ok\n"),
            (&Method::GET, "/readyz") => self.readiness(),
            (&Method::GET, "/inventory") => {
                let internal = param(query, "redaction") == Some("internal");
                let redaction = if internal {
                    Redaction::Internal
                } else {
                    Redaction::Public
                };
                json(&self.inventory(redaction))
            }
            (&Method::GET, "/metrics") => {
                let body = inventory::metrics(&self.inventory(Redaction::Public));
                Response::new(Full::new(Bytes::from(body)))
            }
            (&Method::POST, "/drain") => self.drain_request(query).await,
            (_, "/healthz" | "/readyz" | "/inventory" | "/metrics" | "/drain") => {
                text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n")
            }
            _ => text(StatusCode::NOT_FOUND, "not found\n"),
        }
    }

    fn readiness(&self) -> Answer {
        if self.inner.ready.load(Ordering::Acquire) {
            text(StatusCode::OK, "ready\n")
        } else {
            text(StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
        }
    }

    async fn drain_request(&self, query: &str) -> Answer {
        let (Some(target), Some(deadline)) = (drain_target(query), drain_deadline(query)) else {
            return text(
                StatusCode::BAD_REQUEST,
                "name connector=<32 hex>, route=<route> or peer=<ip>, and deadline_ms up to 600000\n",
            );
        };
        let report = self.drain(&target, deadline).await;
        json(&serde_json::json!({
            "sessions": report.sessions,
            "finished": report.finished,
            "reset": report.reset,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_ids_parse_from_32_hex_digits() {
        let id = connector_id("000102030405060708090a0b0c0d0e0f");
        assert_eq!(
            id,
            Some(ConnectorId([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
            ]))
        );
        assert_eq!(connector_id("00"), None);
        assert_eq!(connector_id("zz0102030405060708090a0b0c0d0e0f"), None);
        assert_eq!(connector_id("é0102030405060708090a0b0c0d0e0"), None);
    }

    #[test]
    fn drain_deadlines_default_and_are_capped() {
        assert_eq!(drain_deadline("route=mcp"), Some(DEFAULT_DRAIN));
        assert_eq!(
            drain_deadline("deadline_ms=250"),
            Some(Duration::from_millis(250))
        );
        assert_eq!(drain_deadline("deadline_ms=600001"), None);
        assert_eq!(drain_deadline("deadline_ms=soon"), None);
    }

    #[test]
    fn without_a_token_only_loopback_is_served() {
        let request = Request::new(());
        let open = AdminConfig::default();
        assert!(authorized(
            &open,
            "127.0.0.1".parse().unwrap_or(IpAddr::from([0; 4])),
            &request
        ));
        assert!(authorized(
            &open,
            "::1".parse().unwrap_or(IpAddr::from([0; 4])),
            &request
        ));
        assert!(!authorized(&open, IpAddr::from([192, 0, 2, 1]), &request));
    }

    #[test]
    fn tokens_compare_whole() {
        assert!(same(b"secret", b"secret"));
        assert!(!same(b"secret", b"secreT"));
        assert!(!same(b"secret", b"secret2"));
    }
}
