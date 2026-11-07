// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Tunnelward gateway: admits connectors and sends requests through them.
//!
//! A connector dials in over TLS with ALPN `tw/1` and sends one
//! [`Register`](tw_proto::Register) frame. [`Gateway::admit`] reads it
//! under a timeout, answers [`Accept`](tw_proto::Accept) or
//! [`Reject`](tw_proto::Reject), and on acceptance becomes the HTTP/2
//! client on that same connection (ADR 0001). [`Gateway::send`] then routes
//! a request to a connector by host and path.
//!
//! The gateway is a library first: [`Gateway::admit`] takes any accepted
//! stream and [`Gateway::send`] any request, so an embedding server
//! decides how it listens. [`Gateway::serve_connectors`] is the plain TCP
//! loop the `tunnelward` binary will use. Identity checks, pools and the
//! agent-facing ingress arrive in later releases (v0.0.5 to v0.0.10).

mod admit;
mod cidr;
mod client_addr;
mod config;
mod drain;
mod error;
mod forwarding;
mod ingress;
mod kill;
mod listener;
mod observer;
mod pool;
pub mod proxy_protocol;
mod ratelimit;
mod registry;
mod resolver;
mod retry;
mod route;

pub use cidr::{Cidr, CidrError};
pub use client_addr::ClientAddr;
pub use config::{Config, IngressConfig};
pub use drain::{DrainReport, DrainTarget};
pub use error::{AdmitError, SendError};
pub use ingress::{Ingress, IngressBody};
pub use observer::{ProxyObserver, RequestInfo};
pub use pool::ResponseBody;
pub use ratelimit::RateLimit;
pub use resolver::{LongestFirst, RouteResolver, Target};

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsAcceptor;

use pool::Lease;
use registry::{Pick, Registry};

/// How one attempt to send a request failed.
enum Attempt {
    /// The connector never saw the request: safe to send elsewhere.
    Unprocessed(u64, hyper::Error),
    /// Anything else.
    Failed(SendError),
}

impl Attempt {
    fn into_send_error(self) -> SendError {
        match self {
            Self::Unprocessed(_, e) => SendError::Http(e),
            Self::Failed(e) => e,
        }
    }
}

/// A gateway. Cloning is cheap and shares the same registry.
#[derive(Clone)]
pub struct Gateway {
    inner: Arc<Inner>,
}

struct Inner {
    config: Config,
    acceptor: TlsAcceptor,
    registry: Registry,
    limiter: ratelimit::Limiter,
    next_request: std::sync::atomic::AtomicU64,
}

impl Gateway {
    /// A gateway with no connectors yet.
    #[must_use]
    pub fn new(config: Config) -> Self {
        let acceptor = TlsAcceptor::from(config.tls.clone());
        let limiter = ratelimit::Limiter::new(config.ingress.rate_limit);
        Self {
            inner: Arc::new(Inner {
                config,
                acceptor,
                registry: Registry::default(),
                limiter,
                next_request: std::sync::atomic::AtomicU64::new(0),
            }),
        }
    }

    /// Accepts connector connections on `listener` until it fails, admitting
    /// each on its own task.
    ///
    /// # Errors
    ///
    /// The listener's accept error.
    pub async fn serve_connectors(&self, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (tcp, peer) = listener.accept().await?;
            if !self.allows(peer.ip()) {
                // Closed before any TLS work: an unlisted source costs one accept.
                continue;
            }
            let gateway = self.clone();
            tokio::spawn(async move { gateway.admit_from(tcp, Some(peer.ip())).await });
        }
    }

    /// Whether the connector allowlist admits `ip`. An empty list admits
    /// every address. Embedders that accept connections themselves call this
    /// before [`Gateway::admit`].
    #[must_use]
    pub fn allows(&self, ip: std::net::IpAddr) -> bool {
        let allow = &self.inner.config.connector_allow;
        allow.is_empty() || allow.iter().any(|range| range.contains(ip))
    }

    /// The routes of every live connector, sorted.
    #[must_use]
    pub fn routes(&self) -> Vec<String> {
        self.inner.registry.routes()
    }

    /// Requests in flight across every connector, response bodies included.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.inner.registry.in_flight()
    }

    /// Requests waiting for a connector with a free slot.
    #[must_use]
    pub fn waiting(&self) -> u32 {
        self.inner.registry.waiting()
    }

    /// Sends `request` to a connector that serves its host and path. A
    /// request without a scheme and authority gets `http` and its `Host`
    /// header. Among the connectors whose claim ranks highest, the less
    /// loaded of two picked at random takes it. When none has a free slot,
    /// or the route is kept with no connector, the request waits up to
    /// `max_wait` in a queue bounded by `limits.max_waiting_per_route`.
    ///
    /// The returned body holds the request's slot until it ends or is
    /// dropped.
    ///
    /// # Errors
    ///
    /// [`SendError::NoRoute`] when nothing serves it,
    /// [`SendError::Unavailable`] when the wait ends or the queue is full,
    /// [`SendError::Http`] when the request fails on the connection.
    pub async fn send(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<ResponseBody>, SendError> {
        let request = route::absolute(request)?;
        let target = Target::of(&request);
        let spare = retry::copy(&request);
        match self.attempt(&target, request).await {
            Err(Attempt::Unprocessed(session, _)) => {
                // That connection is going away: stop choosing it, try another.
                self.inner.registry.mark_draining(|e| e.session == session);
                self.attempt(&target, spare)
                    .await
                    .map_err(Attempt::into_send_error)
            }
            other => other.map_err(Attempt::into_send_error),
        }
    }

    async fn attempt(
        &self,
        target: &Target,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<ResponseBody>, Attempt> {
        let Lease {
            session,
            mut sender,
            slot,
        } = self.acquire(target).await.map_err(Attempt::Failed)?;
        // A connection that cannot take a request has sent nothing yet.
        sender
            .ready()
            .await
            .map_err(|e| Attempt::Unprocessed(session, e))?;
        let response = sender.send_request(request).await.map_err(|e| {
            if retry::unprocessed(&e) {
                Attempt::Unprocessed(session, e)
            } else {
                Attempt::Failed(SendError::Http(e))
            }
        })?;
        Ok(response.map(|body| ResponseBody::new(body, slot)))
    }

    fn pick(&self, target: &Target) -> Pick {
        self.inner
            .registry
            .pick(self.inner.config.resolver.as_ref(), target)
    }

    async fn acquire(&self, target: &Target) -> Result<Lease, SendError> {
        match self.pick(target) {
            Pick::Ready(lease) => Ok(lease),
            Pick::None => Err(SendError::NoRoute),
            Pick::Wait(route) => self.wait(target, &route).await,
        }
    }

    async fn wait(&self, target: &Target, route: &str) -> Result<Lease, SendError> {
        let config = &self.inner.config;
        let _queued = self
            .inner
            .registry
            .enqueue(route, config.limits.max_waiting_per_route)
            .ok_or_else(|| self.unavailable())?;
        let deadline = Instant::now() + config.max_wait;
        let changed = self.inner.registry.changed();
        loop {
            let notified = changed.notified();
            tokio::pin!(notified);
            // Registered before looking, so a release in between is not missed.
            notified.as_mut().enable();
            match self.pick(target) {
                Pick::Ready(lease) => return Ok(lease),
                Pick::None => return Err(SendError::NoRoute),
                Pick::Wait(_) => {}
            }
            timeout_at(deadline, notified)
                .await
                .map_err(|_| self.unavailable())?;
        }
    }

    /// `Unavailable`, with `Retry-After` of `max_wait` rounded up to whole
    /// seconds, at least one.
    fn unavailable(&self) -> SendError {
        let wait = self.inner.config.max_wait;
        let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
        SendError::Unavailable {
            retry_after: Duration::from_secs(secs.max(1)),
        }
    }

    fn remove(&self, session: u64) {
        self.inner
            .registry
            .remove(session, self.inner.config.routes_keep_time);
    }
}
