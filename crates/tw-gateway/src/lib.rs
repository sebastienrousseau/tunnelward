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
mod error;
mod registry;
mod route;

pub use admit::Config;
pub use error::{AdmitError, SendError};

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tw_proto::ConnectorId;

use registry::Registry;

/// A gateway. Cloning is cheap and shares the same registry.
#[derive(Clone)]
pub struct Gateway {
    inner: Arc<Inner>,
}

struct Inner {
    config: Config,
    acceptor: TlsAcceptor,
    registry: Registry,
}

impl Gateway {
    /// A gateway with no connectors yet.
    #[must_use]
    pub fn new(config: Config) -> Self {
        let acceptor = TlsAcceptor::from(config.tls.clone());
        Self {
            inner: Arc::new(Inner {
                config,
                acceptor,
                registry: Registry::default(),
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
            let (tcp, _) = listener.accept().await?;
            let gateway = self.clone();
            tokio::spawn(async move { gateway.admit(tcp).await });
        }
    }

    /// The routes of every live connector, sorted, for inventory and tests.
    #[must_use]
    pub fn routes(&self) -> Vec<String> {
        self.inner.registry.routes()
    }

    /// Sends `request` to the connector that serves its host and path.
    /// A request without a scheme and authority gets `http` and its `Host`
    /// header.
    ///
    /// # Errors
    ///
    /// [`SendError::NoRoute`] when no live connector serves it,
    /// [`SendError::Http`] when the request fails on the connection.
    pub async fn send(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>, SendError> {
        let request = route::absolute(request)?;
        let target = route::Target::of(&request);
        let mut sender = self
            .inner
            .registry
            .pick(&target)
            .ok_or(SendError::NoRoute)?;
        sender.ready().await.map_err(SendError::Http)?;
        sender.send_request(request).await.map_err(SendError::Http)
    }

    fn remove(&self, id: ConnectorId) {
        self.inner.registry.remove(id);
    }
}
