// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Binding a gateway's listeners and serving them until one stops.

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tunnelward_gateway::{AdminConfig, Gateway};

/// A gateway's bound listeners.
pub(crate) struct Listeners {
    pub(crate) connectors: TcpListener,
    pub(crate) ingress: TcpListener,
    pub(crate) admin: Option<(TcpListener, AdminConfig)>,
}

impl Listeners {
    /// Where each listener is bound, port 0 resolved:
    /// `connectors on A, agents on B[, admin on C]`.
    pub(crate) fn describe(&self) -> String {
        let addr = |l: &TcpListener| {
            l.local_addr()
                .map_or_else(|e| e.to_string(), |a| a.to_string())
        };
        let admin = self
            .admin
            .as_ref()
            .map(|(l, _)| format!(", admin on {}", addr(l)));
        format!(
            "connectors on {}, agents on {}{}",
            addr(&self.connectors),
            addr(&self.ingress),
            admin.unwrap_or_default()
        )
    }
}

/// Binds `addr`, naming it in the error.
pub(crate) async fn bind(addr: SocketAddr) -> Result<TcpListener, String> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot listen on {addr}: {e}"))
}

/// Serves every listener on its own task until the first one stops.
pub(crate) async fn until_one_stops(gateway: &Gateway, listeners: Listeners) -> Result<(), String> {
    let mut servers = JoinSet::new();
    let g = gateway.clone();
    servers.spawn(async move { g.serve_connectors(listeners.connectors).await });
    let g = gateway.clone();
    servers.spawn(async move { g.serve_ingress(listeners.ingress).await });
    if let Some((listener, admin)) = listeners.admin {
        let g = gateway.clone();
        servers.spawn(async move { g.serve_admin(listener, admin).await });
    }
    match servers.join_next().await {
        Some(Ok(Err(e))) => Err(format!("a listener failed: {e}")),
        Some(Err(e)) => Err(format!("a listener stopped: {e}")),
        Some(Ok(Ok(()))) | None => Ok(()),
    }
}
