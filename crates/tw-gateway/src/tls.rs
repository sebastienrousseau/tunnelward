// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Replacing certificates without a restart (G16).

use std::sync::{Arc, PoisonError};

use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

use crate::Gateway;

impl Gateway {
    /// Replaces the connector listener's TLS configuration, for example
    /// after its certificate is renewed. Handshakes from now on use it;
    /// established connections keep theirs.
    pub fn set_tls(&self, tls: Arc<ServerConfig>) {
        let mut acceptor = self
            .inner
            .acceptor
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *acceptor = TlsAcceptor::from(tls);
    }

    /// Replaces the ingress TLS configuration; `None` serves plain HTTP
    /// from now on.
    pub fn set_ingress_tls(&self, tls: Option<Arc<ServerConfig>>) {
        let mut acceptor = self
            .inner
            .ingress_tls
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *acceptor = tls.map(TlsAcceptor::from);
    }

    pub(crate) fn acceptor(&self) -> TlsAcceptor {
        self.inner
            .acceptor
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn ingress_acceptor(&self) -> Option<TlsAcceptor> {
        self.inner
            .ingress_tls
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
