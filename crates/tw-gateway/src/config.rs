// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Gateway configuration.

use std::sync::Arc;
use std::time::Duration;

use tw_crypto::rustls::ServerConfig;
use tw_proto::Limits;

use crate::{LongestFirst, RouteResolver};

/// How a gateway admits connectors and routes requests. [`Config::new`]
/// gives the defaults; every field is public to change one.
#[derive(Debug, Clone)]
pub struct Config {
    /// TLS for the connector listener: from `tw_crypto::server_config`
    /// with client certificates required and ALPN `tw/1`.
    pub tls: Arc<ServerConfig>,
    /// Frame, HTTP/2 and queue limits.
    pub limits: Limits,
    /// Lease granted in `Accept`; renewal arrives in v0.0.6.
    pub lease_secs: u32,
    /// Longest the TLS handshake and register frame may take together.
    pub registration_timeout: Duration,
    /// Longest a request waits for a connector with a free slot (FR-8).
    pub max_wait: Duration,
    /// How long a route stays known after its last connector leaves.
    /// Requests for it wait, then get `Unavailable`, instead of `NoRoute`.
    pub routes_keep_time: Duration,
    /// Chooses which claim serves a request.
    pub resolver: Arc<dyn RouteResolver>,
}

impl Config {
    /// Defaults: [`Limits::default`], 30 s lease, 10 s registration
    /// timeout, 2 s `max_wait`, routes kept for 2 h, [`LongestFirst`].
    #[must_use]
    pub fn new(tls: Arc<ServerConfig>) -> Self {
        Self {
            tls,
            limits: Limits::default(),
            lease_secs: 30,
            registration_timeout: Duration::from_secs(10),
            max_wait: Duration::from_secs(2),
            routes_keep_time: Duration::from_secs(2 * 60 * 60),
            resolver: Arc::new(LongestFirst),
        }
    }
}
