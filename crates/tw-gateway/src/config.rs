// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Gateway configuration.

use std::sync::Arc;
use std::time::Duration;

use tunnelward_crypto::rustls::ServerConfig;
use tunnelward_proto::Limits;

use crate::{Cidr, LongestFirst, ProxyObserver, RateLimit, RouteResolver};

/// How a gateway admits connectors and routes requests. [`Config::new`]
/// gives the defaults; every field is public to change one.
#[derive(Debug, Clone)]
pub struct Config {
    /// TLS for the connector listener: from `tunnelward_crypto::server_config`
    /// with client certificates required and ALPN `tw/1`.
    pub tls: Arc<ServerConfig>,
    /// Frame, HTTP/2 and queue limits.
    pub limits: Limits,
    /// Lease granted in `Accept`: the longest a connection may live. When it
    /// ends the connection drains, and the connector reconnects (ADR 0005).
    pub lease_secs: u32,
    /// How long in-flight requests get to finish when a lease ends.
    pub drain_grace: Duration,
    /// How often an idle connector connection is pinged (HTTP/2 PING), and
    /// how long the answer may take before the connection is dropped.
    pub keep_alive: Duration,
    /// Longest the TLS handshake and register frame may take together.
    pub registration_timeout: Duration,
    /// Longest a request waits for a connector with a free slot (FR-8).
    pub max_wait: Duration,
    /// How long a route stays known after its last connector leaves.
    /// Requests for it wait, then get `Unavailable`, instead of `NoRoute`.
    pub routes_keep_time: Duration,
    /// Chooses which claim serves a request.
    pub resolver: Arc<dyn RouteResolver>,
    /// Source addresses connectors may connect from (G9). Empty admits
    /// every address; mutual TLS still applies either way.
    pub connector_allow: Vec<Cidr>,
    /// Routes that belong to named identities (FR-3). A route not listed
    /// belongs to whichever identity holds it, while connected or kept.
    pub route_owners: Vec<RouteOwner>,
    /// The agent-facing ingress.
    pub ingress: IngressConfig,
    /// State shared with other gateways (ADR 0004): replay caches,
    /// idempotency keys, rate counters. In this process by default.
    pub state: Arc<dyn crate::SharedState>,
    /// The audit log (FR-15, FR-18): an entry for every ingress request
    /// and admin action, and signed receipts when it has them on. None by
    /// default.
    pub audit: Option<Arc<tunnelward_audit::Sink>>,
}

/// The identities allowed to claim one route (FR-3). Any other identity
/// claiming it is refused with `RouteOwned` (TW-R004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteOwner {
    /// The route, exactly as connectors claim it.
    pub route: String,
    /// SPIFFE IDs allowed to claim it.
    pub identities: Vec<String>,
}

/// How the agent-facing ingress behaves (G12, G13).
#[derive(Debug, Clone)]
pub struct IngressConfig {
    /// TLS for agents, from `tunnelward_crypto::server_config` with no client
    /// certificates and ALPN `h2` and `http/1.1`. `None` serves plain
    /// HTTP/1.1, for a gateway behind a TLS-terminating load balancer.
    pub tls: Option<Arc<ServerConfig>>,
    /// Proxies whose `Forwarded` and `X-Forwarded-For` are believed, and
    /// whose PROXY headers are read (FR-11).
    pub trusted_proxies: Vec<Cidr>,
    /// Read a PROXY v1 or v2 header first on connections from trusted
    /// proxies.
    pub proxy_protocol: bool,
    /// Longest request URI, in bytes (414 above it).
    pub max_url_len: usize,
    /// Largest request body, in bytes (413 above it).
    pub max_body: usize,
    /// Longest the gateway waits for a connector's response headers (504).
    pub request_timeout: Duration,
    /// Longest an idle client connection stays open.
    pub idle_timeout: Duration,
    /// Per-client-address limits (429 above them).
    pub rate_limit: RateLimit,
    /// The gateway's name in `Via`.
    pub via_name: String,
    /// Also send `X-Forwarded-For`, `-Proto` and `-Host`.
    pub legacy_forwarded: bool,
    /// Hooks called for every request (G11).
    pub observers: Vec<Arc<dyn ProxyObserver>>,
    /// CORS rules per path (G17). Empty: no CORS headers, and browsers
    /// keep their same-origin rule.
    pub cors: Vec<crate::CorsRule>,
    /// Bearer tokens agents must present (MCP authorisation). `None`
    /// lets every request through, as before.
    pub agent_auth: Option<crate::AgentAuth>,
    /// Published provider ranges; requests from them are tagged (FR-12).
    pub providers: Option<std::sync::Arc<crate::Providers>>,
    /// Agents whose Web Bot Auth signatures are verified (FR-12).
    pub bot_auth: Option<std::sync::Arc<crate::BotAuth>>,
    /// Connector enrolment and renewal on this ingress. `None` serves
    /// neither endpoint.
    pub enrolment: Option<std::sync::Arc<crate::Enrolment>>,
    /// The tool policy (FR-4), replaceable at runtime with
    /// [`crate::Gateway::set_policy`]. `None` decides nothing.
    pub policy: Option<std::sync::Arc<dyn tunnelward_policy::PolicyEngine>>,
}

impl Default for IngressConfig {
    /// Plain HTTP, no trusted proxies, URL 8 KiB, body 16 MiB, 60 s
    /// request and idle timeouts, [`RateLimit::default`], `Via` name
    /// `tunnelward`, legacy headers on.
    fn default() -> Self {
        Self {
            tls: None,
            trusted_proxies: Vec::new(),
            proxy_protocol: false,
            max_url_len: 8 * 1024,
            max_body: 16 * 1024 * 1024,
            request_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(60),
            rate_limit: RateLimit::default(),
            via_name: "tunnelward".to_owned(),
            legacy_forwarded: true,
            observers: Vec::new(),
            cors: Vec::new(),
            agent_auth: None,
            providers: None,
            bot_auth: None,
            enrolment: None,
            policy: None,
        }
    }
}

impl Config {
    /// Defaults: [`Limits::default`], 1 h lease with 30 s to drain, 10 s registration
    /// timeout, 2 s `max_wait`, routes kept for 2 h, [`LongestFirst`], every
    /// source address allowed, no configured route owners.
    #[must_use]
    pub fn new(tls: Arc<ServerConfig>) -> Self {
        Self {
            tls,
            limits: Limits::default(),
            lease_secs: 3600,
            drain_grace: Duration::from_secs(30),
            keep_alive: Duration::from_secs(20),
            registration_timeout: Duration::from_secs(10),
            max_wait: Duration::from_secs(2),
            routes_keep_time: Duration::from_secs(2 * 60 * 60),
            resolver: Arc::new(LongestFirst),
            connector_allow: Vec::new(),
            route_owners: Vec::new(),
            ingress: IngressConfig::default(),
            state: Arc::new(crate::InMemory::default()),
            audit: None,
        }
    }
}
