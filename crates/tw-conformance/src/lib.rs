// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tunnelward conformance kit (alpha): protocol checks anyone can run
//! against a gateway, to show it speaks `tw/1` as Tunnelward's gateway
//! does and refuses what it must refuse.
//!
//! The checks connect as a connector with the identity given (an
//! X.509-SVID the gateway trusts) and need nothing else from the
//! gateway's operator:
//!
//! | Check | The gateway must |
//! | :--- | :--- |
//! | `alpn` | refuse a connection that does not offer `tw/1` |
//! | `malformed` | answer bytes that are not a frame with `Reject` `Malformed` |
//! | `oversized` | answer a length prefix over its limit before reading the body |
//! | `version` | answer an unknown protocol version with `UnsupportedVersion` |
//! | `identity` | answer a SPIFFE ID that is not the certificate's with `IdentityMismatch` |
//! | `register` | accept a valid registration, then open HTTP/2 as the client |
//!
//! `tunnelward conformance` runs them from the command line.

mod checks;

use core::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::rustls::{ClientConfig, RootCertStore};
use tunnelward_crypto::{Identity, KeyExchange, client_config};
use tunnelward_proto::{ALPN, Limits};

/// The gateway the checks run against, and who they connect as.
#[derive(Clone)]
pub struct Target {
    addr: String,
    server_name: ServerName<'static>,
    /// TLS offering `tw/1`.
    tw: Arc<ClientConfig>,
    /// TLS offering only `h2`.
    other: Arc<ClientConfig>,
    spiffe_id: String,
    route: String,
    timeout: Duration,
    limits: Limits,
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target")
            .field("addr", &self.addr)
            .field("spiffe_id", &self.spiffe_id)
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

impl Target {
    /// The gateway at `addr` (`host:port`), whose certificate names
    /// `server_name` and chains to `roots`, reached as `spiffe_id`, the
    /// SPIFFE ID in `identity`'s certificate. The `register` check claims
    /// the route `conformance`, and every check waits at most 5 s.
    ///
    /// # Errors
    ///
    /// The server name or the TLS configuration is not usable.
    pub fn new(
        addr: impl Into<String>,
        server_name: &str,
        roots: &Arc<RootCertStore>,
        identity: &Identity,
        spiffe_id: impl Into<String>,
    ) -> Result<Self, String> {
        let tls = |alpn: &[&[u8]]| {
            let id = Identity {
                chain: identity.chain.clone(),
                key: identity.key.clone_key(),
            };
            client_config(roots.clone(), Some(id), KeyExchange::default(), alpn)
                .map(Arc::new)
                .map_err(|e| format!("TLS: {e}"))
        };
        Ok(Self {
            addr: addr.into(),
            server_name: ServerName::try_from(server_name.to_owned())
                .map_err(|e| format!("server name {server_name:?}: {e}"))?,
            tw: tls(&[ALPN])?,
            other: tls(&[b"h2"])?,
            spiffe_id: spiffe_id.into(),
            route: "conformance".into(),
            timeout: Duration::from_secs(5),
            limits: Limits::default(),
        })
    }

    /// The same target, registering `route` in the `register` check.
    #[must_use]
    pub fn with_route(mut self, route: impl Into<String>) -> Self {
        self.route = route.into();
        self
    }

    /// The same target, waiting at most `timeout` for each answer.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// How one check went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    /// The check's name, such as `malformed`.
    pub check: &'static str,
    /// Whether the gateway did what it must.
    pub passed: bool,
    /// What the gateway did.
    pub detail: String,
}

/// Every check's outcome, in the order they ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The kit's version, so a report says what it was judged against.
    pub kit: &'static str,
    /// The outcomes.
    pub outcomes: Vec<Outcome>,
}

impl Report {
    /// Whether every check passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.outcomes.iter().all(|o| o.passed)
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for o in &self.outcomes {
            let mark = if o.passed { "pass" } else { "FAIL" };
            writeln!(f, "{mark} {:<10} {}", o.check, o.detail)?;
        }
        let passed = self.outcomes.iter().filter(|o| o.passed).count();
        write!(f, "{passed} of {} checks passed", self.outcomes.len())
    }
}

/// Runs every check against `target`, one after another.
pub async fn run(target: &Target) -> Report {
    let outcomes = vec![
        checks::alpn(target).await,
        checks::malformed(target).await,
        checks::oversized(target).await,
        checks::version(target).await,
        checks::identity(target).await,
        checks::register(target).await,
    ];
    Report {
        kit: env!("CARGO_PKG_VERSION"),
        outcomes,
    }
}
