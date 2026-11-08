// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! What the gateway holds, at two redaction levels (FR-9), and the same
//! counters as Prometheus text (G15).

use std::collections::HashSet;
use std::fmt::Write as _;

use serde::Serialize;

use crate::Gateway;
use crate::registry::Snapshot;

/// How much an inventory reveals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Redaction {
    /// Counts only: no addresses, routes, domains or identifiers.
    #[default]
    Public,
    /// Every connection, with its connector, address, routes and load.
    Internal,
}

/// The gateway's live state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Inventory {
    /// Open connector connections.
    pub connections: usize,
    /// Distinct connectors behind them.
    pub connectors: usize,
    /// Distinct routes they claim.
    pub routes: usize,
    /// Requests in flight.
    pub in_flight: u32,
    /// Requests waiting for a free slot.
    pub waiting: u32,
    /// Connections draining.
    pub draining: u32,
    /// One entry per connection, at [`Redaction::Internal`] only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Vec<Connection>>,
}

/// One connector connection, as [`Redaction::Internal`] shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Connection {
    /// The connector's id, as 32 hex digits.
    pub connector: String,
    /// Where it connected from, when the listener knew.
    pub peer: Option<String>,
    /// Routes it claims.
    pub routes: Vec<String>,
    /// Domains it claims.
    pub domains: Vec<String>,
    /// Most requests it takes at once.
    pub capacity: u32,
    /// Requests it is serving now.
    pub in_flight: u32,
    /// Whether it is draining.
    pub draining: bool,
    /// Whether it is dark: connected, but taking no new request (G14).
    pub dark: bool,
}

impl From<Snapshot> for Connection {
    fn from(s: Snapshot) -> Self {
        Self {
            connector: hex(&s.id.0),
            peer: s.peer.map(|ip| ip.to_string()),
            routes: s.routes,
            domains: s.domains,
            capacity: s.capacity,
            in_flight: s.in_flight,
            draining: s.draining,
            dark: s.dark,
        }
    }
}

/// Lower-case hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _infallible = write!(out, "{b:02x}");
            out
        })
}

impl Gateway {
    /// The gateway's live state at `redaction`.
    #[must_use]
    pub fn inventory(&self, redaction: Redaction) -> Inventory {
        let registry = &self.inner.registry;
        let snapshot = registry.snapshot();
        let connectors: HashSet<_> = snapshot.iter().map(|s| s.id).collect();
        let routes: HashSet<_> = snapshot.iter().flat_map(|s| s.routes.iter()).collect();
        let (connectors, routes) = (connectors.len(), routes.len());
        Inventory {
            connections: snapshot.len(),
            connectors,
            routes,
            in_flight: snapshot.iter().map(|s| s.in_flight).sum(),
            waiting: registry.waiting(),
            draining: registry.draining(),
            detail: (redaction == Redaction::Internal)
                .then(|| snapshot.into_iter().map(Connection::from).collect()),
        }
    }
}

/// `inventory`'s counters in the Prometheus text format.
pub(crate) fn metrics(inventory: &Inventory) -> String {
    let gauges: [(&str, &str, u64); 6] = [
        (
            "connections",
            "Open connector connections",
            inventory.connections as u64,
        ),
        (
            "connectors",
            "Distinct connectors",
            inventory.connectors as u64,
        ),
        ("routes", "Distinct routes claimed", inventory.routes as u64),
        (
            "in_flight",
            "Requests in flight",
            u64::from(inventory.in_flight),
        ),
        (
            "waiting",
            "Requests waiting for a slot",
            u64::from(inventory.waiting),
        ),
        (
            "draining",
            "Connections draining",
            u64::from(inventory.draining),
        ),
    ];
    gauges.iter().fold(String::new(), |mut out, (name, help, value)| {
        let _infallible = write!(
            out,
            "# HELP tunnelward_{name} {help}\n# TYPE tunnelward_{name} gauge\ntunnelward_{name} {value}\n"
        );
        out
    })
}
