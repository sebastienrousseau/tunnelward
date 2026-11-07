// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a [`Connector`](crate::Connector) reports (G8).

use std::net::SocketAddr;

use tw_proto::RejectCode;

/// Something that happened to a connector. Subscribe with
/// [`Connector::events`](crate::Connector::events); a subscriber that falls
/// more than 256 events behind misses the oldest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectorEvent {
    /// The gateway list was resolved, and changed.
    Resolved {
        /// Every gateway address now in use.
        gateways: Vec<SocketAddr>,
    },
    /// A connection registered.
    Registered {
        /// The gateway.
        gateway: SocketAddr,
        /// The lease the gateway granted, in seconds.
        lease_secs: u32,
    },
    /// A gateway refused the registration.
    Rejected {
        /// The gateway.
        gateway: SocketAddr,
        /// Why, as a stable code.
        code: RejectCode,
        /// The gateway's reason.
        reason: String,
    },
    /// A connection could not be opened or registered.
    Failed {
        /// The gateway.
        gateway: SocketAddr,
        /// What went wrong.
        error: String,
    },
    /// A connection is being replaced before its lease ends; its
    /// successor is dialled first.
    Renewing {
        /// The gateway.
        gateway: SocketAddr,
    },
    /// A connection ended.
    Disconnected {
        /// The gateway.
        gateway: SocketAddr,
    },
    /// The connector stopped.
    Stopped {
        /// Whether every request in flight finished before the deadline.
        completed: bool,
    },
}
