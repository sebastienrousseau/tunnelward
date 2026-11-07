// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Hard limits. Every one is configurable, has a documented default, and
//! is checked before the memory it bounds is allocated.

use serde::{Deserialize, Serialize};

/// Bytes in the big-endian length prefix in front of every frame.
pub const LENGTH_PREFIX_LEN: usize = 4;

const KIB: u32 = 1024;
const MIB: u32 = 1024 * KIB;

/// HTTP/2 limits the gateway grants a connector connection in
/// [`Accept`](crate::Accept). They are on the wire, so both sides agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamLimits {
    /// Concurrent streams on one connector connection.
    pub max_concurrent_streams: u32,
    /// Bytes in one request or response header list.
    pub max_header_list_size: u32,
    /// HTTP/2 initial flow-control window per stream, in bytes.
    pub initial_stream_window: u32,
    /// HTTP/2 initial flow-control window per connection, in bytes.
    pub initial_connection_window: u32,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 256,
            max_header_list_size: 64 * KIB,
            initial_stream_window: 256 * KIB,
            initial_connection_window: 4 * MIB,
        }
    }
}

/// The limits a gateway enforces. [`Limits::default`] gives the values in
/// the specification's hard-limits table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest frame body accepted, in bytes, before identity is known.
    pub max_frame_len: u32,
    /// Routes one connector identity may claim.
    pub max_routes_per_identity: u16,
    /// Domains one connector identity may claim.
    pub max_domains_per_identity: u16,
    /// Domains one gateway serves.
    pub max_domains: u32,
    /// Requests waiting for a free connector, per route.
    pub max_waiting_per_route: u32,
    /// Bytes of a JSON-RPC body parsed for a policy decision.
    pub max_policy_body: u32,
    /// Registration attempts accepted per source per minute.
    pub registrations_per_minute: u32,
    /// HTTP/2 limits granted to each connector connection.
    pub stream: StreamLimits,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_len: 64 * KIB,
            max_routes_per_identity: 64,
            max_domains_per_identity: 16,
            max_domains: 1024,
            max_waiting_per_route: 1024,
            max_policy_body: MIB,
            registrations_per_minute: 60,
            stream: StreamLimits::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_specification_table() {
        let l = Limits::default();
        assert_eq!(l.max_frame_len, 65_536);
        assert_eq!(l.stream.max_header_list_size, 65_536);
        assert_eq!(l.stream.max_concurrent_streams, 256);
        assert_eq!(l.stream.initial_stream_window, 262_144);
        assert_eq!(l.stream.initial_connection_window, 4_194_304);
        assert_eq!(l.max_routes_per_identity, 64);
        assert_eq!(l.max_domains_per_identity, 16);
        assert_eq!(l.max_domains, 1024);
        assert_eq!(l.max_waiting_per_route, 1024);
        assert_eq!(l.max_policy_body, 1_048_576);
        assert_eq!(l.registrations_per_minute, 60);
    }
}
