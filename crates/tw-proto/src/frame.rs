// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The frames exchanged before a connector connection turns into HTTP/2.
//!
//! A connector sends one [`Register`]; the gateway answers with one
//! [`Accept`] or [`Reject`]. Field names are the CBOR map keys, so a
//! rename here is a wire change.

use serde::{Deserialize, Serialize};

use crate::code::RejectCode;
use crate::limits::StreamLimits;

/// The protocol version this crate speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// The TLS ALPN identifier for a connector connection.
pub const ALPN: &[u8] = b"tw/1";

/// A connector process's identifier, stable for the life of the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectorId(#[serde(with = "serde_bytes")] pub [u8; 16]);

/// What the MCP server behind a connector says it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpDescriptor {
    /// The server's name, as in its MCP `initialize` result.
    pub name: String,
    /// The server's version, as in its MCP `initialize` result.
    pub version: String,
    /// SHA-256 of the server's tool list, so a change of tools is visible.
    #[serde(with = "serde_bytes")]
    pub tools_digest: [u8; 32],
}

/// A connector asks to serve routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    /// Protocol version; must be [`PROTOCOL_VERSION`].
    pub version: u16,
    /// The connector process.
    pub connector_id: ConnectorId,
    /// The connector's SPIFFE ID; must match its client certificate.
    pub spiffe_id: String,
    /// Path-prefix routes the connector serves, such as `mcp/payments`.
    pub routes: Vec<String>,
    /// The MCP server behind the connector, when there is one.
    pub mcp: Option<McpDescriptor>,
    /// A passmcp attestation bundle (DSSE envelope), when the route needs one.
    #[serde(with = "serde_bytes")]
    pub attestation: Option<Vec<u8>>,
    /// Most concurrent streams the connector accepts; at least 1.
    pub capacity: u32,
}

/// The gateway admits a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accept {
    /// Seconds until the registration expires unless renewed; at least 1.
    pub lease_secs: u32,
    /// HTTP/2 limits for this connection.
    pub limits: StreamLimits,
}

/// The gateway refuses a connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reject {
    /// Why, as a stable code.
    pub code: RejectCode,
    /// A human-readable reason; no control characters.
    pub reason: String,
}

/// One frame on a connector connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    /// Sent by the connector.
    Register(Register),
    /// Sent by the gateway on success.
    Accept(Accept),
    /// Sent by the gateway on refusal.
    Reject(Reject),
}
