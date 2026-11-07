// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tunnelward wire protocol: register frames, limits and error codes.
//!
//! A connector dials the gateway over TLS (ALPN [`ALPN`]) and sends one
//! [`Register`] frame. The gateway answers with [`Accept`] or [`Reject`],
//! and on acceptance both sides switch the same stream to HTTP/2 with
//! reversed roles (ADR 0001). This crate owns only those first frames:
//! their types, the length-prefixed CBOR codec, the validation rules and
//! the hard limits.
//!
//! ```
//! use tw_proto::{decode, encode, ConnectorId, Decoded, Frame, Limits, Register, PROTOCOL_VERSION};
//!
//! let limits = Limits::default();
//! let frame = Frame::Register(Register {
//!     version: PROTOCOL_VERSION,
//!     connector_id: ConnectorId([7; 16]),
//!     spiffe_id: "spiffe://example.org/ns/prod/sa/payments".into(),
//!     routes: vec!["mcp/payments".into()],
//!     domains: vec!["mcp.example.org".into()],
//!     mcp: None,
//!     attestation: None,
//!     capacity: 32,
//! });
//! let bytes = encode(&frame, &limits)?;
//! assert_eq!(
//!     decode(&bytes, &limits)?,
//!     Decoded::Frame { frame, consumed: bytes.len() },
//! );
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod code;
mod codec;
mod frame;
#[cfg(feature = "io")]
pub mod io;
mod limits;
mod validate;

pub use code::{RejectCode, UnknownCode};
pub use codec::{DecodeError, Decoded, EncodeError, decode, encode};
pub use frame::{
    ALPN, Accept, ConnectorId, Frame, McpDescriptor, PROTOCOL_VERSION, Register, Reject,
};
pub use limits::{LENGTH_PREFIX_LEN, Limits, StreamLimits};
pub use validate::{
    CATCH_ALL_ROUTE, Invalid, MAX_DOMAIN_LEN, MAX_MCP_NAME_LEN, MAX_MCP_VERSION_LEN,
    MAX_REASON_LEN, MAX_ROUTE_LEN, MAX_ROUTE_SEGMENTS, MAX_SEGMENT_LEN, MAX_SPIFFE_ID_LEN,
    is_domain, is_route, is_spiffe_id, validate,
};
