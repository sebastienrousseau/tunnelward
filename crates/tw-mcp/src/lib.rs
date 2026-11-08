// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tunnelward MCP envelope parsing for Streamable HTTP and SSE.
//!
//! An MCP client sends JSON-RPC 2.0 messages in the body of an HTTP POST.
//! A gateway that applies policy per tool needs the envelope, not the
//! arguments: the method, the id, the tool a `tools/call` names, and the
//! client's self-description. [`parse`] reads exactly that from a body of
//! at most [`MAX_BODY`] bytes, skipping everything else unread, and
//! refuses anything that is not JSON-RPC 2.0.
//!
//! ```
//! use tunnelward_mcp::{Kind, parse};
//!
//! let body = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call",
//!                 "params":{"name":"get_weather","arguments":{"city":"Paris"}}}"#;
//! let envelope = parse(body)?;
//! let call = &envelope.messages[0];
//! assert_eq!(call.kind, Kind::Request);
//! assert_eq!(call.method.as_deref(), Some("tools/call"));
//! assert_eq!(call.tool.as_deref(), Some("get_weather"));
//! # Ok::<(), tunnelward_mcp::EnvelopeError>(())
//! ```
//!
//! Self-described fields ([`ClientInfo`], a `traceparent` in `_meta`) are
//! what the client says about itself: evidence, never identity.

mod envelope;

pub use envelope::{ClientInfo, Envelope, EnvelopeError, Id, Kind, Message, parse};

/// The largest body [`parse`] reads: 1 MiB. A bigger body is refused
/// before any of it is parsed.
pub const MAX_BODY: usize = 1 << 20;

/// The most messages a batch may hold.
pub const MAX_BATCH: usize = 64;

/// The header that carries an MCP session id (Streamable HTTP).
pub const SESSION_HEADER: &str = "mcp-session-id";

/// The content type of a Server-Sent Events stream.
pub const EVENT_STREAM: &str = "text/event-stream";

/// Whether a `Content-Type` value is JSON, which is how MCP clients send
/// their messages.
#[must_use]
pub fn is_json(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case("application/json"))
}
