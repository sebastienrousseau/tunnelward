// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Hooks into every ingress request (G11), for metrics, logs and audit.
//! OpenTelemetry (v0.0.16) is built on the same hooks.

use core::fmt;
use std::time::Duration;

use http::{Method, StatusCode, Uri};

use tunnelward_mcp::Envelope;

use crate::ClientAddr;

/// One ingress request, as observers see it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RequestInfo {
    /// Unique per gateway process, in arrival order.
    pub id: u64,
    /// The request method.
    pub method: Method,
    /// The request URI, as the client sent it.
    pub uri: Uri,
    /// Who sent it (FR-11).
    pub client: ClientAddr,
    /// The request's id, a ULID: sent to the connector and back to the
    /// client in `tw-request-id`.
    pub request_id: String,
    /// `User-Agent`, as the client declares it (at most 256 bytes).
    pub user_agent: Option<String>,
    /// A well-formed W3C `traceparent` header, when the client sent one.
    pub traceparent: Option<String>,
    /// The MCP session (`Mcp-Session-Id`), when the client sent one.
    pub mcp_session: Option<String>,
}

/// Called at each step of an ingress request. Every method has an empty
/// default; implement the ones you need. Calls happen on the request's own
/// task, so keep them short.
pub trait ProxyObserver: fmt::Debug + Send + Sync {
    /// The request arrived, before any check.
    fn on_request(&self, _info: &RequestInfo) {}

    /// The body is an MCP envelope (a JSON POST that parsed as JSON-RPC
    /// 2.0): the methods and tools it calls, and what the client declares.
    fn on_envelope(&self, _info: &RequestInfo, _envelope: &Envelope) {}

    /// The response headers are ready: from a connector, or from the
    /// gateway itself for a refused request.
    fn on_response(&self, _info: &RequestInfo, _status: StatusCode, _elapsed: Duration) {}

    /// The response body ended or was dropped, after `bytes` bytes.
    fn on_complete(&self, _info: &RequestInfo, _bytes: u64, _elapsed: Duration) {}

    /// The gateway answered with an error instead of a connector's
    /// response, and why.
    fn on_failure(&self, _info: &RequestInfo, _status: StatusCode, _reason: &str) {}
}
