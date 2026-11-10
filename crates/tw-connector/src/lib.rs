// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tunnelward connector: dials a gateway, registers, then serves the
//! gateway's requests over the connection it opened.
//!
//! The connector never listens. It opens TLS to the gateway with ALPN
//! `tw/1`, sends one [`Register`](tunnelward_proto::Register) frame and reads the
//! answer. On [`Accept`](tunnelward_proto::Accept) the same stream becomes an
//! HTTP/2 connection with the roles reversed: the gateway is the HTTP/2
//! client and the connector the server (ADR 0001), so requests flow in
//! through a connection that was opened outwards.
//!
//! [`register`] does the first part and returns a [`Registered`] session;
//! [`Registered::serve`] runs the HTTP/2 server until the gateway closes
//! the connection. [`Forward`] is a service that sends each request on to
//! a local HTTP server; [`StdioBridge`] serves a local stdio MCP server as
//! Streamable HTTP, one process per session. [`Connector`] keeps several connections to several
//! gateways up for good: it renews them before their leases end, reconnects
//! with jittered backoff, follows DNS, reports [`ConnectorEvent`]s, and
//! shuts down gracefully.

mod backoff;
mod error;
mod event;
mod forward;
mod session;
mod slot;
mod stdio;
mod supervisor;

pub use backoff::Backoff;
pub use error::Error;
pub use event::ConnectorEvent;
pub use forward::{Forward, ForwardBody, RequestHook, Target};
pub use session::{Config, Registered, register};
pub use stdio::{StdioBody, StdioBridge, StdioConfig};
pub use supervisor::{Connector, ConnectorConfig, Gateways};
