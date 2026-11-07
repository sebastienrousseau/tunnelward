// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tunnelward connector: dials a gateway, registers, then serves the
//! gateway's requests over the connection it opened.
//!
//! The connector never listens. It opens TLS to the gateway with ALPN
//! `tw/1`, sends one [`Register`](tw_proto::Register) frame and reads the
//! answer. On [`Accept`](tw_proto::Accept) the same stream becomes an
//! HTTP/2 connection with the roles reversed: the gateway is the HTTP/2
//! client and the connector the server (ADR 0001), so requests flow in
//! through a connection that was opened outwards.
//!
//! [`register`] does the first part and returns a [`Registered`] session;
//! [`Registered::serve`] runs the HTTP/2 server until the gateway closes
//! the connection. [`Forward`] is a service that sends each request on to
//! a local HTTP server. Reconnecting, several gateways and draining arrive
//! in v0.0.6.

mod backoff;
mod error;
mod forward;
mod session;

pub use backoff::Backoff;
pub use error::Error;
pub use forward::{Forward, ForwardBody, Target};
pub use session::{Config, Registered, register};
