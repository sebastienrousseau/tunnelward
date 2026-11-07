// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Gateway errors.

use core::fmt;
use std::io;

use tw_proto::RejectCode;
use tw_proto::io::{ReadError, WriteError};

/// A connector connection was not admitted, or its session ended badly.
#[derive(Debug)]
#[non_exhaustive]
pub enum AdmitError {
    /// The TLS handshake failed.
    Tls(io::Error),
    /// The connector did not negotiate ALPN `tw/1`; the connection was closed.
    Alpn,
    /// No register frame arrived within the registration timeout.
    Timeout,
    /// The stream failed or ended before a whole frame arrived.
    Read(ReadError),
    /// The gateway refused the registration and told the connector why.
    Rejected(RejectCode),
    /// The answer could not be written.
    Write(WriteError),
    /// The HTTP/2 handshake failed after acceptance.
    Http(hyper::Error),
}

impl fmt::Display for AdmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls(e) => write!(f, "TLS handshake failed: {e}"),
            Self::Alpn => f.write_str("connector did not negotiate tw/1"),
            Self::Timeout => f.write_str("no registration within the timeout"),
            Self::Read(e) => e.fmt(f),
            Self::Rejected(code) => write!(f, "registration rejected: {code:?}"),
            Self::Write(e) => e.fmt(f),
            Self::Http(e) => write!(f, "HTTP/2 handshake failed: {e}"),
        }
    }
}

impl std::error::Error for AdmitError {}

/// A request could not be sent through a connector.
#[derive(Debug)]
#[non_exhaustive]
pub enum SendError {
    /// No live connector serves the request's host and path.
    NoRoute,
    /// The request's URI could not be made absolute.
    BadRequest(http::Error),
    /// The request failed on the connector connection.
    Http(hyper::Error),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoute => f.write_str("no connector serves this route"),
            Self::BadRequest(e) => write!(f, "bad request: {e}"),
            Self::Http(e) => write!(f, "request through connector failed: {e}"),
        }
    }
}

impl std::error::Error for SendError {}
