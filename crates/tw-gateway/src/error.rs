// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Gateway errors.

use core::fmt;
use std::io;

use tunnelward_proto::RejectCode;
use tunnelward_proto::io::{ReadError, WriteError};

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

impl AdmitError {
    /// The error's stable id, explained at [`AdmitError::docs_url`]. A
    /// rejection carries its [`RejectCode`]'s id.
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Self::Tls(_) => "TW-A001",
            Self::Alpn => "TW-A002",
            Self::Timeout => "TW-A003",
            Self::Read(_) => "TW-A004",
            Self::Rejected(code) => code.id(),
            Self::Write(_) => "TW-A005",
            Self::Http(_) => "TW-A006",
        }
    }

    /// Where this error is explained.
    #[must_use]
    pub fn docs_url(&self) -> String {
        tunnelward_proto::error_url(self.id())
    }
}

/// A request could not be sent through a connector.
#[derive(Debug)]
#[non_exhaustive]
pub enum SendError {
    /// No live connector serves the request's host and path, no route is
    /// kept for it, and no connector for it is being admitted.
    NoRoute,
    /// The route exists but no connector had a free slot within
    /// `max_wait`, or its wait queue was full. Answer 503 with this
    /// `Retry-After`.
    Unavailable {
        /// How long the client should wait before retrying.
        retry_after: std::time::Duration,
    },
    /// The request's URI could not be made absolute.
    BadRequest(http::Error),
    /// The request failed on the connector connection.
    Http(hyper::Error),
}

impl SendError {
    /// The error's stable id, explained at [`SendError::docs_url`].
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Self::NoRoute => "TW-S001",
            Self::Unavailable { .. } => "TW-S002",
            Self::BadRequest(_) => "TW-S003",
            Self::Http(_) => "TW-S004",
        }
    }

    /// Where this error is explained.
    #[must_use]
    pub fn docs_url(&self) -> String {
        tunnelward_proto::error_url(self.id())
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoute => f.write_str("no connector serves this route"),
            Self::Unavailable { retry_after } => {
                write!(
                    f,
                    "no connector free; retry after {} s",
                    retry_after.as_secs()
                )
            }
            Self::BadRequest(e) => write!(f, "bad request: {e}"),
            Self::Http(e) => write!(f, "request through connector failed: {e}"),
        }
    }
}

impl std::error::Error for SendError {}
