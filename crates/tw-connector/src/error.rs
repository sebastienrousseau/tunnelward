// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Why a connector session failed.

use core::fmt;
use std::io;

use tunnelward_proto::Reject;
use tunnelward_proto::io::{ReadError, WriteError};

/// A connector session failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The TCP connection or TLS handshake failed.
    Connect(io::Error),
    /// The gateway did not agree to ALPN `tw/1`.
    Alpn,
    /// Registration took longer than the configured timeout.
    Timeout,
    /// The register frame could not be sent.
    Write(WriteError),
    /// The gateway's answer could not be read.
    Read(ReadError),
    /// The gateway refused the registration.
    Rejected(Reject),
    /// The gateway answered with something other than Accept or Reject.
    UnexpectedFrame,
    /// The HTTP/2 connection failed after registration.
    Http(hyper::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "cannot reach the gateway: {e}"),
            Self::Alpn => f.write_str("the gateway did not agree to protocol tw/1"),
            Self::Timeout => f.write_str("registration timed out"),
            Self::Write(e) => e.fmt(f),
            Self::Read(e) => e.fmt(f),
            Self::Rejected(r) => write!(f, "registration rejected ({:?}): {}", r.code, r.reason),
            Self::UnexpectedFrame => f.write_str("the gateway sent an unexpected frame"),
            Self::Http(e) => write!(f, "HTTP/2 connection failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) => Some(e),
            Self::Write(e) => Some(e),
            Self::Read(e) => Some(e),
            Self::Http(e) => Some(e),
            _ => None,
        }
    }
}
