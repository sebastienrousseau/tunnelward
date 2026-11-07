// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stable rejection codes. A code's number never changes meaning; new
//! codes take new numbers.

use core::fmt;
use serde::{Deserialize, Serialize};

/// Why a gateway refused a registration. Sent in [`Reject`](crate::Reject)
/// as a `u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
#[non_exhaustive]
pub enum RejectCode {
    /// The frame could not be parsed.
    Malformed = 1,
    /// The protocol version is not one the gateway speaks.
    UnsupportedVersion = 2,
    /// The SPIFFE ID in the frame does not match the client certificate.
    IdentityMismatch = 3,
    /// A claimed route belongs to another identity.
    RouteOwned = 4,
    /// A claimed route, or another field, is not valid.
    Invalid = 5,
    /// The route requires a passmcp attestation and none was sent.
    AttestationRequired = 6,
    /// The attestation is expired, revoked, unsigned or for another server.
    AttestationInvalid = 7,
    /// Policy does not allow this identity to register.
    PolicyDenied = 8,
    /// Too many registration attempts from this source.
    RateLimited = 9,
    /// The gateway is at capacity.
    Overloaded = 10,
    /// The gateway failed; retry later.
    Internal = 11,
}

const ALL: [RejectCode; 11] = [
    RejectCode::Malformed,
    RejectCode::UnsupportedVersion,
    RejectCode::IdentityMismatch,
    RejectCode::RouteOwned,
    RejectCode::Invalid,
    RejectCode::AttestationRequired,
    RejectCode::AttestationInvalid,
    RejectCode::PolicyDenied,
    RejectCode::RateLimited,
    RejectCode::Overloaded,
    RejectCode::Internal,
];

impl From<RejectCode> for u16 {
    fn from(code: RejectCode) -> Self {
        code as u16
    }
}

/// A number that is not a known [`RejectCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownCode(pub u16);

impl fmt::Display for UnknownCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown reject code {}", self.0)
    }
}

impl std::error::Error for UnknownCode {}

impl TryFrom<u16> for RejectCode {
    type Error = UnknownCode;

    fn try_from(n: u16) -> Result<Self, Self::Error> {
        ALL.into_iter()
            .find(|c| u16::from(*c) == n)
            .ok_or(UnknownCode(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_stable_and_round_trip() {
        for (i, code) in ALL.into_iter().enumerate() {
            let n = u16::from(code);
            assert_eq!(usize::from(n), i + 1, "{code:?} keeps its number");
            assert_eq!(RejectCode::try_from(n), Ok(code));
        }
        assert_eq!(RejectCode::try_from(0), Err(UnknownCode(0)));
        assert_eq!(RejectCode::try_from(12), Err(UnknownCode(12)));
    }
}
