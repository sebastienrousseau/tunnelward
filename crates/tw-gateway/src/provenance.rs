// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The first parts of a request's provenance (FR-14): its request id,
//! and what the client declares about itself. Declared fields are
//! evidence, never identity.

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use http::HeaderMap;

/// The header carrying a request's id, to the connector and back to the
/// client.
pub(crate) const REQUEST_ID: http::HeaderName = http::HeaderName::from_static("tw-request-id");

/// Longest declared header value kept, in bytes.
const MAX_DECLARED: usize = 256;

/// Crockford's base32 alphabet, as ULIDs use it.
const BASE32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A new ULID: 48 bits of milliseconds since 1970, then 80 random bits,
/// as 26 characters that sort by time.
pub(crate) fn request_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let mut random = [0_u8; 10];
    // Without randomness the id is still unique enough per millisecond
    // for logs; it is never a secret.
    let _filled = SystemRandom::new().fill(&mut random);
    let tail = random
        .iter()
        .fold(0_u128, |acc, b| acc << 8 | u128::from(*b));
    let value = (millis & 0xffff_ffff_ffff) << 80 | tail;
    (0..26)
        .rev()
        .map(|i| char::from(BASE32[usize::try_from(value >> (i * 5) & 31).unwrap_or(0)]))
        .collect()
}

/// A W3C trace context `traceparent` (version 00): lower-case hex,
/// non-zero trace and parent ids. Anything else is ignored, not trusted.
pub(crate) fn valid_traceparent(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    let hex = |s: &str, len: usize| {
        s.len() == len
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let nonzero = |s: &str| s.bytes().any(|b| b != b'0');
    matches!(parts.as_slice(), [version, trace, parent, flags]
        if hex(version, 2) && *version != "ff" && hex(trace, 32) && nonzero(trace)
            && hex(parent, 16) && nonzero(parent) && hex(flags, 2))
}

/// A header's value as text, cut to [`MAX_DECLARED`] bytes on a character
/// boundary, if present and visible ASCII.
pub(crate) fn declared(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?;
    let mut end = value.len().min(MAX_DECLARED);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    Some(value[..end].to_owned())
}

/// The `traceparent` header, if it is well formed.
pub(crate) fn traceparent(headers: &HeaderMap) -> Option<String> {
    declared(headers, "traceparent").filter(|t| valid_traceparent(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_are_26_crockford_characters_that_sort_by_time() {
        let (a, b) = (request_id(), request_id());
        assert_eq!(a.len(), 26);
        assert!(a.bytes().all(|c| BASE32.contains(&c)), "{a}");
        assert_ne!(a, b);
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(request_id()[..10] > a[..10]);
    }

    #[test]
    fn traceparents_follow_w3c() {
        let good = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert!(valid_traceparent(good));
        for bad in [
            "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01",
            "00-00000000000000000000000000000000-b7ad6b7169203331-01",
            "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01",
            "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331",
            "00-0af7651916cd43dd8448eb211c8031-b7ad6b7169203331-01",
        ] {
            assert!(!valid_traceparent(bad), "{bad}");
        }
    }

    #[test]
    fn declared_values_are_cut_to_256_bytes() {
        let mut headers = HeaderMap::new();
        let long = "a".repeat(300);
        headers.insert(
            "user-agent",
            long.parse().unwrap_or_else(|_| unreachable!()),
        );
        assert_eq!(declared(&headers, "user-agent").map(|v| v.len()), Some(256));
        assert_eq!(declared(&headers, "absent"), None);
    }
}
