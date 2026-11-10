// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Tunnelward's audit log (FR-15, FR-18; ADR 0008).
//!
//! - [`Sink`] appends [`Entry`] records to a hash-chained JSON Lines
//!   file from a thread of its own, with signed checkpoints.
//! - [`verify::verify`] checks such a file offline.
//! - [`receipt`] issues and checks signed call receipts.
//! - [`Pseudonyms`] turns addresses and fingerprints into keyed hashes.
//! - [`ocsf`] writes entries as OCSF events.
//!
//! Each line has `seq`, `prev` (the SHA-256 of the previous line's
//! bytes), `time` in milliseconds since 1970 and `kind`. Checkpoints
//! sign `seq`, `prev` and `time` with a composite ML-DSA-65 + Ed25519
//! key ([`tunnelward_crypto::composite`]).

pub mod b64;
mod calls;
mod chain;
mod entry;
pub mod ocsf;
mod pseudonym;
mod raw;
pub mod receipt;
mod sink;
pub mod verify;

pub use calls::calls;
pub use chain::{GENESIS, hash_line, key_id};
pub use entry::{AdminEntry, Call, Entry, RequestEntry};
pub use pseudonym::{KEY_LEN as PSEUDONYM_KEY_LEN, Pseudonyms};
pub use raw::Raw;
pub use sink::{MAX_RAW_DAYS, Settings, Sink};

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ok = write!(s, "{b:02x}");
        s
    })
}

/// Hex decoded; `None` for an odd length or a non-hex digit.
#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// SHA-256 of `bytes`, in hex.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes).as_ref())
}

/// Milliseconds since 1970, now.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_refuses_bad_input() {
        assert_eq!(hex(&[0, 0xab, 0xff]), "00abff");
        assert_eq!(unhex("00abff"), Some(vec![0, 0xab, 0xff]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn digests_are_sha256() {
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
