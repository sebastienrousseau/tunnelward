// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The chain: each line names the hash of the one before it, and a
//! checkpoint signs the head.

use tunnelward_crypto::composite;

/// The `prev` of the first line: 64 zeros.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What a checkpoint signature covers, before its fields.
const CHECKPOINT_LABEL: &[u8] = b"tunnelward audit checkpoint v1\0";

/// The hash the next line names as `prev`: SHA-256 of `line`'s bytes,
/// without its newline, in hex.
#[must_use]
pub fn hash_line(line: &[u8]) -> String {
    crate::digest(line)
}

/// A short name for a public key: the first 8 bytes of its SHA-256, in
/// hex.
#[must_use]
pub fn key_id(public: &[u8]) -> String {
    crate::digest(public)[..16].to_owned()
}

/// The message a checkpoint at `seq` signs.
fn message(seq: u64, prev: &str, time: u64) -> Vec<u8> {
    [
        CHECKPOINT_LABEL,
        &seq.to_be_bytes(),
        prev.as_bytes(),
        &time.to_be_bytes(),
    ]
    .concat()
}

/// The signature for a checkpoint at `seq`, after the line hashed to
/// `prev`, at `time`.
pub(crate) fn sign(
    key: &composite::SigningKey,
    seq: u64,
    prev: &str,
    time: u64,
) -> Result<Vec<u8>, composite::KeyError> {
    key.sign(&message(seq, prev, time))
}

/// Whether `signature` is `public`'s checkpoint signature for those
/// fields.
pub(crate) fn verify(public: &[u8], seq: u64, prev: &str, time: u64, signature: &[u8]) -> bool {
    composite::verify(public, &message(seq, prev, time), signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_checkpoint_signature_covers_every_field() {
        let (key, _) = composite::SigningKey::generate().unwrap();
        let public = key.public_key();
        let sig = sign(&key, 7, GENESIS, 1000).unwrap();
        assert!(verify(&public, 7, GENESIS, 1000, &sig));
        assert!(!verify(&public, 8, GENESIS, 1000, &sig));
        assert!(!verify(&public, 7, &"1".repeat(64), 1000, &sig));
        assert!(!verify(&public, 7, GENESIS, 1001, &sig));
        assert_eq!(key_id(&public).len(), 16);
    }
}
