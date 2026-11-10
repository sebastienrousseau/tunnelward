// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Keyed-hash pseudonyms (FR-18, D7): the same value under the same key
//! gives the same pseudonym, so entries for one client link together,
//! but the value cannot be recovered or tested for without the key.

use aws_lc_rs::hmac;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// Length of a pseudonym key, in bytes.
pub const KEY_LEN: usize = 32;

/// Bytes of the HMAC kept, as 32 hex digits.
const KEPT: usize = 16;

/// Pseudonyms under one key.
pub struct Pseudonyms {
    key: hmac::Key,
}

impl core::fmt::Debug for Pseudonyms {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pseudonyms").finish_non_exhaustive()
    }
}

impl Pseudonyms {
    /// Pseudonyms under `key`.
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
        }
    }

    /// A new random key.
    ///
    /// # Errors
    ///
    /// The system's random source failed.
    pub fn generate_key() -> Result<[u8; KEY_LEN], String> {
        let mut key = [0; KEY_LEN];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| "no random bytes".to_owned())?;
        Ok(key)
    }

    /// The pseudonym of `value` in `field` (for example `ip`): 128 bits
    /// of HMAC-SHA-256, in hex. The field is part of the input, so one
    /// value gives different pseudonyms in different fields.
    #[must_use]
    pub fn of(&self, field: &str, value: &[u8]) -> String {
        let mut context = hmac::Context::with_key(&self.key);
        context.update(field.as_bytes());
        context.update(&[0]);
        context.update(value);
        crate::hex(&context.sign().as_ref()[..KEPT])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudonyms_are_stable_per_key_and_field() {
        let a = Pseudonyms::new(&[1; KEY_LEN]);
        let b = Pseudonyms::new(&[2; KEY_LEN]);
        let ip = a.of("ip", b"192.0.2.1");
        assert_eq!(ip.len(), 32);
        assert_eq!(ip, a.of("ip", b"192.0.2.1"));
        assert_ne!(ip, a.of("ip", b"192.0.2.2"));
        assert_ne!(ip, a.of("cert", b"192.0.2.1"));
        assert_ne!(ip, b.of("ip", b"192.0.2.1"));
        assert!(!ip.contains("192"));
    }
}
