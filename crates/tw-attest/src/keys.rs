// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The keys whose signatures a gateway believes.

use core::fmt;

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ED25519, ParsedPublicKey};
use tunnelward_crypto::rustls::pki_types::SubjectPublicKeyInfoDer;
use tunnelward_crypto::rustls::pki_types::pem::PemObject;

/// A public key trusted to sign passmcp attestations: ECDSA P-256 with
/// SHA-256 (what `cosign generate-key-pair` makes) or Ed25519.
pub struct TrustedKey {
    key: ParsedPublicKey,
    kind: &'static str,
    id: String,
}

impl TrustedKey {
    /// A key from a PEM `PUBLIC KEY` block (`SubjectPublicKeyInfo`).
    ///
    /// # Errors
    ///
    /// A message naming what is wrong: no PEM public key, or a key of
    /// another type or curve.
    pub fn from_pem(pem: &[u8]) -> Result<Self, String> {
        let spki = SubjectPublicKeyInfoDer::from_pem_slice(pem)
            .map_err(|e| format!("not a PEM public key: {e}"))?;
        Self::from_spki(spki.as_ref())
    }

    /// A key from DER `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    ///
    /// As [`TrustedKey::from_pem`].
    pub fn from_spki(der: &[u8]) -> Result<Self, String> {
        let id = tunnelward_audit::digest(der);
        if let Ok(key) = ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, der) {
            return Ok(Self {
                key,
                kind: "ECDSA P-256",
                id,
            });
        }
        if let Ok(key) = ParsedPublicKey::new(&ED25519, der) {
            return Ok(Self {
                key,
                kind: "Ed25519",
                id,
            });
        }
        Err("only ECDSA P-256 and Ed25519 keys are supported".into())
    }

    /// Whether `signature` over `message` verifies under this key.
    #[must_use]
    pub fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        self.key.verify_sig(message, signature).is_ok()
    }

    /// SHA-256 of the key's `SubjectPublicKeyInfo`, in hex.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// `ECDSA P-256` or `Ed25519`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        self.kind
    }
}

impl fmt::Debug for TrustedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedKey")
            .field("kind", &self.kind)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_kinds_and_refuses_others() {
        let p256 = include_bytes!("../tests/vectors/cosign-p256.pub");
        let ed = include_bytes!("../tests/vectors/ed25519.pub");
        assert_eq!(TrustedKey::from_pem(p256).unwrap().kind(), "ECDSA P-256");
        assert_eq!(TrustedKey::from_pem(ed).unwrap().kind(), "Ed25519");
        assert!(
            TrustedKey::from_pem(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
                .is_err()
        );
        assert!(TrustedKey::from_spki(&[0x30, 0x00]).is_err());
    }
}
