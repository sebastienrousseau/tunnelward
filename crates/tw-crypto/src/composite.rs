// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Composite signatures: ML-DSA-65 (FIPS 204) and Ed25519 over the same
//! message, both of which must verify. A flaw in either algorithm alone
//! does not let a signature be forged, so artefacts Tunnelward signs and
//! verifies itself are safe against a quantum attacker without betting
//! on a young algorithm alone.
//!
//! Both components sign the message behind a fixed domain label, so a
//! component signature cannot be lifted out and used elsewhere. This is
//! Tunnelward's own format, not the IETF LAMPS composite-signature
//! encoding, which is still a draft.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ED25519, Ed25519KeyPair, KeyPair, ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
};

/// What every component signs, before the message.
const DOMAIN: &[u8] = b"tunnelward composite ML-DSA-65+Ed25519 v1\0";
/// The start of an encoded private key.
const MAGIC: &[u8] = b"TWCK1";

/// Ed25519 public key length.
const ED25519_PUBLIC: usize = 32;
/// Ed25519 signature length.
const ED25519_SIGNATURE: usize = 64;
/// ML-DSA-65 public key length (FIPS 204).
pub const ML_DSA_65_PUBLIC: usize = 1952;
/// ML-DSA-65 signature length (FIPS 204).
pub const ML_DSA_65_SIGNATURE: usize = 3309;
/// A composite public key: Ed25519 then ML-DSA-65.
pub const PUBLIC_LEN: usize = ED25519_PUBLIC + ML_DSA_65_PUBLIC;
/// A composite signature: Ed25519 then ML-DSA-65.
pub const SIGNATURE_LEN: usize = ED25519_SIGNATURE + ML_DSA_65_SIGNATURE;

/// A key that cannot be made or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyError(&'static str);

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for KeyError {}

/// A composite signing key.
pub struct SigningKey {
    ed25519: Ed25519KeyPair,
    ml_dsa: PqdsaKeyPair,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

impl SigningKey {
    /// A new key, and its encoding for [`SigningKey::from_bytes`]: keep
    /// that secret.
    ///
    /// # Errors
    ///
    /// Key generation failed.
    pub fn generate() -> Result<(Self, Vec<u8>), KeyError> {
        let ed = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| KeyError("Ed25519 key generation failed"))?;
        let ml = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
            .and_then(|k| k.to_pkcs8v1())
            .map_err(|_| KeyError("ML-DSA-65 key generation failed"))?;
        let ed_len = u16::try_from(ed.as_ref().len()).map_err(|_| KeyError("key too long"))?;
        let encoded = [MAGIC, &ed_len.to_be_bytes(), ed.as_ref(), ml.as_ref()].concat();
        Ok((Self::from_bytes(&encoded)?, encoded))
    }

    /// The key [`SigningKey::generate`] encoded.
    ///
    /// # Errors
    ///
    /// The bytes are not such a key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let malformed = KeyError("not a composite key");
        let rest = bytes.strip_prefix(MAGIC).ok_or(malformed)?;
        let (len, rest) = rest.split_first_chunk::<2>().ok_or(malformed)?;
        let (ed, ml) = rest
            .split_at_checked(usize::from(u16::from_be_bytes(*len)))
            .ok_or(malformed)?;
        Ok(Self {
            ed25519: Ed25519KeyPair::from_pkcs8(ed).map_err(|_| malformed)?,
            ml_dsa: PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, ml).map_err(|_| malformed)?,
        })
    }

    /// The public key: Ed25519, then ML-DSA-65.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        [
            self.ed25519.public_key().as_ref(),
            self.ml_dsa.public_key().as_ref(),
        ]
        .concat()
    }

    /// The composite signature over `message`.
    ///
    /// # Errors
    ///
    /// ML-DSA signing failed.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let labelled = [DOMAIN, message].concat();
        let mut ml = vec![0; ML_DSA_65_SIGNATURE];
        let written = self
            .ml_dsa
            .sign(&labelled, &mut ml)
            .map_err(|_| KeyError("ML-DSA-65 signing failed"))?;
        ml.truncate(written);
        Ok([self.ed25519.sign(&labelled).as_ref(), &ml].concat())
    }
}

/// Whether `signature` is a composite signature over `message` by
/// `public`: both components must verify.
#[must_use]
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Some((ed_key, ml_key)), Some((ed_sig, ml_sig))) = (
        (public.len() == PUBLIC_LEN).then(|| public.split_at(ED25519_PUBLIC)),
        (signature.len() == SIGNATURE_LEN).then(|| signature.split_at(ED25519_SIGNATURE)),
    ) else {
        return false;
    };
    let labelled = [DOMAIN, message].concat();
    let ed = UnparsedPublicKey::new(&ED25519, ed_key).verify(&labelled, ed_sig);
    let ml = UnparsedPublicKey::new(&ML_DSA_65, ml_key).verify(&labelled, ml_sig);
    ed.is_ok() && ml.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    type Res = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_signature_verifies_with_its_key_only() -> Res {
        let (key, encoded) = SigningKey::generate()?;
        let public = key.public_key();
        assert_eq!(public.len(), PUBLIC_LEN);
        let sig = key.sign(b"snapshot")?;
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(verify(&public, b"snapshot", &sig));
        assert!(!verify(&public, b"another", &sig));
        let reloaded = SigningKey::from_bytes(&encoded)?;
        assert_eq!(reloaded.public_key(), public);
        let (other, _) = SigningKey::generate()?;
        assert!(!verify(&other.public_key(), b"snapshot", &sig));
        Ok(())
    }

    #[test]
    fn each_component_must_verify() -> Res {
        let (key, _) = SigningKey::generate()?;
        let (public, sig) = (key.public_key(), key.sign(b"m")?);
        let (other, _) = SigningKey::generate()?;
        let other_sig = other.sign(b"m")?;
        let ed_swapped = [&other_sig[..ED25519_SIGNATURE], &sig[ED25519_SIGNATURE..]].concat();
        let ml_swapped = [&sig[..ED25519_SIGNATURE], &other_sig[ED25519_SIGNATURE..]].concat();
        assert!(!verify(&public, b"m", &ed_swapped), "a forged Ed25519 half");
        assert!(!verify(&public, b"m", &ml_swapped), "a forged ML-DSA half");
        assert!(
            !verify(&public, b"m", &sig[..ED25519_SIGNATURE]),
            "stripped"
        );
        Ok(())
    }

    #[test]
    fn a_component_signature_does_not_verify_without_the_label() -> Res {
        let (key, _) = SigningKey::generate()?;
        let sig = key.sign(b"m")?;
        let plain = UnparsedPublicKey::new(&ED25519, &key.public_key()[..ED25519_PUBLIC])
            .verify(b"m", &sig[..ED25519_SIGNATURE]);
        assert!(plain.is_err());
        assert!(SigningKey::from_bytes(b"TWCK1\x00").is_err());
        Ok(())
    }
}
