// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! X-Wing (draft-connolly-cfrg-xwing-kem-11): ML-KEM-768 and X25519,
//! combined with SHA3-256, on aws-lc-rs (ADR 0016). Public keys,
//! ciphertexts and shared secrets are the draft's. The private key is
//! kept expanded (ML-KEM's 2400-byte key and X25519's 32 bytes) rather
//! than as the draft's 32-byte seed, since aws-lc-rs has neither SHAKE256
//! nor seeded ML-KEM key generation; the known-answer tests reach the
//! draft's keys through kyberlib.

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::digest::{SHA3_256, digest};
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};

use crate::hpke::{HpkeError, Kem};

/// The draft's label, `\.//^\`.
const LABEL: &[u8; 6] = b"\\.//^\\";
const ML_KEM_PUBLIC: usize = 1184;
const ML_KEM_CIPHERTEXT: usize = 1088;
const ML_KEM_PRIVATE: usize = 2400;
/// An X-Wing public key: ML-KEM-768's, then X25519's.
pub const PUBLIC_KEY_LEN: usize = ML_KEM_PUBLIC + 32;
/// An X-Wing ciphertext: ML-KEM-768's, then the X25519 share.
pub const CIPHERTEXT_LEN: usize = ML_KEM_CIPHERTEXT + 32;
/// This crate's private key encoding: ML-KEM-768's expanded key, then
/// X25519's.
pub const PRIVATE_KEY_LEN: usize = ML_KEM_PRIVATE + 32;

/// X-Wing as an HPKE KEM, id 0x647a.
#[derive(Debug, Clone, Copy)]
pub struct XWing;

impl Kem for XWing {
    const ID: u16 = 0x647a;

    fn encap(public: &[u8]) -> Result<([u8; 32], Vec<u8>), HpkeError> {
        encapsulate(public)
    }
}

/// SHA3-256(`ss_M || ss_X || ct_X || pk_X || label`).
fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> [u8; 32] {
    let input = [ss_m, ss_x, ct_x, pk_x, LABEL].concat();
    let mut ss = [0u8; 32];
    ss.copy_from_slice(digest(&SHA3_256, &input).as_ref());
    ss
}

/// FIPS 203's encapsulation key check: every 12-bit coefficient of the
/// encoded vector is below q = 3329.
fn ml_kem_public_ok(public: &[u8]) -> bool {
    let vector = &public[..ML_KEM_PUBLIC - 32];
    vector.as_chunks::<3>().0.iter().all(|b| {
        let first = u16::from(b[0]) | (u16::from(b[1] & 0x0f) << 8);
        let second = u16::from(b[1] >> 4) | (u16::from(b[2]) << 4);
        first < 3329 && second < 3329
    })
}

/// `Encapsulate(pk)`: the shared secret and the ciphertext.
///
/// # Errors
///
/// [`HpkeError::Key`] for a public key of the wrong length or one that
/// fails the ML-KEM encapsulation key check; [`HpkeError::Kem`] if a
/// step fails.
pub fn encapsulate(public: &[u8]) -> Result<([u8; 32], Vec<u8>), HpkeError> {
    if public.len() != PUBLIC_KEY_LEN || !ml_kem_public_ok(public) {
        return Err(HpkeError::Key);
    }
    let (pk_m, pk_x) = public.split_at(ML_KEM_PUBLIC);
    let (ct_m, ss_m) = ml_kem_encapsulate(pk_m)?;
    let ephemeral = PrivateKey::generate(&X25519).map_err(|_| HpkeError::Kem)?;
    let ct_x = ephemeral.compute_public_key().map_err(|_| HpkeError::Kem)?;
    let ss_x = x25519(&ephemeral, pk_x)?;
    let ss = combiner(&ss_m, &ss_x, ct_x.as_ref(), pk_x);
    Ok((ss, [ct_m.as_slice(), ct_x.as_ref()].concat()))
}

/// ML-KEM-768's ciphertext and shared secret for `pk_m`.
fn ml_kem_encapsulate(pk_m: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    let ek = EncapsulationKey::new(&ML_KEM_768, pk_m).map_err(|_| HpkeError::Key)?;
    let (ct, ss) = ek.encapsulate().map_err(|_| HpkeError::Kem)?;
    Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
}

fn x25519(private: &PrivateKey, peer: &[u8]) -> Result<[u8; 32], HpkeError> {
    agreement::agree(
        private,
        UnparsedPublicKey::new(&X25519, peer),
        HpkeError::Kem,
        |shared| {
            let mut out = [0u8; 32];
            out.copy_from_slice(shared);
            Ok(out)
        },
    )
}

/// An X-Wing private key, with its public key.
pub struct PrivateKeyXWing {
    ml_kem: DecapsulationKey,
    x25519: PrivateKey,
    public: Vec<u8>,
}

impl core::fmt::Debug for PrivateKeyXWing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrivateKeyXWing(..)")
    }
}

impl PrivateKeyXWing {
    /// A new random key.
    ///
    /// # Errors
    ///
    /// [`HpkeError::Kem`] if aws-lc-rs cannot generate one.
    pub fn generate() -> Result<Self, HpkeError> {
        let ml_kem = DecapsulationKey::generate(&ML_KEM_768).map_err(|_| HpkeError::Kem)?;
        let pk_m = (ml_kem.encapsulation_key())
            .and_then(|k| k.key_bytes())
            .map_err(|_| HpkeError::Kem)?;
        let x25519 = PrivateKey::generate(&X25519).map_err(|_| HpkeError::Kem)?;
        Self::assemble(ml_kem, pk_m.as_ref(), x25519)
    }

    /// The key [`PrivateKeyXWing::to_bytes`] wrote.
    ///
    /// # Errors
    ///
    /// [`HpkeError::Key`] for bytes that are not one, including an
    /// ML-KEM key whose stored hash of its public key does not match
    /// (FIPS 203's decapsulation key check).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        if bytes.len() != PRIVATE_KEY_LEN {
            return Err(HpkeError::Key);
        }
        let (ml_kem, x25519) = bytes.split_at(ML_KEM_PRIVATE);
        // dk = dk_PKE (1152) || ek (1184) || H(ek) (32) || z (32).
        let pk_m = &ml_kem[1152..1152 + ML_KEM_PUBLIC];
        let hash = &ml_kem[1152 + ML_KEM_PUBLIC..ML_KEM_PRIVATE - 32];
        if digest(&SHA3_256, pk_m).as_ref() != hash {
            return Err(HpkeError::Key);
        }
        let decaps = DecapsulationKey::new(&ML_KEM_768, ml_kem).map_err(|_| HpkeError::Key)?;
        let x25519 = PrivateKey::from_private_key(&X25519, x25519).map_err(|_| HpkeError::Key)?;
        Self::assemble(decaps, pk_m, x25519)
    }

    fn assemble(
        ml_kem: DecapsulationKey,
        pk_m: &[u8],
        x25519: PrivateKey,
    ) -> Result<Self, HpkeError> {
        let pk_x = x25519.compute_public_key().map_err(|_| HpkeError::Key)?;
        let public = [pk_m, pk_x.as_ref()].concat();
        Ok(Self {
            ml_kem,
            x25519,
            public,
        })
    }

    /// The private key's bytes, to store owner-only.
    ///
    /// # Errors
    ///
    /// [`HpkeError::Key`] if aws-lc-rs will not export them.
    pub fn to_bytes(&self) -> Result<Vec<u8>, HpkeError> {
        let ml_kem = self.ml_kem.key_bytes().map_err(|_| HpkeError::Key)?;
        let x25519: Curve25519SeedBin<'_> =
            self.x25519.as_be_bytes().map_err(|_| HpkeError::Key)?;
        Ok([ml_kem.as_ref(), x25519.as_ref()].concat())
    }

    /// The public key, [`PUBLIC_KEY_LEN`] bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// `Decapsulate(sk, ct)`. ML-KEM rejects implicitly: a tampered
    /// ciphertext gives a different secret, not an error.
    ///
    /// # Errors
    ///
    /// [`HpkeError::Key`] for a ciphertext of the wrong length;
    /// [`HpkeError::Kem`] for a degenerate X25519 share.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32], HpkeError> {
        if ciphertext.len() != CIPHERTEXT_LEN {
            return Err(HpkeError::Key);
        }
        let (ct_m, ct_x) = ciphertext.split_at(ML_KEM_CIPHERTEXT);
        let ss_m = self
            .ml_kem
            .decapsulate(Ciphertext::from(ct_m))
            .map_err(|_| HpkeError::Kem)?;
        let ss_x = x25519(&self.x25519, ct_x)?;
        Ok(combiner(
            ss_m.as_ref(),
            &ss_x,
            ct_x,
            &self.public[ML_KEM_PUBLIC..],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_round_trips_and_decapsulates_what_was_encapsulated() {
        let key = PrivateKeyXWing::generate().unwrap();
        assert_eq!(key.public_key().len(), PUBLIC_KEY_LEN);
        let (ss, ct) = encapsulate(key.public_key()).unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_LEN);
        assert_eq!(key.decapsulate(&ct).unwrap(), ss);
        let again = PrivateKeyXWing::from_bytes(&key.to_bytes().unwrap()).unwrap();
        assert_eq!(again.public_key(), key.public_key());
        assert_eq!(again.decapsulate(&ct).unwrap(), ss);
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert_ne!(
            key.decapsulate(&tampered).unwrap(),
            ss,
            "implicit rejection"
        );
    }

    #[test]
    fn malformed_public_keys_and_ciphertexts_are_refused() {
        let key = PrivateKeyXWing::generate().unwrap();
        let mut over_q = key.public_key().to_vec();
        over_q[0] = 0xff;
        over_q[1] |= 0x0f; // first coefficient 0xfff, above q
        assert_eq!(encapsulate(&over_q).unwrap_err(), HpkeError::Key);
        assert_eq!(
            encapsulate(&key.public_key()[1..]).unwrap_err(),
            HpkeError::Key
        );
        assert_eq!(key.decapsulate(&[0u8; 10]).unwrap_err(), HpkeError::Key);
        assert!(PrivateKeyXWing::from_bytes(&[0u8; 10]).is_err());
        let mut corrupt = key.to_bytes().unwrap();
        corrupt[1152] ^= 1; // the public key inside no longer matches H(ek)
        assert_eq!(
            PrivateKeyXWing::from_bytes(&corrupt).unwrap_err(),
            HpkeError::Key
        );
    }
}
