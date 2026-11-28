// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gateway-blind mode's cryptography (ADR 0016, experimental): a call's
//! arguments sealed with HPKE (X-Wing, HKDF-SHA256, AES-256-GCM) to the
//! connector's X-Wing key, and its answer sealed back under a key both
//! sides export from the same HPKE context. The gateway relays both and
//! reads neither.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

use crate::hpke::{self, Aead, HpkeError};
use crate::xwing::{PrivateKeyXWing, XWing};

/// HPKE `info`: binds every context to this protocol and version.
pub const INFO: &[u8] = b"tunnelward blind v1";
/// The exporter context the answer's key comes from, also its AAD.
pub const RESPONSE_LABEL: &[u8] = b"tunnelward blind response";
const AEAD: Aead = Aead::Aes256Gcm;

/// A sealed call: the X-Wing encapsulation, the ciphertext, and the key
/// its answer will come back under.
#[derive(Debug)]
pub struct Sealed {
    /// The encapsulation, [`crate::xwing::CIPHERTEXT_LEN`] bytes.
    pub enc: Vec<u8>,
    /// The arguments, encrypted with their tag.
    pub ciphertext: Vec<u8>,
    /// Opens the answer.
    pub response: ResponseKey,
}

/// The key one call's answer is sealed under. Used once, so its nonce
/// is fixed.
pub struct ResponseKey([u8; 32]);

impl core::fmt::Debug for ResponseKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ResponseKey(..)")
    }
}

impl ResponseKey {
    fn from_context(context: &hpke::Context) -> Result<Self, HpkeError> {
        let mut key = [0u8; 32];
        context.export(RESPONSE_LABEL, &mut key)?;
        Ok(Self(key))
    }

    fn aead(&self) -> Result<LessSafeKey, HpkeError> {
        let key = UnboundKey::new(&AES_256_GCM, &self.0).map_err(|_| HpkeError::Key)?;
        Ok(LessSafeKey::new(key))
    }

    /// Seals the answer.
    ///
    /// # Errors
    ///
    /// [`HpkeError::Key`] only if aws-lc-rs refuses the key.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let mut out = plaintext.to_vec();
        let nonce = Nonce::assume_unique_for_key([0u8; 12]);
        (self.aead()?)
            .seal_in_place_append_tag(nonce, Aad::from(RESPONSE_LABEL), &mut out)
            .map_err(|_| HpkeError::Key)?;
        Ok(out)
    }

    /// Opens the answer.
    ///
    /// # Errors
    ///
    /// [`HpkeError::Open`] when it does not authenticate.
    pub fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let mut out = ciphertext.to_vec();
        let nonce = Nonce::assume_unique_for_key([0u8; 12]);
        let len = (self.aead()?)
            .open_in_place(nonce, Aad::from(RESPONSE_LABEL), &mut out)
            .map_err(|_| HpkeError::Open)?
            .len();
        out.truncate(len);
        Ok(out)
    }
}

/// Seals `plaintext` to the connector key `public`, bound to `aad`.
///
/// # Errors
///
/// What X-Wing refuses about `public`.
pub fn seal(public: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, HpkeError> {
    let (enc, mut context) = hpke::setup_sender::<XWing>(public, INFO, AEAD)?;
    let ciphertext = context.seal(aad, plaintext)?;
    Ok(Sealed {
        enc,
        ciphertext,
        response: ResponseKey::from_context(&context)?,
    })
}

/// Opens a call sealed to `key`, bound to `aad`: the plaintext, and the
/// key to seal its answer with.
///
/// # Errors
///
/// [`HpkeError::Open`] when it was not sealed to this key with this
/// `aad`, or was changed; [`HpkeError::Key`] for a malformed `enc`.
pub fn open(
    key: &PrivateKeyXWing,
    aad: &[u8],
    enc: &[u8],
    ciphertext: &[u8],
) -> Result<(Vec<u8>, ResponseKey), HpkeError> {
    let shared = key.decapsulate(enc)?;
    let mut context = hpke::setup_recipient(<XWing as hpke::Kem>::ID, &shared, INFO, AEAD)?;
    let plaintext = context.open(aad, ciphertext)?;
    Ok((plaintext, ResponseKey::from_context(&context)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_and_its_answer_round_trip_and_bind_their_aad() {
        let key = PrivateKeyXWing::generate().unwrap();
        let sealed = seal(
            key.public_key(),
            b"tools/call\0transfer",
            br#"{"amount":5}"#,
        )
        .unwrap();
        let (plain, response) = open(
            &key,
            b"tools/call\0transfer",
            &sealed.enc,
            &sealed.ciphertext,
        )
        .unwrap();
        assert_eq!(plain, br#"{"amount":5}"#);
        let answer = response.seal(br#"{"result":{"ok":true}}"#).unwrap();
        assert_eq!(
            sealed.response.open(&answer).unwrap(),
            br#"{"result":{"ok":true}}"#
        );

        let swapped = open(
            &key,
            b"tools/call\0read_balance",
            &sealed.enc,
            &sealed.ciphertext,
        );
        assert_eq!(
            swapped.unwrap_err(),
            HpkeError::Open,
            "the tool name is bound"
        );
        let other = PrivateKeyXWing::generate().unwrap();
        let elsewhere = open(
            &other,
            b"tools/call\0transfer",
            &sealed.enc,
            &sealed.ciphertext,
        );
        assert_eq!(
            elsewhere.unwrap_err(),
            HpkeError::Open,
            "only the connector's key opens it"
        );
        let mut tampered = answer.clone();
        tampered[0] ^= 1;
        assert_eq!(
            sealed.response.open(&tampered).unwrap_err(),
            HpkeError::Open
        );
        let another = seal(key.public_key(), b"tools/call\0transfer", b"{}").unwrap();
        assert!(
            another.response.open(&answer).is_err(),
            "each call has its own answer key"
        );
    }
}
