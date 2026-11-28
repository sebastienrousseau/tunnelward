// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HPKE (RFC 9180), base mode, written here over aws-lc-rs's HMAC, HKDF
//! and AEADs (ADR 0016). The KEM is pluggable ([`Kem`]); gateway-blind
//! mode uses X-Wing ([`crate::xwing::XWing`]). Checked against RFC 9180's
//! test vectors.

use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Prk};
use aws_lc_rs::hmac;

/// KDF id of HKDF-SHA256, the only KDF here.
const KDF_HKDF_SHA256: u16 = 0x0001;
/// The hash length of HKDF-SHA256.
const NH: usize = 32;
/// The nonce length of both AEADs.
const NN: usize = 12;
/// Mode base: no PSK, no sender authentication.
const MODE_BASE: u8 = 0x00;

/// Why an HPKE operation failed. Deliberately coarse: a recipient
/// learns no more than "it did not open".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HpkeError {
    /// A key or an encapsulation of the wrong length or form.
    Key,
    /// The KEM failed (an encapsulation key check, a degenerate share).
    Kem,
    /// The ciphertext did not authenticate.
    Open,
    /// The sequence number would wrap.
    MessageLimit,
}

impl core::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Key => "HPKE: a key or encapsulation is malformed",
            Self::Kem => "HPKE: the KEM failed",
            Self::Open => "HPKE: the ciphertext does not open",
            Self::MessageLimit => "HPKE: too many messages for one context",
        })
    }
}

impl std::error::Error for HpkeError {}

/// A KEM HPKE can run on: its id, and encapsulation to a public key.
/// Decapsulation belongs to the private key type.
pub trait Kem {
    /// The KEM id in the HPKE registry.
    const ID: u16;
    /// Encapsulates to `public`: the shared secret and the encapsulation.
    ///
    /// # Errors
    ///
    /// [`HpkeError::Key`] or [`HpkeError::Kem`].
    fn encap(public: &[u8]) -> Result<([u8; 32], Vec<u8>), HpkeError>;
}

/// The AEADs offered: both are in every runtime the SDKs target
/// (`WebCrypto` has no ChaCha20-Poly1305).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Aead {
    /// AES-128-GCM, id 0x0001.
    Aes128Gcm,
    /// AES-256-GCM, id 0x0002.
    Aes256Gcm,
}

impl Aead {
    fn id(self) -> u16 {
        match self {
            Self::Aes128Gcm => 0x0001,
            Self::Aes256Gcm => 0x0002,
        }
    }

    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm => &aead::AES_256_GCM,
        }
    }
}

/// `"HPKE" || kem || kdf || aead`, or `"KEM" || kem` for a KEM's own
/// labels.
pub(crate) fn suite_id(kem: u16, aead: Option<Aead>) -> Vec<u8> {
    match aead {
        Some(aead) => [
            b"HPKE".as_slice(),
            &kem.to_be_bytes(),
            &KDF_HKDF_SHA256.to_be_bytes(),
            &aead.id().to_be_bytes(),
        ]
        .concat(),
        None => [b"KEM".as_slice(), &kem.to_be_bytes()].concat(),
    }
}

/// An output length for aws-lc-rs's HKDF-Expand.
struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// `LabeledExtract(salt, label, ikm)`: HKDF-Extract is HMAC(salt, ikm)
/// (RFC 5869), computed directly so its bytes are available.
pub(crate) fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; NH] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut context = hmac::Context::with_key(&key);
    for part in [b"HPKE-v1".as_slice(), suite, label, ikm] {
        context.update(part);
    }
    let mut prk = [0u8; NH];
    prk.copy_from_slice(context.sign().as_ref());
    prk
}

/// `LabeledExpand(prk, label, info, L)`.
pub(crate) fn labeled_expand(
    prk: &[u8; NH],
    suite: &[u8],
    (label, info): (&[u8], &[u8]),
    out: &mut [u8],
) -> Result<(), HpkeError> {
    let length = u16::try_from(out.len())
        .map_err(|_| HpkeError::Key)?
        .to_be_bytes();
    let parts = [&length[..], b"HPKE-v1", suite, label, info];
    Prk::new_less_safe(HKDF_SHA256, prk)
        .expand(&parts, Len(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| HpkeError::Key)
}

/// An HPKE context: the key and base nonce of its one direction, its
/// sequence number, and the exporter secret.
pub struct Context {
    key: LessSafeKey,
    base_nonce: [u8; NN],
    exporter: [u8; NH],
    suite: Vec<u8>,
    seq: u64,
}

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Context")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

/// `KeySchedule` in base mode.
pub(crate) fn key_schedule(
    kem: u16,
    aead: Aead,
    shared_secret: &[u8],
    info: &[u8],
) -> Result<Context, HpkeError> {
    let suite = suite_id(kem, Some(aead));
    let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
    let context = [&[MODE_BASE][..], &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(&suite, shared_secret, b"secret", b"");
    let algorithm = aead.algorithm();
    let mut key = vec![0u8; algorithm.key_len()];
    labeled_expand(&secret, &suite, (b"key", &context), &mut key)?;
    let mut base_nonce = [0u8; NN];
    labeled_expand(&secret, &suite, (b"base_nonce", &context), &mut base_nonce)?;
    let mut exporter = [0u8; NH];
    labeled_expand(&secret, &suite, (b"exp", &context), &mut exporter)?;
    let key = UnboundKey::new(algorithm, &key).map_err(|_| HpkeError::Key)?;
    Ok(Context {
        key: LessSafeKey::new(key),
        base_nonce,
        exporter,
        suite,
        seq: 0,
    })
}

impl Context {
    /// The nonce for the next message: `base_nonce XOR I2OSP(seq, Nn)`.
    fn nonce(&self) -> Nonce {
        let mut nonce = self.base_nonce;
        for (n, s) in nonce[NN - 8..].iter_mut().zip(self.seq.to_be_bytes()) {
            *n ^= s;
        }
        Nonce::assume_unique_for_key(nonce)
    }

    fn advance(&mut self) -> Result<(), HpkeError> {
        self.seq = self.seq.checked_add(1).ok_or(HpkeError::MessageLimit)?;
        Ok(())
    }

    /// Encrypts `plaintext` with `aad`: the ciphertext and its tag.
    ///
    /// # Errors
    ///
    /// [`HpkeError::MessageLimit`] after 2^64 messages.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let mut out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(self.nonce(), Aad::from(aad), &mut out)
            .map_err(|_| HpkeError::Key)?;
        self.advance()?;
        Ok(out)
    }

    /// Decrypts `ciphertext` with `aad`.
    ///
    /// # Errors
    ///
    /// [`HpkeError::Open`] when it does not authenticate.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let mut out = ciphertext.to_vec();
        let len = self
            .key
            .open_in_place(self.nonce(), Aad::from(aad), &mut out)
            .map_err(|_| HpkeError::Open)?
            .len();
        out.truncate(len);
        self.advance()?;
        Ok(out)
    }

    /// `Export(exporter_context, L)`.
    ///
    /// # Errors
    ///
    /// [`HpkeError::Key`] for `L` over 255 * 32.
    pub fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), HpkeError> {
        labeled_expand(&self.exporter, &self.suite, (b"sec", exporter_context), out)
    }
}

/// `SetupBaseS`: encapsulates to `public` and returns the encapsulation
/// and the sender's context.
///
/// # Errors
///
/// What the KEM refuses.
pub fn setup_sender<K: Kem>(
    public: &[u8],
    info: &[u8],
    aead: Aead,
) -> Result<(Vec<u8>, Context), HpkeError> {
    let (shared_secret, enc) = K::encap(public)?;
    Ok((enc, key_schedule(K::ID, aead, &shared_secret, info)?))
}

/// `SetupBaseR`, given the shared secret the recipient's private key
/// decapsulated.
///
/// # Errors
///
/// [`HpkeError::Key`] only for an AEAD key aws-lc-rs refuses.
pub fn setup_recipient(
    kem: u16,
    shared_secret: &[u8; 32],
    info: &[u8],
    aead: Aead,
) -> Result<Context, HpkeError> {
    key_schedule(kem, aead, shared_secret, info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};

    fn unhex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// DHKEM(X25519, HKDF-SHA256), `kem_id` 0x0020: only to run RFC 9180's
    /// vectors, which fix the ephemeral key through `DeriveKeyPair`.
    const DHKEM_X25519: u16 = 0x0020;

    fn derive_key_pair(ikm: &[u8]) -> PrivateKey {
        let suite = suite_id(DHKEM_X25519, None);
        let prk = labeled_extract(&suite, b"", b"dkp_prk", ikm);
        let mut sk = [0u8; 32];
        labeled_expand(&prk, &suite, (b"sk", b""), &mut sk).unwrap();
        PrivateKey::from_private_key(&X25519, &sk).unwrap()
    }

    fn dhkem_shared(private: &PrivateKey, peer: &[u8], kem_context: &[u8]) -> [u8; 32] {
        let dh = agreement::agree(private, UnparsedPublicKey::new(&X25519, peer), (), |dh| {
            Ok(dh.to_vec())
        })
        .unwrap();
        let suite = suite_id(DHKEM_X25519, None);
        let prk = labeled_extract(&suite, b"", b"eae_prk", &dh);
        let mut shared = [0u8; 32];
        labeled_expand(&prk, &suite, (b"shared_secret", kem_context), &mut shared).unwrap();
        shared
    }

    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";

    /// RFC 9180 A.1.1's KEM: the key pairs `DeriveKeyPair` gives and the
    /// shared secret, which both sides derive alike.
    fn a_1_1_shared_secret() -> [u8; 32] {
        let sk_e = derive_key_pair(&unhex(
            "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
        ));
        let sk_r = derive_key_pair(&unhex(
            "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
        ));
        let pk_e = sk_e.compute_public_key().unwrap().as_ref().to_vec();
        let pk_r = sk_r.compute_public_key().unwrap().as_ref().to_vec();
        assert_eq!(
            pk_e,
            unhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
        );
        assert_eq!(
            pk_r,
            unhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
        );
        let kem_context = [pk_e.as_slice(), &pk_r].concat();
        let shared = dhkem_shared(&sk_e, &pk_r, &kem_context);
        assert_eq!(
            shared.to_vec(),
            unhex("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc")
        );
        assert_eq!(dhkem_shared(&sk_r, &pk_e, &kem_context), shared);
        shared
    }

    /// RFC 9180 A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
    /// AES-128-GCM, base mode: the schedule and the encryptions.
    #[test]
    fn rfc_9180_a_1_1_encryptions() {
        let shared = a_1_1_shared_secret();
        let info = unhex(INFO);
        let mut sender = key_schedule(DHKEM_X25519, Aead::Aes128Gcm, &shared, &info).unwrap();
        assert_eq!(
            sender.base_nonce.to_vec(),
            unhex("56d890e5accaaf011cff4b7d")
        );
        assert_eq!(
            sender.exporter.to_vec(),
            unhex("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8")
        );
        let mut recipient = setup_recipient(DHKEM_X25519, &shared, &info, Aead::Aes128Gcm).unwrap();
        let pt = unhex(PT);
        let expected = [
            (
                0,
                "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
            ),
            (
                1,
                "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
            ),
            (
                2,
                "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
            ),
            // 255 and 256: the nonce XOR crosses a byte boundary.
            (
                255,
                "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a",
            ),
            (
                256,
                "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2",
            ),
        ];
        for (seq, ct) in expected {
            (sender.seq, recipient.seq) = (seq, seq);
            let aad = format!("Count-{seq}");
            let sealed = sender.seal(aad.as_bytes(), &pt).unwrap();
            assert_eq!(sealed, unhex(ct), "sequence {seq}");
            assert_eq!(recipient.open(aad.as_bytes(), &sealed).unwrap(), pt);
        }
    }

    /// RFC 9180 A.1.1.2: the exported values.
    #[test]
    fn rfc_9180_a_1_1_exports() {
        let shared = a_1_1_shared_secret();
        let sender = key_schedule(DHKEM_X25519, Aead::Aes128Gcm, &shared, &unhex(INFO)).unwrap();
        for (context, value) in [
            (
                "",
                "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee",
            ),
            (
                "00",
                "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5",
            ),
            (
                "54657374436f6e74657874",
                "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931",
            ),
        ] {
            let mut out = [0u8; 32];
            sender.export(&unhex(context), &mut out).unwrap();
            assert_eq!(out.to_vec(), unhex(value), "export {context:?}");
        }
    }

    #[test]
    fn a_tampered_ciphertext_or_aad_does_not_open() {
        let shared = [7u8; 32];
        let mut sender = key_schedule(0x647a, Aead::Aes256Gcm, &shared, b"i").unwrap();
        let sealed = sender.seal(b"aad", b"secret").unwrap();
        let mut flipped = sealed.clone();
        flipped[0] ^= 1;
        let fresh = || setup_recipient(0x647a, &shared, b"i", Aead::Aes256Gcm).unwrap();
        assert_eq!(fresh().open(b"aad", &flipped), Err(HpkeError::Open));
        assert_eq!(fresh().open(b"other", &sealed), Err(HpkeError::Open));
        assert_eq!(fresh().open(b"aad", &sealed).unwrap(), b"secret");
        let other_info = setup_recipient(0x647a, &shared, b"j", Aead::Aes256Gcm)
            .unwrap()
            .open(b"aad", &sealed);
        assert_eq!(other_info, Err(HpkeError::Open), "info is bound");
    }
}
