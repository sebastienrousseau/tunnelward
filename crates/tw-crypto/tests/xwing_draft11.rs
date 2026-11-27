// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! X-Wing against draft-connolly-cfrg-xwing-kem-11's known answers
//! (ADR 0016). The draft's private key is a 32-byte seed, expanded with
//! SHAKE256 and ML-KEM's seeded key generation, which aws-lc-rs does not
//! offer; kyberlib (a test dependency only) expands it, and this crate
//! must then give the draft's public key and decapsulate the draft's
//! ciphertext to the draft's shared secret. A second implementation
//! checks the first.

use aws_lc_rs::agreement::{PrivateKey, X25519};
use kyberlib::{KemCore, MlKem768};
use tunnelward_crypto::hpke::{Aead, setup_recipient, setup_sender};
use tunnelward_crypto::xwing::{PrivateKeyXWing, XWing, encapsulate};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

struct Vector {
    seed: Vec<u8>,
    pk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn vectors() -> Vec<Vector> {
    let text = include_str!("xwing_draft11.txt");
    let values: Vec<&str> = text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    values
        .chunks(5)
        .map(|v| Vector {
            seed: unhex(v[0]),
            pk: unhex(v[1]),
            ct: unhex(v[3]),
            ss: unhex(v[4]),
        })
        .collect()
}

/// The draft's `GenerateKeyPairDerand(seed)`, as this crate's private
/// key bytes: ML-KEM-768's expanded key, then X25519's.
fn private_key_from_seed(seed: &[u8]) -> Res<Vec<u8>> {
    let mut expanded = [0u8; 96];
    kyberlib::hash::shake256(seed, &mut expanded);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&expanded[..32]);
    z.copy_from_slice(&expanded[32..64]);
    let (dk, _ek) = MlKem768::generate_from_seed(&d, &z).map_err(|e| format!("{e:?}"))?;
    Ok([dk.as_bytes().as_slice(), &expanded[64..]].concat())
}

#[test]
fn the_drafts_known_answers() -> Res<()> {
    let vectors = vectors();
    assert_eq!(vectors.len(), 3);
    for (i, v) in vectors.iter().enumerate() {
        let key = PrivateKeyXWing::from_bytes(&private_key_from_seed(&v.seed)?)?;
        assert_eq!(key.public_key(), v.pk.as_slice(), "vector {i}: public key");
        assert_eq!(
            key.decapsulate(&v.ct)?.as_slice(),
            v.ss.as_slice(),
            "vector {i}: shared secret"
        );
        // The X25519 half alone, from aws-lc-rs: the draft's pk_X.
        let sk_x = &private_key_from_seed(&v.seed)?[2400..];
        let pk_x = PrivateKey::from_private_key(&X25519, sk_x)?.compute_public_key()?;
        assert_eq!(
            pk_x.as_ref(),
            &v.pk[1184..],
            "vector {i}: X25519 public key"
        );
        // This crate's encapsulation to the draft's key opens with it.
        let (ss, ct) = encapsulate(&v.pk)?;
        assert_eq!(key.decapsulate(&ct)?, ss, "vector {i}: round trip");
    }
    Ok(())
}

#[test]
fn hpke_on_x_wing_round_trips() -> Res<()> {
    let key = PrivateKeyXWing::generate()?;
    let (enc, mut sender) = setup_sender::<XWing>(key.public_key(), b"info", Aead::Aes256Gcm)?;
    let sealed = sender.seal(b"aad", b"tool arguments")?;
    let shared = key.decapsulate(&enc)?;
    let mut recipient = setup_recipient(0x647a, &shared, b"info", Aead::Aes256Gcm)?;
    assert_eq!(recipient.open(b"aad", &sealed)?, b"tool arguments");
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    sender.export(b"response", &mut a)?;
    recipient.export(b"response", &mut b)?;
    assert_eq!(a, b, "both sides export the same secret");
    Ok(())
}
