// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ML-DSA-65 against NIST's ACVP vectors (`vectors/ml-dsa-65-acvp.txt`):
//! the composite signature's post-quantum half is the algorithm FIPS 204
//! specifies, as NIST tests it.

use aws_lc_rs::signature::{ML_DSA_65, UnparsedPublicKey};
use tunnelward_crypto::composite::{ML_DSA_65_PUBLIC, ML_DSA_65_SIGNATURE};

const VECTORS: &str = include_str!("vectors/ml-dsa-65-acvp.txt");

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn unhex(text: &str) -> Res<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|i| {
            Ok(u8::from_str_radix(
                text.get(i..i + 2).ok_or("odd hex")?,
                16,
            )?)
        })
        .collect()
}

/// A case: public key, message, signature, and whether it must verify.
type Case = (Vec<u8>, Vec<u8>, Vec<u8>, bool);

/// The value of `name` in a `name = value` block.
fn field<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    block
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(" = "))
}

/// The bytes of the hex field `name`.
fn bytes(block: &str, name: &str) -> Res<Vec<u8>> {
    unhex(field(block, name).ok_or_else(|| format!("no {name}"))?)
}

/// One `name = hex` block.
fn case(block: &str) -> Res<Case> {
    let pass = field(block, "expect") != Some("fail");
    Ok((
        bytes(block, "pk")?,
        bytes(block, "msg")?,
        bytes(block, "sig")?,
        pass,
    ))
}

fn cases() -> Res<Vec<Case>> {
    VECTORS
        .split("\n\n")
        .filter(|b| b.contains("pk = "))
        .map(case)
        .collect()
}

#[test]
fn nist_ml_dsa_65_vectors_verify_as_expected() -> Res<()> {
    let cases = cases()?;
    assert_eq!(
        cases.len(),
        3,
        "two valid signatures and one that must fail"
    );
    for (pk, msg, sig, pass) in &cases {
        assert_eq!(
            (pk.len(), sig.len()),
            (ML_DSA_65_PUBLIC, ML_DSA_65_SIGNATURE)
        );
        let verified = UnparsedPublicKey::new(&ML_DSA_65, pk)
            .verify(msg, sig)
            .is_ok();
        assert_eq!(verified, *pass);
    }
    Ok(())
}

#[test]
fn a_changed_bit_in_a_valid_vector_fails() -> Res<()> {
    for (pk, msg, sig, pass) in cases()? {
        if !pass {
            continue;
        }
        let mut tampered = sig.clone();
        tampered[100] ^= 1;
        assert!(
            UnparsedPublicKey::new(&ML_DSA_65, &pk)
                .verify(&msg, &tampered)
                .is_err()
        );
        let mut other = msg.clone();
        other[0] ^= 1;
        assert!(
            UnparsedPublicKey::new(&ML_DSA_65, &pk)
                .verify(&other, &sig)
                .is_err()
        );
    }
    Ok(())
}
