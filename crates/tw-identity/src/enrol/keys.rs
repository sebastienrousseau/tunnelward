// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keys, signing requests and proofs: what a connector makes and the
//! gateway checks before its CA signs anything.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};

use super::EnrolError;
use crate::der;
use crate::x509::{
    self, BIT_STRING, ECDSA_WITH_SHA256, SEQUENCE, bits, ecdsa_sha256, oid, seq, tlv,
};

pub(super) fn load_key(pkcs8: &[u8]) -> Result<EcdsaKeyPair, EnrolError> {
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8)
        .map_err(|_| EnrolError::Malformed("the private key"))
}

/// A new ECDSA P-256 private key, PKCS#8 DER.
///
/// # Errors
///
/// [`EnrolError::Unavailable`] when the system has no randomness.
pub fn new_key() -> Result<Vec<u8>, EnrolError> {
    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .map(|k| k.as_ref().to_vec())
        .map_err(|_| EnrolError::Unavailable("key generation failed"))
}

/// `content` signed with `key`, as a signed X.509 structure: `content`,
/// the algorithm, the signature.
pub(super) fn signed(key: &EcdsaKeyPair, content: &[u8]) -> Result<Vec<u8>, EnrolError> {
    let signature = key
        .sign(&SystemRandom::new(), content)
        .map_err(|_| EnrolError::Unavailable("signing failed"))?;
    Ok(seq(&[content, &ecdsa_sha256(), &bits(signature.as_ref())]))
}

/// `data` signed with the PKCS#8 key `pkcs8` (ECDSA P-256, SHA-256,
/// ASN.1 signature): a renewal's proof that it holds the current key.
///
/// # Errors
///
/// The key does not load, or signing failed.
pub fn sign(pkcs8: &[u8], data: &[u8]) -> Result<Vec<u8>, EnrolError> {
    load_key(pkcs8)?
        .sign(&SystemRandom::new(), data)
        .map(|s| s.as_ref().to_vec())
        .map_err(|_| EnrolError::Unavailable("signing failed"))
}

/// Whether `signature` over `data` verifies with the key in `cert`.
#[must_use]
pub fn verify(cert: &[u8], data: &[u8], signature: &[u8]) -> bool {
    public_key(cert).is_some_and(|key| {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
            .verify(data, signature)
            .is_ok()
    })
}

/// A PKCS#10 certificate signing request for the PKCS#8 key `pkcs8`,
/// with an empty subject: the gateway decides the identity.
///
/// # Errors
///
/// The key does not load, or signing failed.
pub fn request(pkcs8: &[u8]) -> Result<Vec<u8>, EnrolError> {
    let key = load_key(pkcs8)?;
    let info = seq(&[
        &tlv(0x02, &[0]),
        &seq(&[]),
        &x509::p256_spki(key.public_key().as_ref()),
        &tlv(0xa0, &[]),
    ]);
    signed(&key, &info)
}

/// The P-256 public key (uncompressed point) a signing request asks to
/// certify, once its signature proves the sender holds the key.
///
/// # Errors
///
/// [`EnrolError::Malformed`] or [`EnrolError::BadSignature`].
pub fn requested_key(csr: &[u8]) -> Result<Vec<u8>, EnrolError> {
    let malformed = EnrolError::Malformed("the signing request");
    let content = der::whole(csr, SEQUENCE).ok_or(malformed)?;
    let x509::Raw {
        encoded: info,
        tag: info_tag,
        content: info_content,
        rest,
    } = x509::raw(content).ok_or(malformed)?;
    let outer = der::items(rest).ok_or(malformed)?;
    let inner = der::items(info_content).ok_or(malformed)?;
    let ([(SEQUENCE, algorithm), (BIT_STRING, signature)], SEQUENCE) = (outer.as_slice(), info_tag)
    else {
        return Err(malformed);
    };
    let [(0x02, [0]), (SEQUENCE, _), (SEQUENCE, spki), (0xa0, _)] = inner.as_slice() else {
        return Err(malformed);
    };
    let key = x509::p256_point(spki).ok_or(malformed)?;
    let signature = signature.strip_prefix(&[0]).ok_or(malformed)?;
    if *algorithm != oid(ECDSA_WITH_SHA256).as_slice() {
        return Err(malformed);
    }
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
        .verify(info, signature)
        .map_err(|_| EnrolError::BadSignature)?;
    Ok(key.to_vec())
}

/// The P-256 public key (uncompressed point) in the certificate `cert`.
#[must_use]
pub fn public_key(cert: &[u8]) -> Option<&[u8]> {
    x509::p256_point(x509::tbs(cert)?.spki)
}

/// Whether the PKCS#8 key `pkcs8` is the key `cert` certifies.
#[must_use]
pub fn key_matches(cert: &[u8], pkcs8: &[u8]) -> bool {
    load_key(pkcs8).is_ok_and(|key| public_key(cert) == Some(key.public_key().as_ref()))
}

/// When the certificate `cert` starts and stops being valid, in seconds
/// since 1970.
#[must_use]
pub fn validity(cert: &[u8]) -> Option<(u64, u64)> {
    x509::tbs(cert).map(|t| t.validity)
}

/// `der` as a PEM block labelled `label`, such as `CERTIFICATE` or
/// `PRIVATE KEY`.
#[must_use]
pub fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut body = String::new();
    for chunk in der.chunks(3) {
        let n =
            chunk.iter().fold(0_u32, |acc, &b| acc << 8 | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            body.push(if i <= chunk.len() {
                char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63])
            } else {
                '='
            });
            if body.len() % 65 == 64 {
                body.push('\n');
            }
        }
    }
    let body = body.trim_end();
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::super::Ca;
    use super::*;

    type Res = Result<(), Box<dyn std::error::Error>>;

    const ID: &str = "spiffe://example.org/connector";

    fn ca() -> Result<Ca, EnrolError> {
        let (cert, key) = Ca::generate("Test CA", Duration::from_secs(86_400), SystemTime::now())?;
        Ca::load(&cert, &key)
    }

    #[test]
    fn pem_wraps_base64_at_64_columns() {
        assert_eq!(
            pem("X", b"hello"),
            "-----BEGIN X-----\naGVsbG8=\n-----END X-----\n"
        );
        let long = pem("X", &[0; 48]);
        let lines: Vec<&str> = long.lines().collect();
        assert_eq!(lines.len(), 3, "48 bytes are exactly one 64-column line");
        assert_eq!(lines[1].len(), 64);
        assert_eq!(pem("X", &[0; 49]).lines().nth(2), Some("AA=="));
    }

    #[test]
    fn a_tampered_request_is_refused() -> Res {
        let mut csr = request(&new_key()?)?;
        // The last byte is in the signature.
        let last = csr.len() - 1;
        csr[last] ^= 1;
        assert_eq!(requested_key(&csr), Err(EnrolError::BadSignature));
        let mut csr = request(&new_key()?)?;
        // Byte 40 is inside the public key the signature covers.
        csr[40] ^= 1;
        assert!(requested_key(&csr).is_err());
        assert_eq!(
            requested_key(b"junk"),
            Err(EnrolError::Malformed("the signing request"))
        );
        Ok(())
    }

    #[test]
    fn a_renewal_proof_verifies_only_with_the_certified_key() -> Res {
        let ca = ca()?;
        let key = new_key()?;
        let svid = ca.issue(
            ID,
            &requested_key(&request(&key)?)?,
            Duration::from_secs(60),
            SystemTime::now(),
        )?;
        let proof = sign(&key, b"next request")?;
        assert!(verify(&svid, b"next request", &proof));
        assert!(!verify(&svid, b"another request", &proof));
        assert!(!verify(
            &svid,
            b"next request",
            &sign(&new_key()?, b"next request")?
        ));
        Ok(())
    }
}
