// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The algorithm of a certificate's public key, for a crypto inventory
//! (`tunnelward crypto report`). In TLS 1.3 the key decides the
//! signature scheme a peer signs its handshake with, except that an
//! RSA key may sign with any of the three RSA-PSS hashes.

use crate::{OID, SEQUENCE, der};

/// `[0] EXPLICIT Version` in a `TBSCertificate`.
const VERSION: u8 = 0xa0;
const BIT_STRING: u8 = 0x03;
const INTEGER: u8 = 0x02;

// Object identifiers, DER-encoded without tag and length.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const NAMED: [(&[u8], &str); 8] = [
    (&[0x2b, 0x65, 0x70], "Ed25519"),
    (&[0x2b, 0x65, 0x71], "Ed448"),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11],
        "ML-DSA-44",
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
        "ML-DSA-65",
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
        "ML-DSA-87",
    ),
    (
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        "ECDSA P-256",
    ),
    (&[0x2b, 0x81, 0x04, 0x00, 0x22], "ECDSA P-384"),
    (&[0x2b, 0x81, 0x04, 0x00, 0x23], "ECDSA P-521"),
];

/// The name of `cert`'s (DER) public-key algorithm: `ECDSA P-256`,
/// `Ed25519`, `ML-DSA-65`, `RSA 2048` and the like, or `unknown` with the
/// algorithm's identifier in hex. `None` when `cert` does not parse. It
/// does not verify the certificate.
#[must_use]
pub fn key_algorithm(cert: &[u8]) -> Option<String> {
    let [(SEQUENCE, algorithm), (BIT_STRING, key)] = der::items(spki(cert)?)?[..] else {
        return None;
    };
    name(&der::items(algorithm)?, key)
}

/// The name for an `AlgorithmIdentifier`'s parts, given the key bits.
fn name(algorithm: &[(u8, &[u8])], key: &[u8]) -> Option<String> {
    match *algorithm {
        [(OID, EC_PUBLIC_KEY), (OID, curve)] => Some(named(curve).map_or_else(
            || format!("ECDSA unknown curve {}", hex(curve)),
            str::to_owned,
        )),
        [(OID, RSA | RSA_PSS), ..] => {
            Some(rsa_bits(key).map_or_else(|| "RSA".to_owned(), |bits| format!("RSA {bits}")))
        }
        [(OID, id), ..] => {
            Some(named(id).map_or_else(|| format!("unknown {}", hex(id)), str::to_owned))
        }
        _ => None,
    }
}

/// The content of `cert`'s `SubjectPublicKeyInfo`.
fn spki(cert: &[u8]) -> Option<&[u8]> {
    let certificate = der::items(der::whole(cert, SEQUENCE)?)?;
    let (SEQUENCE, tbs) = *certificate.first()? else {
        return None;
    };
    let mut fields = der::items(tbs)?;
    if fields.first().is_some_and(|(tag, _)| *tag == VERSION) {
        fields.remove(0);
    }
    // serialNumber, signature, issuer, validity, subject, then the key.
    match *fields.get(5)? {
        (SEQUENCE, spki) => Some(spki),
        _ => None,
    }
}

/// The name of a key or curve identifier this module knows.
fn named(id: &[u8]) -> Option<&'static str> {
    NAMED.iter().find(|(o, _)| *o == id).map(|(_, n)| *n)
}

/// The modulus size of an RSA key's BIT STRING content.
fn rsa_bits(key: &[u8]) -> Option<usize> {
    let (0, public) = key.split_first().map(|(u, p)| (*u, p))? else {
        return None;
    };
    let [(INTEGER, modulus), (INTEGER, _)] = der::items(der::whole(public, SEQUENCE)?)?[..] else {
        return None;
    };
    let significant = modulus.iter().skip_while(|b| **b == 0).count();
    Some(significant * 8)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::{bits, oid, seq, tlv};

    /// A certificate shell whose key is `spki`, with or without a version.
    fn cert(spki: &[u8], versioned: bool) -> Vec<u8> {
        let name = seq(&[]);
        let mut tbs = Vec::new();
        if versioned {
            tbs.extend(tlv(VERSION, &tlv(INTEGER, &[2])));
        }
        for part in [
            &tlv(INTEGER, &[1])[..],
            &seq(&[]),
            &name,
            &seq(&[]),
            &name,
            spki,
        ] {
            tbs.extend_from_slice(part);
        }
        seq(&[&tlv(SEQUENCE, &tbs), &seq(&[]), &bits(&[0])])
    }

    #[test]
    fn the_test_pki_keys_are_p256() {
        let name = key_algorithm(tunnelward_testpki::CONNECTOR.0);
        assert_eq!(name.as_deref(), Some("ECDSA P-256"));
    }

    #[test]
    fn each_known_algorithm_is_named() {
        let alone = |id: &[u8]| seq(&[&seq(&[&oid(id)]), &bits(&[1, 2])]);
        assert_eq!(
            key_algorithm(&cert(&alone(NAMED[0].0), true)).as_deref(),
            Some("Ed25519")
        );
        assert_eq!(
            key_algorithm(&cert(&alone(NAMED[3].0), false)).as_deref(),
            Some("ML-DSA-65")
        );
        let p384 = seq(&[&seq(&[&oid(EC_PUBLIC_KEY), &oid(NAMED[6].0)]), &bits(&[4])]);
        assert_eq!(
            key_algorithm(&cert(&p384, true)).as_deref(),
            Some("ECDSA P-384")
        );
        let modulus = [&[0][..], &[0xc5; 256]].concat();
        let rsa_key = seq(&[&tlv(INTEGER, &modulus), &tlv(INTEGER, &[1, 0, 1])]);
        let rsa = seq(&[&seq(&[&oid(RSA), &tlv(0x05, &[])]), &bits(&rsa_key)]);
        assert_eq!(
            key_algorithm(&cert(&rsa, true)).as_deref(),
            Some("RSA 2048")
        );
        let odd = seq(&[&seq(&[&oid(&[0x2a, 0x03])]), &bits(&[1])]);
        assert_eq!(
            key_algorithm(&cert(&odd, true)).as_deref(),
            Some("unknown 2a03")
        );
        assert_eq!(key_algorithm(b"not a certificate"), None);
    }
}
