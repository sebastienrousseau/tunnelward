// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! JSON Web Keys (RFC 7517, 7518, 8037) and the JWS algorithms the
//! gateway accepts: ES256, RS256, PS256 and `EdDSA` (Ed25519). Symmetric
//! keys and `none` are never accepted.

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256,
    RsaPublicKeyComponents, UnparsedPublicKey,
};
use serde::Deserialize;

use super::b64;

/// A JWS algorithm the gateway verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alg {
    Es256,
    Rs256,
    Ps256,
    EdDsa,
}

impl Alg {
    /// The algorithm named `name` in a JWS header, if accepted.
    pub(crate) fn named(name: &str) -> Option<Self> {
        match name {
            "ES256" => Some(Self::Es256),
            "RS256" => Some(Self::Rs256),
            "PS256" => Some(Self::Ps256),
            "EdDSA" => Some(Self::EdDsa),
            _ => None,
        }
    }
}

/// A public key's material.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Material {
    /// P-256, as the uncompressed point `04 || x || y`.
    P256(Vec<u8>),
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    Ed25519(Vec<u8>),
}

impl Material {
    /// An RSA key from its modulus and exponent. Leading zero bytes are
    /// dropped: RFC 7518 forbids them, some issuers send them anyway, and
    /// the verifier refuses them.
    fn rsa(n: &[u8], e: &[u8]) -> Self {
        let trim = |b: &[u8]| b[b.iter().take_while(|&&x| x == 0).count()..].to_vec();
        Self::Rsa {
            n: trim(n),
            e: trim(e),
        }
    }
}

/// One verification key from a JWK Set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Key {
    pub(crate) kid: Option<String>,
    /// The key's own `alg`, when it names one.
    alg: Option<String>,
    material: Material,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<serde_json::Value>,
}

/// The verification keys in the JWK Set `json`. Keys for encryption, of
/// a type or curve not accepted, or that do not parse are skipped, as
/// RFC 7517 section 5 allows; `None` if `json` is not a JWK Set.
pub(crate) fn parse_set(json: &[u8]) -> Option<Vec<Key>> {
    let set: JwkSet = serde_json::from_slice(json).ok()?;
    Some(
        set.keys
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Jwk>(v).ok())
            .filter_map(key)
            .collect(),
    )
}

fn key(jwk: Jwk) -> Option<Key> {
    if jwk.usage.as_deref().is_some_and(|u| u != "sig") {
        return None;
    }
    let material = material(&jwk)?;
    Some(Key {
        kid: jwk.kid,
        alg: jwk.alg,
        material,
    })
}

/// A JWK's public key, for the types and curves accepted.
fn material(jwk: &Jwk) -> Option<Material> {
    match (jwk.kty.as_str(), jwk.crv.as_deref()) {
        ("EC", Some("P-256")) => p256(jwk),
        ("RSA", _) => rsa(jwk),
        ("OKP", Some("Ed25519")) => decode(jwk.x.as_ref()).map(Material::Ed25519),
        _ => None,
    }
}

fn decode(field: Option<&String>) -> Option<Vec<u8>> {
    field.and_then(|f| b64::decode(f))
}

fn rsa(jwk: &Jwk) -> Option<Material> {
    Some(Material::rsa(
        &decode(jwk.n.as_ref())?,
        &decode(jwk.e.as_ref())?,
    ))
}

/// A P-256 point from its coordinates, 32 bytes each.
fn p256(jwk: &Jwk) -> Option<Material> {
    let (x, y) = (decode(jwk.x.as_ref())?, decode(jwk.y.as_ref())?);
    (x.len() == 32 && y.len() == 32).then(|| Material::P256([&[4][..], &x, &y].concat()))
}

impl Key {
    /// Whether this key may verify a signature made with `alg`.
    pub(crate) fn fits(&self, alg: Alg, name: &str) -> bool {
        let kind = matches!(
            (alg, &self.material),
            (Alg::Es256, Material::P256(_))
                | (Alg::Rs256 | Alg::Ps256, Material::Rsa { .. })
                | (Alg::EdDsa, Material::Ed25519(_))
        );
        kind && self.alg.as_deref().is_none_or(|a| a == name)
    }

    /// Whether `signature` over `message` verifies with this key and `alg`.
    pub(crate) fn verifies(&self, alg: Alg, message: &[u8], signature: &[u8]) -> bool {
        match (&self.material, alg) {
            (Material::P256(point), Alg::Es256) => {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                    .verify(message, signature)
                    .is_ok()
            }
            (Material::Ed25519(x), Alg::EdDsa) => UnparsedPublicKey::new(&ED25519, x)
                .verify(message, signature)
                .is_ok(),
            (Material::Rsa { n, e }, Alg::Rs256 | Alg::Ps256) => {
                let params = if alg == Alg::Rs256 {
                    &RSA_PKCS1_2048_8192_SHA256
                } else {
                    &RSA_PSS_2048_8192_SHA256
                };
                RsaPublicKeyComponents { n, e }
                    .verify(params, message, signature)
                    .is_ok()
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_of_each_kind_parse_and_others_are_skipped() {
        let set = br#"{"keys":[
            {"kty":"EC","crv":"P-256","kid":"ec","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            {"kty":"RSA","kid":"rsa","n":"AQAB","e":"AQAB","alg":"RS256"},
            {"kty":"OKP","crv":"Ed25519","kid":"ed","x":"AAAA"},
            {"kty":"oct","k":"c2VjcmV0"},
            {"kty":"EC","crv":"P-384","x":"AA","y":"AA"},
            {"kty":"RSA","use":"enc","n":"AQAB","e":"AQAB"},
            {"kty":"EC","crv":"P-256","x":"AA","y":"AA"},
            "not a key"
        ]}"#;
        let keys = parse_set(set).unwrap_or_default();
        let kids: Vec<_> = keys.iter().filter_map(|k| k.kid.as_deref()).collect();
        assert_eq!(kids, ["ec", "rsa", "ed"]);
        assert!(keys[1].fits(Alg::Rs256, "RS256"));
        assert!(!keys[1].fits(Alg::Ps256, "PS256"), "its alg is RS256");
        assert!(!keys[0].fits(Alg::EdDsa, "EdDSA"));
        assert_eq!(parse_set(b"[]"), None);
    }

    /// One DER TLV's content and the rest: test-only, definite lengths.
    fn tlv(der: &[u8]) -> (&[u8], &[u8]) {
        let (len, at) = match der[1] {
            n if n < 0x80 => (usize::from(n), 2),
            n => {
                let count = usize::from(n & 0x7f);
                let len = der[2..2 + count]
                    .iter()
                    .fold(0, |a, &b| a << 8 | usize::from(b));
                (len, 2 + count)
            }
        };
        (&der[at..at + len], &der[at + len..])
    }

    /// A fresh RSA key as a [`Key`], and the key pair to sign with.
    fn rsa_key() -> (Key, aws_lc_rs::rsa::KeyPair) {
        let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .unwrap_or_else(|_| panic!("RSA key generation"));
        let der = aws_lc_rs::signature::KeyPair::public_key(&pair)
            .as_ref()
            .to_vec();
        let (seq, _) = tlv(&der);
        let (n, rest) = tlv(seq);
        let (e, _) = tlv(rest);
        let material = Material::rsa(n, e);
        (
            Key {
                kid: None,
                alg: None,
                material,
            },
            pair,
        )
    }

    #[test]
    fn rs256_and_ps256_signatures_verify_and_tampering_does_not() {
        use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RSA_PSS_SHA256};
        let (key, pair) = rsa_key();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        for (alg, padding) in [
            (
                Alg::Rs256,
                &RSA_PKCS1_SHA256 as &'static dyn aws_lc_rs::signature::RsaEncoding,
            ),
            (Alg::Ps256, &RSA_PSS_SHA256),
        ] {
            let mut sig = vec![0; pair.public_modulus_len()];
            pair.sign(padding, &rng, b"header.payload", &mut sig)
                .unwrap_or_else(|_| panic!("signing"));
            assert!(key.verifies(alg, b"header.payload", &sig), "{alg:?}");
            assert!(
                !key.verifies(alg, b"header.payloaD", &sig),
                "{alg:?} tampered"
            );
            assert!(
                !key.verifies(Alg::Es256, b"header.payload", &sig),
                "wrong algorithm"
            );
        }
    }

    #[test]
    fn only_asymmetric_algorithms_are_named() {
        for name in ["HS256", "none", "ES384", "RS512", ""] {
            assert_eq!(Alg::named(name), None, "{name}");
        }
    }
}
