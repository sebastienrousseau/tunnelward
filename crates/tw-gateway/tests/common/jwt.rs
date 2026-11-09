// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Signing keys and JWT access tokens for the agent-auth tests.

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
};

use super::Res;

/// Unpadded base64url.
pub fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0_u32, |acc, &b| acc << 8 | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            let index = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
            out.push(char::from(ALPHABET[index]));
        }
    }
    out
}

/// Seconds since the epoch, now.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

enum Pair {
    Es256(EcdsaKeyPair),
    EdDsa(Ed25519KeyPair),
}

/// A signing key with its key id.
pub struct Signer {
    kid: String,
    pair: Pair,
}

impl Signer {
    /// A fresh P-256 key (ES256).
    pub fn es256(kid: &str) -> Res<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| "key generation")?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .map_err(|_| "key load")?;
        Ok(Self {
            kid: kid.to_owned(),
            pair: Pair::Es256(pair),
        })
    }

    /// A fresh Ed25519 key (`EdDSA`).
    pub fn eddsa(kid: &str) -> Res<Self> {
        let pair = Ed25519KeyPair::generate().map_err(|_| "key generation")?;
        Ok(Self {
            kid: kid.to_owned(),
            pair: Pair::EdDsa(pair),
        })
    }

    /// This key as a JWK.
    pub fn jwk(&self) -> String {
        match &self.pair {
            Pair::Es256(p) => {
                let point = p.public_key().as_ref();
                format!(
                    r#"{{"kty":"EC","crv":"P-256","kid":"{}","x":"{}","y":"{}"}}"#,
                    self.kid,
                    b64(&point[1..33]),
                    b64(&point[33..65])
                )
            }
            Pair::EdDsa(p) => format!(
                r#"{{"kty":"OKP","crv":"Ed25519","kid":"{}","x":"{}"}}"#,
                self.kid,
                b64(p.public_key().as_ref())
            ),
        }
    }

    /// A JWK Set of `signers`.
    pub fn jwks(signers: &[&Self]) -> String {
        let keys: Vec<String> = signers.iter().map(|s| s.jwk()).collect();
        format!(r#"{{"keys":[{}]}}"#, keys.join(","))
    }

    /// A token with `claims`, signed by this key.
    pub fn token(&self, claims: &str) -> Res<String> {
        let alg = match self.pair {
            Pair::Es256(_) => "ES256",
            Pair::EdDsa(_) => "EdDSA",
        };
        let header = format!(r#"{{"alg":"{alg}","kid":"{}","typ":"at+jwt"}}"#, self.kid);
        let signed = format!("{}.{}", b64(header.as_bytes()), b64(claims.as_bytes()));
        let signature = match &self.pair {
            Pair::Es256(p) => p
                .sign(&SystemRandom::new(), signed.as_bytes())
                .map_err(|_| "signing")?
                .as_ref()
                .to_vec(),
            Pair::EdDsa(p) => p.sign(signed.as_bytes()).as_ref().to_vec(),
        };
        Ok(format!("{signed}.{}", b64(&signature)))
    }
}

/// Claims for `aud` from `iss`, valid for an hour, granting `scope`.
pub fn claims(iss: &str, aud: &str, scope: &str) -> String {
    let now = now();
    format!(
        r#"{{"iss":"{iss}","aud":"{aud}","sub":"agent-1","client_id":"claude","scope":"{scope}","iat":{now},"exp":{}}}"#,
        now + 3600
    )
}
