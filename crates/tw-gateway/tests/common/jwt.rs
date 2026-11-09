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

    fn alg(&self) -> &'static str {
        match self.pair {
            Pair::Es256(_) => "ES256",
            Pair::EdDsa(_) => "EdDSA",
        }
    }

    /// `header` and `claims` signed by this key, as a compact JWS.
    fn sign(&self, header: &str, claims: &str) -> Res<String> {
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

    /// A token with `claims`, signed by this key.
    pub fn token(&self, claims: &str) -> Res<String> {
        let header = format!(
            r#"{{"alg":"{}","kid":"{}","typ":"at+jwt"}}"#,
            self.alg(),
            self.kid
        );
        self.sign(&header, claims)
    }

    /// The public key as a JWK with only its required members, in the
    /// order RFC 7638 hashes them.
    fn public_jwk(&self) -> String {
        match &self.pair {
            Pair::Es256(p) => {
                let point = p.public_key().as_ref();
                format!(
                    r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                    b64(&point[1..33]),
                    b64(&point[33..65])
                )
            }
            Pair::EdDsa(p) => format!(
                r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
                b64(p.public_key().as_ref())
            ),
        }
    }

    /// The RFC 7638 thumbprint, as a `DPoP`-bound token's `cnf.jkt`.
    pub fn thumbprint(&self) -> String {
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, self.public_jwk().as_bytes());
        b64(digest.as_ref())
    }

    /// A `DPoP` proof (RFC 9449) by this key for `method` and `url`, with
    /// `token`'s hash, issued at `iat`, with `jti`.
    pub fn proof(&self, method: &str, url: &str, token: &str, iat: u64, jti: &str) -> Res<String> {
        self.forged_proof("dpop+jwt", self, (method, url, token), (iat, jti))
    }

    /// A proof signed by this key whose header says `typ` and carries
    /// `shown`'s public key: a forgery when `shown` is another key.
    pub fn forged_proof(
        &self,
        typ: &str,
        shown: &Signer,
        (method, url, token): (&str, &str, &str),
        (iat, jti): (u64, &str),
    ) -> Res<String> {
        let header = format!(
            r#"{{"typ":"{typ}","alg":"{}","jwk":{}}}"#,
            self.alg(),
            shown.public_jwk()
        );
        let ath =
            b64(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes()).as_ref());
        let claims = format!(
            r#"{{"jti":"{jti}","htm":"{method}","htu":"{url}","iat":{iat},"ath":"{ath}"}}"#
        );
        self.sign(&header, &claims)
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
