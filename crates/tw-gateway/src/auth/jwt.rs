// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! JWT access tokens (RFC 7519, RFC 9068): the compact form split and
//! decoded, and the claims a resource server checks.

use serde::Deserialize;

use super::b64;
use super::jwk::Alg;

/// Longest token read, in bytes.
pub(crate) const MAX_TOKEN: usize = 8 * 1024;

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    typ: Option<String>,
    /// Critical extensions: none are understood, so any makes the token
    /// unusable (RFC 7515 section 4.1.11).
    crit: Option<serde_json::Value>,
}

/// `aud`: one audience or several.
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

/// The claims checked or recorded.
#[derive(Deserialize)]
pub(crate) struct Claims {
    pub(crate) iss: String,
    aud: Audience,
    pub(crate) exp: u64,
    pub(crate) nbf: Option<u64>,
    pub(crate) client_id: Option<String>,
    pub(crate) azp: Option<String>,
    pub(crate) scope: Option<String>,
    /// For single-use tokens (FR-13).
    pub(crate) jti: Option<String>,
    /// What the token is bound to (RFC 7800): a `DPoP` key or a client
    /// certificate.
    pub(crate) cnf: Option<Confirmation>,
}

/// `cnf`: the key or certificate a token is bound to.
#[derive(Deserialize)]
pub(crate) struct Confirmation {
    /// RFC 9449: the SHA-256 thumbprint of the `DPoP` key.
    pub(crate) jkt: Option<String>,
    /// RFC 8705: the SHA-256 of the client certificate.
    #[serde(rename = "x5t#S256")]
    pub(crate) x5t_s256: Option<String>,
}

impl Claims {
    /// Whether `resource` is among the audiences.
    pub(crate) fn for_audience(&self, resource: &str) -> bool {
        match &self.aud {
            Audience::One(a) => a == resource,
            Audience::Many(all) => all.iter().any(|a| a == resource),
        }
    }

    /// The scopes granted, from the space-separated `scope`.
    pub(crate) fn scopes(&self) -> Vec<&str> {
        self.scope
            .as_deref()
            .map(|s| s.split(' ').filter(|s| !s.is_empty()).collect())
            .unwrap_or_default()
    }
}

/// A token split and decoded, its signature not yet checked.
pub(crate) struct Token {
    pub(crate) alg: Alg,
    pub(crate) alg_name: String,
    pub(crate) kid: Option<String>,
    pub(crate) claims: Claims,
    /// `header.payload`, the bytes the signature covers.
    pub(crate) signed: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

/// `token` split, decoded and checked for shape: three parts, an accepted
/// algorithm, no critical extensions, an access-token `typ` if any.
pub(crate) fn parse(token: &str) -> Result<Token, &'static str> {
    if token.len() > MAX_TOKEN {
        return Err("the token is too long");
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("the token is not a signed JWT");
    };
    let header: Header = json(h).ok_or("the token header does not parse")?;
    let alg = Alg::named(&header.alg).ok_or("the token's algorithm is not accepted")?;
    if header.crit.is_some() {
        return Err("the token has critical extensions");
    }
    if header
        .typ
        .as_deref()
        .is_some_and(|t| !is_access_token_type(t))
    {
        return Err("the token is not an access token");
    }
    let claims: Claims = json(p).ok_or("the token claims do not parse")?;
    let signature = b64::decode(s).ok_or("the token signature does not decode")?;
    Ok(Token {
        alg,
        alg_name: header.alg,
        kid: header.kid,
        claims,
        signed: token.as_bytes()[..h.len() + 1 + p.len()].to_vec(),
        signature,
    })
}

/// `JWT` and RFC 9068's `at+jwt`, case-insensitively, with or without
/// the `application/` prefix.
fn is_access_token_type(typ: &str) -> bool {
    let t = typ.to_ascii_lowercase();
    let t = t.strip_prefix("application/").unwrap_or(&t);
    t == "jwt" || t == "at+jwt"
}

fn json<T: for<'de> Deserialize<'de>>(part: &str) -> Option<T> {
    serde_json::from_slice(&b64::decode(part)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk.iter().fold(0_u32, |acc, &b| acc << 8 | u32::from(b))
                << (8 * (3 - chunk.len()));
            for i in 0..=chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            }
        }
        out
    }

    fn token(header: &str, claims: &str) -> String {
        format!(
            "{}.{}.{}",
            enc(header.as_bytes()),
            enc(claims.as_bytes()),
            enc(b"sig")
        )
    }

    const CLAIMS: &str =
        r#"{"iss":"https://as","aud":["x","https://gw"],"exp":9,"scope":"a  b","azp":"c"}"#;

    #[test]
    fn a_well_formed_token_parses() {
        let t = parse(&token(
            r#"{"alg":"ES256","kid":"k","typ":"at+jwt"}"#,
            CLAIMS,
        ));
        let t = t.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((t.alg, t.kid.as_deref()), (Alg::Es256, Some("k")));
        assert!(t.claims.for_audience("https://gw") && !t.claims.for_audience("https://other"));
        assert_eq!(t.claims.scopes(), ["a", "b"]);
        assert_eq!(t.signature, b"sig");
    }

    #[test]
    fn malformed_and_unsafe_tokens_are_refused() {
        let cases = [
            (token(r#"{"alg":"none"}"#, CLAIMS), "algorithm"),
            (token(r#"{"alg":"HS256"}"#, CLAIMS), "algorithm"),
            (
                token(r#"{"alg":"ES256","crit":["b64"]}"#, CLAIMS),
                "critical",
            ),
            (
                token(r#"{"alg":"ES256","typ":"dpop+jwt"}"#, CLAIMS),
                "access token",
            ),
            (token(r#"{"alg":"ES256"}"#, r#"{"iss":"x"}"#), "claims"),
            ("a.b".to_owned(), "not a signed JWT"),
            ("a.b.c.d".to_owned(), "not a signed JWT"),
            ("x".repeat(MAX_TOKEN + 1), "too long"),
        ];
        for (t, why) in cases {
            let err = parse(&t).err().unwrap_or("parsed");
            assert!(err.contains(why), "{why}: got {err}");
        }
    }
}
