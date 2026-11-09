// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `DPoP` proofs (RFC 9449 section 4.3): a JWT the client signs with its
//! own key for each request, naming the method and URL, carrying a hash
//! of the access token, and putting the public key in its header. A token
//! bound to that key (`cnf.jkt`) is useless without it, so a copied token
//! does not work from another client.
//!
//! This module checks one proof; the caller records its `jti` in the
//! shared store, so a proof is accepted once.

use serde::Deserialize;

use super::b64;
use super::jwk::{self, Alg};

/// Largest proof read.
const MAX_PROOF: usize = 8 * 1024;
/// Longest `jti` accepted, so a proof cannot fill the store with keys.
const MAX_JTI: usize = 256;

#[derive(Deserialize)]
struct Header {
    typ: Option<String>,
    alg: String,
    jwk: Option<serde_json::Value>,
    crit: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Claims {
    jti: String,
    htm: String,
    htu: String,
    iat: u64,
    ath: Option<String>,
}

/// A proof that checked out: the thumbprint of its key and its `jti`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Proof {
    pub(crate) jkt: String,
    pub(crate) jti: String,
}

/// The request a proof must be for.
pub(crate) struct For<'a> {
    pub(crate) method: &'a str,
    /// The request URL as the client used it, without query.
    pub(crate) url: &'a str,
    /// The access token presented with it.
    pub(crate) token: &'a str,
    /// Seconds since 1970.
    pub(crate) now: u64,
    /// How far `iat` may be from `now`, either way.
    pub(crate) window: u64,
}

fn json<T: for<'de> Deserialize<'de>>(part: &str) -> Option<T> {
    serde_json::from_slice(&b64::decode(part)?).ok()
}

/// Checks `proof` for the request `want`.
///
/// # Errors
///
/// A sentence naming the check that failed, for `error_description`.
pub(crate) fn verify(proof: &str, want: &For<'_>) -> Result<Proof, &'static str> {
    if proof.len() > MAX_PROOF {
        return Err("the DPoP proof is too long");
    }
    let mut parts = proof.split('.');
    let (Some(h), Some(c), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("the DPoP proof is not a signed JWT");
    };
    let header: Header = json(h).ok_or("the DPoP proof header does not parse")?;
    let (alg, key) = key_of(&header)?;
    let signature = b64::decode(s).ok_or("the DPoP proof signature does not decode")?;
    let signed = &proof.as_bytes()[..h.len() + 1 + c.len()];
    if !key.verifies(alg, signed, &signature) {
        return Err("the DPoP proof signature does not verify");
    }
    let claims: Claims = json(c).ok_or("the DPoP proof claims do not parse")?;
    for_this_request(&claims, want)?;
    Ok(Proof {
        jkt: key.thumbprint(),
        jti: claims.jti,
    })
}

/// The algorithm and public key the header names, after the header's
/// own checks: `typ`, no critical extensions, a public key that fits.
fn key_of(header: &Header) -> Result<(Alg, jwk::Key), &'static str> {
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err("the DPoP proof's typ is not dpop+jwt");
    }
    if header.crit.is_some() {
        return Err("the DPoP proof has critical extensions");
    }
    let alg = Alg::named(&header.alg).ok_or("the DPoP proof's algorithm is not accepted")?;
    let key = header
        .jwk
        .as_ref()
        .and_then(jwk::parse_public)
        .ok_or("the DPoP proof carries no usable public key")?;
    if !key.fits(alg, &header.alg) {
        return Err("the DPoP proof's key does not fit its algorithm");
    }
    Ok((alg, key))
}

fn for_this_request(claims: &Claims, want: &For<'_>) -> Result<(), &'static str> {
    if claims.jti.is_empty() || claims.jti.len() > MAX_JTI {
        return Err("the DPoP proof's jti is missing or too long");
    }
    if claims.htm != want.method {
        return Err("the DPoP proof is for another method");
    }
    if normal(&claims.htu).is_none_or(|htu| Some(htu) != normal(want.url)) {
        return Err("the DPoP proof is for another URL");
    }
    if claims.iat.abs_diff(want.now) > want.window {
        return Err("the DPoP proof is too old or from the future");
    }
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, want.token.as_bytes());
    if claims.ath.as_deref() != Some(b64::encode(hash.as_ref()).as_str()) {
        return Err("the DPoP proof is for another access token");
    }
    Ok(())
}

/// `url` normalised for comparison (RFC 9449 section 4.3, item 9): scheme
/// and host in lower case, the default port dropped, no query or
/// fragment, an empty path as `/`. `None` if it is not an absolute URL.
pub(crate) fn normal(url: &str) -> Option<String> {
    let without = url.split(['?', '#']).next()?;
    let uri: http::Uri = without.parse().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let host = uri.host()?.to_ascii_lowercase();
    let port = match (scheme.as_str(), uri.port_u16()) {
        ("https", Some(443)) | ("http", Some(80)) | (_, None) => String::new(),
        (_, Some(p)) => format!(":{p}"),
    };
    let path = match uri.path() {
        "" => "/",
        p => p,
    };
    Some(format!("{scheme}://{host}{port}{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_compare_after_normalising() {
        assert_eq!(
            normal("HTTPS://MCP.Example.org:443/mcp?x=1#f").as_deref(),
            Some("https://mcp.example.org/mcp")
        );
        assert_eq!(normal("https://h").as_deref(), Some("https://h/"));
        assert_eq!(
            normal("https://h:8443/a").as_deref(),
            Some("https://h:8443/a")
        );
        assert_eq!(normal("/relative"), None);
    }
}
