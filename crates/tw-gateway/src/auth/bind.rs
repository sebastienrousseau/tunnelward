// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Token replay defences (FR-13): a token bound to a key (`cnf.jkt`,
//! `DPoP`) or to a client certificate (`cnf.x5t#S256`, RFC 8705) works
//! only for its holder; paths can demand such a token, and single use of
//! each token (`jti`). The checks here are the ones that need no store;
//! they return the keys the caller records, once each, in the shared
//! store.

use std::time::Duration;

use http::HeaderMap;

use super::dpop::{self, For};
use super::jwt::Claims;
use super::{AgentAuth, Denial};

/// What a path demands of the tokens presented for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRule {
    /// The rule covers this path and everything under it on a `/`
    /// boundary; `/` covers every path. The longest match wins.
    pub path: String,
    /// Only tokens bound to a `DPoP` key or a client certificate.
    pub sender_constrained: bool,
    /// Each token once: its `jti` is recorded until it expires.
    pub single_use: bool,
}

impl TokenRule {
    fn covers(&self, path: &str) -> bool {
        let base = self.path.trim_end_matches('/');
        base.is_empty()
            || path == base
            || path
                .strip_prefix(base)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

/// The rule for `path`: the longest that covers it.
pub(crate) fn rule_for<'a>(rules: &'a [TokenRule], path: &str) -> Option<&'a TokenRule> {
    rules
        .iter()
        .filter(|r| r.covers(path))
        .max_by_key(|r| r.path.trim_end_matches('/').len())
}

/// How the token was presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scheme {
    Bearer,
    Dpop,
}

/// The request a token arrives with.
pub(crate) struct Request<'a> {
    pub(crate) method: &'a http::Method,
    pub(crate) path: &'a str,
    pub(crate) headers: &'a HeaderMap,
    /// SHA-256 of the client's TLS certificate, when it sent one.
    pub(crate) client_cert: Option<&'a [u8; 32]>,
}

/// A key to record once in the shared store, and for how long.
pub(crate) type Once = (String, Duration);

/// The binding checks for `claims`, presented with `scheme` as `token`
/// on `request`; the keys to record once.
pub(crate) fn check(
    auth: &AgentAuth,
    presented: (Scheme, &str),
    claims: &Claims,
    request: &Request<'_>,
    now: u64,
) -> Result<Vec<Once>, Denial> {
    let mut once = Vec::new();
    let cnf = claims.cnf.as_ref();
    if let Some(proof) = key_bound(auth, presented, cnf, request, now)? {
        once.push(proof);
    }
    if let Some(thumb) = cnf.and_then(|c| c.x5t_s256.as_deref()) {
        certificate_holder(thumb, request.client_cert)?;
    }
    once.extend(path_rule(auth, claims, request.path, now)?);
    Ok(once)
}

/// What the rule for `path` demands: a bound token, and the token's
/// `jti` to record when it is single use.
fn path_rule(
    auth: &AgentAuth,
    claims: &Claims,
    path: &str,
    now: u64,
) -> Result<Option<Once>, Denial> {
    let Some(rule) = rule_for(&auth.token_rules, path) else {
        return Ok(None);
    };
    let bound = claims
        .cnf
        .as_ref()
        .is_some_and(|c| c.jkt.is_some() || c.x5t_s256.is_some());
    if rule.sender_constrained && !bound {
        return Err(Denial::Invalid(
            "this path needs a token bound to a DPoP key or a client certificate",
        ));
    }
    rule.single_use
        .then(|| single_use(auth, claims, now))
        .transpose()
}

/// The `DPoP` binding: a token bound to a key needs the `DPoP` scheme
/// and a proof by that key; the scheme needs a bound token. The proof's
/// key to record, when there is one.
fn key_bound(
    auth: &AgentAuth,
    (scheme, token): (Scheme, &str),
    cnf: Option<&super::jwt::Confirmation>,
    request: &Request<'_>,
    now: u64,
) -> Result<Option<Once>, Denial> {
    match (cnf.and_then(|c| c.jkt.as_deref()), scheme) {
        (Some(jkt), Scheme::Dpop) => proven(auth, jkt, token, request, now).map(Some),
        (Some(_), Scheme::Bearer) => Err(Denial::Invalid("a DPoP-bound token sent as Bearer")),
        (None, Scheme::Dpop) => Err(Denial::Invalid("the token is not bound to a DPoP key")),
        (None, Scheme::Bearer) => Ok(None),
    }
}

/// Checks the one `DPoP` proof against the token bound to `jkt`.
fn proven(
    auth: &AgentAuth,
    jkt: &str,
    token: &str,
    request: &Request<'_>,
    now: u64,
) -> Result<Once, Denial> {
    let mut proofs = request.headers.get_all("dpop").iter();
    let (Some(proof), None) = (proofs.next(), proofs.next()) else {
        return Err(Denial::Proof("give exactly one DPoP header"));
    };
    let proof = proof
        .to_str()
        .map_err(|_| Denial::Proof("the DPoP header is not text"))?;
    let url = format!("{}{}", super::origin(&auth.resource), request.path);
    let window = auth.dpop_window.as_secs();
    let want = For {
        method: request.method.as_str(),
        url: &url,
        token,
        now,
        window,
    };
    let checked = dpop::verify(proof, &want).map_err(Denial::Proof)?;
    if checked.jkt != jkt {
        return Err(Denial::Proof("the DPoP proof's key is not the token's"));
    }
    let ttl = Duration::from_secs(2 * window + 1);
    Ok((format!("dpop:{}:{}", checked.jkt, checked.jti), ttl))
}

fn certificate_holder(thumb: &str, client_cert: Option<&[u8; 32]>) -> Result<(), Denial> {
    let presented = client_cert.map(|c| super::b64::encode(c));
    if presented.as_deref() == Some(thumb) {
        Ok(())
    } else {
        Err(Denial::Invalid(
            "the token is bound to a client certificate this connection did not present",
        ))
    }
}

/// The token's `jti`, to record until the token expires.
fn single_use(auth: &AgentAuth, claims: &Claims, now: u64) -> Result<Once, Denial> {
    let jti = claims
        .jti
        .as_deref()
        .filter(|j| !j.is_empty() && j.len() <= 256)
        .ok_or(Denial::Invalid(
            "this path needs single-use tokens, and the token has no jti",
        ))?;
    let left = claims
        .exp
        .saturating_add(auth.leeway.as_secs())
        .saturating_sub(now);
    Ok((
        format!("jti:{}:{jti}", claims.iss),
        Duration::from_secs(left.max(1)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(path: &str) -> TokenRule {
        TokenRule {
            path: path.into(),
            sender_constrained: true,
            single_use: false,
        }
    }

    #[test]
    fn the_longest_covering_rule_wins_on_a_slash_boundary() {
        let rules = [rule("/"), rule("/mcp"), rule("/mcp/pay")];
        let found = |p: &str| rule_for(&rules, p).map(|r| r.path.as_str());
        assert_eq!(found("/mcp/pay/x"), Some("/mcp/pay"));
        assert_eq!(found("/mcp/payments"), Some("/mcp"));
        assert_eq!(found("/other"), Some("/"));
        assert_eq!(rule_for(&rules[1..], "/other"), None);
    }
}
