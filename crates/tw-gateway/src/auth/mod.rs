// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Agent-side authorisation (MCP authorisation spec): the gateway as an
//! OAuth 2.1 resource server. Each request carries a bearer JWT access
//! token from a configured issuer, signed with one of its keys, for this
//! gateway's resource (RFC 8707: `aud`), in date, with the scopes asked
//! for. The gateway publishes its protected-resource metadata (RFC 9728)
//! and never passes the token on to a connector.

pub(crate) mod b64;
mod jwk;
mod jwt;
mod keys;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use http::header::AUTHORIZATION;

pub(crate) use jwk::Alg;
pub use keys::{KeyError, KeySet};

/// Standard base64 with padding, as Structured Fields byte sequences use.
pub(crate) fn b64_standard(text: &str) -> Option<Vec<u8>> {
    b64::decode_standard(text)
}

/// Where the protected-resource metadata lives (RFC 9728 section 3).
const WELL_KNOWN: &str = "/.well-known/oauth-protected-resource";

/// The tokens a gateway accepts from agents.
#[derive(Debug, Clone)]
pub struct AgentAuth {
    /// The gateway's canonical URI as agents use it, for example
    /// `https://mcp.example.org`: a token's `aud` must name it.
    pub resource: String,
    /// The authorisation servers whose tokens are accepted.
    pub issuers: Vec<Issuer>,
    /// Scopes every token must grant (403 `insufficient_scope` without).
    pub scopes: Vec<String>,
    /// Clock skew allowed on `exp` and `nbf`.
    pub leeway: Duration,
}

/// One authorisation server and its keys.
#[derive(Debug, Clone)]
pub struct Issuer {
    /// Its issuer identifier, exactly as in the tokens' `iss`.
    pub issuer: String,
    /// Its signing keys.
    pub keys: Arc<KeySet>,
}

impl AgentAuth {
    /// `resource` accepting tokens from `issuers`, no scopes required,
    /// 60 s of leeway.
    #[must_use]
    pub fn new(resource: impl Into<String>, issuers: Vec<Issuer>) -> Self {
        Self {
            resource: resource.into(),
            issuers,
            scopes: Vec::new(),
            leeway: Duration::from_secs(60),
        }
    }
}

/// Who a valid token says is calling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Principal {
    /// `client_id` (RFC 9068), else `azp`.
    pub(crate) client_id: Option<String>,
}

/// A request the ingress refuses: its error id, status, reason and
/// `WWW-Authenticate` challenge.
pub(crate) struct Refused {
    pub(crate) id: &'static str,
    pub(crate) status: http::StatusCode,
    pub(crate) reason: String,
    pub(crate) challenge: String,
}

/// [`check`], as the ingress answers it: TW-I008 (401) for a missing or
/// invalid token, TW-I009 (403) for missing scopes.
pub(crate) fn authorise(auth: &AgentAuth, headers: &HeaderMap) -> Result<Principal, Refused> {
    check(auth, headers, SystemTime::now()).map_err(|denial| {
        let (id, status, reason) = match &denial {
            Denial::Missing | Denial::Invalid(_) => (
                "TW-I008",
                http::StatusCode::UNAUTHORIZED,
                match &denial {
                    Denial::Invalid(why) => why,
                    _ => "no bearer token",
                },
            ),
            Denial::Scope => (
                "TW-I009",
                http::StatusCode::FORBIDDEN,
                "the token lacks a required scope",
            ),
        };
        Refused {
            id,
            status,
            reason: reason.to_owned(),
            challenge: challenge(auth, &denial),
        }
    })
}

/// Whether `method` and `path` ask for the metadata document.
pub(crate) fn is_metadata_request(auth: &AgentAuth, method: &http::Method, path: &str) -> bool {
    (method == http::Method::GET || method == http::Method::HEAD) && path == metadata_path(auth)
}

/// Why a request was not authorised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Denial {
    /// No bearer token: 401 with the metadata URL only.
    Missing,
    /// A token that fails a check: 401 `invalid_token`.
    Invalid(&'static str),
    /// A valid token without the scopes: 403 `insufficient_scope`.
    Scope,
}

/// Checks the bearer token in `headers` against `auth` at `now`.
pub(crate) fn check(
    auth: &AgentAuth,
    headers: &HeaderMap,
    now: SystemTime,
) -> Result<Principal, Denial> {
    let token = jwt::parse(bearer(headers)?).map_err(Denial::Invalid)?;
    signed_by_an_issuer(auth, &token)?;
    let claims = &token.claims;
    in_date(claims, now, auth.leeway)?;
    if !claims.for_audience(&auth.resource) {
        return Err(Denial::Invalid("the token is not for this resource"));
    }
    let granted = claims.scopes();
    if !auth.scopes.iter().all(|s| granted.contains(&s.as_str())) {
        return Err(Denial::Scope);
    }
    Ok(Principal {
        client_id: claims.client_id.clone().or_else(|| claims.azp.clone()),
    })
}

/// Fails unless `token`'s issuer is listed and one of its keys verifies
/// the signature.
fn signed_by_an_issuer(auth: &AgentAuth, token: &jwt::Token) -> Result<(), Denial> {
    let issuer = auth
        .issuers
        .iter()
        .find(|i| i.issuer == token.claims.iss)
        .ok_or(Denial::Invalid("the token's issuer is not trusted"))?;
    let keys = issuer
        .keys
        .candidates(token.alg, &token.alg_name, token.kid.as_deref());
    keys.iter()
        .any(|k| k.verifies(token.alg, &token.signed, &token.signature))
        .then_some(())
        .ok_or(Denial::Invalid("the token's signature does not verify"))
}

/// The one `Authorization: Bearer` token; several headers are refused.
fn bearer(headers: &HeaderMap) -> Result<&str, Denial> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(if headers.contains_key(AUTHORIZATION) {
            Denial::Invalid("more than one Authorization header")
        } else {
            Denial::Missing
        });
    };
    let text = value
        .to_str()
        .map_err(|_| Denial::Invalid("the Authorization header is not text"))?;
    match text.split_once(' ') {
        Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() => {
            Ok(token.trim())
        }
        _ => Err(Denial::Missing),
    }
}

fn in_date(claims: &jwt::Claims, now: SystemTime, leeway: Duration) -> Result<(), Denial> {
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let leeway = leeway.as_secs();
    if claims.exp.saturating_add(leeway) <= now {
        return Err(Denial::Invalid("the token has expired"));
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(leeway))
    {
        return Err(Denial::Invalid("the token is not valid yet"));
    }
    Ok(())
}

/// The path the gateway serves its metadata on: the well-known prefix,
/// then the resource's own path (RFC 9728 section 3.1).
pub(crate) fn metadata_path(auth: &AgentAuth) -> String {
    let path = resource_path(&auth.resource);
    format!("{WELL_KNOWN}{}", path.trim_end_matches('/'))
}

fn resource_path(resource: &str) -> &str {
    let rest = resource.split_once("://").map_or(resource, |(_, r)| r);
    rest.find('/').map_or("", |i| &rest[i..])
}

/// The metadata URL, absolute, for `WWW-Authenticate`.
fn metadata_url(auth: &AgentAuth) -> String {
    let resource = auth.resource.trim_end_matches('/');
    let path = resource_path(resource);
    let origin = &resource[..resource.len() - path.len()];
    format!("{origin}{}", metadata_path(auth))
}

/// The protected-resource metadata document (RFC 9728 section 2).
pub(crate) fn metadata(auth: &AgentAuth) -> Vec<u8> {
    let mut doc = serde_json::json!({
        "resource": auth.resource,
        "authorization_servers": auth.issuers.iter().map(|i| &i.issuer).collect::<Vec<_>>(),
        "bearer_methods_supported": ["header"],
    });
    if !auth.scopes.is_empty() {
        doc["scopes_supported"] = serde_json::json!(auth.scopes);
    }
    doc.to_string().into_bytes()
}

/// The `WWW-Authenticate` value for `denial` (RFC 6750 section 3, RFC
/// 9728 section 5.1).
pub(crate) fn challenge(auth: &AgentAuth, denial: &Denial) -> String {
    let meta = format!("resource_metadata=\"{}\"", metadata_url(auth));
    match denial {
        Denial::Missing => format!("Bearer {meta}"),
        Denial::Invalid(why) => {
            format!("Bearer error=\"invalid_token\", error_description=\"{why}\", {meta}")
        }
        Denial::Scope => format!(
            "Bearer error=\"insufficient_scope\", scope=\"{}\", {meta}",
            auth.scopes.join(" ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(resource: &str) -> AgentAuth {
        AgentAuth::new(resource, Vec::new())
    }

    #[test]
    fn metadata_paths_follow_rfc_9728() {
        let root = auth("https://mcp.example.org");
        assert_eq!(metadata_path(&root), WELL_KNOWN);
        assert_eq!(
            metadata_url(&root),
            format!("https://mcp.example.org{WELL_KNOWN}")
        );
        let nested = auth("https://gw.example.org/mcp/");
        assert_eq!(metadata_path(&nested), format!("{WELL_KNOWN}/mcp"));
        assert_eq!(
            metadata_url(&nested),
            format!("https://gw.example.org{WELL_KNOWN}/mcp")
        );
    }

    #[test]
    fn bearer_tokens_are_found_once() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer(&headers), Err(Denial::Missing));
        headers.insert(AUTHORIZATION, http::HeaderValue::from_static("bearer abc"));
        assert_eq!(bearer(&headers), Ok("abc"));
        headers.insert(AUTHORIZATION, http::HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer(&headers), Err(Denial::Missing));
        headers.append(AUTHORIZATION, http::HeaderValue::from_static("Bearer x"));
        assert!(matches!(bearer(&headers), Err(Denial::Invalid(_))));
    }

    #[test]
    fn challenges_name_the_metadata_and_the_error() {
        let mut a = auth("https://gw");
        a.scopes = vec!["mcp".into(), "read".into()];
        let url = format!("resource_metadata=\"https://gw{WELL_KNOWN}\"");
        assert_eq!(challenge(&a, &Denial::Missing), format!("Bearer {url}"));
        assert!(challenge(&a, &Denial::Scope).contains("insufficient_scope\", scope=\"mcp read\""));
        assert!(challenge(&a, &Denial::Invalid("x")).starts_with("Bearer error=\"invalid_token\""));
    }
}
