// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Agent-side authorisation (MCP authorisation spec): the gateway as an
//! OAuth 2.1 resource server. Each request carries a bearer JWT access
//! token from a configured issuer, signed with one of its keys, for this
//! gateway's resource (RFC 8707: `aud`), in date, with the scopes asked
//! for. The gateway publishes its protected-resource metadata (RFC 9728)
//! and never passes the token on to a connector.

pub(crate) use tunnelward_audit::b64;
mod bind;
mod dpop;
mod jwk;
mod jwt;
mod keys;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use http::header::AUTHORIZATION;

pub(crate) use bind::Request;
pub use bind::TokenRule;
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
    /// What paths demand of tokens: binding to the sender, single use
    /// (FR-13). A path no rule covers takes any valid token.
    pub token_rules: Vec<TokenRule>,
    /// How far a `DPoP` proof's `iat` may be from now, either way.
    pub dpop_window: Duration,
    /// Whether the ingress asks for client certificates, so tokens bound
    /// to one (RFC 8705) can work; the metadata says so.
    pub certificate_bound: bool,
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
    /// 60 s of leeway, no token rules, a 60 s `DPoP` window.
    #[must_use]
    pub fn new(resource: impl Into<String>, issuers: Vec<Issuer>) -> Self {
        Self {
            resource: resource.into(),
            issuers,
            scopes: Vec::new(),
            leeway: Duration::from_secs(60),
            token_rules: Vec::new(),
            dpop_window: Duration::from_secs(60),
            certificate_bound: false,
        }
    }
}

/// Who a valid token says is calling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Principal {
    /// `client_id` (RFC 9068), else `azp`.
    pub(crate) client_id: Option<String>,
    /// Keys to record once in the shared store: the `DPoP` proof's `jti`,
    /// the token's own on single-use paths. A key already there is a
    /// replay.
    pub(crate) once: Vec<bind::Once>,
    /// The token is bound to a `DPoP` key or a client certificate, and
    /// the binding checked out: cryptographic evidence (FR-14).
    pub(crate) bound: bool,
}

/// A request the ingress refuses: its error id, status, reason and
/// `WWW-Authenticate` challenge.
pub(crate) struct Refused {
    pub(crate) id: &'static str,
    pub(crate) status: http::StatusCode,
    pub(crate) reason: String,
    pub(crate) challenge: Option<String>,
}

/// [`check`], as the ingress answers it: TW-I008 (401) for a missing or
/// invalid token, TW-I009 (403) for missing scopes.
pub(crate) fn authorise(auth: &AgentAuth, request: &Request<'_>) -> Result<Principal, Refused> {
    check(auth, request, SystemTime::now()).map_err(|denial| refused(auth, &denial))
}

/// [`authorise`], then records each key the token and its proof must use
/// once. A key already recorded is a replay (`TW-I008`); a store that
/// cannot answer refuses the request (`TW-I012`, 503: fail closed).
pub(crate) async fn authorise_once(
    auth: &AgentAuth,
    state: &dyn crate::SharedState,
    request: &Request<'_>,
) -> Result<Principal, Refused> {
    let principal = authorise(auth, request)?;
    for (key, ttl) in &principal.once {
        match state.first_use(key, *ttl).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(refused(
                    auth,
                    &Denial::Invalid("the token or DPoP proof was used before"),
                ));
            }
            Err(e) => {
                return Err(Refused {
                    id: crate::state::UNAVAILABLE,
                    status: http::StatusCode::SERVICE_UNAVAILABLE,
                    reason: format!("cannot check for replay: {e}"),
                    challenge: None,
                });
            }
        }
    }
    Ok(principal)
}

/// `denial` as the ingress answers it.
pub(crate) fn refused(auth: &AgentAuth, denial: &Denial) -> Refused {
    {
        let (id, status, reason) = match denial {
            Denial::Missing | Denial::Invalid(_) | Denial::Proof(_) => (
                "TW-I008",
                http::StatusCode::UNAUTHORIZED,
                match denial {
                    Denial::Invalid(why) | Denial::Proof(why) => why,
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
            challenge: Some(challenge(auth, denial)),
        }
    }
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
    /// A `DPoP` proof that fails: 401 `invalid_dpop_proof`.
    Proof(&'static str),
}

/// Checks the token `request` carries against `auth` at `now`.
pub(crate) fn check(
    auth: &AgentAuth,
    request: &Request<'_>,
    now: SystemTime,
) -> Result<Principal, Denial> {
    let (scheme, raw) = presented(request.headers)?;
    let token = jwt::parse(raw).map_err(Denial::Invalid)?;
    signed_by_an_issuer(auth, &token)?;
    let claims = &token.claims;
    in_date(claims, now, auth.leeway)?;
    if !claims.for_audience(&auth.resource) {
        return Err(Denial::Invalid("the token is not for this resource"));
    }
    has_scopes(auth, claims)?;
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let once = bind::check(auth, (scheme, raw), claims, request, secs)?;
    Ok(Principal {
        client_id: claims.client_id.clone().or_else(|| claims.azp.clone()),
        once,
        bound: bind::is_bound(claims),
    })
}

fn has_scopes(auth: &AgentAuth, claims: &jwt::Claims) -> Result<(), Denial> {
    let granted = claims.scopes();
    auth.scopes
        .iter()
        .all(|s| granted.contains(&s.as_str()))
        .then_some(())
        .ok_or(Denial::Scope)
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

/// The one `Authorization` token and its scheme, `Bearer` or `DPoP`;
/// several headers are refused.
fn presented(headers: &HeaderMap) -> Result<(bind::Scheme, &str), Denial> {
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
    let (scheme, token) = text.split_once(' ').ok_or(Denial::Missing)?;
    let token = token.trim();
    match scheme.to_ascii_lowercase().as_str() {
        _ if token.is_empty() => Err(Denial::Missing),
        "bearer" => Ok((bind::Scheme::Bearer, token)),
        "dpop" => Ok((bind::Scheme::Dpop, token)),
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

/// The resource's scheme and authority: `https://mcp.example.org`.
pub(crate) fn origin(resource: &str) -> &str {
    let resource = resource.trim_end_matches('/');
    &resource[..resource.len() - resource_path(resource).len()]
}

/// The metadata URL, absolute, for `WWW-Authenticate`.
fn metadata_url(auth: &AgentAuth) -> String {
    format!("{}{}", origin(&auth.resource), metadata_path(auth))
}

/// The JWS algorithms accepted on tokens and `DPoP` proofs.
const ALGS: [&str; 4] = ["ES256", "RS256", "PS256", "EdDSA"];

/// The protected-resource metadata document (RFC 9728 section 2).
pub(crate) fn metadata(auth: &AgentAuth) -> Vec<u8> {
    let mut doc = serde_json::json!({
        "resource": auth.resource,
        "authorization_servers": auth.issuers.iter().map(|i| &i.issuer).collect::<Vec<_>>(),
        "bearer_methods_supported": ["header"],
        "dpop_signing_alg_values_supported": ALGS,
    });
    if !auth.scopes.is_empty() {
        doc["scopes_supported"] = serde_json::json!(auth.scopes);
    }
    if auth.certificate_bound {
        doc["tls_client_certificate_bound_access_tokens"] = serde_json::json!(true);
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
        Denial::Proof(why) => format!(
            "DPoP error=\"invalid_dpop_proof\", error_description=\"{why}\", algs=\"{}\"",
            ALGS.join(" ")
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
    fn tokens_are_found_once_with_their_scheme() {
        let mut headers = HeaderMap::new();
        assert_eq!(presented(&headers), Err(Denial::Missing));
        headers.insert(AUTHORIZATION, http::HeaderValue::from_static("bearer abc"));
        assert_eq!(presented(&headers), Ok((bind::Scheme::Bearer, "abc")));
        headers.insert(AUTHORIZATION, http::HeaderValue::from_static("DPoP abc"));
        assert_eq!(presented(&headers), Ok((bind::Scheme::Dpop, "abc")));
        headers.insert(AUTHORIZATION, http::HeaderValue::from_static("Basic abc"));
        assert_eq!(presented(&headers), Err(Denial::Missing));
        headers.append(AUTHORIZATION, http::HeaderValue::from_static("Bearer x"));
        assert!(matches!(presented(&headers), Err(Denial::Invalid(_))));
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
