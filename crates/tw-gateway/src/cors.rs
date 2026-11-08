// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! CORS per route (G17), so browser-based MCP clients can call the
//! gateway from the origins an operator allows, and from no other.
//!
//! Credentials (cookies) are never allowed: MCP clients authenticate with
//! a bearer token in `Authorization`, which needs no credentials mode.

use std::time::Duration;

use http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_METHOD,
    HeaderValue, ORIGIN, VARY,
};
use http::{HeaderMap, Method, Request};

/// Which origins may call the routes under a path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CorsRule {
    /// The rule covers this path and everything under it on a `/`
    /// boundary; `/` covers every path. The longest match wins.
    pub path: String,
    /// Allowed origins, exactly as browsers send them
    /// (`https://app.example.org`), or `*` for any origin.
    pub origins: Vec<String>,
    /// How long a browser may cache a preflight answer.
    pub max_age: Duration,
}

impl CorsRule {
    /// A rule for `path` allowing `origins`, with a 10-minute preflight cache.
    #[must_use]
    pub fn new(path: impl Into<String>, origins: Vec<String>) -> Self {
        Self {
            path: path.into(),
            origins,
            max_age: Duration::from_secs(600),
        }
    }

    fn covers(&self, path: &str) -> bool {
        let base = self.path.trim_end_matches('/');
        path == base
            || base.is_empty()
            || path
                .strip_prefix(base)
                .is_some_and(|rest| rest.starts_with('/'))
    }

    fn allows(&self, origin: &str) -> bool {
        self.origins.iter().any(|o| o == "*" || o == origin)
    }
}

/// The request headers a browser may send: what MCP Streamable HTTP uses.
const ALLOW_HEADERS: &str = "authorization, content-type, accept, mcp-session-id, mcp-protocol-version, last-event-id, traceparent";
/// The response headers a page may read.
const EXPOSE_HEADERS: &str = "mcp-session-id, tw-request-id, tw-error";
const ALLOW_METHODS: &str = "GET, POST, DELETE, OPTIONS";

/// What CORS says about one request.
pub(crate) enum Cors {
    /// No `Origin`, or no rule for its path: nothing to add.
    None,
    /// A preflight from an allowed origin: answer it with these headers.
    Preflight(HeaderMap),
    /// A preflight from an origin no rule allows.
    Refused,
    /// An allowed origin: add these headers to the response.
    Allowed(HeaderMap),
}

fn rule<'a>(rules: &'a [CorsRule], path: &str) -> Option<&'a CorsRule> {
    rules
        .iter()
        .filter(|r| r.covers(path))
        .max_by_key(|r| r.path.len())
}

fn base_headers(origin: &HeaderValue) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    headers.insert(VARY, HeaderValue::from_static("origin"));
    headers
}

/// Decides CORS for `request` under `rules`.
pub(crate) fn decide<B>(rules: &[CorsRule], request: &Request<B>) -> Cors {
    let Some(origin) = request.headers().get(ORIGIN) else {
        return Cors::None;
    };
    let preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(ACCESS_CONTROL_REQUEST_METHOD);
    let rule = rule(rules, request.uri().path());
    let allowed = rule.filter(|r| origin.to_str().is_ok_and(|o| r.allows(o)));
    match (allowed, preflight) {
        (Some(rule), true) => {
            let mut headers = base_headers(origin);
            headers.insert(
                ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static(ALLOW_METHODS),
            );
            headers.insert(
                ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static(ALLOW_HEADERS),
            );
            headers.insert(
                ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from(rule.max_age.as_secs()),
            );
            Cors::Preflight(headers)
        }
        (Some(_), false) => {
            let mut headers = base_headers(origin);
            headers.insert(
                ACCESS_CONTROL_EXPOSE_HEADERS,
                HeaderValue::from_static(EXPOSE_HEADERS),
            );
            Cors::Allowed(headers)
        }
        (None, true) if !rules.is_empty() => Cors::Refused,
        (None, _) => Cors::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_cover_paths_on_slash_boundaries() {
        let rule = CorsRule::new("/mcp", vec![]);
        assert!(rule.covers("/mcp") && rule.covers("/mcp/x"));
        assert!(!rule.covers("/mcpx") && !rule.covers("/other"));
        assert!(CorsRule::new("/", vec![]).covers("/anything"));
    }

    #[test]
    fn the_longest_rule_wins() {
        let rules = [
            CorsRule::new("/", vec!["https://a".into()]),
            CorsRule::new("/mcp/private", vec![]),
        ];
        assert_eq!(
            rule(&rules, "/mcp/private/x").map(|r| r.path.as_str()),
            Some("/mcp/private")
        );
        assert_eq!(
            rule(&rules, "/mcp/public").map(|r| r.path.as_str()),
            Some("/")
        );
    }
}
