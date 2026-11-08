// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Matching a request to a route claim.

use bytes::Bytes;
use http::uri::{Authority, Scheme, Uri};
use http_body_util::Full;
use hyper::Request;
use tw_proto::CATCH_ALL_ROUTE;

use crate::SendError;

/// What routing looks at: the host, lowercased without its port, and the
/// path.
pub(crate) struct Target {
    pub(crate) host: Option<String>,
    pub(crate) path: String,
}

impl Target {
    pub(crate) fn of(request: &Request<Full<Bytes>>) -> Self {
        let host = request.uri().host().map(str::to_ascii_lowercase);
        Self {
            host,
            path: request.uri().path().to_owned(),
        }
    }
}

/// Gives `request` a scheme (`http`) and an authority (its `Host` header,
/// else `localhost`) when it lacks them: HTTP/2 requires both.
pub(crate) fn absolute(
    mut request: Request<Full<Bytes>>,
) -> Result<Request<Full<Bytes>>, SendError> {
    if request.uri().scheme().is_some() && request.uri().authority().is_some() {
        return Ok(request);
    }
    let host = request
        .headers()
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let authority = Authority::try_from(host).map_err(|e| SendError::BadRequest(e.into()))?;
    let mut parts = request.uri().clone().into_parts();
    parts.scheme = Some(Scheme::HTTP);
    parts.authority = Some(authority);
    *request.uri_mut() = Uri::from_parts(parts).map_err(|e| SendError::BadRequest(e.into()))?;
    Ok(request)
}

/// Whether a connector claiming `domains` serves `host`. No domains means
/// any host; `*.example.org` matches any name ending in `.example.org`.
pub(crate) fn domain_matches(domains: &[String], host: Option<&str>) -> bool {
    if domains.is_empty() {
        return true;
    }
    let Some(host) = host else { return false };
    domains.iter().any(|d| match d.strip_prefix('*') {
        Some(suffix) => host.len() > suffix.len() && host.ends_with(suffix),
        None => d == host,
    })
}

/// How well `route` claims `path`: `None` when it does not, otherwise a
/// score where a longer route wins and the catch-all scores lowest.
/// `mcp/echo` claims `/mcp/echo` and `/mcp/echo/...`, never `/mcp/echoes`.
pub(crate) fn route_score(route: &str, path: &str) -> Option<usize> {
    if route == CATCH_ALL_ROUTE {
        return Some(0);
    }
    let rest = path.strip_prefix('/')?.strip_prefix(route)?;
    (rest.is_empty() || rest.starts_with('/')).then_some(route.len() + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_claims_match_on_segment_boundaries() {
        assert_eq!(route_score("mcp/echo", "/mcp/echo"), Some(9));
        assert_eq!(route_score("mcp/echo", "/mcp/echo/x/y"), Some(9));
        assert_eq!(route_score("mcp", "/mcp/echo"), Some(4));
        assert_eq!(route_score("mcp/echo", "/mcp/echoes"), None);
        assert_eq!(route_score("mcp/echo", "/mcp"), None);
        assert_eq!(route_score("*", "/anything"), Some(0));
    }

    #[test]
    fn domains_match_exactly_or_by_wildcard() {
        let d = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(domain_matches(&[], None));
        assert!(domain_matches(&[], Some("x.org")));
        assert!(domain_matches(
            &d(&["mcp.example.org"]),
            Some("mcp.example.org")
        ));
        assert!(!domain_matches(&d(&["mcp.example.org"]), Some("evil.org")));
        assert!(!domain_matches(&d(&["mcp.example.org"]), None));
        assert!(domain_matches(
            &d(&["*.example.org"]),
            Some("a.b.example.org")
        ));
        assert!(!domain_matches(&d(&["*.example.org"]), Some("example.org")));
        assert!(!domain_matches(
            &d(&["*.example.org"]),
            Some("badexample.org")
        ));
    }
}
