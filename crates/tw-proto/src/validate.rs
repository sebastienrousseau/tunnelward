// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checks a frame's contents after it has parsed.

use core::fmt;

use crate::code::RejectCode;
use crate::frame::{Accept, Frame, McpDescriptor, PROTOCOL_VERSION, Register, Reject};
use crate::limits::Limits;

/// Longest SPIFFE ID accepted, per the SPIFFE specification.
pub const MAX_SPIFFE_ID_LEN: usize = 2048;
/// Longest route claim, in bytes.
pub const MAX_ROUTE_LEN: usize = 255;
/// Most `/`-separated segments in a route claim.
pub const MAX_ROUTE_SEGMENTS: usize = 8;
/// Longest route segment, in bytes.
pub const MAX_SEGMENT_LEN: usize = 63;
/// Longest MCP server name, in bytes.
pub const MAX_MCP_NAME_LEN: usize = 128;
/// Longest MCP server version, in bytes.
pub const MAX_MCP_VERSION_LEN: usize = 64;
/// Longest domain name, in bytes (RFC 1035, without the trailing dot).
pub const MAX_DOMAIN_LEN: usize = 253;
/// The route claim that serves every path.
pub const CATCH_ALL_ROUTE: &str = "*";
/// Longest rejection reason, in bytes.
pub const MAX_REASON_LEN: usize = 1024;

/// A frame that parsed but breaks a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid {
    /// The code a gateway sends back for it.
    pub code: RejectCode,
    /// Which rule, for logs.
    pub rule: &'static str,
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid frame: {}", self.rule)
    }
}

impl std::error::Error for Invalid {}

fn check(ok: bool, rule: &'static str) -> Result<(), Invalid> {
    if ok {
        Ok(())
    } else {
        Err(Invalid {
            code: RejectCode::Invalid,
            rule,
        })
    }
}

/// Checks every field of `frame` against the protocol rules and `limits`.
///
/// # Errors
///
/// The first rule the frame breaks.
pub fn validate(frame: &Frame, limits: &Limits) -> Result<(), Invalid> {
    match frame {
        Frame::Register(r) => validate_register(r, limits),
        Frame::Accept(a) => validate_accept(a),
        Frame::Reject(r) => validate_reject(r),
    }
}

fn validate_register(r: &Register, limits: &Limits) -> Result<(), Invalid> {
    if r.version != PROTOCOL_VERSION {
        return Err(Invalid {
            code: RejectCode::UnsupportedVersion,
            rule: "unsupported protocol version",
        });
    }
    check(is_spiffe_id(&r.spiffe_id), "spiffe_id is not a SPIFFE ID")?;
    check(r.capacity > 0, "capacity is zero")?;
    validate_routes(&r.routes, limits)?;
    validate_domains(&r.domains, limits)?;
    r.mcp.as_ref().map_or(Ok(()), validate_mcp)
}

fn validate_routes(routes: &[String], limits: &Limits) -> Result<(), Invalid> {
    check(!routes.is_empty(), "no routes claimed")?;
    check(
        routes.len() <= usize::from(limits.max_routes_per_identity),
        "too many routes",
    )?;
    check(routes.iter().all(|x| is_route(x)), "route is not valid")?;
    check(has_no_duplicates(routes), "route claimed twice")
}

fn validate_domains(domains: &[String], limits: &Limits) -> Result<(), Invalid> {
    check(
        domains.len() <= usize::from(limits.max_domains_per_identity),
        "too many domains",
    )?;
    check(domains.iter().all(|x| is_domain(x)), "domain is not valid")?;
    check(has_no_duplicates(domains), "domain claimed twice")
}

fn validate_mcp(m: &McpDescriptor) -> Result<(), Invalid> {
    check(is_text(&m.name, MAX_MCP_NAME_LEN), "mcp.name is not valid")?;
    check(
        is_text(&m.version, MAX_MCP_VERSION_LEN),
        "mcp.version is not valid",
    )
}

fn validate_accept(a: &Accept) -> Result<(), Invalid> {
    let s = &a.limits;
    check(a.lease_secs > 0, "lease_secs is zero")?;
    check(
        s.max_concurrent_streams > 0
            && s.max_header_list_size > 0
            && s.initial_stream_window > 0
            && s.initial_connection_window > 0,
        "a stream limit is zero",
    )
}

fn validate_reject(r: &Reject) -> Result<(), Invalid> {
    check(
        r.reason.len() <= MAX_REASON_LEN && !r.reason.chars().any(char::is_control),
        "reason is not valid",
    )
}

fn has_no_duplicates(items: &[String]) -> bool {
    let mut seen: Vec<&str> = items.iter().map(String::as_str).collect();
    seen.sort_unstable();
    seen.windows(2).all(|w| w[0] != w[1])
}

/// Non-empty, at most `max` bytes, no control characters.
fn is_text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}

/// A route claim: [`CATCH_ALL_ROUTE`], or 1 to 8 `/`-separated segments,
/// each 1 to 63 bytes of `[a-z0-9-]` starting with a letter or digit;
/// 255 bytes at most.
#[must_use]
pub fn is_route(route: &str) -> bool {
    if route == CATCH_ALL_ROUTE {
        return true;
    }
    let segments = route.split('/').count();
    route.len() <= MAX_ROUTE_LEN
        && segments <= MAX_ROUTE_SEGMENTS
        && route.split('/').all(is_route_segment)
}

fn is_route_segment(seg: &str) -> bool {
    let b = seg.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_SEGMENT_LEN
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// A lowercase DNS name: dot-separated labels of 1 to 63 bytes of
/// `[a-z0-9-]` that neither start nor end with `-`, 253 bytes at most, no
/// trailing dot. A leading `*.` matches one or more labels and needs at
/// least two labels after it.
#[must_use]
pub fn is_domain(domain: &str) -> bool {
    match domain.strip_prefix("*.") {
        Some(rest) => rest.split('.').count() >= 2 && is_hostname(rest),
        None => is_hostname(domain),
    }
}

fn is_hostname(name: &str) -> bool {
    name.len() <= MAX_DOMAIN_LEN && name.split('.').all(is_label)
}

fn is_label(label: &str) -> bool {
    let b = label.as_bytes();
    (1..=MAX_SEGMENT_LEN).contains(&b.len())
        && b.first() != Some(&b'-')
        && b.last() != Some(&b'-')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// A SPIFFE ID as the SPIFFE ID specification defines it, with a
/// non-empty workload path: `spiffe://<trust-domain>/<path>`, the trust
/// domain lowercase `[a-z0-9.-_]`, path segments `[A-Za-z0-9.-_]` and
/// never `.` or `..`, 2048 bytes at most.
#[must_use]
pub fn is_spiffe_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("spiffe://") else {
        return false;
    };
    let Some((domain, path)) = rest.split_once('/') else {
        return false;
    };
    id.len() <= MAX_SPIFFE_ID_LEN && is_trust_domain(domain) && path.split('/').all(is_path_segment)
}

fn is_trust_domain(d: &str) -> bool {
    !d.is_empty()
        && d.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'-' | b'_')
        })
}

fn is_path_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg != "."
        && seg != ".."
        && seg
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_claims() {
        for ok in [
            "mcp",
            "mcp/payments",
            "a/b/c/d/e/f/g/h",
            "0x-1",
            &"a".repeat(63),
        ] {
            assert!(is_route(ok), "{ok}");
        }
        let long = ["abc"; 64].join("/");
        let too_long = format!("{}/{}", "a".repeat(63), "b".repeat(200));
        for bad in [
            "",
            "/",
            "mcp/",
            "/mcp",
            "mcp//x",
            "MCP",
            "-mcp",
            "mcp/pay ments",
            "a/b/c/d/e/f/g/h/i",
            &"a".repeat(64),
            &long,
            &too_long,
            "mcp/é",
        ] {
            assert!(!is_route(bad), "{bad}");
        }
    }

    #[test]
    fn spiffe_ids() {
        for ok in [
            "spiffe://example.org/ns/prod/sa/payments",
            "spiffe://a/b",
            "spiffe://t-d_1.x/A.b-c_D",
        ] {
            assert!(is_spiffe_id(ok), "{ok}");
        }
        let long = format!("spiffe://example.org/{}", "a".repeat(2048));
        for bad in [
            "",
            "spiffe://",
            "spiffe://example.org",
            "spiffe://example.org/",
            "spiffe://Example.org/x",
            "spiffe://example.org/a//b",
            "spiffe://example.org/./x",
            "spiffe://example.org/../x",
            "spiffe://example.org/x?q",
            "spiffe://user@example.org/x",
            "spiffe://example.org:443/x",
            "https://example.org/x",
            "SPIFFE://example.org/x",
            &long,
        ] {
            assert!(!is_spiffe_id(bad), "{bad}");
        }
    }

    #[test]
    fn catch_all_route() {
        assert!(is_route("*"));
        for bad in ["*/x", "mcp/*", "**", "* "] {
            assert!(!is_route(bad), "{bad}");
        }
    }

    #[test]
    fn domains() {
        let label63 = "a".repeat(63);
        let long_ok = [label63.as_str(); 3].join(".") + "." + &"b".repeat(61);
        for ok in [
            "localhost",
            "mcp.example.org",
            "*.example.org",
            "a-1.b2.c",
            long_ok.as_str(),
        ] {
            assert!(is_domain(ok), "{ok}");
        }
        let too_long = long_ok.clone() + "c";
        let label64 = "a".repeat(64) + ".org";
        for bad in [
            "",
            ".",
            "example.org.",
            ".example.org",
            "Example.org",
            "-a.org",
            "a-.org",
            "a..org",
            "*.org",
            "*",
            "a.*.org",
            "*.*.org",
            "x*.example.org",
            "exa mple.org",
            "é.org",
            "example.org:443",
            too_long.as_str(),
            label64.as_str(),
        ] {
            assert!(!is_domain(bad), "{bad}");
        }
    }

    #[test]
    fn duplicates() {
        let r = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(has_no_duplicates(&r(&["a", "b"])));
        assert!(!has_no_duplicates(&r(&["a", "b", "a"])));
    }
}
