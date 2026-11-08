// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The forwarding headers a connector sees (G12).
//!
//! Whatever forwarding headers the client sent are removed: the gateway
//! has already resolved the client (FR-11) and states it once, in
//! `Forwarded` and, unless turned off, the legacy `X-Forwarded-*` headers.
//! `Via` gains the gateway's own hop.

use std::fmt::Write as _;
use std::net::IpAddr;

use http::HeaderMap;
use http::header::{FORWARDED, HeaderName, HeaderValue, VIA};

const SPOOFABLE: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
];

/// How the gateway names itself and what it states.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stamp<'a> {
    pub(crate) client: IpAddr,
    pub(crate) proto: &'static str,
    pub(crate) host: Option<&'a str>,
    pub(crate) via: &'a str,
    pub(crate) http_version: &'static str,
    pub(crate) legacy: bool,
}

/// Replaces the forwarding headers in `headers` with `stamp`'s.
pub(crate) fn rewrite(headers: &mut HeaderMap, stamp: &Stamp<'_>) {
    for name in SPOOFABLE {
        headers.remove(*name);
    }
    insert(headers, FORWARDED, &forwarded_value(stamp));
    let via = via_value(headers, stamp);
    insert(headers, VIA, &via);
    if stamp.legacy {
        legacy(headers, stamp);
    }
}

fn forwarded_value(stamp: &Stamp<'_>) -> String {
    let client = match stamp.client {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("\"[{ip}]\""),
    };
    let mut value = format!("for={client};proto={}", stamp.proto);
    if let Some(host) = stamp.host.filter(|h| is_token_safe(h)) {
        let _ = write!(value, ";host=\"{host}\"");
    }
    value
}

/// The client's `Via` chain with the gateway's hop added.
fn via_value(headers: &HeaderMap, stamp: &Stamp<'_>) -> String {
    let hop = format!("{} {}", stamp.http_version, stamp.via);
    match headers.get(VIA).and_then(|v| v.to_str().ok()) {
        Some(existing) => format!("{existing}, {hop}"),
        None => hop,
    }
}

fn legacy(headers: &mut HeaderMap, stamp: &Stamp<'_>) {
    insert(
        headers,
        HeaderName::from_static("x-forwarded-for"),
        &stamp.client.to_string(),
    );
    insert(
        headers,
        HeaderName::from_static("x-forwarded-proto"),
        stamp.proto,
    );
    if let Some(host) = stamp.host {
        insert(headers, HeaderName::from_static("x-forwarded-host"), host);
    }
}

/// A host safe to put in a quoted `Forwarded` value.
fn is_token_safe(host: &str) -> bool {
    host.bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b':' | b'[' | b']'))
}

fn insert(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(client: &str, legacy: bool) -> Stamp<'static> {
        Stamp {
            client: client.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
            proto: "https",
            host: Some("mcp.example.org"),
            via: "tunnelward",
            http_version: "2",
            legacy,
        }
    }

    fn get<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
        h.get(name).and_then(|v| v.to_str().ok())
    }

    #[test]
    fn client_sent_forwarding_headers_are_replaced() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("forwarded", "for=6.6.6.6"),
            ("x-forwarded-for", "6.6.6.6"),
            ("x-real-ip", "6.6.6.6"),
            ("via", "1.1 cdn"),
        ] {
            h.append(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        rewrite(&mut h, &stamp("203.0.113.7", true));
        assert_eq!(
            get(&h, "forwarded"),
            Some("for=203.0.113.7;proto=https;host=\"mcp.example.org\"")
        );
        assert_eq!(get(&h, "x-forwarded-for"), Some("203.0.113.7"));
        assert_eq!(get(&h, "x-forwarded-host"), Some("mcp.example.org"));
        assert_eq!(get(&h, "via"), Some("1.1 cdn, 2 tunnelward"));
        assert_eq!(get(&h, "x-real-ip"), None);
    }

    #[test]
    fn ipv6_is_quoted_and_legacy_headers_can_be_off() {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("6.6.6.6"),
        );
        rewrite(&mut h, &stamp("2001:db8::7", false));
        assert_eq!(
            get(&h, "forwarded"),
            Some("for=\"[2001:db8::7]\";proto=https;host=\"mcp.example.org\"")
        );
        assert_eq!(
            get(&h, "x-forwarded-for"),
            None,
            "the spoofed one is gone and none is added"
        );
    }
}
