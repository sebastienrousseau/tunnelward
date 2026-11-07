// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Who the client is (FR-11, G12).
//!
//! The socket's peer address is the only fact the gateway observes itself.
//! `Forwarded` and `X-Forwarded-For` are believed only as far back as the
//! hops that are trusted proxies: walking from the peer towards the client,
//! the first address outside the trusted ranges is the client. Everything
//! further back is what someone claimed, and is recorded as such.

use std::net::{IpAddr, SocketAddr};

use http::HeaderMap;
use http::header::FORWARDED;

use crate::Cidr;

/// What the gateway knows about a request's origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAddr {
    /// The address the gateway's socket saw (after PROXY protocol, if any).
    pub peer: IpAddr,
    /// The client: the peer, or the first untrusted hop behind trusted proxies.
    pub client: IpAddr,
    /// Addresses claimed beyond the trust boundary, nearest first. Declared
    /// only: never used as the client.
    pub declared: Vec<String>,
}

impl ClientAddr {
    /// Resolves the client from `peer`, the request's forwarding headers,
    /// and the ranges whose addresses are trusted proxies.
    #[must_use]
    pub fn resolve(peer: SocketAddr, headers: &HeaderMap, trusted: &[Cidr]) -> Self {
        let peer = peer.ip().to_canonical();
        let is_trusted = |ip: IpAddr| trusted.iter().any(|range| range.contains(ip));
        // Hops in the order they were added: client first, nearest proxy last.
        let hops = forwarded_hops(headers);
        let mut client = peer;
        let mut rest = hops.iter().rev();
        while is_trusted(client) {
            let Some(hop) = rest.next() else { break };
            match parse_ip(hop) {
                Some(ip) => client = ip,
                None => break,
            }
        }
        let declared = if client == peer && !is_trusted(peer) {
            hops.iter().rev().cloned().collect()
        } else {
            rest.cloned().collect()
        };
        Self {
            peer,
            client,
            declared,
        }
    }
}

/// The `for` addresses of `Forwarded`, or else `X-Forwarded-For`, in order.
fn forwarded_hops(headers: &HeaderMap) -> Vec<String> {
    let forwarded = header_list(headers, FORWARDED.as_str())
        .filter_map(|e| for_value(&e))
        .collect::<Vec<_>>();
    if forwarded.is_empty() {
        header_list(headers, "x-forwarded-for")
            .filter(|hop| !hop.is_empty())
            .collect()
    } else {
        forwarded
    }
}

/// Every comma-separated element of every `name` header, trimmed.
fn header_list<'a>(headers: &'a HeaderMap, name: &str) -> impl Iterator<Item = String> + 'a {
    headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|element| element.trim().to_owned())
}

/// The `for=` value of one `Forwarded` element, unquoted.
fn for_value(element: &str) -> Option<String> {
    element.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("for")
            .then(|| value.trim().trim_matches('"').to_owned())
    })
}

/// An address from a forwarding header: `1.2.3.4`, `1.2.3.4:80`,
/// `[2001:db8::1]`, `[2001:db8::1]:80` or `2001:db8::1`. Obfuscated
/// identifiers (`_hidden`, `unknown`) are not addresses.
fn parse_ip(hop: &str) -> Option<IpAddr> {
    if let Ok(ip) = hop.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    if let Ok(sock) = hop.parse::<SocketAddr>() {
        return Some(sock.ip().to_canonical());
    }
    let inner = hop.strip_prefix('[')?.split(']').next()?;
    inner.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    fn cidrs(list: &[&str]) -> Vec<Cidr> {
        list.iter().filter_map(|c| c.parse().ok()).collect()
    }

    fn peer(s: &str) -> SocketAddr {
        s.parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
    }

    #[test]
    fn an_untrusted_peer_is_the_client_whatever_it_claims() {
        let h = headers(&[("x-forwarded-for", "1.2.3.4, 5.6.7.8")]);
        let c = ClientAddr::resolve(peer("198.51.100.9:443"), &h, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(c.client, ip("198.51.100.9"));
        assert_eq!(c.declared, vec!["5.6.7.8".to_owned(), "1.2.3.4".to_owned()]);
    }

    #[test]
    fn trusted_proxies_are_walked_back_to_the_first_untrusted_hop() {
        let h = headers(&[("x-forwarded-for", "203.0.113.7, 1.2.3.4, 10.0.0.2")]);
        let c = ClientAddr::resolve(peer("10.0.0.1:443"), &h, &cidrs(&["10.0.0.0/8"]));
        // 10.0.0.1 (peer) and 10.0.0.2 are trusted; 1.2.3.4 is not, so it is
        // the client, and 203.0.113.7 is only claimed.
        assert_eq!(c.client, ip("1.2.3.4"));
        assert_eq!(c.declared, vec!["203.0.113.7".to_owned()]);
    }

    #[test]
    fn forwarded_wins_over_x_forwarded_for_and_parses_ports_and_ipv6() {
        let h = headers(&[
            (
                "forwarded",
                "for=\"[2001:db8::7]:4711\";proto=https, for=10.0.0.3",
            ),
            ("x-forwarded-for", "9.9.9.9"),
        ]);
        let c = ClientAddr::resolve(peer("10.0.0.1:443"), &h, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(c.client, ip("2001:db8::7"));
        assert_eq!(c.declared, Vec::<String>::new());
    }

    #[test]
    fn an_unparseable_hop_stops_the_walk_at_the_last_trusted_address() {
        let h = headers(&[("forwarded", "for=_hidden, for=10.0.0.4")]);
        let c = ClientAddr::resolve(peer("10.0.0.1:443"), &h, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(c.client, ip("10.0.0.4"));
    }

    #[test]
    fn a_trusted_peer_with_no_headers_is_itself_the_client() {
        let c = ClientAddr::resolve(
            peer("[::ffff:10.0.0.1]:443"),
            &HeaderMap::new(),
            &cidrs(&["10.0.0.0/8"]),
        );
        assert_eq!(c.client, ip("10.0.0.1"));
        assert_eq!(c.peer, ip("10.0.0.1"));
    }
}
