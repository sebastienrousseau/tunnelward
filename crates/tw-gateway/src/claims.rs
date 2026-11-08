// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Whether a registration's claims fit beside what the gateway already
//! holds: the domain cap, route ownership (FR-3) and the routes one
//! identity may claim. The registry calls [`check`] under its lock, with
//! every connection, kept route and admission in progress.

use std::collections::HashSet;

use tunnelward_proto::{Register, RejectCode};

use crate::RouteOwner;

/// What one connection, kept route or admission in progress holds.
pub(crate) struct Holding<'a> {
    pub(crate) spiffe_id: &'a str,
    pub(crate) routes: &'a [String],
    pub(crate) domains: &'a [String],
    /// Connected or being admitted; kept routes are not live.
    pub(crate) live: bool,
}

/// The limits and owners a claim is checked against.
pub(crate) struct Rules<'a> {
    pub(crate) max_domains: u32,
    pub(crate) max_routes_per_identity: u16,
    pub(crate) owners: &'a [RouteOwner],
}

/// A refusal: its code and the reason sent with it.
pub(crate) type Refusal = (RejectCode, String);

/// `Ok` when `claim` fits beside `held` under `rules`.
pub(crate) fn check(
    held: &[Holding<'_>],
    claim: &Register,
    rules: &Rules<'_>,
) -> Result<(), Refusal> {
    owned_elsewhere(held, claim, rules.owners)?;
    routes_per_identity(held, claim, rules.max_routes_per_identity)?;
    domains_per_gateway(held, claim, rules.max_domains)
}

/// Refuses a route that a configured owner list or another identity's
/// holding (live or kept) gives to someone else.
fn owned_elsewhere(
    held: &[Holding<'_>],
    claim: &Register,
    owners: &[RouteOwner],
) -> Result<(), Refusal> {
    let me = claim.spiffe_id.as_str();
    for route in &claim.routes {
        let allowed = match owners.iter().find(|o| &o.route == route) {
            Some(owner) => owner.identities.iter().any(|id| id == me),
            None => !held
                .iter()
                .any(|h| h.spiffe_id != me && h.routes.contains(route)),
        };
        if !allowed {
            let reason = format!("route {route:?} belongs to another identity");
            return Err((RejectCode::RouteOwned, reason));
        }
    }
    Ok(())
}

/// Refuses a claim that takes its identity past `max` distinct routes
/// across its live connections.
fn routes_per_identity(held: &[Holding<'_>], claim: &Register, max: u16) -> Result<(), Refusal> {
    let me = claim.spiffe_id.as_str();
    let mut routes: HashSet<&str> = held
        .iter()
        .filter(|h| h.live && h.spiffe_id == me)
        .flat_map(|h| h.routes.iter().map(String::as_str))
        .collect();
    routes.extend(claim.routes.iter().map(String::as_str));
    if routes.len() > usize::from(max) {
        let reason = format!(
            "{me} would claim {} routes; the limit is {max}",
            routes.len()
        );
        return Err((RejectCode::Invalid, reason));
    }
    Ok(())
}

/// Refuses a claim that takes the gateway past `max` distinct domains,
/// kept routes included.
fn domains_per_gateway(held: &[Holding<'_>], claim: &Register, max: u32) -> Result<(), Refusal> {
    let mut domains: HashSet<&str> = held
        .iter()
        .flat_map(|h| h.domains.iter().map(String::as_str))
        .collect();
    domains.extend(claim.domains.iter().map(String::as_str));
    if domains.len() > usize::try_from(max).unwrap_or(usize::MAX) {
        let reason = format!("the gateway already serves its maximum of {max} domains");
        return Err((RejectCode::Overloaded, reason));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelward_proto::{ConnectorId, PROTOCOL_VERSION};

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn claim(id: &str, routes: &[&str], domains: &[&str]) -> Register {
        Register {
            version: PROTOCOL_VERSION,
            connector_id: ConnectorId([0; 16]),
            spiffe_id: id.to_owned(),
            routes: strings(routes),
            domains: strings(domains),
            mcp: None,
            attestation: None,
            capacity: 1,
        }
    }

    const RULES: Rules<'static> = Rules {
        max_domains: 2,
        max_routes_per_identity: 2,
        owners: &[],
    };

    #[test]
    fn a_kept_route_counts_for_ownership_but_not_for_the_route_limit() {
        let (routes, none) = (strings(&["a", "b"]), Vec::new());
        let kept = [Holding {
            spiffe_id: "spiffe://x/a",
            routes: &routes,
            domains: &none,
            live: false,
        }];
        let rival = claim("spiffe://x/b", &["a"], &[]);
        assert_eq!(
            check(&kept, &rival, &RULES).map_err(|e| e.0),
            Err(RejectCode::RouteOwned)
        );
        let same = claim("spiffe://x/a", &["c", "d"], &[]);
        assert_eq!(
            check(&kept, &same, &RULES),
            Ok(()),
            "kept routes do not count"
        );
    }

    #[test]
    fn ownership_is_checked_before_the_limits() {
        let routes = strings(&["a"]);
        let domains = strings(&["a.example", "b.example"]);
        let live = [Holding {
            spiffe_id: "spiffe://x/a",
            routes: &routes,
            domains: &domains,
            live: true,
        }];
        let both = claim("spiffe://x/b", &["a"], &["c.example"]);
        assert_eq!(
            check(&live, &both, &RULES).map_err(|e| e.0),
            Err(RejectCode::RouteOwned)
        );
    }
}
