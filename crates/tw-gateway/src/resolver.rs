// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Which route claim serves a request (G3).

use core::fmt;

use crate::route::{domain_matches, route_score};

/// What routing looks at: the host, lowercased without its port, and the
/// path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The request's host, if it has one.
    pub host: Option<String>,
    /// The request's path.
    pub path: String,
}

/// Ranks route claims for a request. Every connector whose claim has the
/// highest rank forms the pool the request is sent to.
pub trait RouteResolver: fmt::Debug + Send + Sync {
    /// The rank of a connector claiming `route` on `domains` for
    /// `target`: `None` when the claim does not serve it, otherwise
    /// higher is better.
    fn rank(&self, route: &str, domains: &[String], target: &Target) -> Option<u32>;
}

/// The default: the claim's domains must match (none means any host),
/// then the longest route on a `/` boundary wins, and the catch-all `*`
/// ranks lowest.
#[derive(Debug, Clone, Copy, Default)]
pub struct LongestFirst;

impl RouteResolver for LongestFirst {
    fn rank(&self, route: &str, domains: &[String], target: &Target) -> Option<u32> {
        if !domain_matches(domains, target.host.as_deref()) {
            return None;
        }
        route_score(route, &target.path).and_then(|s| u32::try_from(s).ok())
    }
}
