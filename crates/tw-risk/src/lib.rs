// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Tunnelward risk signals (FR-16, ADR 0011): a score from 0 to 100 for
//! each request, from four signals that need no IP data.
//!
//! - **Velocity**: calls per subject, per tool and per IP prefix in a
//!   window, each against its own limit. The counts come from the caller
//!   (the gateway counts them in its shared store, so they hold across
//!   gateways); a count the store could not give is skipped.
//! - **Drift**: after a warm-up, a step from one tool to another the
//!   subject has never taken; it stays on the subject for the window.
//! - **Canary tools**: a call to a tool no legitimate agent uses.
//! - **Canary records**: a request body holding a planted value.
//!
//! A canary scores 100 and blocks the subject and its MCP session for
//! [`Settings::block`].
//!
//! ```
//! use tunnelward_risk::{Counts, Request, Risk, Settings};
//!
//! let risk = Risk::new(Settings {
//!     canary_tools: vec!["export_all_customers".into()],
//!     ..Settings::default()
//! });
//! let tools = ["export_all_customers".to_owned()];
//! let request = Request { subject: "agent-7", session: Some("s1"), tools: &tools, body: b"{}" };
//! let assessment = risk.assess(&request, &Counts::default());
//! assert_eq!(assessment.score, 100);
//! assert!(risk.blocked("agent-7", None, std::time::Instant::now()));
//! ```

mod baseline;
mod blocks;
mod settings;
mod signal;

use std::net::IpAddr;
use std::time::Instant;

use aws_lc_rs::digest::{SHA256, digest};

pub use settings::Settings;
pub use signal::{Assessment, Scope, Signal};

use baseline::{Baselines, Bounds};
use blocks::Blocks;

/// One request, as the score sees it.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// Who sent it: the OAuth client id, else the client address.
    pub subject: &'a str,
    /// Its MCP session, if it named one.
    pub session: Option<&'a str>,
    /// The tools it calls, in order.
    pub tools: &'a [String],
    /// Its body, or as much of it as is searched for canary records.
    pub body: &'a [u8],
}

/// Velocity counts for one request, this request included; `None` where
/// the store could not count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    /// Calls by the subject.
    pub subject: Option<u64>,
    /// Calls by the subject to each tool the request calls, in order.
    pub tools: Vec<Option<u64>>,
    /// Calls from the client's IP prefix.
    pub prefix: Option<u64>,
}

/// The score's settings, baselines and blocks for one gateway.
#[derive(Debug, Default)]
pub struct Risk {
    settings: Settings,
    baselines: Baselines,
    blocks: Blocks,
}

impl Risk {
    /// A score with `settings` and nothing learnt yet.
    #[must_use]
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            ..Self::default()
        }
    }

    /// The settings.
    #[must_use]
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Whether a canary has blocked `subject` or `session` at `now`.
    #[must_use]
    pub fn blocked(&self, subject: &str, session: Option<&str>, now: Instant) -> bool {
        self.blocks.is_blocked(&block_key("subject", subject), now)
            || session.is_some_and(|s| self.blocks.is_blocked(&block_key("session", s), now))
    }

    /// Scores `request` with its velocity `counts`, learning its steps;
    /// a canary blocks its subject and session.
    #[must_use]
    pub fn assess(&self, request: &Request<'_>, counts: &Counts) -> Assessment {
        let mut assessment = Assessment::default();
        self.velocity(counts, &mut assessment);
        self.drift(request, &mut assessment);
        self.canaries(request, &mut assessment);
        if assessment.canary() {
            self.block(request);
        }
        assessment
    }

    fn velocity(&self, counts: &Counts, assessment: &mut Assessment) {
        let s = &self.settings;
        let limits = [
            (Scope::Subject, counts.subject, s.per_subject),
            (Scope::Prefix, counts.prefix, s.per_prefix),
        ];
        let tools = counts.tools.iter().map(|c| (Scope::Tool, *c, s.per_tool));
        // One signal per scope, however many tools crossed theirs.
        let mut seen_tool = false;
        for (scope, count, limit) in limits.into_iter().chain(tools) {
            let Some(count) = count.filter(|c| *c > limit) else {
                continue;
            };
            if scope == Scope::Tool && std::mem::replace(&mut seen_tool, true) {
                continue;
            }
            let signal = Signal::Velocity {
                scope,
                count,
                limit,
            };
            assessment.add(signal, s.velocity_weight);
        }
    }

    fn drift(&self, request: &Request<'_>, assessment: &mut Assessment) {
        let s = &self.settings;
        let bounds = Bounds {
            warmup: s.warmup,
            max_steps: s.max_steps,
            max_subjects: s.max_subjects,
        };
        let mut drifted = None;
        for tool in request.tools {
            let step = self.baselines.step(request.subject, tool, &bounds);
            if let (Some(from), None) = (step, &drifted) {
                drifted = Some((from, tool.clone()));
            }
        }
        // A drift stays on the subject for the window: the calls after a
        // switch to new behaviour are as suspect as the switch.
        let drifted = drifted.or_else(|| self.baselines.recent(request.subject, s.window));
        if let Some((from, to)) = drifted {
            assessment.add(Signal::Drift { from, to }, s.drift_weight);
        }
    }

    fn canaries(&self, request: &Request<'_>, assessment: &mut Assessment) {
        let s = &self.settings;
        let tool = (request.tools.iter()).find(|t| s.canary_tools.contains(t));
        if let Some(tool) = tool {
            assessment.add(Signal::CanaryTool(tool.clone()), 100);
        }
        let planted = (s.canary_records.iter()).any(|r| contains(request.body, r.as_bytes()));
        if planted {
            assessment.add(Signal::CanaryRecord, 100);
        }
    }

    fn block(&self, request: &Request<'_>) {
        let s = &self.settings;
        let until = Instant::now() + s.block;
        let subject = block_key("subject", request.subject);
        self.blocks.block(subject, until, s.max_blocked);
        if let Some(session) = request.session {
            self.blocks
                .block(block_key("session", session), until, s.max_blocked);
        }
    }
}

fn block_key(kind: &str, value: &str) -> String {
    format!("{kind}:{value}")
}

/// The shared-store key velocity counts `value` of `kind` under: a
/// SHA-256 digest, so no address is stored in the clear.
#[must_use]
pub fn key(kind: &str, value: &str) -> String {
    let sum = digest(&SHA256, format!("{kind}\n{value}").as_bytes());
    format!("tw:risk:{kind}:{}", tunnelward_audit::hex(sum.as_ref()))
}

/// `ip`'s prefix for velocity: the /24 of an IPv4 address, the /48 of
/// an IPv6 one (an IPv4-mapped address counts as IPv4).
#[must_use]
pub fn prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
            || {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            },
            |v4| prefix(IpAddr::V4(v4)),
        ),
    }
}

/// Whether `needle` occurs in `haystack`; an empty needle never does.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_and_keys() {
        assert_eq!(prefix("192.0.2.77".parse().unwrap()), "192.0.2.0/24");
        assert_eq!(
            prefix("2001:db8:1:2::9".parse().unwrap()),
            "2001:db8:1::/48"
        );
        assert_eq!(prefix("::ffff:192.0.2.1".parse().unwrap()), "192.0.2.0/24");
        let k = key("prefix", "192.0.2.0/24");
        assert!(k.starts_with("tw:risk:prefix:") && !k.contains("192.0.2"));
        assert_ne!(key("subject", "a"), key("tool", "a"));
    }

    #[test]
    fn contains_finds_and_misses() {
        assert!(contains(b"{\"q\":\"CANARY-77\"}", b"CANARY-77"));
        assert!(!contains(b"CANARY-7", b"CANARY-77"));
        assert!(!contains(b"anything", b""));
    }
}
