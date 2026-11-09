// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Tunnelward per-tool policy (FR-4): which agent may make which MCP call
//! on which route, given how well the gateway knows who sent it (FR-14).
//!
//! A [`Policy`] is a list of [`Rule`]s, each permitting or forbidding the
//! calls it matches. A forbid that matches wins; otherwise a permit that
//! matches allows the call; otherwise the policy's default applies.
//! Before any rule, the D6 baseline applies: every call needs at least a
//! provider-range match or a valid token, and a tool marked high impact
//! needs cryptographic evidence.
//!
//! The engine is behind [`PolicyEngine`], so another one (Cedar, once its
//! dependencies are audited) can stand in without the gateway changing.

/// How a call's sender is known, weakest first (FR-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Evidence {
    /// Only what the client says about itself: `User-Agent`, MCP
    /// `clientInfo`.
    Declared,
    /// What the gateway's own socket saw, checked against published
    /// data: the client address inside a provider's egress range.
    Network,
    /// Signed or key-bound: a `DPoP`- or certificate-bound token, a
    /// verified Web Bot Auth signature. Forging it needs a stolen key.
    Cryptographic,
}

impl Evidence {
    /// The level named `name`: `declared`, `network` or `cryptographic`.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        match name {
            "declared" => Some(Self::Declared),
            "network" => Some(Self::Network),
            "cryptographic" => Some(Self::Cryptographic),
            _ => None,
        }
    }

    /// The level's name, as [`Evidence::named`] reads it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Network => "network",
            Self::Cryptographic => "cryptographic",
        }
    }
}

/// One call, as the gateway sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call<'a> {
    /// The agent's `client_id` from a valid token, if it presented one.
    pub agent: Option<&'a str>,
    /// The provider the request was tagged with, if any.
    pub provider: Option<&'a str>,
    /// The request path.
    pub path: &'a str,
    /// The JSON-RPC method (`tools/call`), or `http:<METHOD>` for a
    /// request that is not JSON-RPC.
    pub method: &'a str,
    /// The tool, for `tools/call`.
    pub tool: Option<&'a str>,
    /// How well the sender is known.
    pub evidence: Evidence,
}

/// What a rule does to the calls it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Allow, unless a forbid also matches.
    Permit,
    /// Deny, whatever else matches.
    Forbid,
}

/// One rule. An empty list matches anything; a pattern is exact, `*`, or
/// ends in `*` to match a prefix. Paths match on a `/` boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// What the rule does.
    pub effect: Effect,
    /// Agents' `client_id`s; a call with no token matches only an empty
    /// list or `*`.
    pub agents: Vec<String>,
    /// Provider tags.
    pub providers: Vec<String>,
    /// Paths: each covers itself and everything under it.
    pub paths: Vec<String>,
    /// JSON-RPC methods.
    pub methods: Vec<String>,
    /// Tool names.
    pub tools: Vec<String>,
    /// The least evidence a call needs for the rule to match.
    pub evidence: Option<Evidence>,
}

impl Rule {
    /// A rule with `effect` that matches every call.
    #[must_use]
    pub fn any(effect: Effect) -> Self {
        Self {
            effect,
            agents: Vec::new(),
            providers: Vec::new(),
            paths: Vec::new(),
            methods: Vec::new(),
            tools: Vec::new(),
            evidence: None,
        }
    }

    /// Whether the rule covers `call`.
    #[must_use]
    pub fn matches(&self, call: &Call<'_>) -> bool {
        any_of(&self.agents, call.agent, glob)
            && any_of(&self.providers, call.provider, glob)
            && any_of(&self.paths, Some(call.path), covers)
            && any_of(&self.methods, Some(call.method), glob)
            && any_of(&self.tools, call.tool, glob)
            && self.evidence.is_none_or(|least| call.evidence >= least)
    }
}

/// Whether `patterns` (empty: anything) let `value` through. A missing
/// value passes only an empty list or `*`.
fn any_of(patterns: &[String], value: Option<&str>, test: fn(&str, &str) -> bool) -> bool {
    patterns.is_empty()
        || patterns
            .iter()
            .any(|p| p == "*" || value.is_some_and(|v| test(p, v)))
}

/// `pattern` is exact, or ends in `*` for a prefix.
fn glob(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}

/// `base` covers `path` and everything under it on a `/` boundary.
fn covers(base: &str, path: &str) -> bool {
    let base = base.trim_end_matches('/');
    base.is_empty()
        || path == base
        || path
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// A decision and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The call may proceed. `high_impact` says it needs an idempotency
    /// key (FR-13).
    Allow {
        /// The tool is marked high impact.
        high_impact: bool,
    },
    /// The call is refused, with a sentence saying why.
    Deny(String),
}

/// Decides calls.
pub trait PolicyEngine: Send + Sync + std::fmt::Debug {
    /// The decision for `call`.
    fn decide(&self, call: &Call<'_>) -> Decision;
}

/// The in-house rules engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The rules, in any order: forbid wins.
    pub rules: Vec<Rule>,
    /// What applies when no rule matches.
    pub default: Effect,
    /// Tools marked high impact (patterns as in [`Rule`]): they need
    /// cryptographic evidence and an idempotency key.
    pub high_impact: Vec<String>,
    /// Apply the D6 baseline before the rules.
    pub baseline: bool,
}

impl Policy {
    /// No rules, deny by default, the D6 baseline on.
    #[must_use]
    pub fn deny_by_default() -> Self {
        Self {
            rules: Vec::new(),
            default: Effect::Forbid,
            high_impact: Vec::new(),
            baseline: true,
        }
    }

    fn is_high_impact(&self, call: &Call<'_>) -> bool {
        call.tool
            .is_some_and(|t| self.high_impact.iter().any(|p| glob(p, t)))
    }

    /// The D6 baseline: why `call` falls short of it, if it does.
    fn below_baseline(&self, call: &Call<'_>, high_impact: bool) -> Option<String> {
        if !self.baseline {
            return None;
        }
        if call.evidence < Evidence::Network && call.agent.is_none() {
            return Some(
                "the call has neither a valid token nor a provider-range match (D6)".into(),
            );
        }
        (high_impact && call.evidence < Evidence::Cryptographic).then(|| {
            format!(
                "the tool is high impact and needs cryptographic evidence; the call has {} (D6)",
                call.evidence.name()
            )
        })
    }
}

impl PolicyEngine for Policy {
    fn decide(&self, call: &Call<'_>) -> Decision {
        let high_impact = self.is_high_impact(call);
        if let Some(why) = self.below_baseline(call, high_impact) {
            return Decision::Deny(why);
        }
        let matching = |effect| {
            self.rules
                .iter()
                .position(|r| r.effect == effect && r.matches(call))
        };
        if let Some(i) = matching(Effect::Forbid) {
            return Decision::Deny(format!("forbidden by rule {}", i + 1));
        }
        if matching(Effect::Permit).is_some() || self.default == Effect::Permit {
            return Decision::Allow { high_impact };
        }
        Decision::Deny("no rule permits the call".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(tool: &'static str, evidence: Evidence) -> Call<'static> {
        Call {
            agent: Some("claude"),
            provider: Some("anthropic"),
            path: "/mcp/payments",
            method: "tools/call",
            tool: Some(tool),
            evidence,
        }
    }

    fn permit(tools: &[&str]) -> Rule {
        Rule {
            tools: tools.iter().map(|t| (*t).to_owned()).collect(),
            ..Rule::any(Effect::Permit)
        }
    }

    fn policy(rules: Vec<Rule>) -> Policy {
        Policy {
            rules,
            ..Policy::deny_by_default()
        }
    }

    #[test]
    fn a_permit_allows_and_nothing_else_does_by_default() {
        let p = policy(vec![permit(&["refund"])]);
        assert_eq!(
            p.decide(&call("refund", Evidence::Network)),
            Decision::Allow { high_impact: false }
        );
        assert_eq!(
            p.decide(&call("transfer", Evidence::Network)),
            Decision::Deny("no rule permits the call".into())
        );
    }

    #[test]
    fn a_forbid_wins_over_any_permit() {
        let forbid = Rule {
            tools: vec!["delete_*".into()],
            ..Rule::any(Effect::Forbid)
        };
        let p = policy(vec![permit(&["*"]), forbid]);
        assert_eq!(
            p.decide(&call("delete_account", Evidence::Cryptographic)),
            Decision::Deny("forbidden by rule 2".into())
        );
        assert!(matches!(
            p.decide(&call("read", Evidence::Network)),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn a_rule_can_demand_cryptographic_evidence() {
        let strict = Rule {
            evidence: Some(Evidence::Cryptographic),
            ..permit(&["transfer"])
        };
        let p = policy(vec![strict]);
        assert!(matches!(
            p.decide(&call("transfer", Evidence::Cryptographic)),
            Decision::Allow { .. }
        ));
        assert!(
            matches!(
                p.decide(&call("transfer", Evidence::Network)),
                Decision::Deny(_)
            ),
            "FR-14: the same call from a network-verified client"
        );
    }

    #[test]
    fn the_d6_baseline_comes_first() {
        let mut p = policy(vec![permit(&["*"])]);
        p.high_impact = vec!["transfer".into()];
        let anonymous = Call {
            agent: None,
            ..call("read", Evidence::Declared)
        };
        assert!(matches!(p.decide(&anonymous), Decision::Deny(why) if why.contains("D6")));
        let with_token = Call {
            agent: Some("claude"),
            ..anonymous.clone()
        };
        assert!(matches!(p.decide(&with_token), Decision::Allow { .. }));
        assert!(matches!(
            p.decide(&call("transfer", Evidence::Network)),
            Decision::Deny(why) if why.contains("high impact")
        ));
        assert_eq!(
            p.decide(&call("transfer", Evidence::Cryptographic)),
            Decision::Allow { high_impact: true }
        );
        p.baseline = false;
        assert!(matches!(p.decide(&anonymous), Decision::Allow { .. }));
    }

    #[test]
    fn patterns_paths_and_missing_values() {
        let scoped = Rule {
            agents: vec!["claude".into()],
            paths: vec!["/mcp".into()],
            methods: vec!["tools/*".into()],
            ..Rule::any(Effect::Permit)
        };
        assert!(scoped.matches(&call("x", Evidence::Network)));
        let elsewhere = Call {
            path: "/mcpx",
            ..call("x", Evidence::Network)
        };
        assert!(!scoped.matches(&elsewhere), "paths match on a / boundary");
        let no_agent = Call {
            agent: None,
            ..call("x", Evidence::Network)
        };
        assert!(!scoped.matches(&no_agent));
        let anyone = Rule {
            agents: vec!["*".into()],
            ..Rule::any(Effect::Permit)
        };
        assert!(anyone.matches(&no_agent), "* matches a missing value");
    }

    #[test]
    fn evidence_orders_and_names_round_trip() {
        assert!(Evidence::Declared < Evidence::Network);
        assert!(Evidence::Network < Evidence::Cryptographic);
        for e in [
            Evidence::Declared,
            Evidence::Network,
            Evidence::Cryptographic,
        ] {
            assert_eq!(Evidence::named(e.name()), Some(e));
        }
        assert_eq!(Evidence::named("strong"), None);
    }
}
