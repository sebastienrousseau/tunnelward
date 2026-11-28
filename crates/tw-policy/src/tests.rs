// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Unit tests for the rules engine.

use super::*;

fn call(tool: &'static str, evidence: Evidence) -> Call<'static> {
    Call {
        agent: Some("claude"),
        provider: Some("anthropic"),
        path: "/mcp/payments",
        method: "tools/call",
        tool: Some(tool),
        evidence,
        mismatch: false,
        risk: 0,
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
fn a_rule_can_forbid_calls_whose_claims_do_not_hold() {
    let forbid = Rule {
        mismatch: Some(true),
        ..Rule::any(Effect::Forbid)
    };
    let p = policy(vec![permit(&["*"]), forbid]);
    let honest = call("read", Evidence::Network);
    let dressed_up = Call {
        mismatch: true,
        ..honest.clone()
    };
    assert!(matches!(p.decide(&honest), Decision::Allow { .. }));
    assert_eq!(
        p.decide(&dressed_up),
        Decision::Deny("forbidden by rule 2".into())
    );
}

#[test]
fn a_rule_can_forbid_risky_calls() {
    let forbid = Rule {
        risk: Some(70),
        ..Rule::any(Effect::Forbid)
    };
    let p = policy(vec![permit(&["*"]), forbid]);
    let calm = Call {
        risk: 69,
        ..call("read", Evidence::Network)
    };
    let risky = Call {
        risk: 70,
        ..calm.clone()
    };
    assert!(matches!(p.decide(&calm), Decision::Allow { .. }));
    assert_eq!(
        p.decide(&risky),
        Decision::Deny("forbidden by rule 2".into())
    );
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

#[test]
fn shadow_paths_cover_themselves_and_below_and_high_impact_stays_known() {
    let p = Policy {
        shadow: vec!["/mcp/payments".into()],
        high_impact: vec!["transfer".into()],
        ..policy(Vec::new())
    };
    let on = call("transfer", Evidence::Network);
    let below = Call {
        path: "/mcp/payments/eu",
        ..on.clone()
    };
    let beside = Call {
        path: "/mcp/paymentsx",
        ..on.clone()
    };
    assert!(p.shadowed(&on) && p.shadowed(&below));
    assert!(!p.shadowed(&beside), "on a / boundary");
    assert!(
        matches!(p.decide(&on), Decision::Deny(_)),
        "the decision is unchanged"
    );
    assert!(p.high_impact(&on));
    assert!(!p.high_impact(&call("read", Evidence::Network)));
    assert!(!Policy::deny_by_default().shadowed(&on));
}
