// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The tool policy (FR-4): its file, the gateway file's `[policy]`
//! section that names it, and `tunnelward policy test`.
//!
//! ```toml
//! # policy.toml, read again when it changes
//! default = "deny"                  # when no rule matches: deny or allow
//! baseline = true                   # D6: a token or a provider-range match
//!                                   # for every call; cryptographic
//!                                   # evidence for high-impact tools
//! high_impact = ["transfer", "refund*"]   # also need an Idempotency-Key
//!
//! [[rules]]                         # forbid wins over permit
//! effect = "permit"                 # or "forbid"
//! agents = ["claude"]               # client_id; each list optional,
//! providers = ["anthropic"]         # empty or absent matches anything;
//! paths = ["/mcp/payments"]         # a trailing * matches a prefix
//! methods = ["tools/call"]          # http:GET for plain requests
//! tools = ["read_*"]
//! evidence = "network"              # least: declared, network, cryptographic
//! ```
//!
//! ```toml
//! # the gateway file
//! [policy]
//! file = "policy.toml"
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;
use tunnelward_policy::{Call, Decision, Effect, Evidence, Policy, PolicyEngine, Rule};

use crate::config::{Problems, resolve};

/// The gateway file's `[policy]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Section {
    file: PathBuf,
}

impl Section {
    /// The policy file, relative to the gateway file's directory `base`.
    pub(crate) fn path(&self, base: &Path) -> PathBuf {
        resolve(base, &self.file)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    default: Option<String>,
    baseline: Option<bool>,
    #[serde(default)]
    high_impact: Vec<String>,
    #[serde(default)]
    rules: Vec<RulePart>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulePart {
    effect: String,
    #[serde(default)]
    agents: Vec<String>,
    #[serde(default)]
    providers: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    tools: Vec<String>,
    evidence: Option<String>,
}

fn effect(name: &str, at: &str, problems: &mut Problems) -> Effect {
    match name {
        "permit" | "allow" => Effect::Permit,
        "forbid" | "deny" => Effect::Forbid,
        other => {
            problems.push(format!("{at}: {other:?}: give permit or forbid"));
            Effect::Forbid
        }
    }
}

fn evidence(name: &str, at: &str, problems: &mut Problems) -> Option<Evidence> {
    let level = Evidence::named(name);
    if level.is_none() {
        problems.push(format!(
            "{at} evidence {name:?}: give declared, network or cryptographic"
        ));
    }
    level
}

fn rule(part: &RulePart, at: &str, problems: &mut Problems) -> Rule {
    let bad_paths = part
        .paths
        .iter()
        .filter(|p| !p.starts_with('/') && *p != "*");
    problems.extend(bad_paths.map(|p| format!("{at} paths: {p:?}: start it with /")));
    Rule {
        effect: effect(&part.effect, at, problems),
        agents: part.agents.clone(),
        providers: part.providers.clone(),
        paths: part.paths.clone(),
        methods: part.methods.clone(),
        tools: part.tools.clone(),
        evidence: part
            .evidence
            .as_deref()
            .and_then(|e| evidence(e, at, problems)),
    }
}

fn read(path: &Path) -> Result<File, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The policy in the file at `path`, or every problem with it.
pub(crate) fn load(path: &Path) -> Result<Policy, Problems> {
    let file = read(path).map_err(|e| vec![e])?;
    let mut problems = Problems::new();
    let at = path.display().to_string();
    let default = file.default.as_deref().map_or(Effect::Forbid, |d| {
        effect(d, &format!("{at} default"), &mut problems)
    });
    let rules = file
        .rules
        .iter()
        .enumerate()
        .map(|(i, r)| rule(r, &format!("{at} rule {}", i + 1), &mut problems))
        .collect();
    let policy = Policy {
        rules,
        default,
        high_impact: file.high_impact,
        baseline: file.baseline.unwrap_or(true),
    };
    problems.is_empty().then_some(policy).ok_or(problems)
}

/// Checks the gateway file's `[policy]`; every problem goes to `problems`.
pub(crate) fn check(base: &Path, section: &Section, problems: &mut Problems) -> Option<Policy> {
    load(&section.path(base))
        .map_err(|p| problems.extend(p))
        .ok()
}

/// One case in a `tunnelward policy test` file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    agent: Option<String>,
    provider: Option<String>,
    path: String,
    method: String,
    tool: Option<String>,
    evidence: String,
    expect: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cases {
    #[serde(rename = "case")]
    cases: Vec<Case>,
}

/// The outcome of one case: a line to print, and whether it passed.
fn run_case(policy: &Policy, case: &Case) -> (String, bool) {
    let Some(level) = Evidence::named(&case.evidence) else {
        return (
            format!(
                "FAIL {}: evidence {:?} is not a level",
                case.name, case.evidence
            ),
            false,
        );
    };
    let call = Call {
        agent: case.agent.as_deref(),
        provider: case.provider.as_deref(),
        path: &case.path,
        method: &case.method,
        tool: case.tool.as_deref(),
        evidence: level,
    };
    let (got, why) = match policy.decide(&call) {
        Decision::Allow { high_impact: true } => ("allow", "high impact".to_owned()),
        Decision::Allow { .. } => ("allow", String::new()),
        Decision::Deny(why) => ("deny", why),
    };
    if got == case.expect {
        (format!("ok   {}", case.name), true)
    } else {
        let line = format!(
            "FAIL {}: expected {}, got {got} ({why})",
            case.name, case.expect
        );
        (line, false)
    }
}

/// `tunnelward policy test`: runs the cases in `cases` against the
/// policy in `policy`; the report, and whether every case passed.
pub(crate) fn test(policy: &Path, cases: &Path) -> Result<(String, bool), String> {
    let policy = load(policy).map_err(|p| p.join("\n"))?;
    let text = std::fs::read_to_string(cases).map_err(|e| format!("{}: {e}", cases.display()))?;
    let cases: Cases = toml::from_str(&text).map_err(|e| format!("{}: {e}", cases.display()))?;
    let outcomes: Vec<(String, bool)> = cases.cases.iter().map(|c| run_case(&policy, c)).collect();
    let failed = outcomes.iter().filter(|(_, ok)| !ok).count();
    let mut report: Vec<String> = outcomes.into_iter().map(|(line, _)| line).collect();
    report.push(format!("{} cases, {failed} failed", report.len()));
    Ok((report.join("\n"), failed == 0))
}
