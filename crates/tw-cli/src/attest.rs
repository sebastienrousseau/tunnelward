// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Admission by passmcp attestation (FR-5, ADR 0009): the gateway
//! file's `[attestation]` section, and `tunnelward attest verify`.
//!
//! ```toml
//! [attestation]
//! keys = ["passmcp-ci.pub"]         # PEM public keys (cosign.pub): ECDSA
//!                                   # P-256 or Ed25519
//! revoked = "revoked.txt"           # optional: one statement digest per
//!                                   # line; read again when it changes
//!
//! [[attestation.routes]]            # a route that needs a statement
//! route = "mcp/payments"
//! targets = [{ transport = "http", endpoint = "http://127.0.0.1:8080/mcp" }]
//! max_age_days = 30                 # optional, default 30
//! max_fail = 0                      # optional, default 0
//! require = ["auth.unauthenticated_tools"]   # optional: must have passed
//! min_score = 80                    # optional
//! ```

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use tunnelward_attest::{Admission, Attested, Revoked, Rule, Target, TrustedKey};
use tunnelward_proto::is_route;

use crate::config::{Problems, resolve};

/// The gateway file's `[attestation]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Section {
    keys: Vec<PathBuf>,
    revoked: Option<PathBuf>,
    #[serde(default)]
    routes: Vec<RoutePart>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutePart {
    route: String,
    targets: Vec<TargetPart>,
    max_age_days: Option<u32>,
    max_fail: Option<u32>,
    #[serde(default)]
    require: Vec<String>,
    min_score: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetPart {
    transport: String,
    endpoint: String,
}

impl Section {
    /// The key and revocation files, to read again when they change.
    pub(crate) fn paths(&self, base: &Path) -> Vec<PathBuf> {
        let files = self.keys.iter().chain(&self.revoked);
        files.map(|p| resolve(base, p)).collect()
    }
}

/// The admission `section` describes, every problem noted.
pub(crate) fn check(
    base: &Path,
    section: &Section,
    problems: &mut Problems,
) -> Option<Arc<Admission>> {
    let before = problems.len();
    if section.keys.is_empty() {
        problems.push("[attestation] keys: name at least one public key".into());
    }
    let keys: Vec<TrustedKey> = (section.keys.iter())
        .filter_map(|p| note(problems, key(&resolve(base, p))))
        .collect();
    let revoked = match &section.revoked {
        Some(p) => note(problems, revoked(&resolve(base, p))).unwrap_or_default(),
        None => Revoked::default(),
    };
    let rules = rules(&section.routes, problems);
    (problems.len() == before).then(|| Arc::new(Admission::new(keys, rules, revoked)))
}

fn note<T>(problems: &mut Problems, result: Result<T, String>) -> Option<T> {
    result.map_err(|e| problems.push(e)).ok()
}

fn key(path: &Path) -> Result<TrustedKey, String> {
    let pem =
        std::fs::read(path).map_err(|e| format!("[attestation] keys: {}: {e}", path.display()))?;
    TrustedKey::from_pem(&pem).map_err(|e| format!("[attestation] keys: {}: {e}", path.display()))
}

fn revoked(path: &Path) -> Result<Revoked, String> {
    let at = |e: String| format!("[attestation] revoked: {}: {e}", path.display());
    let text = std::fs::read_to_string(path).map_err(|e| at(e.to_string()))?;
    Revoked::parse(&text).map_err(at)
}

/// The `[[attestation.routes]]`, each route named once.
fn rules(parts: &[RoutePart], problems: &mut Problems) -> Vec<Rule> {
    if parts.is_empty() {
        problems.push("[attestation]: add a [[attestation.routes]] entry".into());
    }
    let mut seen = HashSet::new();
    for part in parts {
        if !seen.insert(&part.route) {
            problems.push(format!(
                "[[attestation.routes]] route {:?} is listed twice",
                part.route
            ));
        }
    }
    parts.iter().map(|p| rule(p, problems)).collect()
}

fn rule(part: &RoutePart, problems: &mut Problems) -> Rule {
    rule_problems(part, problems);
    let targets = part.targets.iter().map(|t| Target {
        transport: t.transport.clone(),
        endpoint: t.endpoint.trim().to_owned(),
    });
    let mut rule = Rule::new(part.route.clone(), targets.collect());
    if let Some(days) = part.max_age_days {
        rule.max_age = Duration::from_secs(u64::from(days) * 86_400);
    }
    rule.max_fail = part.max_fail.unwrap_or(0);
    rule.require.clone_from(&part.require);
    rule.min_score = part.min_score;
    rule
}

fn rule_problems(part: &RoutePart, problems: &mut Problems) {
    let at = format!("[[attestation.routes]] route {:?}", part.route);
    if !is_route(&part.route) {
        problems.push(format!("{at} is not a route"));
    }
    if part.targets.is_empty() {
        problems.push(format!("{at}: name at least one target"));
    }
    if part.targets.iter().any(|t| !is_target(t)) {
        problems.push(format!(
            "{at}: a target needs transport http or stdio and an endpoint"
        ));
    }
    let score = part.min_score.is_some_and(|s| !(0.0..=100.0).contains(&s));
    if part.max_age_days == Some(0) || score {
        problems.push(format!(
            "{at}: max_age_days is at least 1, min_score 0 to 100"
        ));
    }
}

fn is_target(t: &TargetPart) -> bool {
    matches!(t.transport.as_str(), "http" | "stdio") && !t.endpoint.trim().is_empty()
}

/// What `tunnelward attest verify` prints about a statement.
fn describe(a: &Attested) -> String {
    let ran = crate::providers::humantime(a.ran_at);
    let server = a.server.as_ref().map_or_else(
        || "not recorded".to_owned(),
        |s| format!("{} {}", s.name, s.version),
    );
    let c = a.counts;
    let score = a.score.map_or_else(|| "none".to_owned(), |s| s.to_string());
    format!(
        "statement {}\nsubject   sha256:{}\ntarget    {} {}\nserver    {server}\nran at    {ran}\nverdicts  {} pass, {} warn, {} fail, {} skip, {} info\nscore     {score}\nsigned by {}",
        a.digest_hex(),
        a.subject,
        a.transport,
        a.endpoint,
        c.pass,
        c.warn,
        c.fail,
        c.skip,
        c.info,
        a.key,
    )
}

/// How `tunnelward attest verify` checks a bundle.
pub(crate) enum Check<'a> {
    /// A signature by any of these keys.
    Keys(Vec<PathBuf>),
    /// The gateway file's `[attestation]`, for this route.
    Gateway(&'a Path, &'a str),
}

/// `tunnelward attest verify`: checks `bundle` as `check` says.
pub(crate) fn verify(bundle: &Path, check: &Check<'_>) -> Result<String, String> {
    let bytes = std::fs::read(bundle).map_err(|e| format!("{}: {e}", bundle.display()))?;
    match check {
        Check::Keys(paths) => {
            let keys = paths
                .iter()
                .map(|k| key(k))
                .collect::<Result<Vec<_>, _>>()?;
            let attested = tunnelward_attest::verify(&bytes, &keys).map_err(|e| e.to_string())?;
            Ok(describe(&attested))
        }
        Check::Gateway(config, route) => decide(&bytes, &*admission(config)?, route),
    }
}

/// The gateway's decision on `bytes` for `route`, with what it says.
fn decide(bytes: &[u8], admission: &Admission, route: &str) -> Result<String, String> {
    let attested = tunnelward_attest::verify(bytes, admission.keys()).map_err(|e| e.to_string())?;
    let routes = [route.to_owned()];
    let facts = describe(&attested);
    match admission.admit(&routes, Some(bytes), None, SystemTime::now()) {
        Ok(Some(_)) => Ok(format!("{facts}\nadmitted  route {route}")),
        Ok(None) => Err(format!("route {route} has no [[attestation.routes]] rule")),
        Err(r) => Err(format!(
            "{facts}\nrefused   {} {route}: {}",
            r.code.id(),
            r.reason
        )),
    }
}

/// A gateway file's `[attestation]`, checked.
fn admission(path: &Path) -> Result<Arc<Admission>, String> {
    let file = crate::config::load(path)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let section = file
        .attestation()
        .ok_or("the gateway file has no [attestation]")?;
    let mut problems = Problems::new();
    check(base, section, &mut problems).ok_or_else(|| problems.join("\n"))
}
