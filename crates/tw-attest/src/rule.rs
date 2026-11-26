// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! What a route demands of an attestation, and the gateway's set of rules.

use std::time::{Duration, SystemTime};

use tunnelward_proto::{McpDescriptor, RejectCode};

use crate::{Attested, Error, FUTURE_SKEW, Revoked, TrustedKey, subject_digest, verify};

/// A server a route may be served by, as passmcp names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `http` or `stdio`.
    pub transport: String,
    /// The URL, or the command line, exactly as passmcp evaluated it.
    pub endpoint: String,
}

impl Target {
    /// A Streamable HTTP server at `url`.
    #[must_use]
    pub fn http(url: impl Into<String>) -> Self {
        Self {
            transport: "http".into(),
            endpoint: url.into(),
        }
    }

    /// A stdio server started with `command`.
    #[must_use]
    pub fn stdio(command: impl Into<String>) -> Self {
        Self {
            transport: "stdio".into(),
            endpoint: command.into(),
        }
    }

    /// The subject digest a statement about this target carries.
    #[must_use]
    pub fn digest(&self) -> String {
        subject_digest(&self.transport, &self.endpoint)
    }
}

/// What one route demands of a connector's attestation (FR-5).
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    /// The route, exactly as connectors claim it.
    pub route: String,
    /// The servers that may serve it; the statement must be about one.
    pub targets: Vec<Target>,
    /// How long after its run a statement is accepted.
    pub max_age: Duration,
    /// Most failed checks allowed.
    pub max_fail: u32,
    /// Checks that must have passed.
    pub require: Vec<String>,
    /// Lowest score accepted, when set; a statement with no score fails it.
    pub min_score: Option<f64>,
}

impl Rule {
    /// `route` served by one of `targets`: statements up to 30 days old,
    /// no failed check, nothing else required.
    #[must_use]
    pub fn new(route: impl Into<String>, targets: Vec<Target>) -> Self {
        Self {
            route: route.into(),
            targets,
            max_age: Duration::from_secs(30 * 86_400),
            max_fail: 0,
            require: Vec::new(),
            min_score: None,
        }
    }

    /// Whether `attested`, offered by a connector that reports `mcp`,
    /// admits it to this route at `now`.
    ///
    /// # Errors
    ///
    /// The first demand not met.
    pub fn check(
        &self,
        attested: &Attested,
        mcp: Option<&McpDescriptor>,
        now: SystemTime,
    ) -> Result<(), Error> {
        if attested.ran_at > now + FUTURE_SKEW {
            return Err(Error::Future);
        }
        if now.duration_since(attested.ran_at).unwrap_or_default() > self.max_age {
            return Err(Error::Expired);
        }
        if !self.targets.iter().any(|t| t.digest() == attested.subject) {
            return Err(Error::Target(format!(
                "{} {} is not a target of route {}",
                attested.transport, attested.endpoint, self.route
            )));
        }
        same_server(attested, mcp)?;
        self.verdicts(attested)
    }

    fn verdicts(&self, attested: &Attested) -> Result<(), Error> {
        if attested.counts.fail > self.max_fail {
            let (fail, max) = (attested.counts.fail, self.max_fail);
            return Err(Error::Verdicts(format!(
                "{fail} failed, at most {max} allowed"
            )));
        }
        for id in &self.require {
            match attested.status(id) {
                Some("pass") => {}
                Some(other) => return Err(Error::Verdicts(format!("{id} is {other}"))),
                None => return Err(Error::Verdicts(format!("{id} was not assessed"))),
            }
        }
        match (self.min_score, attested.score) {
            (Some(min), Some(score)) if score < min => {
                Err(Error::Verdicts(format!("score {score} is under {min}")))
            }
            (Some(min), None) => Err(Error::Verdicts(format!("no score, {min} required"))),
            _ => Ok(()),
        }
    }
}

/// When both the connector and the statement name the server, they agree.
fn same_server(attested: &Attested, mcp: Option<&McpDescriptor>) -> Result<(), Error> {
    let (Some(said), Some(seen)) = (mcp, attested.server.as_ref()) else {
        return Ok(());
    };
    if seen.name.is_empty() || (said.name == seen.name && said.version == seen.version) {
        return Ok(());
    }
    Err(Error::Server(format!(
        "the connector reports {} {}, the run saw {} {}",
        said.name, said.version, seen.name, seen.version
    )))
}

/// Why a registration was refused, as its `Reject` says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// `AttestationRequired` or `AttestationInvalid`.
    pub code: RejectCode,
    /// What was wrong.
    pub reason: String,
}

/// The keys, rules and revocations a gateway admits connectors by.
#[derive(Debug, Default)]
pub struct Admission {
    keys: Vec<TrustedKey>,
    rules: Vec<Rule>,
    revoked: Revoked,
}

impl Admission {
    /// Rules signed for by `keys`, less `revoked` statements.
    #[must_use]
    pub fn new(keys: Vec<TrustedKey>, rules: Vec<Rule>, revoked: Revoked) -> Self {
        Self {
            keys,
            rules,
            revoked,
        }
    }

    /// Whether a connector claiming `routes` with the statement in
    /// `bundle` may register at `now`. `Ok(Some(digest))` when a rule
    /// applied and the statement met it; `Ok(None)` when no claimed route
    /// has a rule, and anything sent is ignored.
    ///
    /// # Errors
    ///
    /// The refusal to send back.
    pub fn admit(
        &self,
        routes: &[String],
        bundle: Option<&[u8]>,
        mcp: Option<&McpDescriptor>,
        now: SystemTime,
    ) -> Result<Option<[u8; 32]>, Refusal> {
        let rules: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|r| routes.contains(&r.route))
            .collect();
        let Some(first) = rules.first() else {
            return Ok(None);
        };
        let Some(bundle) = bundle else {
            return Err(Refusal {
                code: RejectCode::AttestationRequired,
                reason: format!("route {} requires a passmcp attestation", first.route),
            });
        };
        let invalid = |e: Error| Refusal {
            code: RejectCode::AttestationInvalid,
            reason: e.to_string(),
        };
        let attested = verify(bundle, &self.keys).map_err(invalid)?;
        if self.revoked.contains(&attested.digest) {
            return Err(invalid(Error::Revoked));
        }
        for rule in rules {
            rule.check(&attested, mcp, now).map_err(invalid)?;
        }
        Ok(Some(attested.digest))
    }

    /// Whether the statement with this digest is revoked.
    #[must_use]
    pub fn is_revoked(&self, digest: &[u8; 32]) -> bool {
        self.revoked.contains(digest)
    }

    /// The rules.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The trusted keys.
    #[must_use]
    pub fn keys(&self) -> &[TrustedKey] {
        &self.keys
    }
}
