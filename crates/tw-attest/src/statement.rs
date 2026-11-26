// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The passmcp statement, checked as passmcp checks it
//! (`passmcp-reporting/attestation`, `Statement.Validate`).

use std::collections::BTreeMap;

use aws_lc_rs::digest::{SHA256, SHA512, digest};
use serde::Deserialize;
use tunnelward_audit::hex;

/// The in-toto statement type.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// passmcp's MCP evaluation predicate.
pub const PREDICATE_TYPE: &str = "https://satellion.com/attestation/mcp-evaluation/v1";
/// What passmcp's subject digest covers.
pub const SUBJECT_KIND: &str = "mcp-target-descriptor";

/// The parts of a statement the gateway reads; other fields are ignored.
#[derive(Debug, Deserialize)]
pub(crate) struct Statement {
    #[serde(rename = "_type")]
    pub(crate) kind: String,
    pub(crate) subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub(crate) predicate_type: String,
    pub(crate) predicate: Evaluation,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Subject {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) digest: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Evaluation {
    #[serde(default)]
    pub(crate) subject_kind: String,
    pub(crate) target: Target,
    #[serde(default)]
    pub(crate) judged_against: Basis,
    #[serde(default)]
    pub(crate) instrument: Instrument,
    #[serde(default)]
    pub(crate) ran_at: String,
    #[serde(default)]
    pub(crate) verdicts: Vec<Verdict>,
    #[serde(default)]
    pub(crate) counts: Counts,
    pub(crate) score: Option<Score>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Target {
    #[serde(default)]
    pub(crate) transport: String,
    #[serde(default)]
    pub(crate) endpoint: String,
    pub(crate) server: Option<Server>,
}

/// What the server said it was, when the statement records it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Server {
    /// Its name.
    #[serde(default)]
    pub name: String,
    /// Its version.
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Basis {
    #[serde(default)]
    pub(crate) rubric: String,
    #[serde(default)]
    pub(crate) check_inventory: String,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Instrument {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) version: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Verdict {
    #[serde(default)]
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) status: String,
}

/// The verdicts by status.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Counts {
    /// Checks that passed.
    #[serde(default)]
    pub pass: u32,
    /// Checks that warned.
    #[serde(default)]
    pub warn: u32,
    /// Checks that failed.
    #[serde(default)]
    pub fail: u32,
    /// Checks skipped.
    #[serde(default)]
    pub skip: u32,
    /// Informational results.
    #[serde(default)]
    pub info: u32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Score {
    pub(crate) total: f64,
}

/// The canonical string passmcp's subject digest covers.
#[must_use]
pub fn descriptor(transport: &str, endpoint: &str) -> String {
    format!("{transport}\n{}", endpoint.trim())
}

/// SHA-256 of `descriptor(transport, endpoint)`, in hex: the subject
/// digest a statement about that target carries.
#[must_use]
pub fn subject_digest(transport: &str, endpoint: &str) -> String {
    hex(digest(&SHA256, descriptor(transport, endpoint).as_bytes()).as_ref())
}

impl Statement {
    /// Every problem passmcp would report, or none.
    pub(crate) fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut note = |m: String| out.push(m);
        if self.kind != STATEMENT_TYPE {
            note(format!("_type is {:?}", self.kind));
        }
        if self.predicate_type != PREDICATE_TYPE {
            note(format!("predicateType is {:?}", self.predicate_type));
        }
        self.subject_problems(&mut note);
        self.predicate.problems(&mut note);
        out
    }

    fn subject_problems(&self, note: &mut impl FnMut(String)) {
        let [subject] = self.subject.as_slice() else {
            note(format!("{} subjects, not one", self.subject.len()));
            return;
        };
        let target = &self.predicate.target;
        if subject.name.trim() != target.endpoint.trim() {
            note("the subject is not named for the target's endpoint".into());
        }
        let text = descriptor(&target.transport, &target.endpoint);
        let known = [("sha256", &SHA256), ("sha512", &SHA512)];
        let mut found = false;
        for (name, algorithm) in known {
            if let Some(given) = subject.digest.get(name) {
                found = true;
                if !given.eq_ignore_ascii_case(&hex(digest(algorithm, text.as_bytes()).as_ref())) {
                    note(format!(
                        "the subject {name} digest does not cover the target"
                    ));
                }
            }
        }
        if !found {
            note("the subject has no sha256 or sha512 digest".into());
        }
    }
}

impl Evaluation {
    fn problems(&self, note: &mut impl FnMut(String)) {
        if self.subject_kind != SUBJECT_KIND {
            note(format!("subjectKind is {:?}", self.subject_kind));
        }
        if self.target.endpoint.trim().is_empty() {
            note("the target has no endpoint".into());
        }
        if !matches!(self.target.transport.as_str(), "http" | "stdio") {
            note(format!("unknown transport {:?}", self.target.transport));
        }
        self.record_problems(note);
        self.verdict_problems(note);
    }

    /// The run's own record: instrument, time, verdicts and basis.
    fn record_problems(&self, note: &mut impl FnMut(String)) {
        if self.instrument.name.is_empty() || self.instrument.version.is_empty() {
            note("the instrument is not identified".into());
        }
        if self.ran_at.is_empty() {
            note("no run time".into());
        }
        if self.verdicts.is_empty() {
            note("no verdicts".into());
        }
        if self.judged_against.check_inventory.is_empty() {
            note("no check inventory version".into());
        }
        if self.score.is_some() && self.judged_against.rubric.is_empty() {
            note("a score with no rubric version".into());
        }
    }

    fn verdict_problems(&self, note: &mut impl FnMut(String)) {
        let mut counted = Counts::default();
        for v in &self.verdicts {
            let slot = match v.status.as_str() {
                "pass" => &mut counted.pass,
                "warn" => &mut counted.warn,
                "fail" => &mut counted.fail,
                "skip" => &mut counted.skip,
                "info" => &mut counted.info,
                other => {
                    note(format!("verdict {:?} has status {other:?}", v.id));
                    continue;
                }
            };
            *slot = slot.saturating_add(1);
            if v.id.is_empty() {
                note("a verdict has no id".into());
            }
        }
        if counted != self.counts {
            note("the counts disagree with the verdicts".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/vectors/statement.json");

    fn fixture() -> serde_json::Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    fn problems(value: &serde_json::Value) -> Vec<String> {
        serde_json::from_value::<Statement>(value.clone())
            .unwrap()
            .problems()
    }

    #[test]
    fn passmcps_own_fixture_has_no_problems() {
        assert_eq!(problems(&fixture()), Vec::<String>::new());
    }

    #[test]
    fn the_subject_digest_is_passmcps() {
        // passmcp-reporting's fixture names this digest for this target.
        assert_eq!(
            subject_digest("http", " https://mcp.example.com/mcp "),
            "a386a033799c95c21f3d01b2f0efcf71b95b1ef2a420908ce34e3c1eb41a2325"
        );
    }

    #[test]
    fn each_edit_is_a_problem() {
        let edits: [(&str, serde_json::Value); 9] = [
            ("/_type", "x".into()),
            ("/predicateType", "x".into()),
            ("/subject/0/name", "https://other.example/mcp".into()),
            ("/subject/0/digest/sha256", "00".into()),
            ("/predicate/subjectKind", "artifact".into()),
            ("/predicate/target/transport", "ftp".into()),
            ("/predicate/instrument/name", "".into()),
            ("/predicate/counts/pass", 99.into()),
            ("/predicate/judgedAgainst/checkInventory", "".into()),
        ];
        for (path, value) in edits {
            let mut statement = fixture();
            *statement.pointer_mut(path).unwrap() = value;
            assert!(!problems(&statement).is_empty(), "{path} was not caught");
        }
    }

    #[test]
    fn a_sha512_digest_counts_and_must_recompute() {
        let mut statement = fixture();
        let digests = statement.pointer_mut("/subject/0/digest").unwrap();
        *digests = serde_json::json!({ "sha512": "00" });
        assert_eq!(
            problems(&statement),
            ["the subject sha512 digest does not cover the target"]
        );
    }
}
