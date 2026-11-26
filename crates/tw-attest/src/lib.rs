// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Tunnelward admission by passmcp attestation (FR-5, ADR 0009).
//!
//! A route can require that the MCP server behind a connector holds a
//! passmcp attestation: an in-toto statement about one server, in a DSSE
//! envelope (bare, or inside a Sigstore bundle as `cosign attest-blob`
//! writes it), signed by a key the gateway trusts. [`verify`] checks the
//! envelope, the signature and the statement; a [`Rule`] then decides
//! whether that statement admits a connector to a route, and
//! [`Admission`] holds the rules, the keys and the revoked statements a
//! gateway applies.
//!
//! ```
//! use std::time::{Duration, UNIX_EPOCH};
//! use tunnelward_attest::{Admission, Limits, Rule, Target, TrustedKey};
//!
//! let key = TrustedKey::from_pem(include_bytes!("../tests/vectors/cosign-p256.pub"))?;
//! let mut rule = Rule::new("mcp/payments", vec![Target::http("https://mcp.example.com/mcp")]);
//! rule.max_fail = 1; // the fixture's run failed protocol.origin
//! let admission = Admission::new(vec![key], vec![rule], Default::default(), Limits::default());
//! let bundle = include_bytes!("../tests/vectors/cosign-bundle.json");
//! let ran = UNIX_EPOCH + Duration::from_secs(1_790_078_400); // 2026-09-22T12:00:00Z
//! let routes = ["mcp/payments".to_owned()];
//! let admitted = admission.admit(&routes, Some(bundle), None, ran + Duration::from_secs(60));
//! assert!(admitted.is_ok());
//! # Ok::<(), String>(())
//! ```

mod envelope;
mod keys;
mod revoked;
mod rule;
mod statement;
mod time;

use core::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest::{SHA256, digest};

pub use envelope::PAYLOAD_TYPE;
pub use keys::TrustedKey;
pub use revoked::Revoked;
pub use rule::{Admission, Refusal, Rule, Target};
pub use statement::{
    Counts, PREDICATE_TYPE, STATEMENT_TYPE, SUBJECT_KIND, Server, descriptor, subject_digest,
};

use envelope::Envelope;
use statement::Statement;

/// Why an attestation cannot be believed, or does not admit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not a DSSE envelope of an in-toto statement.
    Envelope(&'static str),
    /// No signature verifies under a trusted key.
    Unsigned,
    /// The payload is not a passmcp statement, with every problem found.
    Statement(String),
    /// The statement is listed as revoked.
    Revoked,
    /// The run is older than the rule allows.
    Expired,
    /// The run is dated more than [`Limits::future_skew`] ahead.
    Future,
    /// The statement is about a target the route is not served by.
    Target(String),
    /// The server the statement names is not the one the connector reports.
    Server(String),
    /// The verdicts do not meet the rule.
    Verdicts(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(why) => write!(f, "attestation envelope: {why}"),
            Self::Unsigned => f.write_str("no signature by a trusted key"),
            Self::Statement(why) => write!(f, "not a passmcp statement: {why}"),
            Self::Revoked => f.write_str("the attestation is revoked"),
            Self::Expired => f.write_str("the attestation is older than the route allows"),
            Self::Future => f.write_str("the attestation is dated in the future"),
            Self::Target(why) => write!(f, "the attestation is for another server: {why}"),
            Self::Server(why) => write!(f, "the attestation names another server: {why}"),
            Self::Verdicts(why) => write!(f, "the verdicts do not meet the route's rule: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// The bounds a gateway holds attestations to, each configurable
/// (`[attestation]` in the gateway file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most signatures an envelope may carry, counted before any is
    /// decoded: each is tried against every trusted key.
    pub max_signatures: usize,
    /// Most statements a revocation list may name.
    pub max_revoked: usize,
    /// How far ahead of the gateway's clock a run may be dated.
    pub future_skew: Duration,
}

impl Default for Limits {
    /// 8 signatures, 100,000 revoked statements, 5 minutes of skew.
    fn default() -> Self {
        Self {
            max_signatures: 8,
            max_revoked: 100_000,
            future_skew: Duration::from_secs(300),
        }
    }
}

/// A statement whose envelope, signature and contents passed [`verify`].
#[derive(Debug, Clone, PartialEq)]
pub struct Attested {
    /// SHA-256 of the signed payload: the statement's identity, which a
    /// revocation list names.
    pub digest: [u8; 32],
    /// The subject's SHA-256 digest, recomputed, in hex.
    pub subject: String,
    /// `http` or `stdio`.
    pub transport: String,
    /// The URL or command line the run evaluated.
    pub endpoint: String,
    /// What the server said it was, when the statement records it.
    pub server: Option<Server>,
    /// When the run started.
    pub ran_at: SystemTime,
    /// The verdicts by status.
    pub counts: Counts,
    /// The score, when the run assessed one.
    pub score: Option<f64>,
    /// The id of the key whose signature verified ([`TrustedKey::id`]).
    pub key: String,
    verdicts: Vec<(String, String)>,
}

impl Attested {
    /// The status recorded for check `id` (the first, as passmcp reads
    /// it), or `None` when the run did not assess it.
    #[must_use]
    pub fn status(&self, id: &str) -> Option<&str> {
        self.verdicts
            .iter()
            .find(|(v, _)| v == id)
            .map(|(_, s)| s.as_str())
    }

    /// [`Attested::digest`] in hex.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        tunnelward_audit::hex(&self.digest)
    }
}

/// Checks `bytes`, a DSSE envelope or a Sigstore bundle with at most
/// `limits.max_signatures` signatures: a signature by one of `keys` over
/// an in-toto statement that passmcp would accept.
/// Says nothing about freshness, targets or verdicts: that is a [`Rule`].
///
/// # Errors
///
/// The first thing found wrong.
pub fn verify(bytes: &[u8], keys: &[TrustedKey], limits: &Limits) -> Result<Attested, Error> {
    let envelope = Envelope::parse(bytes, limits.max_signatures)?;
    let key = signer(&envelope, keys).ok_or(Error::Unsigned)?;
    let statement: Statement = serde_json::from_slice(&envelope.payload)
        .map_err(|e| Error::Statement(format!("unreadable: {e}")))?;
    let problems = statement.problems();
    if !problems.is_empty() {
        return Err(Error::Statement(problems.join("; ")));
    }
    attested(&envelope.payload, statement, key)
}

/// The first of `keys` that one of the envelope's signatures verifies under.
fn signer<'k>(envelope: &Envelope, keys: &'k [TrustedKey]) -> Option<&'k TrustedKey> {
    let message = envelope.pae();
    keys.iter()
        .find(|k| envelope.signatures.iter().any(|s| k.verifies(&message, s)))
}

/// What a checked statement says, with its payload's digest.
fn attested(payload: &[u8], statement: Statement, key: &TrustedKey) -> Result<Attested, Error> {
    let p = statement.predicate;
    let ran_at = time::parse(&p.ran_at)
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
        .ok_or_else(|| Error::Statement(format!("ranAt {:?} is not RFC 3339", p.ran_at)))?;
    let mut sha = [0; 32];
    sha.copy_from_slice(digest(&SHA256, payload).as_ref());
    Ok(Attested {
        digest: sha,
        subject: subject_digest(&p.target.transport, &p.target.endpoint),
        transport: p.target.transport,
        endpoint: p.target.endpoint.trim().to_owned(),
        server: p.target.server,
        ran_at,
        counts: p.counts,
        score: p.score.map(|s| s.total),
        key: key.id().to_owned(),
        verdicts: p.verdicts.into_iter().map(|v| (v.id, v.status)).collect(),
    })
}
