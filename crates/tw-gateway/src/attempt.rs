// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! A registration attempt as the audit log records it (FR-10): who the
//! certificate proves, what the frame claims, and what the gateway
//! decided.

use std::net::IpAddr;

use tunnelward_audit::{Entry, RegistrationEntry, Sink, hex};
use tunnelward_proto::{Register, RejectCode};

/// What a registration attempt showed before the gateway decided.
#[derive(Debug, Default)]
pub(crate) struct Attempt {
    /// The connector's address.
    pub(crate) peer: Option<IpAddr>,
    /// The SPIFFE ID its certificate proves.
    pub(crate) certificate: Option<String>,
    /// What its register frame claims, when it decoded.
    claim: Option<Claim>,
}

#[derive(Debug)]
struct Claim {
    spiffe_id: String,
    connector_id: [u8; 16],
    routes: Vec<String>,
    domains: Vec<String>,
    mcp: Option<tunnelward_proto::McpDescriptor>,
}

/// What the gateway decided.
pub(crate) enum Verdict<'a> {
    /// Routable, with the digest of the attestation it was admitted with.
    Accepted(Option<[u8; 32]>),
    /// Answered with a `Reject`.
    Refused(RejectCode, &'a str),
    /// Accepted, then the connection failed: the error id and why.
    Failed(&'static str, String),
}

impl Attempt {
    /// Notes what `register` claims.
    pub(crate) fn claims(&mut self, register: &Register) {
        self.claim = Some(Claim {
            spiffe_id: register.spiffe_id.clone(),
            connector_id: register.connector_id.0,
            routes: register.routes.clone(),
            domains: register.domains.clone(),
            mcp: register.mcp.clone(),
        });
    }

    /// Records the attempt and `verdict` in `sink`, when there is one.
    pub(crate) fn record(self, sink: Option<&Sink>, verdict: Verdict<'_>) {
        let Some(sink) = sink else { return };
        let mut entry = RegistrationEntry::default();
        match verdict {
            Verdict::Accepted(attested) => {
                "accepted".clone_into(&mut entry.decision);
                entry.attestation = attested.map(|d| hex(&d));
            }
            Verdict::Refused(code, reason) => {
                "refused".clone_into(&mut entry.decision);
                entry.error = Some(code.id().to_owned());
                entry.reason = Some(reason.to_owned());
            }
            Verdict::Failed(id, reason) => {
                "failed".clone_into(&mut entry.decision);
                entry.error = Some(id.to_owned());
                entry.reason = Some(reason);
            }
        }
        let pseudonyms = sink.pseudonyms();
        entry.peer = self
            .peer
            .map(|ip| pseudonyms.of("ip", ip.to_string().as_bytes()));
        entry.certificate = self.certificate;
        if let Some(claim) = self.claim {
            entry.spiffe_id = Some(claim.spiffe_id);
            entry.connector_id = Some(hex(&claim.connector_id));
            entry.routes = claim.routes;
            entry.domains = claim.domains;
            if let Some(mcp) = claim.mcp {
                entry.tools_digest = Some(hex(&mcp.tools_digest));
                entry.server = Some(mcp.name);
                entry.server_version = Some(mcp.version);
            }
        }
        sink.record(Entry::Registration(Box::new(entry)), None);
    }
}
