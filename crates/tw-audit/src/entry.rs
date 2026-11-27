// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! What an entry records. Addresses and fingerprints are pseudonyms;
//! arguments, request and result bodies are digests (FR-15, FR-18).

use serde::{Deserialize, Serialize};

/// One MCP call in a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Call {
    /// The JSON-RPC method, for example `tools/call`.
    pub method: String,
    /// The tool, for a `tools/call`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// SHA-256 of `params.arguments` as JSON with sorted keys, in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
}

/// One request through the ingress, recorded when its answer ends.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RequestEntry {
    /// The request's id (`tw-request-id`).
    pub request_id: String,
    /// The method.
    pub method: String,
    /// The host the client asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The path, without the query.
    pub path: String,
    /// The client address's pseudonym.
    pub client: String,
    /// The client certificate's pseudonym, when it sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<String>,
    /// The OAuth client its token names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The AI provider the gateway saw, as `provider/agent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// How well the sender is known: `declared`, `network` or
    /// `cryptographic`.
    pub evidence: String,
    /// Claims the evidence does not back, as `source:claimed`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatches: Vec<String>,
    /// `User-Agent`, as declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// A well-formed `traceparent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
    /// `Mcp-Session-Id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_session: Option<String>,
    /// The MCP calls in the body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<Call>,
    /// SHA-256 of the request body, when it was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    /// `forwarded`, `refused` or `answered` (by the gateway itself).
    pub decision: String,
    /// The refusal's error id, for example `TW-I004`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The response status.
    pub status: u16,
    /// Response body bytes sent.
    pub bytes: u64,
    /// SHA-256 of the response body as sent, when it ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<String>,
    /// Microseconds from arrival to the end of the answer.
    pub elapsed_us: u64,
    /// SHA-256 of the `tw-receipt` sent, when one was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    /// The risk score, 0 to 100, when the gateway scores requests
    /// (FR-16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<u8>,
    /// What raised it, such as `velocity:tool:61>60` or `canary-record`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_signals: Vec<String>,
}

/// An operator's action through the admin API.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AdminEntry {
    /// What was done, for example `dark` or `drain`.
    pub action: String,
    /// What it was done to, for example `route=payments`.
    pub target: String,
    /// Whether it changed anything.
    pub changed: bool,
    /// The admin caller's address, as a pseudonym.
    pub peer: String,
    /// Who acted, when a token named them: the control plane's operator
    /// (ADR 0012).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

impl AdminEntry {
    /// An entry for `action` on `target`.
    #[must_use]
    pub fn new(action: &str, target: String, changed: bool, peer: String) -> Self {
        Self {
            action: action.to_owned(),
            target,
            changed,
            peer,
            actor: None,
        }
    }

    /// The entry, naming `actor` as who acted.
    #[must_use]
    pub fn by(mut self, actor: String) -> Self {
        self.actor = Some(actor);
        self
    }
}

/// A connector's registration, as the gateway decided it (FR-10). Only
/// registrations that reach a decision are recorded: the connector has
/// completed mutual TLS, so a source with no certificate cannot write
/// to the log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegistrationEntry {
    /// `accepted`, `refused`, or `failed` (accepted, but the HTTP/2
    /// connection then failed).
    pub decision: String,
    /// The error id, for example `TW-R003`, unless accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Why, as sent to the connector, unless accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The connector address's pseudonym.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// The SPIFFE ID the client certificate proves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// The SPIFFE ID the register frame claims, when it decoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    /// The connector id, in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// The routes claimed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    /// The domains claimed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// SHA-256 of the attestation it was admitted with (FR-5), in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
}

/// What a [`crate::Sink`] records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[non_exhaustive]
pub enum Entry {
    /// A request through the ingress.
    Request(Box<RequestEntry>),
    /// An admin action.
    Admin(AdminEntry),
    /// A connector registration.
    Registration(Box<RegistrationEntry>),
}
