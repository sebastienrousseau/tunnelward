// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway's side of the audit log (FR-15, FR-18, G12, G14): what a
//! request contributes to its entry as it goes, its receipt when the
//! answer starts, and its entry when the answer ends.

use std::sync::Arc;
use std::time::Instant;

use http::HeaderValue;
use tunnelward_audit::receipt::Receipt;
use tunnelward_audit::{Call, Entry, Raw, RequestEntry, Sink};

use crate::{ClaimSource, RequestInfo};

/// The response header carrying a signed receipt.
pub(crate) const RECEIPT: http::HeaderName = http::HeaderName::from_static("tw-receipt");

/// What a request adds to its entry on the way through, beyond
/// [`RequestInfo`]'s own fields.
#[derive(Debug, Clone, Default)]
pub(crate) struct Trail {
    /// The host asked for: the URI's, else the `Host` header's.
    pub(crate) host: Option<String>,
    /// SHA-256 of the client's TLS certificate.
    pub(crate) client_cert: Option<[u8; 32]>,
    /// SHA-256 of the request body, once read.
    pub(crate) request_digest: Option<String>,
    /// Its MCP calls, with argument digests.
    pub(crate) calls: Vec<Call>,
    /// SHA-256 of the receipt sent.
    pub(crate) receipt: Option<String>,
}

/// How the gateway dealt with a request.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Decision {
    /// Sent to a connector.
    Forwarded,
    /// Refused, with this error id.
    Refused(&'static str),
    /// Answered by the gateway itself: a preflight, metadata, enrolment.
    Answered,
}

impl Decision {
    fn name(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Refused(_) => "refused",
            Self::Answered => "answered",
        }
    }

    fn error(self) -> Option<String> {
        match self {
            Self::Refused(id) => Some(id.to_owned()),
            _ => None,
        }
    }
}

/// Reads `body` into the trail: its digest and its calls.
pub(crate) fn body(info: &mut RequestInfo, body: &[u8]) {
    info.trail.request_digest = Some(tunnelward_audit::digest(body));
    info.trail.calls = tunnelward_audit::calls(body);
}

fn source(source: ClaimSource) -> &'static str {
    match source {
        ClaimSource::UserAgent => "user-agent",
        ClaimSource::ClientInfo => "client-info",
    }
}

/// The entry for `info`, as far as it is known when the answer starts.
fn entry(sink: &Sink, info: &RequestInfo, status: u16, decision: Decision) -> RequestEntry {
    let pseudonyms = sink.pseudonyms();
    let mut entry = RequestEntry::default();
    entry.request_id.clone_from(&info.request_id);
    entry.method = info.method.to_string();
    entry.host.clone_from(&info.trail.host);
    info.uri.path().clone_into(&mut entry.path);
    entry.client = pseudonyms.of("ip", info.client.client.to_string().as_bytes());
    entry.client_cert = info.trail.client_cert.map(|c| pseudonyms.of("cert", &c));
    entry.client_id.clone_from(&info.client_id);
    entry.provider = info
        .provider
        .as_ref()
        .map(|p| format!("{}/{}", p.provider, p.agent));
    info.evidence.name().clone_into(&mut entry.evidence);
    entry.mismatches = info
        .mismatches
        .iter()
        .map(|m| format!("{}:{}", source(m.source), m.claimed))
        .collect();
    entry.user_agent.clone_from(&info.user_agent);
    entry.traceparent.clone_from(&info.traceparent);
    entry.mcp_session.clone_from(&info.mcp_session);
    entry.calls.clone_from(&info.trail.calls);
    entry.request_digest.clone_from(&info.trail.request_digest);
    decision.name().clone_into(&mut entry.decision);
    entry.error = decision.error();
    entry.status = status;
    entry.receipt.clone_from(&info.trail.receipt);
    entry
}

/// The signed receipt for `info`'s answer, when receipts are on; notes
/// its digest for the entry.
pub(crate) fn receipt(
    sink: &Sink,
    info: &mut RequestInfo,
    status: u16,
    decision: Decision,
) -> Option<HeaderValue> {
    let body = Receipt::from_entry(&entry(sink, info, status, decision));
    let text = sink.receipt(&body)?;
    let value = HeaderValue::from_str(&text).ok()?;
    info.trail.receipt = Some(tunnelward_audit::digest(text.as_bytes()));
    Some(value)
}

/// What is known when an answer ends.
pub(crate) struct Ended {
    pub(crate) status: u16,
    pub(crate) decision: Decision,
    pub(crate) bytes: u64,
    /// SHA-256 of the body sent; `None` when it did not end cleanly.
    pub(crate) result_digest: Option<String>,
    pub(crate) started: Instant,
}

/// Records `info`'s entry.
pub(crate) fn record(sink: &Sink, info: &RequestInfo, ended: Ended) {
    let mut entry = entry(sink, info, ended.status, ended.decision);
    entry.bytes = ended.bytes;
    entry.result_digest = ended.result_digest;
    entry.elapsed_us = u64::try_from(ended.started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let raw = sink.keeps_raw().then(|| Raw {
        client: info.client.client.to_string(),
        client_cert: info.trail.client_cert.map(|c| tunnelward_audit::hex(&c)),
    });
    sink.record(Entry::Request(Box::new(entry)), raw);
}

/// Records a whole answer the gateway holds: its receipt goes on
/// `headers`, and its entry is written now.
pub(crate) fn answered(
    sink: Option<&Arc<Sink>>,
    info: &mut RequestInfo,
    headers: &mut http::HeaderMap,
    ended: Ended,
) {
    let Some(sink) = sink else { return };
    if let Some(value) = receipt(sink, info, ended.status, ended.decision) {
        headers.insert(RECEIPT, value);
    }
    record(sink, info, ended);
}
