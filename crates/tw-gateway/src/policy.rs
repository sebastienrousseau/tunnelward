// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Tool policy at the ingress (FR-4): every call in a request is decided
//! before the request goes anywhere. A denied JSON-RPC call is answered
//! by the gateway with a JSON-RPC error (`TW-P001`, code -32001) and never
//! reaches the connector.
//!
//! The policy must see what the server will see. A POST whose body is
//! JSON but not a JSON-RPC message the gateway can read is refused, so a
//! body the server reads differently cannot carry a call past the policy;
//! a body that is not JSON at all is decided as `http:POST`.

use bytes::Bytes;
use http::StatusCode;
use serde::de::IgnoredAny;
use tunnelward_mcp::{Envelope, Id, Kind};
use tunnelward_policy::{Call, Decision, Evidence, PolicyEngine};

use crate::RequestInfo;
use crate::refusal::Refusal;

/// The error id of every policy denial.
const ID: &str = "TW-P001";

/// The JSON-RPC error code of a call the policy denies.
const DENIED: i32 = -32001;

/// What the policy says about a request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Forward it; `high_impact` when a call in it is to a high-impact
    /// tool, which needs an idempotency key.
    Forward { high_impact: bool },
}

/// How well the request's sender is known (FR-14): cryptographic for a
/// bound token or a verified signature, network for a provider-range
/// match, declared otherwise.
pub(crate) fn evidence(info: &RequestInfo, bound_token: bool) -> Evidence {
    match info.provider.as_ref().map(|p| p.level) {
        _ if bound_token => Evidence::Cryptographic,
        Some("signature") => Evidence::Cryptographic,
        Some(_) => Evidence::Network,
        None => Evidence::Declared,
    }
}

fn call<'a>(info: &'a RequestInfo, method: &'a str, tool: Option<&'a str>) -> Call<'a> {
    Call {
        agent: info.client_id.as_deref(),
        provider: info.provider.as_ref().map(|p| p.provider.as_str()),
        path: info.uri.path(),
        method,
        tool,
        evidence: info.evidence,
    }
}

/// Decides every call in a request with `method` and `body`.
pub(crate) fn decide(
    engine: &dyn PolicyEngine,
    method: &http::Method,
    body: &Bytes,
    info: &RequestInfo,
) -> Result<Verdict, Refusal> {
    let http_call = || format!("http:{method}");
    if body.is_empty() || serde_json::from_slice::<IgnoredAny>(body).is_err() {
        return single(engine, &call(info, &http_call(), None));
    }
    let envelope = tunnelward_mcp::parse(body).map_err(|e| {
        Refusal::new(
            ID,
            StatusCode::FORBIDDEN,
            format!("the policy cannot read the body: {e}"),
        )
    })?;
    calls(engine, &envelope, info)
}

/// A request that is not JSON-RPC: one call, refused with 403.
fn single(engine: &dyn PolicyEngine, call: &Call<'_>) -> Result<Verdict, Refusal> {
    match engine.decide(call) {
        Decision::Allow { high_impact } => Ok(Verdict::Forward { high_impact }),
        Decision::Deny(why) => Err(Refusal::new(ID, StatusCode::FORBIDDEN, why)),
    }
}

/// Each request and notification in `envelope`; one denial refuses them
/// all, answering each request with a JSON-RPC error.
fn calls(
    engine: &dyn PolicyEngine,
    envelope: &Envelope,
    info: &RequestInfo,
) -> Result<Verdict, Refusal> {
    let mut high_impact = false;
    let mut denied = None;
    for message in envelope
        .messages
        .iter()
        .filter(|m| m.kind != Kind::Response)
    {
        let method = message.method.as_deref().unwrap_or_default();
        match engine.decide(&call(info, method, message.tool.as_deref())) {
            Decision::Allow { high_impact: h } => high_impact |= h,
            Decision::Deny(why) => {
                denied.get_or_insert(why);
            }
        }
    }
    match denied {
        None => Ok(Verdict::Forward { high_impact }),
        Some(why) => Err(json_rpc_refusal(envelope, why)),
    }
}

/// The refusal for a denied envelope: a JSON-RPC error for each request
/// in it (an array for a batch), or 403 when it holds no request.
fn json_rpc_refusal(envelope: &Envelope, why: String) -> Refusal {
    let errors: Vec<serde_json::Value> = envelope
        .messages
        .iter()
        .filter(|m| m.kind == Kind::Request)
        .map(|m| error(m.id.as_ref(), &why))
        .collect();
    let body = match (envelope.batch, errors.as_slice()) {
        (_, []) => return Refusal::new(ID, StatusCode::FORBIDDEN, why),
        (false, [one]) => one.to_string(),
        _ => serde_json::Value::Array(errors).to_string(),
    };
    Refusal {
        json: Some(Bytes::from(body)),
        ..Refusal::new(ID, StatusCode::OK, why)
    }
}

fn error(id: Option<&Id>, why: &str) -> serde_json::Value {
    let id = match id {
        Some(Id::Number(n)) => serde_json::from_str(n).unwrap_or(serde_json::Value::Null),
        Some(Id::String(s)) => serde_json::Value::String(s.clone()),
        None => serde_json::Value::Null,
    };
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": DENIED,
            "message": format!("denied by the gateway's policy: {why}"),
            "data": { "tw_error": ID },
        },
    })
}
