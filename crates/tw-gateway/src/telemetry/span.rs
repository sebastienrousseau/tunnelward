// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! One ingress request as an OTLP JSON span (ADR 0010).

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::RequestInfo;

/// What a span records beyond [`RequestInfo`]: when it started, what the
/// envelope called, and how it ended.
#[derive(Debug, Clone)]
pub(crate) struct Pending {
    pub(crate) start: SystemTime,
    pub(crate) methods: Vec<String>,
    pub(crate) tools: Vec<String>,
    pub(crate) status: Option<u16>,
    pub(crate) failure: Option<String>,
    pub(crate) alerted: bool,
}

impl Pending {
    pub(crate) fn new() -> Self {
        Self {
            start: SystemTime::now(),
            methods: Vec::new(),
            tools: Vec::new(),
            status: None,
            failure: None,
            alerted: false,
        }
    }

    /// The span of `info`'s request, ending now.
    pub(crate) fn span(&self, info: &RequestInfo) -> Value {
        let error = self.failure.is_some() || self.status.is_some_and(|s| s >= 500);
        let mut span = json!({
            "traceId": info.trace.trace_id,
            "spanId": info.trace.span_id,
            "name": format!("{} {}", info.method, info.uri.path()),
            "kind": 2,
            "startTimeUnixNano": nanos(self.start),
            "endTimeUnixNano": nanos(SystemTime::now()),
            "attributes": self.attributes(info),
            "status": status(error, self.failure.as_deref()),
        });
        if let Some(parent) = &info.trace.parent_span_id {
            span["parentSpanId"] = json!(parent);
        }
        if self.alerted {
            span["events"] = json!([alert_event(info)]);
        }
        span
    }

    fn attributes(&self, info: &RequestInfo) -> Vec<Value> {
        let mut out = vec![
            string("http.request.method", info.method.as_str()),
            string("url.path", info.uri.path()),
            string("tunnelward.request_id", &info.request_id),
            string("tunnelward.evidence", info.evidence.name()),
        ];
        out.extend(
            self.status
                .map(|s| int("http.response.status_code", i64::from(s))),
        );
        let optional = [
            ("tunnelward.route", info.route.as_deref()),
            ("tunnelward.client_id", info.client_id.as_deref()),
            (
                "tunnelward.provider",
                info.provider.as_ref().map(|p| p.provider.as_str()),
            ),
            ("tunnelward.tls.group", info.tls_group),
            ("mcp.session.id", info.mcp_session.as_deref()),
        ];
        out.extend(optional.iter().filter_map(|(k, v)| v.map(|v| string(k, v))));
        if !info.mismatches.is_empty() {
            let claimed: Vec<&str> = info.mismatches.iter().map(|m| m.claimed).collect();
            out.push(strings("tunnelward.mismatches", &claimed));
        }
        out.extend(list("mcp.methods", &self.methods));
        out.extend(list("mcp.tools", &self.tools));
        out.extend(risk(info));
        out
    }
}

/// The request's risk score and signals, when it was scored.
fn risk(info: &RequestInfo) -> Vec<Value> {
    let Some(risk) = &info.risk else {
        return Vec::new();
    };
    let signals: Vec<String> = risk.signals.iter().map(ToString::to_string).collect();
    let mut out = vec![int("tunnelward.risk.score", i64::from(risk.score))];
    out.extend(list("tunnelward.risk.signals", &signals));
    out
}

fn alert_event(info: &RequestInfo) -> Value {
    json!({
        "timeUnixNano": nanos(SystemTime::now()),
        "name": "tunnelward.risk.alert",
        "attributes": risk(info),
    })
}

fn status(error: bool, message: Option<&str>) -> Value {
    if error {
        json!({ "code": 2, "message": message.unwrap_or_default() })
    } else {
        json!({ "code": 0 })
    }
}

/// Nanoseconds since 1970, as OTLP JSON writes 64-bit integers.
fn nanos(at: SystemTime) -> String {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
        .to_string()
}

fn string(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

fn int(key: &str, value: i64) -> Value {
    json!({ "key": key, "value": { "intValue": value.to_string() } })
}

fn strings(key: &str, values: &[&str]) -> Value {
    let values: Vec<Value> = values.iter().map(|v| json!({ "stringValue": v })).collect();
    json!({ "key": key, "value": { "arrayValue": { "values": values } } })
}

/// `values` as an array attribute, or nothing when empty.
fn list(key: &str, values: &[String]) -> Option<Value> {
    let refs: Vec<&str> = values.iter().map(String::as_str).collect();
    (!refs.is_empty()).then(|| strings(key, &refs))
}

/// A batch of spans as an OTLP `ExportTraceServiceRequest`.
pub(crate) fn request(service: &str, spans: &[Value]) -> Value {
    json!({
        "resourceSpans": [{
            "resource": { "attributes": [
                string("service.name", service),
                string("service.version", env!("CARGO_PKG_VERSION")),
            ]},
            "scopeSpans": [{
                "scope": { "name": "tunnelward-gateway", "version": env!("CARGO_PKG_VERSION") },
                "spans": spans,
            }],
        }],
    })
}
