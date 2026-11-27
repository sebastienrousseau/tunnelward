// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Audit events as OTLP/HTTP JSON logs: one log record per event, its
//! body the OCSF event as JSON, posted to `<endpoint>/v1/logs` under the
//! same endpoint rules as spans (ADR 0010).

use std::sync::Arc;

use http::Uri;
use serde_json::{Value, json};
use tunnelward_crypto::rustls::RootCertStore;

use crate::telemetry::{post, signal_url};

/// Where audit events go as OTLP logs.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OtlpLogSettings {
    /// The collector's OTLP/HTTP base URL: `https://`, or `http://` to a
    /// loopback address only.
    pub endpoint: String,
    /// The `service.name` the logs carry.
    pub service: String,
    /// Roots trusted for `https://`.
    pub roots: Arc<RootCertStore>,
}

impl OtlpLogSettings {
    /// Logs to `endpoint` as `tunnelward`, trusting `roots`.
    #[must_use]
    pub fn new(endpoint: impl Into<String>, roots: Arc<RootCertStore>) -> Self {
        Self {
            endpoint: endpoint.into(),
            service: "tunnelward".into(),
            roots,
        }
    }

    /// Whether the endpoint is one logs may go to.
    ///
    /// # Errors
    ///
    /// A sentence saying what is wrong with it.
    pub fn check(&self) -> Result<(), String> {
        signal_url(&self.endpoint, "logs")
            .map(drop)
            .map_err(|e| format!("otlp {e}"))
    }
}

pub(super) struct Client {
    url: Uri,
    service: String,
    roots: Arc<RootCertStore>,
}

impl Client {
    pub(super) fn new(settings: OtlpLogSettings) -> Result<Self, String> {
        Ok(Self {
            url: signal_url(&settings.endpoint, "logs")?,
            service: settings.service,
            roots: settings.roots,
        })
    }

    pub(super) async fn send(&self, events: &[Value]) -> Result<(), String> {
        let body = request(&self.service, events).to_string().into_bytes();
        post(&self.url, body, &self.roots).await
    }
}

/// An `ExportLogsServiceRequest` holding `events`.
fn request(service: &str, events: &[Value]) -> Value {
    let records: Vec<Value> = events.iter().map(record).collect();
    json!({
        "resourceLogs": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": service}}
            ]},
            "scopeLogs": [{
                "scope": {"name": "tunnelward.audit", "version": env!("CARGO_PKG_VERSION")},
                "logRecords": records,
            }],
        }],
    })
}

/// One log record: WARN for a failure, else INFO.
fn record(event: &Value) -> Value {
    let (number, text) = if super::is_failure(event) {
        (13, "WARN")
    } else {
        (9, "INFO")
    };
    let time = event.get("time").and_then(Value::as_u64).unwrap_or(0);
    let class = event.get("class_uid").and_then(Value::as_u64).unwrap_or(0);
    json!({
        "timeUnixNano": (u128::from(time) * 1_000_000).to_string(),
        "severityNumber": number,
        "severityText": text,
        "body": {"stringValue": event.to_string()},
        "attributes": [
            {"key": "ocsf.class_uid", "value": {"intValue": class.to_string()}}
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_event_is_one_record_with_its_time_severity_and_class() {
        let events = [
            json!({"class_uid": 4002, "status_id": 1, "time": 1500}),
            json!({"class_uid": 3002, "status_id": 2, "time": 7}),
        ];
        let body = request("gw", &events);
        let records = &body["resourceLogs"][0]["scopeLogs"][0]["logRecords"];
        assert_eq!(records.as_array().map(Vec::len), Some(2));
        assert_eq!(records[0]["timeUnixNano"], "1500000000");
        assert_eq!(records[0]["severityText"], "INFO");
        assert_eq!(records[1]["severityNumber"], 13);
        assert_eq!(records[1]["attributes"][0]["value"]["intValue"], "3002");
        let inner: Value =
            serde_json::from_str(records[0]["body"]["stringValue"].as_str().unwrap()).unwrap();
        assert_eq!(inner, events[0]);
        assert_eq!(
            body["resourceLogs"][0]["resource"]["attributes"][0]["value"]["stringValue"],
            "gw"
        );
    }

    #[test]
    fn logs_follow_the_span_endpoint_rules() {
        let roots = Arc::new(RootCertStore::empty());
        assert!(
            OtlpLogSettings::new("http://127.0.0.1:4318", roots.clone())
                .check()
                .is_ok()
        );
        assert!(
            OtlpLogSettings::new("http://10.0.0.5:4318", roots)
                .check()
                .is_err()
        );
    }
}
