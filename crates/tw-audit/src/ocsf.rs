// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Audit lines as OCSF 1.3.0 events, for a SIEM. A request is an HTTP
//! Activity (class 4002) with the security-control profile's allow or
//! deny; an admin action is an API Activity (class 6003). What OCSF has
//! no field for (evidence, mismatches, digests) goes in `unmapped`.
//! Checkpoints and gaps are the chain's own lines and are not events.
//!
//! The export is a view: the chained file stays the record (ADR 0008).

use serde_json::{Value, json};

use crate::{AdminEntry, Entry, RequestEntry};

/// The OCSF schema version written.
pub const VERSION: &str = "1.3.0";

/// The OCSF event for one audit line, or `None` for a line that is not
/// an entry (a checkpoint, a gap) or does not parse.
#[must_use]
pub fn event(line: &str) -> Option<Value> {
    let value: Value = serde_json::from_str(line).ok()?;
    let seq = value.get("seq")?.as_u64()?;
    let time = value.get("time")?.as_u64()?;
    match serde_json::from_value::<Entry>(value).ok()? {
        Entry::Request(entry) => Some(request(&entry, seq, time)),
        Entry::Admin(entry) => Some(admin(&entry, seq, time)),
    }
}

fn metadata(seq: u64, uid: Option<&str>, profiles: &[&str]) -> Value {
    let mut metadata = json!({
        "version": VERSION,
        "product": {
            "name": "tunnelward",
            "vendor_name": "tunnelward",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "sequence": seq,
        "profiles": profiles,
        "log_name": "audit",
    });
    if let Some(uid) = uid {
        metadata["uid"] = json!(uid);
    }
    metadata
}

/// OCSF's HTTP activity for a method: Connect 1, Delete 2, Get 3, Head 4,
/// Options 5, Post 6, Put 7, Trace 8, else Other 99.
fn http_activity(method: &str) -> u64 {
    let known = [
        "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT", "TRACE",
    ];
    known
        .iter()
        .position(|m| *m == method)
        .map_or(99, |i| i as u64 + 1)
}

fn request(entry: &RequestEntry, seq: u64, time: u64) -> Value {
    let activity = http_activity(&entry.method);
    let refused = entry.decision == "refused";
    let mut url = json!({ "path": entry.path });
    if let Some(host) = &entry.host {
        url["hostname"] = json!(host);
    }
    let mut event = json!({
        "category_uid": 4,
        "class_uid": 4002,
        "activity_id": activity,
        "type_uid": 400_200 + activity,
        "time": time,
        "severity_id": 1,
        "status_id": if entry.status < 400 { 1 } else { 2 },
        "action_id": if refused { 2 } else { 1 },
        "disposition_id": if refused { 2 } else { 1 },
        "duration": entry.elapsed_us / 1000,
        "metadata": metadata(seq, Some(&entry.request_id), &["security_control"]),
        "http_request": {
            "uid": entry.request_id,
            "http_method": entry.method,
            "url": url,
        },
        "http_response": { "code": entry.status, "length": entry.bytes },
        "src_endpoint": { "uid": entry.client },
        "dst_endpoint": { "svc_name": "tunnelward" },
        "unmapped": unmapped(entry),
    });
    if let Some(host) = &entry.host {
        event["dst_endpoint"]["hostname"] = json!(host);
    }
    if let Some(agent) = &entry.user_agent {
        event["http_request"]["user_agent"] = json!(agent);
    }
    if let Some(error) = &entry.error {
        event["status_detail"] = json!(error);
    }
    if let Some(client) = &entry.client_id {
        event["actor"] = json!({ "app_uid": client });
    }
    event
}

/// The entry's fields OCSF has no place for.
fn unmapped(entry: &RequestEntry) -> Value {
    json!({
        "decision": entry.decision,
        "evidence": entry.evidence,
        "provider": entry.provider,
        "mismatches": entry.mismatches,
        "calls": entry.calls,
        "client_cert": entry.client_cert,
        "mcp_session": entry.mcp_session,
        "traceparent": entry.traceparent,
        "request_digest": entry.request_digest,
        "result_digest": entry.result_digest,
        "receipt": entry.receipt,
    })
}

fn admin(entry: &AdminEntry, seq: u64, time: u64) -> Value {
    // Update: an admin action changes the gateway's own state.
    let activity = 3;
    json!({
        "category_uid": 6,
        "class_uid": 6003,
        "activity_id": activity,
        "type_uid": 600_300 + activity,
        "time": time,
        "severity_id": 1,
        "status_id": 1,
        "metadata": metadata(seq, None, &[]),
        "actor": { "app_name": "tunnelward admin API" },
        "api": { "operation": entry.action },
        "src_endpoint": { "uid": entry.peer },
        "unmapped": { "target": entry.target, "changed": entry.changed },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(body: &str) -> String {
        format!(
            r#"{{"seq":4,"prev":"{}","time":1700000000000,{body}}}"#,
            crate::GENESIS
        )
    }

    #[test]
    fn a_refused_post_is_a_denied_http_activity() {
        let text = line(
            r#""kind":"request","request_id":"R1","method":"POST","host":"api.example","path":"/mcp","client":"ab","evidence":"declared","decision":"refused","error":"TW-I004","status":429,"bytes":10,"elapsed_us":2500"#,
        );
        let event = event(&text).unwrap();
        assert_eq!(event["class_uid"], 4002);
        assert_eq!(event["activity_id"], 6);
        assert_eq!(event["type_uid"], 400_206);
        assert_eq!(event["action_id"], 2);
        assert_eq!(event["status_id"], 2);
        assert_eq!(event["status_detail"], "TW-I004");
        assert_eq!(event["metadata"]["uid"], "R1");
        assert_eq!(event["metadata"]["sequence"], 4);
        assert_eq!(event["http_request"]["url"]["hostname"], "api.example");
        assert_eq!(event["src_endpoint"]["uid"], "ab");
        assert_eq!(event["duration"], 2);
    }

    #[test]
    fn admin_actions_are_api_activity_and_marks_are_skipped() {
        let text = line(
            r#""kind":"admin","action":"dark","target":"route=pay","changed":true,"peer":"cd""#,
        );
        let event = event(&text).unwrap();
        assert_eq!(event["class_uid"], 6003);
        assert_eq!(event["api"]["operation"], "dark");
        assert!(super::event(&line(r#""kind":"checkpoint","key":"k","sig":"s""#)).is_none());
        assert!(super::event(&line(r#""kind":"gap","dropped":3"#)).is_none());
        assert!(super::event("nonsense").is_none());
        assert_eq!(http_activity("PATCH"), 99);
        assert_eq!(http_activity("GET"), 3);
    }
}
