// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Registrations in the audit log (FR-10): every registration the
//! gateway decides, accepted or refused, is a chained entry with the
//! identity the certificate proves next to the one the frame claims.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use tunnelward_audit::{Sink, verify};
use tunnelward_connector::{Error as ConnectError, register};
use tunnelward_proto::RejectCode;

use common::{Res, audit_sink, connector_config, gateway_config, logged, registration, start};

const CONNECTOR: &str = "spiffe://example.org/connector";

/// A gateway with an audit log: its address, the sink and the file.
async fn audited(name: &str) -> Res<(String, Arc<Sink>, PathBuf)> {
    let (sink, path) = audit_sink(name)?;
    let mut config = gateway_config()?;
    config.audit = Some(sink.clone());
    let (_gateway, addr) = start(config).await?;
    Ok((addr, sink, path))
}

#[tokio::test]
async fn an_accepted_registration_is_logged_with_its_proven_identity() -> Res<()> {
    let (addr, sink, path) = audited("registration-accepted").await?;
    let session = register(&connector_config(&addr, registration(7, &["pay"], &[]))?).await?;
    let entries = logged(&sink, &path, "registration")?;
    drop(session);
    assert_eq!(entries.len(), 1, "{entries:?}");
    let entry = &entries[0];
    assert_eq!(entry["decision"], "accepted");
    assert_eq!(entry["certificate"], CONNECTOR);
    assert_eq!(entry["spiffe_id"], CONNECTOR);
    assert_eq!(entry["connector_id"], "07".repeat(16));
    assert_eq!(entry["routes"], serde_json::json!(["pay"]));
    assert!(entry.get("error").is_none());
    // The peer is a pseudonym, never the raw address.
    let peer = entry["peer"].as_str().ok_or("no peer")?;
    assert!(!peer.contains("127.0.0.1") && !peer.is_empty());
    let text = std::fs::read(&path)?;
    let report = verify::verify(text.as_slice(), &[sink.public_key()])?;
    assert_eq!(report.entries, 1);
    Ok(())
}

#[tokio::test]
async fn a_refused_registration_is_logged_with_its_code_and_both_identities() -> Res<()> {
    let (addr, sink, path) = audited("registration-refused").await?;
    let mut lie = registration(8, &["pay"], &[]);
    lie.spiffe_id = "spiffe://example.org/someone-else".into();
    let refused = register(&connector_config(&addr, lie)?).await;
    assert!(
        matches!(refused, Err(ConnectError::Rejected(r)) if r.code == RejectCode::IdentityMismatch)
    );
    let entries = logged(&sink, &path, "registration")?;
    assert_eq!(entries.len(), 1, "{entries:?}");
    let entry = &entries[0];
    assert_eq!(entry["decision"], "refused");
    assert_eq!(entry["error"], RejectCode::IdentityMismatch.id());
    assert_eq!(entry["certificate"], CONNECTOR);
    assert_eq!(entry["spiffe_id"], "spiffe://example.org/someone-else");
    assert!(
        entry["reason"]
            .as_str()
            .is_some_and(|r| r.contains(CONNECTOR))
    );
    Ok(())
}

/// ADR 0017: the server a connector reports is in its registration
/// entry, and when its tools change under `Reregister` it registers
/// again with the new digest, which the log shows.
#[tokio::test]
async fn the_reported_server_and_a_change_of_tools_are_logged() -> Res<()> {
    use tunnelward_connector::{Connector, ConnectorEvent, Described, Gateways, OnChange, Pinned};
    let (addr, sink, path) = audited("registration-described").await?;
    let tool = |d: &str| serde_json::json!({ "name": "transfer", "description": d });
    let pinned = Pinned::new(
        Described::new("payments", "2.1.0", &[tool("Moves money.")])?,
        OnChange::Reregister,
    );
    let mut config = common::supervised(Gateways::Static(vec![common::addr(&addr)?]), &addr)?;
    config.connections_per_gateway = 1;
    config.session.pinned = Some(pinned.clone());
    let connector = Connector::start(
        config,
        common::gated_service(Arc::new(tokio::sync::Semaphore::new(64))),
    );
    let mut events = connector.events();
    let registered = |e: &ConnectorEvent| matches!(e, ConnectorEvent::Registered { .. });
    while !registered(&events.recv().await?) {}
    let before = hex(&pinned.descriptor().tools_digest);
    let changed = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": { "tools": [tool("Moves money, and more.")] } });
    let request = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    assert!(pinned.check_exchange(&[request], &[changed]).is_err());
    while !registered(&events.recv().await?) {}
    drop(connector);
    let entries = logged(&sink, &path, "registration")?;
    let accepted: Vec<_> = entries
        .iter()
        .filter(|e| e["decision"] == "accepted")
        .collect();
    assert!(accepted.len() >= 2, "{entries:?}");
    assert_eq!(accepted[0]["server"], "payments");
    assert_eq!(accepted[0]["server_version"], "2.1.0");
    assert_eq!(accepted[0]["tools_digest"], before.as_str());
    let after = hex(&pinned.descriptor().tools_digest);
    assert_ne!(before, after);
    assert_eq!(accepted[accepted.len() - 1]["tools_digest"], after.as_str());
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    tunnelward_audit::hex(bytes)
}
