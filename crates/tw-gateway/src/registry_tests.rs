// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Unit tests for the registry.

use std::time::Duration;

use tunnelward_proto::{ConnectorId, PROTOCOL_VERSION, Register};

use super::*;
use crate::LongestFirst;
use crate::claims::Rules;

const RULES: Rules<'static> = Rules {
    max_domains: 8,
    max_routes_per_identity: 8,
    owners: &[],
};

fn claim(route: &str) -> Register {
    Register {
        version: PROTOCOL_VERSION,
        connector_id: ConnectorId([1; 16]),
        spiffe_id: "spiffe://example.org/connector".into(),
        routes: vec![route.into()],
        domains: Vec::new(),
        mcp: None,
        attestation: None,
        capacity: 1,
    }
}

fn target(path: &str) -> Target {
    Target {
        host: None,
        path: path.into(),
    }
}

/// The connector reads `Accept` before its routes are in the
/// registry; a request in between must wait for it, not be told
/// that nothing serves the route.
#[test]
fn a_route_being_admitted_is_waited_for_not_refused() -> Result<(), String> {
    let registry = Registry::default();
    assert!(matches!(
        registry.pick(&LongestFirst, &target("/mcp/x")),
        Pick::None
    ));
    let reservation = registry.reserve(&claim("mcp"), &RULES).map_err(|e| e.1)?;
    let pick = registry.pick(&LongestFirst, &target("/mcp/x"));
    assert!(
        matches!(pick, Pick::Wait(ref r) if r == "mcp"),
        "wait for mcp"
    );
    assert!(matches!(
        registry.pick(&LongestFirst, &target("/other")),
        Pick::None
    ));
    drop(reservation);
    assert!(matches!(
        registry.pick(&LongestFirst, &target("/mcp/x")),
        Pick::None
    ));
    Ok(())
}

/// An admission that fails wakes the requests waiting for it, so
/// they learn at once that nothing serves the route.
#[tokio::test]
async fn a_reservation_that_ends_wakes_the_waiters() -> Result<(), String> {
    let registry = Registry::default();
    let reservation = registry.reserve(&claim("mcp"), &RULES).map_err(|e| e.1)?;
    let changed = registry.changed();
    let notified = changed.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    drop(reservation);
    tokio::time::timeout(Duration::from_millis(500), notified)
        .await
        .map_err(|_| "no wake-up when the reservation ended".to_owned())
}
