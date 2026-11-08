// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Draining (FR-7) and lease expiry: new requests stop at once, in-flight
//! ones finish or are reset at the deadline.

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tunnelward_gateway::{Config, DrainTarget, Gateway, SendError};
use tunnelward_proto::ConnectorId;

use common::{
    Res, WAIT, eventually, gateway_config, get, registration, send, start, start_connector,
    start_gated_connector,
};

fn config(max_wait_ms: u64) -> Res<Config> {
    Ok(Config {
        max_wait: Duration::from_millis(max_wait_ms),
        ..gateway_config()?
    })
}

fn spawn_get(gateway: &Gateway, uri: &'static str) -> tokio::task::JoinHandle<Res<String>> {
    let g = gateway.clone();
    tokio::spawn(async move { get(&g, uri).await.map(|(_, body)| body) })
}

/// A gateway with one gated connector serving `mcp` and one request held
/// in flight on it; the request finishes when a permit is added.
async fn one_request_held() -> Res<(
    Gateway,
    Arc<Semaphore>,
    tokio::task::JoinHandle<Res<String>>,
)> {
    let (gateway, addr) = start(config(100)?).await?;
    let gate = Arc::new(Semaphore::new(0));
    let reg = registration(1, &["mcp"], &[]);
    let _serving = start_gated_connector(&addr, "a", reg, gate.clone()).await?;
    let held = spawn_get(&gateway, "http://x/mcp/held");
    eventually("a request in flight", || gateway.in_flight() == 1).await?;
    Ok((gateway, gate, held))
}

fn drain_in_background(
    gateway: &Gateway,
    target: DrainTarget,
) -> tokio::task::JoinHandle<tunnelward_gateway::DrainReport> {
    let g = gateway.clone();
    tokio::spawn(async move { g.drain(&target, WAIT).await })
}

async fn assert_unavailable(gateway: &Gateway, uri: &str) -> Res<()> {
    let sent = send(gateway, uri).await?;
    assert!(
        matches!(sent, Err(SendError::Unavailable { .. })),
        "{sent:?}"
    );
    Ok(())
}

#[tokio::test]
async fn draining_stops_new_requests_and_lets_in_flight_ones_finish() -> Res<()> {
    let (gateway, gate, held) = one_request_held().await?;
    let drain = drain_in_background(&gateway, DrainTarget::Route("mcp".into()));
    eventually("the connector to be draining", || gateway.draining() == 1).await?;
    // No new request reaches a draining connector; with no other, it waits and gives up.
    assert_unavailable(&gateway, "http://x/mcp/new").await?;

    gate.add_permits(1);
    assert_eq!(held.await??, "a GET /mcp/held");
    let report = drain.await?;
    assert_eq!((report.sessions, report.finished, report.reset), (1, 1, 0));
    eventually("the connector to leave", || gateway.routes().is_empty()).await
}

#[tokio::test]
async fn requests_still_running_at_the_deadline_are_reset() -> Res<()> {
    let (gateway, addr) = start(config(100)?).await?;
    let gate = Arc::new(Semaphore::new(0));
    let _a = start_gated_connector(&addr, "a", registration(1, &["mcp"], &[]), gate).await?;
    let stuck = spawn_get(&gateway, "http://x/mcp/stuck");
    eventually("a request in flight", || gateway.in_flight() == 1).await?;
    let report = gateway
        .drain(
            &DrainTarget::Connector(ConnectorId([1; 16])),
            Duration::from_millis(200),
        )
        .await;
    assert_eq!((report.sessions, report.finished, report.reset), (1, 0, 1));
    // Reset means at once, not when some timeout fires.
    let outcome = tokio::time::timeout(Duration::from_secs(1), stuck).await;
    let failed = outcome.map_err(|_| "the reset request was still waiting after 1 s")??;
    assert!(failed.is_err(), "the reset request fails");
    eventually("the connector to leave", || gateway.routes().is_empty()).await
}

#[tokio::test]
async fn draining_one_connector_leaves_the_others_serving() -> Res<()> {
    let (gateway, addr) = start(config(2000)?).await?;
    let _a = start_connector(&addr, "a", registration(1, &["mcp"], &[])).await?;
    let _b = start_connector(&addr, "b", registration(2, &["mcp"], &[])).await?;
    let report = gateway
        .drain(&DrainTarget::Connector(ConnectorId([1; 16])), WAIT)
        .await;
    assert_eq!(report.sessions, 1);
    for _ in 0..10 {
        assert_eq!(get(&gateway, "http://x/mcp/1").await?.1, "b GET /mcp/1");
    }
    Ok(())
}

#[tokio::test]
async fn a_drain_that_matches_nothing_reports_nothing() -> Res<()> {
    let (gateway, _) = start(config(100)?).await?;
    let report = gateway
        .drain(&DrainTarget::Route("nothing".into()), WAIT)
        .await;
    assert_eq!((report.sessions, report.finished, report.reset), (0, 0, 0));
    Ok(())
}

#[tokio::test]
async fn an_expired_lease_drains_the_connection() -> Res<()> {
    let cfg = Config {
        lease_secs: 1,
        drain_grace: Duration::from_millis(200),
        ..config(100)?
    };
    let (gateway, addr) = start(cfg).await?;
    let _a = start_connector(&addr, "a", registration(1, &["mcp"], &[])).await?;
    assert_eq!(gateway.routes(), vec!["mcp".to_owned()]);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    eventually("the expired connection to go", || {
        gateway.routes().is_empty()
    })
    .await
}
