// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Pools: load-aware selection, capacity, the bounded wait queue (FR-8),
//! routes kept after their connectors leave (G4), and pluggable route
//! resolution (G3).

mod common;

use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use tokio::sync::Semaphore;
use tw_gateway::{Config, Gateway, LongestFirst, RouteResolver, SendError, Target};

use common::{
    Res, eventually, gateway_config, get, registration, send, start, start_connector,
    start_gated_connector,
};

fn config(max_wait_ms: u64, keep_ms: u64) -> Res<Config> {
    Ok(Config {
        max_wait: Duration::from_millis(max_wait_ms),
        routes_keep_time: Duration::from_millis(keep_ms),
        ..gateway_config()?
    })
}

/// Starts a request on its own task; it completes when the gate opens.
fn spawn_get(gateway: &Gateway, uri: &'static str) -> tokio::task::JoinHandle<Res<String>> {
    let g = gateway.clone();
    tokio::spawn(async move { get(&g, uri).await.map(|(_, body)| body) })
}

#[tokio::test]
async fn the_less_loaded_connector_takes_the_next_request() -> Res<()> {
    let (gateway, addr) = start(config(2000, 0)?).await?;
    let gate = Arc::new(Semaphore::new(0));
    let _a =
        start_gated_connector(&addr, "a", registration(1, &["mcp"], &[]), gate.clone()).await?;
    let _b = start_connector(&addr, "b", registration(2, &["mcp"], &[])).await?;
    // Requests sent while "a" holds one in flight must all go to "b".
    // Until "a" has one, a request may land on either, so send until it does.
    let mut held = Vec::new();
    while gateway.in_flight() == 0 {
        let pending = spawn_get(&gateway, "http://x.org/mcp/hold");
        tokio::time::sleep(Duration::from_millis(20)).await;
        if pending.is_finished() {
            assert_eq!(pending.await??, "b GET /mcp/hold");
        } else {
            held.push(pending);
        }
    }
    for _ in 0..20 {
        assert_eq!(get(&gateway, "http://x.org/mcp/x").await?.1, "b GET /mcp/x");
    }
    gate.add_permits(held.len());
    for h in held {
        assert_eq!(h.await??, "a GET /mcp/hold");
    }
    eventually("in-flight count back to 0", || gateway.in_flight() == 0).await
}

#[tokio::test]
async fn a_full_connector_makes_requests_wait_for_a_slot() -> Res<()> {
    let (gateway, addr) = start(config(5000, 0)?).await?;
    let gate = Arc::new(Semaphore::new(0));
    let one_slot = tw_proto::Register {
        capacity: 1,
        ..registration(1, &["mcp"], &[])
    };
    let _a = start_gated_connector(&addr, "a", one_slot, gate.clone()).await?;
    let first = spawn_get(&gateway, "http://x.org/mcp/1");
    eventually("the first request in flight", || gateway.in_flight() == 1).await?;
    let second = spawn_get(&gateway, "http://x.org/mcp/2");
    eventually("the second request waiting", || gateway.waiting() == 1).await?;
    assert_eq!(gateway.in_flight(), 1, "capacity 1 is never exceeded");
    gate.add_permits(2);
    assert_eq!(first.await??, "a GET /mcp/1");
    assert_eq!(second.await??, "a GET /mcp/2");
    Ok(())
}

#[tokio::test]
async fn waiting_past_max_wait_is_unavailable_with_retry_after() -> Res<()> {
    let (gateway, addr) = start(config(100, 0)?).await?;
    let gate = Arc::new(Semaphore::new(0));
    let one_slot = tw_proto::Register {
        capacity: 1,
        ..registration(1, &["mcp"], &[])
    };
    let _a = start_gated_connector(&addr, "a", one_slot, gate.clone()).await?;
    let first = spawn_get(&gateway, "http://x.org/mcp/1");
    eventually("the first request in flight", || gateway.in_flight() == 1).await?;
    let err = send(&gateway, "http://x.org/mcp/2").await?;
    match err {
        Err(SendError::Unavailable { retry_after }) => {
            assert!(retry_after >= Duration::from_secs(1));
        }
        other => return Err(format!("expected Unavailable, got {other:?}").into()),
    }
    gate.add_permits(1);
    assert_eq!(first.await??, "a GET /mcp/1");
    Ok(())
}

#[tokio::test]
async fn the_wait_queue_is_bounded() -> Res<()> {
    let mut cfg = config(5000, 0)?;
    cfg.limits.max_waiting_per_route = 1;
    let (gateway, addr) = start(cfg).await?;
    let gate = Arc::new(Semaphore::new(0));
    let one_slot = tw_proto::Register {
        capacity: 1,
        ..registration(1, &["mcp"], &[])
    };
    let _a = start_gated_connector(&addr, "a", one_slot, gate.clone()).await?;
    let first = spawn_get(&gateway, "http://x.org/mcp/1");
    eventually("the first request in flight", || gateway.in_flight() == 1).await?;
    let second = spawn_get(&gateway, "http://x.org/mcp/2");
    eventually("the second request waiting", || gateway.waiting() == 1).await?;
    // The queue holds one; the third is refused at once, not after max_wait.
    let started = tokio::time::Instant::now();
    let third = send(&gateway, "http://x.org/mcp/3").await?;
    assert!(
        matches!(third, Err(SendError::Unavailable { .. })),
        "{third:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    gate.add_permits(2);
    assert_eq!(first.await??, "a GET /mcp/1");
    assert_eq!(second.await??, "a GET /mcp/2");
    Ok(())
}

#[tokio::test]
async fn in_flight_is_released_when_a_response_body_is_dropped_unread() -> Res<()> {
    let (gateway, addr) = start(config(2000, 0)?).await?;
    let _a = start_connector(&addr, "a", registration(1, &["mcp"], &[])).await?;
    let response = send(&gateway, "http://x.org/mcp/x").await??;
    assert_eq!(gateway.in_flight(), 1, "the body is still open");
    drop(response);
    assert_eq!(gateway.in_flight(), 0);
    let read = send(&gateway, "http://x.org/mcp/y").await??;
    let _bytes = read.into_body().collect().await?;
    assert_eq!(gateway.in_flight(), 0);
    Ok(())
}

#[tokio::test]
async fn a_route_whose_connectors_left_is_unavailable_until_the_keep_time_ends() -> Res<()> {
    let (gateway, addr) = start(config(100, 400)?).await?;
    let serving = start_connector(&addr, "a", registration(1, &["mcp"], &[])).await?;
    serving.abort();
    eventually("the connector to leave", || gateway.routes().is_empty()).await?;
    let kept = send(&gateway, "http://x.org/mcp/x").await?;
    assert!(
        matches!(kept, Err(SendError::Unavailable { .. })),
        "{kept:?}"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let gone = send(&gateway, "http://x.org/mcp/x").await?;
    assert!(matches!(gone, Err(SendError::NoRoute)), "{gone:?}");
    Ok(())
}

#[tokio::test]
async fn a_request_waiting_on_a_kept_route_is_served_when_a_connector_returns() -> Res<()> {
    let (gateway, addr) = start(config(5000, 60_000)?).await?;
    let serving = start_connector(&addr, "a", registration(1, &["mcp"], &[])).await?;
    serving.abort();
    eventually("the connector to leave", || gateway.routes().is_empty()).await?;
    let waiting = spawn_get(&gateway, "http://x.org/mcp/x");
    eventually("the request to wait", || gateway.waiting() == 1).await?;
    let _back = start_connector(&addr, "b", registration(2, &["mcp"], &[])).await?;
    assert_eq!(waiting.await??, "b GET /mcp/x");
    Ok(())
}

/// Prefers the shortest route instead of the longest.
#[derive(Debug)]
struct ShortestFirst;

impl RouteResolver for ShortestFirst {
    fn rank(&self, route: &str, domains: &[String], target: &Target) -> Option<u32> {
        let longest = LongestFirst.rank(route, domains, target)?;
        Some(u32::MAX - longest)
    }
}

#[tokio::test]
async fn the_route_resolver_is_pluggable() -> Res<()> {
    let cfg = Config {
        resolver: Arc::new(ShortestFirst),
        ..config(2000, 0)?
    };
    let (gateway, addr) = start(cfg).await?;
    let _a = start_connector(&addr, "short", registration(1, &["mcp"], &[])).await?;
    let _b = start_connector(&addr, "long", registration(2, &["mcp/tools"], &[])).await?;
    assert_eq!(
        get(&gateway, "http://x.org/mcp/tools/1").await?.1,
        "short GET /mcp/tools/1"
    );
    Ok(())
}
