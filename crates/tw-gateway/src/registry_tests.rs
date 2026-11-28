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

/// A live link over an in-memory HTTP/2 connection whose server end
/// answers nothing the tests send; they only take and free its slots.
async fn link() -> Result<Link, String> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let (client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let service = hyper::service::service_fn(|_req| async {
            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::new())))
        });
        let _ended = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(server), service)
            .await;
    });
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
            .await
            .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ended = conn.await;
    });
    Ok(Link {
        sender,
        grant: 16,
        peer: None,
        kill: Arc::new(crate::kill::KillSwitch::default()),
        attested: None,
        tls: crate::admin::Tls::default(),
    })
}

/// A slot that frees while requests wait goes to the one that has
/// waited longest: a request arriving at that moment queues behind
/// them instead of taking it (the waiting-queue bypass).
#[tokio::test]
async fn a_freed_slot_goes_to_the_queue_not_a_newcomer() -> Result<(), String> {
    let registry = Registry::default();
    let _session = registry.insert(claim("mcp"), link().await?);
    let Pick::Ready(first) = registry.pick(&LongestFirst, &target("/mcp/1")) else {
        return Err("the free slot was not taken".into());
    };
    let Pick::Wait(route) = registry.pick(&LongestFirst, &target("/mcp/2")) else {
        return Err("a full connector did not make the request wait".into());
    };
    let queued = registry.enqueue(&route, 8).ok_or("queue full")?;
    drop(first);
    assert!(
        matches!(
            registry.pick(&LongestFirst, &target("/mcp/3")),
            Pick::Wait(_)
        ),
        "a newcomer took the slot ahead of the queue"
    );
    assert!(
        matches!(
            registry.pick_queued(&LongestFirst, &target("/mcp/2"), &queued),
            Pick::Ready(_)
        ),
        "the longest waiter did not get the slot"
    );
    Ok(())
}
