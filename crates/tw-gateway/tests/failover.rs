// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! FR-1's acceptance test: kill a gateway under load. Its in-flight
//! requests fail at once, the other gateway's requests finish, and new
//! requests succeed on the other gateway within one backoff window.

mod common;

use std::sync::Arc;
use std::time::Duration;

use hyper::StatusCode;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, broadcast};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tunnelward_connector::{Connector, ConnectorEvent, Gateways};
use tunnelward_gateway::Gateway;

use common::{Res, WAIT, addr, eventually, gated_service, gateway_config, get, start, supervised};

/// Requests held in flight on each gateway when the other one dies.
const LOAD: u32 = 8;

/// A TCP relay to `target`. Aborting the returned task drops every
/// relayed socket at once, which is what the connector and the gateway
/// see when the gateway's process is killed.
async fn relay(target: String) -> Res<(String, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    let task = tokio::spawn(async move {
        let mut links = JoinSet::new();
        while let Ok((mut inbound, _)) = listener.accept().await {
            let target = target.clone();
            links.spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(target).await {
                    let _closed = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    Ok((addr, task))
}

/// Sends `LOAD` requests through `gateway`, each on its own task.
fn load(gateway: &Gateway, tag: &str) -> Vec<JoinHandle<Res<(StatusCode, String)>>> {
    (0..LOAD)
        .map(|n| {
            let gateway = gateway.clone();
            let uri = format!("http://x/mcp/{tag}/{n}");
            tokio::spawn(async move { get(&gateway, &uri).await })
        })
        .collect()
}

/// Two gateways, with `a` behind a relay, and a gated connector holding
/// two connections to each.
struct Rig {
    a: Gateway,
    b: Gateway,
    relay: JoinHandle<()>,
    gate: Arc<Semaphore>,
    connector: Connector,
    backoff_cap: Duration,
}

async fn rig() -> Res<Rig> {
    let (a, a_addr) = start(gateway_config()?).await?;
    let (b, b_addr) = start(gateway_config()?).await?;
    let (relay_addr, relay) = relay(a_addr).await?;
    let gate = Arc::new(Semaphore::new(0));
    let list = vec![addr(&relay_addr)?, addr(&b_addr)?];
    let config = supervised(Gateways::Static(list), &b_addr)?;
    let backoff_cap = config.backoff_cap;
    let connector = Connector::start(config, gated_service(gate.clone()));
    eventually("two connections on each gateway", || {
        a.routes().len() == 2 && b.routes().len() == 2
    })
    .await?;
    Ok(Rig {
        a,
        b,
        relay,
        gate,
        connector,
        backoff_cap,
    })
}

/// Every request fails, and none by timing out.
async fn all_fail_promptly(requests: Vec<JoinHandle<Res<(StatusCode, String)>>>) -> Res<()> {
    for request in requests {
        match request.await? {
            Ok(answer) => return Err(format!("succeeded on a killed gateway: {answer:?}").into()),
            Err(e) if e.to_string().contains("timed out") => {
                return Err(format!("failed late: {e}").into());
            }
            Err(_) => {}
        }
    }
    Ok(())
}

/// Every request succeeds with 200.
async fn all_succeed(requests: Vec<JoinHandle<Res<(StatusCode, String)>>>) -> Res<()> {
    for request in requests {
        let (status, body) = request.await??;
        if status != StatusCode::OK {
            return Err(format!("{status} {body}").into());
        }
    }
    Ok(())
}

/// Waits for `count` `Disconnected` events.
async fn disconnects(events: &mut broadcast::Receiver<ConnectorEvent>, count: u32) -> Res<()> {
    let mut seen = 0;
    while seen < count {
        if let ConnectorEvent::Disconnected { .. } = events.recv().await? {
            seen += 1;
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_killed_gateway_fails_only_its_own_requests() -> Res<()> {
    let rig = rig().await?;
    let mut events = rig.connector.events();
    let (on_a, on_b) = (load(&rig.a, "a"), load(&rig.b, "b"));
    eventually("requests in flight on both", || {
        rig.a.in_flight() == LOAD && rig.b.in_flight() == LOAD
    })
    .await?;

    let killed = Instant::now();
    rig.relay.abort();
    all_fail_promptly(on_a).await?;
    assert!(
        killed.elapsed() < WAIT / 2,
        "took {:?} to fail",
        killed.elapsed()
    );
    eventually("the killed gateway's routes gone", || {
        rig.a.routes().is_empty()
    })
    .await?;

    rig.gate.add_permits(usize::MAX >> 4);
    all_succeed(on_b).await?;
    let after = Instant::now();
    assert_eq!(get(&rig.b, "http://x/mcp/after").await?.0, StatusCode::OK);
    assert!(
        after.elapsed() < rig.backoff_cap,
        "took {:?}",
        after.elapsed()
    );
    disconnects(&mut events, 2).await?;
    assert!(rig.connector.shutdown(WAIT).await);
    Ok(())
}
