// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The supervised connector (FR-1, G6 to G8): several connections to
//! several gateways, reconnects, lease renewal with no failed request,
//! graceful shutdown, DNS discovery and events.

mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tokio::sync::{Semaphore, broadcast};
use tw_connector::{Connector, ConnectorConfig, ConnectorEvent, Gateways};
use tw_gateway::{Config, DrainTarget};
use tw_proto::ConnectorId;

use common::{
    Res, WAIT, connector_config, echo, eventually, gateway_config, get, registration, start,
};

type Body = Full<Bytes>;

fn echo_service() -> impl hyper::service::Service<
    Request<Incoming>,
    Response = Response<Body>,
    Error = Infallible,
    Future: Send,
> + Clone
+ Send
+ Sync
+ 'static {
    service_fn(|req: Request<Incoming>| std::future::ready(Ok::<_, Infallible>(echo("c", &req))))
}

/// A service whose every request waits for a permit from `gate`.
fn gated_service(
    gate: Arc<Semaphore>,
) -> impl hyper::service::Service<
    Request<Incoming>,
    Response = Response<Body>,
    Error = Infallible,
    Future: Send,
> + Clone
+ Send
+ Sync
+ 'static {
    service_fn(move |req: Request<Incoming>| {
        let gate = gate.clone();
        async move {
            drop(gate.acquire_owned().await);
            Ok::<_, Infallible>(echo("c", &req))
        }
    })
}

fn supervised(gateways: Gateways, any_addr: &str) -> Res<ConnectorConfig> {
    let mut config = ConnectorConfig::new(
        gateways,
        connector_config(any_addr, registration(1, &["mcp"], &[]))?,
    );
    config.backoff_base = Duration::from_millis(50);
    config.backoff_cap = Duration::from_millis(200);
    Ok(config)
}

fn addr(text: &str) -> Res<SocketAddr> {
    Ok(text.parse()?)
}

/// Two gateways and one supervised connector for both.
async fn two_gateways_one_connector() -> Res<(tw_gateway::Gateway, tw_gateway::Gateway, Connector)>
{
    let (a, a_addr) = start(gateway_config()?).await?;
    let (b, b_addr) = start(gateway_config()?).await?;
    let connector = start_supervised(&[&a_addr, &b_addr])?;
    Ok((a, b, connector))
}

/// A supervised echo connector for the gateways at `addrs`.
fn start_supervised(addrs: &[&str]) -> Res<Connector> {
    let list = addrs.iter().map(|a| addr(a)).collect::<Res<Vec<_>>>()?;
    let any = addrs.first().copied().unwrap_or("127.0.0.1:1");
    Ok(Connector::start(
        supervised(Gateways::Static(list), any)?,
        echo_service(),
    ))
}

async fn expect_disconnect_then_register(
    events: &mut broadcast::Receiver<ConnectorEvent>,
) -> Res<()> {
    expect_event(events, "Disconnected", |e| {
        matches!(e, ConnectorEvent::Disconnected { .. })
    })
    .await?;
    expect_event(events, "Registered", |e| {
        matches!(e, ConnectorEvent::Registered { .. })
    })
    .await?;
    Ok(())
}

/// Waits for an event `want` accepts, failing after [`WAIT`].
async fn expect_event(
    events: &mut broadcast::Receiver<ConnectorEvent>,
    what: &str,
    want: impl Fn(&ConnectorEvent) -> bool,
) -> Res<ConnectorEvent> {
    let found = tokio::time::timeout(WAIT, async {
        loop {
            match events.recv().await {
                Ok(event) if want(&event) => return Ok(event),
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => return Err(e),
            }
        }
    });
    Ok(found.await.map_err(|_| format!("no {what} event"))??)
}

#[tokio::test]
async fn it_keeps_two_connections_to_each_gateway() -> Res<()> {
    let (a, b, connector) = two_gateways_one_connector().await?;
    eventually("two connections on each gateway", || {
        a.routes().len() == 2 && b.routes().len() == 2
    })
    .await?;
    assert_eq!(get(&a, "http://x/mcp/a").await?.1, "c GET /mcp/a");
    assert_eq!(get(&b, "http://x/mcp/b").await?.1, "c GET /mcp/b");
    assert!(connector.shutdown(WAIT).await);
    eventually("both gateways empty", || {
        a.routes().is_empty() && b.routes().is_empty()
    })
    .await
}

#[tokio::test]
async fn it_reconnects_after_its_connections_are_drained() -> Res<()> {
    let (gateway, gw_addr) = start(gateway_config()?).await?;
    let connector = start_supervised(&[&gw_addr])?;
    let mut events = connector.events();
    eventually("two connections", || gateway.routes().len() == 2).await?;
    let report = gateway
        .drain(&DrainTarget::Connector(ConnectorId([1; 16])), WAIT)
        .await;
    assert_eq!(report.sessions, 2);
    expect_disconnect_then_register(&mut events).await?;
    eventually("two connections again", || gateway.routes().len() == 2).await?;
    assert_eq!(
        get(&gateway, "http://x/mcp/back").await?.1,
        "c GET /mcp/back"
    );
    assert!(connector.shutdown(WAIT).await);
    Ok(())
}

#[tokio::test]
async fn lease_renewal_loses_no_request() -> Res<()> {
    let config = Config {
        lease_secs: 1,
        drain_grace: Duration::from_secs(5),
        ..gateway_config()?
    };
    let (gateway, gw_addr) = start(config).await?;
    let connector = Connector::start(
        supervised(Gateways::Static(vec![addr(&gw_addr)?]), &gw_addr)?,
        echo_service(),
    );
    let mut events = connector.events();
    eventually("two connections", || gateway.routes().len() == 2).await?;
    let until = tokio::time::Instant::now() + Duration::from_millis(3500);
    let mut sent = 0_u32;
    while tokio::time::Instant::now() < until {
        let (status, body) = get(&gateway, "http://x/mcp/n").await?;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, "c GET /mcp/n"),
            "request {sent}"
        );
        sent += 1;
    }
    expect_event(&mut events, "Renewing", |e| {
        matches!(e, ConnectorEvent::Renewing { .. })
    })
    .await?;
    assert!(sent > 100, "only {sent} requests in 3.5 s");
    assert!(connector.shutdown(WAIT).await);
    Ok(())
}

#[tokio::test]
async fn shutdown_lets_requests_finish_and_reports_it() -> Res<()> {
    let (gateway, gw_addr) = start(Config {
        max_wait: Duration::from_millis(100),
        ..gateway_config()?
    })
    .await?;
    let gate = Arc::new(Semaphore::new(0));
    let connector = Connector::start(
        supervised(Gateways::Static(vec![addr(&gw_addr)?]), &gw_addr)?,
        gated_service(gate.clone()),
    );
    eventually("two connections", || gateway.routes().len() == 2).await?;
    let g = gateway.clone();
    let held = tokio::spawn(async move { get(&g, "http://x/mcp/held").await });
    eventually("a request in flight", || gateway.in_flight() == 1).await?;
    let stopping = tokio::spawn(connector.shutdown(WAIT));
    tokio::time::sleep(Duration::from_millis(100)).await;
    gate.add_permits(1);
    assert_eq!(held.await??.1, "c GET /mcp/held");
    assert!(stopping.await?, "every request finished in time");
    eventually("the gateway empty", || gateway.routes().is_empty()).await
}

#[tokio::test]
async fn shutdown_reports_requests_still_running_at_the_deadline() -> Res<()> {
    let (gateway, gw_addr) = start(gateway_config()?).await?;
    let gate = Arc::new(Semaphore::new(0));
    let connector = Connector::start(
        supervised(Gateways::Static(vec![addr(&gw_addr)?]), &gw_addr)?,
        gated_service(gate),
    );
    eventually("two connections", || gateway.routes().len() == 2).await?;
    let g = gateway.clone();
    let _held = tokio::spawn(async move { get(&g, "http://x/mcp/held").await });
    eventually("a request in flight", || gateway.in_flight() == 1).await?;
    assert!(!connector.shutdown(Duration::from_millis(200)).await);
    Ok(())
}

#[tokio::test]
async fn gateways_are_found_through_dns() -> Res<()> {
    let (gateway, gw_addr) = start(gateway_config()?).await?;
    let port = addr(&gw_addr)?.port();
    let dns = Gateways::Dns {
        name: "localhost".into(),
        port,
        refresh: Duration::from_secs(60),
    };
    let connector = Connector::start(supervised(dns, &gw_addr)?, echo_service());
    // `localhost` may also resolve to ::1, where nothing listens; the
    // connections to 127.0.0.1 are what count.
    eventually("two connections through localhost", || {
        gateway.routes().len() == 2
    })
    .await?;
    assert_eq!(get(&gateway, "http://x/mcp/dns").await?.1, "c GET /mcp/dns");
    assert!(connector.shutdown(WAIT).await);
    Ok(())
}

#[tokio::test]
async fn an_unreachable_gateway_is_reported_and_retried() -> Res<()> {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await?
        .local_addr()?;
    let connector = Connector::start(
        supervised(Gateways::Static(vec![closed]), &closed.to_string())?,
        echo_service(),
    );
    let mut events = connector.events();
    let first = expect_event(&mut events, "Failed", |e| {
        matches!(e, ConnectorEvent::Failed { .. })
    })
    .await?;
    let second = expect_event(&mut events, "a second Failed", |e| {
        matches!(e, ConnectorEvent::Failed { .. })
    })
    .await?;
    assert!(matches!(first, ConnectorEvent::Failed { gateway, .. } if gateway == closed));
    assert!(matches!(second, ConnectorEvent::Failed { .. }));
    assert!(connector.shutdown(WAIT).await);
    Ok(())
}
