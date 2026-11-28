// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The five defect classes of the mu-cranker-router audit, as Tunnelward
//! tests (M1's exit criterion): dark host bypass, per-domain leak, header
//! flood, malformed frame blast radius, waiting-queue bypass. Each states
//! the guarantee Tunnelward makes against that class and checks it end to
//! end over loopback.

mod common;

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tokio::sync::Semaphore;
use tunnelward_connector::register;
use tunnelward_gateway::{Config, DrainTarget, Gateway, Redaction, SendError};
use tunnelward_proto::{ConnectorId, Register};

use common::ingress::{h1, ingress_config, start_ingress};
use common::{
    Res, connector_config, eventually, gateway_config, get, registration, send, start,
    start_connector,
};

type Error = Box<dyn std::error::Error + Send + Sync>;
type Answer = Response<BoxBody<Bytes, Error>>;

fn connections(gateway: &Gateway) -> usize {
    gateway.inventory(Redaction::Public).connections
}

async fn gateway() -> Res<(Gateway, String)> {
    start(Config {
        max_wait: Duration::from_millis(200),
        ..gateway_config()?
    })
    .await
}

/// Registers a connector answering with `answer`, serving on its own task.
async fn serve(
    addr: &str,
    register_as: Register,
    answer: fn(&Request<Incoming>) -> Answer,
) -> Res<tokio::task::JoinHandle<()>> {
    let session = register(&connector_config(addr, register_as)?).await?;
    Ok(tokio::spawn(async move {
        let service = service_fn(move |req| std::future::ready(Ok::<_, Infallible>(answer(&req))));
        let _ended = session.serve(service).await;
    }))
}

fn text(body: &str) -> BoxBody<Bytes, Error> {
    Full::new(Bytes::from(body.to_owned()))
        .map_err(|never| match never {})
        .boxed()
}

/// A body that sends one chunk and then fails, so the connector resets
/// the stream part-way through the answer.
struct Broken(bool);

impl Body for Broken {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        if self.0 {
            return Poll::Ready(Some(Err("cut part-way".into())));
        }
        self.0 = true;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"part")))))
    }
}

/// `/mcp/broken` resets its stream, `/mcp/flood` answers with a header
/// list over the gateway's limit; anything else is answered `ok <path>`.
fn hostile(req: &Request<Incoming>) -> Answer {
    match req.uri().path() {
        "/mcp/broken" => Response::new(Broken(false).boxed()),
        "/mcp/flood" => {
            let mut response = Response::new(text("flood"));
            for i in 0..80 {
                let name = format!("x-flood-{i}");
                let value = "v".repeat(1024);
                if let (Ok(n), Ok(v)) = (
                    hyper::header::HeaderName::try_from(name),
                    hyper::header::HeaderValue::try_from(value),
                ) {
                    response.headers_mut().insert(n, v);
                }
            }
            response
        }
        path => Response::new(text(&format!("ok {path}"))),
    }
}

/// Dark host bypass: a dark connection takes no new request by any of
/// its claims (a route or the catch-all, on its domain), and the work
/// goes to a lit connection when there is one.
#[tokio::test]
async fn a_dark_connection_is_not_reached_by_domain_route_or_catch_all() -> Res<()> {
    let (gateway, addr) = gateway().await?;
    let _dark = start_connector(
        &addr,
        "dark",
        registration(1, &["mcp", "*"], &["a.example"]),
    )
    .await?;
    eventually("registered", || gateway.routes().len() == 2).await?;
    assert!(gateway.set_dark(DrainTarget::Connector(ConnectorId([1; 16])), true));
    none_reached(&gateway, &DARK_CLAIMS).await?;
    let _lit =
        start_connector(&addr, "lit", registration(2, &["mcp", "*"], &["a.example"])).await?;
    eventually("both connected", || connections(&gateway) == 2).await?;
    all_served_by(&gateway, &DARK_CLAIMS, "lit ").await
}

/// A request for each of the dark connector's claims: its route, and
/// the catch-all, on its domain.
const DARK_CLAIMS: [&str; 2] = ["http://a.example/mcp/x", "http://a.example/other"];

/// Every request in `uris` waits and is unavailable: none is served.
async fn none_reached(gateway: &Gateway, uris: &[&str]) -> Res<()> {
    for uri in uris {
        let sent = send(gateway, uri).await?;
        assert!(
            matches!(sent, Err(SendError::Unavailable { .. })),
            "{uri} reached a dark connection: {sent:?}"
        );
    }
    Ok(())
}

async fn all_served_by(gateway: &Gateway, uris: &[&str], name: &str) -> Res<()> {
    for uri in uris {
        assert!(get(gateway, uri).await?.1.starts_with(name), "{uri}");
    }
    Ok(())
}

/// Per-domain leak: a connector's claims serve only the hosts it claims,
/// so a request is served only by a connector that claims its host. A
/// host nobody claims, a look-alike of a claimed one, or a claimed host
/// whose connector left is never handed to another domain's connector.
#[tokio::test]
async fn a_request_never_reaches_another_domains_connector() -> Res<()> {
    let (gateway, addr) = gateway().await?;
    let a = start_connector(&addr, "a", registration(1, &["*"], &["a.example"])).await?;
    let _b = start_connector(&addr, "b", registration(2, &["*"], &["*.b.example"])).await?;
    eventually("registered", || connections(&gateway) == 2).await?;
    assert_eq!(get(&gateway, "http://A.Example/x").await?.1, "a GET /x");
    assert_eq!(get(&gateway, "http://api.b.example/x").await?.1, "b GET /x");
    no_route(&gateway, &LOOK_ALIKES).await?;
    a.abort();
    eventually("a gone", || connections(&gateway) == 1).await?;
    let sent = send(&gateway, "http://a.example/x").await?;
    assert!(
        matches!(
            sent,
            Err(SendError::NoRoute | SendError::Unavailable { .. })
        ),
        "a.example went to another connector: {sent:?}"
    );
    Ok(())
}

/// Hosts nobody claims, next to the claimed `a.example` and `*.b.example`.
const LOOK_ALIKES: [&str; 5] = [
    "http://c.example/x",
    "http://xa.example/x",
    "http://a.example.evil.org/x",
    "http://b.example/x",
    "http://evilb.example/x",
];

async fn no_route(gateway: &Gateway, uris: &[&str]) -> Res<()> {
    for uri in uris {
        let sent = send(gateway, uri).await?;
        assert!(matches!(sent, Err(SendError::NoRoute)), "{uri}: {sent:?}");
    }
    Ok(())
}

/// Header flood, agent side: a request whose headers are over the limit
/// is refused with 431 before it reaches a connector, and the gateway
/// goes on serving.
#[tokio::test]
async fn an_agents_header_flood_is_refused_and_the_gateway_goes_on() -> Res<()> {
    let (_gateway, connectors, ingress) = start_ingress(ingress_config(|_| {})?).await?;
    let _c = start_connector(&connectors, "echo", registration(1, &["mcp"], &[])).await?;
    let mut flood = Request::get("/mcp/x").header("host", "h");
    for i in 0..80 {
        flood = flood.header(format!("x-flood-{i}"), "v".repeat(1024));
    }
    let refused = h1(&ingress, flood.body(Full::new(Bytes::new()))?).await;
    assert!(
        refused
            .as_ref()
            .map_or(true, |r| r.0 == StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE),
        "{refused:?}"
    );
    let ok = Request::get("/mcp/x")
        .header("host", "h")
        .body(Full::new(Bytes::new()))?;
    assert_eq!(h1(&ingress, ok).await?.2, "echo GET /mcp/x");
    Ok(())
}

/// Header flood, connector side: an answer whose headers are over the
/// limit fails that request alone; the connection stays registered and
/// serves the next one.
#[tokio::test]
async fn a_connectors_header_flood_fails_only_its_own_request() -> Res<()> {
    let (gateway, addr) = gateway().await?;
    let _c = serve(&addr, registration(1, &["mcp"], &[]), hostile).await?;
    eventually("registered", || connections(&gateway) == 1).await?;
    let flood = send(&gateway, "http://h/mcp/flood").await?;
    assert!(flood.is_err(), "an oversized header list was accepted");
    assert_eq!(get(&gateway, "http://h/mcp/next").await?.1, "ok /mcp/next");
    assert_eq!(connections(&gateway), 1);
    Ok(())
}

/// Malformed frame blast radius: a stream the connector cuts part-way
/// fails alone. Requests in flight on the same connection at that moment
/// finish, and the connection stays registered.
#[tokio::test]
async fn a_broken_stream_does_not_take_its_siblings_down() -> Res<()> {
    let (gateway, addr) = gateway().await?;
    let _c = serve(&addr, registration(1, &["mcp"], &[]), hostile).await?;
    eventually("registered", || connections(&gateway) == 1).await?;
    let siblings: Vec<_> = (0..16)
        .map(|i| {
            let g = gateway.clone();
            tokio::spawn(async move { get(&g, &format!("http://h/mcp/{i}")).await })
        })
        .collect();
    let broken = send(&gateway, "http://h/mcp/broken").await?;
    if let Ok(response) = broken {
        assert!(
            response.into_body().collect().await.is_err(),
            "the cut was hidden"
        );
    }
    for (i, sibling) in siblings.into_iter().enumerate() {
        assert_eq!(sibling.await??.1, format!("ok /mcp/{i}"));
    }
    assert_eq!(connections(&gateway), 1, "the connection survived");
    Ok(())
}

/// Waiting-queue bypass: when a slot frees, the request that has waited
/// longest takes it. A request that arrives while others wait joins the
/// queue behind them instead of taking the freed slot first.
#[tokio::test]
async fn a_newcomer_does_not_jump_the_wait_queue() -> Res<()> {
    let (gateway, addr) = patient_gateway().await?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(Semaphore::new(0));
    let _c = serve_in_order(&addr, seen.clone(), gate.clone()).await?;
    eventually("registered", || connections(&gateway) == 1).await?;
    let mut sent = queue_in_order(&gateway, 4).await?;
    // Free the slot one answer at a time, and send a newcomer each time a
    // slot frees: it must still be served after every earlier request.
    for i in 0..4 {
        gate.add_permits(1);
        sent.push(spawn_get(&gateway, format!("http://h/mcp/new{i}")));
    }
    gate.add_permits(4);
    all_answered(sent).await?;
    let seen = seen.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(
        &seen[..4],
        ["/mcp/0", "/mcp/1", "/mcp/2", "/mcp/3"],
        "{seen:?}"
    );
    Ok(())
}

type Sent = tokio::task::JoinHandle<Res<(StatusCode, String)>>;

/// Sends `/mcp/0` to `/mcp/<count - 1>`, each once the one before is in
/// flight or queued, so their order of arrival is known.
async fn queue_in_order(gateway: &Gateway, count: u32) -> Res<Vec<Sent>> {
    let mut sent = Vec::new();
    for i in 0..count {
        sent.push(spawn_get(gateway, format!("http://h/mcp/{i}")));
        eventually("queued in order", || {
            gateway.in_flight() + gateway.waiting() == i + 1
        })
        .await?;
    }
    Ok(sent)
}

fn spawn_get(gateway: &Gateway, uri: String) -> Sent {
    let g = gateway.clone();
    tokio::spawn(async move { get(&g, &uri).await })
}

async fn all_answered(sent: Vec<Sent>) -> Res<()> {
    for request in sent {
        let _answer = request.await??;
    }
    Ok(())
}

/// A gateway that lets requests wait 5 s for a slot.
async fn patient_gateway() -> Res<(Gateway, String)> {
    start(Config {
        max_wait: Duration::from_secs(5),
        ..gateway_config()?
    })
    .await
}

/// A one-slot connector that records the order requests reach it, each
/// waiting for a permit from `gate` before it is answered.
async fn serve_in_order(
    addr: &str,
    seen: Arc<Mutex<Vec<String>>>,
    gate: Arc<Semaphore>,
) -> Res<tokio::task::JoinHandle<()>> {
    let one_slot = Register {
        capacity: 1,
        ..registration(1, &["mcp"], &[])
    };
    let session = register(&connector_config(addr, one_slot)?).await?;
    Ok(tokio::spawn(async move {
        let service = service_fn(move |req: Request<Incoming>| {
            let (seen, gate) = (seen.clone(), gate.clone());
            async move {
                if let Ok(mut seen) = seen.lock() {
                    seen.push(req.uri().path().to_owned());
                }
                drop(gate.acquire_owned().await);
                Ok::<_, Infallible>(Response::new(text("ok")))
            }
        });
        let _ended = session.serve(service).await;
    }))
}
