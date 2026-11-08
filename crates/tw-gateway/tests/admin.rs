// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The admin API (FR-9): health, readiness, inventory at both redaction
//! levels, Prometheus counters, drain, and the bearer token.

mod common;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tunnelward_gateway::{AdminConfig, Gateway};

use common::{Res, eventually, gateway_config, registration, start, start_connector};

/// A gateway with one echo connector on `mcp/a`, and its admin API.
async fn admin_rig(admin: AdminConfig) -> Res<(Gateway, String)> {
    let (gateway, addr) = start(gateway_config()?).await?;
    let _connector =
        start_connector(&addr, "c", registration(7, &["mcp/a"], &["a.example"])).await?;
    eventually("the connector registered", || gateway.routes().len() == 1).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let admin_addr = listener.local_addr()?.to_string();
    let serving = gateway.clone();
    tokio::spawn(async move { serving.serve_admin(listener, admin).await });
    Ok((gateway, admin_addr))
}

/// Sends one request to the admin API and reads the answer.
async fn call(
    addr: &str,
    method: Method,
    path: &str,
    token: Option<&str>,
) -> Res<(StatusCode, String)> {
    let io = TokioIo::new(TcpStream::connect(addr).await?);
    let (mut sender, connection) = http1::handshake(io).await?;
    tokio::spawn(connection);
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "admin");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = sender
        .send_request(request.body(Empty::<Bytes>::new())?)
        .await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8(body.to_vec())?))
}

#[tokio::test]
async fn health_and_readiness_answer() -> Res<()> {
    let (_gateway, admin) = admin_rig(AdminConfig::default()).await?;
    assert_eq!(
        call(&admin, Method::GET, "/healthz", None).await?,
        (StatusCode::OK, "ok\n".into())
    );
    assert_eq!(
        call(&admin, Method::GET, "/readyz", None).await?,
        (StatusCode::OK, "ready\n".into())
    );
    assert_eq!(
        call(&admin, Method::GET, "/nope", None).await?.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&admin, Method::POST, "/healthz", None).await?.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    Ok(())
}

#[tokio::test]
async fn a_gateway_not_serving_connectors_is_not_ready() -> Res<()> {
    let gateway = Gateway::new(gateway_config()?);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let admin = listener.local_addr()?.to_string();
    let serving = gateway.clone();
    tokio::spawn(async move { serving.serve_admin(listener, AdminConfig::default()).await });
    assert_eq!(
        call(&admin, Method::GET, "/readyz", None).await?.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}

#[tokio::test]
async fn the_public_inventory_reveals_counts_only() -> Res<()> {
    let (_gateway, admin) = admin_rig(AdminConfig::default()).await?;
    let (status, body) = call(&admin, Method::GET, "/inventory", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        r#"{"connections":1,"connectors":1,"routes":1,"in_flight":0,"waiting":0,"draining":0}"#
    );
    for secret in ["127.0.0.1", "mcp/a", "a.example", "07070707"] {
        assert!(!body.contains(secret), "{secret} leaked: {body}");
    }
    Ok(())
}

#[tokio::test]
async fn the_internal_inventory_shows_each_connection() -> Res<()> {
    let (_gateway, admin) = admin_rig(AdminConfig::default()).await?;
    let (_, body) = call(&admin, Method::GET, "/inventory?redaction=internal", None).await?;
    for shown in [
        r#""peer":"127.0.0.1""#,
        r#""routes":["mcp/a"]"#,
        r#""domains":["a.example"]"#,
    ] {
        assert!(body.contains(shown), "{shown} missing: {body}");
    }
    assert!(
        body.contains(&format!(r#""connector":"{}""#, "07".repeat(16))),
        "{body}"
    );
    Ok(())
}

#[tokio::test]
async fn metrics_are_prometheus_text() -> Res<()> {
    let (_gateway, admin) = admin_rig(AdminConfig::default()).await?;
    let (status, body) = call(&admin, Method::GET, "/metrics", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("# TYPE tunnelward_connections gauge\ntunnelward_connections 1\n"),
        "{body}"
    );
    assert!(body.contains("tunnelward_in_flight 0\n"), "{body}");
    Ok(())
}

#[tokio::test]
async fn drain_by_route_empties_it() -> Res<()> {
    let (gateway, admin) = admin_rig(AdminConfig::default()).await?;
    let (status, body) = call(
        &admin,
        Method::POST,
        "/drain?route=mcp/a&deadline_ms=1000",
        None,
    )
    .await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, r#"{"finished":1,"reset":0,"sessions":1}"#)
    );
    eventually("the route gone", || gateway.routes().is_empty()).await?;
    let (status, _) = call(
        &admin,
        Method::POST,
        "/drain?route=x&deadline_ms=600001",
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        call(&admin, Method::POST, "/drain", None).await?.0,
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn a_token_is_required_when_set() -> Res<()> {
    let (_gateway, admin) = admin_rig(AdminConfig::with_token("s3cret")).await?;
    assert_eq!(
        call(&admin, Method::GET, "/healthz", None).await?.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&admin, Method::GET, "/healthz", Some("wrong"))
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&admin, Method::GET, "/healthz", Some("s3cret"))
            .await?
            .0,
        StatusCode::OK
    );
    Ok(())
}
