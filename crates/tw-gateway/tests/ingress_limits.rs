// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Ingress limits and refusals (G13): status codes, error ids,
//! `Retry-After`, timeouts.

mod common;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use tokio::sync::Semaphore;
use tunnelward_connector::register;
use tunnelward_gateway::RateLimit;

use common::ingress::{get, h1, ingress_config, start_ingress};
use common::{
    Res, connector_config, eventually, registration, start_connector, start_gated_connector,
};

#[tokio::test]
async fn refusals_have_the_right_status() -> Res<()> {
    let config = ingress_config(|i| {
        i.max_url_len = 64;
        i.max_body = 16;
    })?;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    let _c = start_connector(&connectors, "echo", registration(1, &["mcp"], &[])).await?;
    assert_eq!(
        h1(&ingress, get("/nothing")?).await?.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h1(&ingress, get(&format!("/mcp/{}", "a".repeat(80)))?)
            .await?
            .0,
        StatusCode::URI_TOO_LONG
    );
    let big = Request::post("/mcp/x")
        .header("host", "h")
        .body(Full::new(Bytes::from(vec![b'x'; 17])))?;
    assert_eq!(h1(&ingress, big).await?.0, StatusCode::PAYLOAD_TOO_LARGE);
    let ok = Request::post("/mcp/x")
        .header("host", "h")
        .body(Full::new(Bytes::from(vec![b'x'; 16])))?;
    assert_eq!(h1(&ingress, ok).await?.0, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn refusals_name_their_error_id_and_its_docs() -> Res<()> {
    let config = ingress_config(|i| i.max_url_len = 64)?;
    let (_gateway, _connectors, ingress) = start_ingress(config).await?;
    let long = format!("/mcp/{}", "a".repeat(80));
    for (path, id) in [("/nothing", "TW-S001"), (long.as_str(), "TW-I001")] {
        let (_, headers, body) = h1(&ingress, get(path)?).await?;
        assert_eq!(
            headers.get("tw-error").and_then(|v| v.to_str().ok()),
            Some(id)
        );
        let url = tunnelward_proto::error_url(id);
        assert!(body.contains(&format!("[{id}] {url}")), "{body}");
    }
    Ok(())
}

#[tokio::test]
async fn a_client_over_its_rate_gets_429_with_retry_after() -> Res<()> {
    let config = ingress_config(|i| {
        i.rate_limit = RateLimit {
            per_second: 1.0,
            burst: 2,
            max_clients: 10,
        }
    })?;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    let _c = start_connector(&connectors, "echo", registration(1, &["mcp"], &[])).await?;
    assert_eq!(h1(&ingress, get("/mcp/1")?).await?.0, StatusCode::OK);
    assert_eq!(h1(&ingress, get("/mcp/2")?).await?.0, StatusCode::OK);
    let (status, headers, _) = h1(&ingress, get("/mcp/3")?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        headers.get("retry-after").and_then(|v| v.to_str().ok()),
        Some("1")
    );
    Ok(())
}

#[tokio::test]
async fn a_slow_connector_is_504() -> Res<()> {
    let config = ingress_config(|i| i.request_timeout = Duration::from_millis(200))?;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    let gate = Arc::new(Semaphore::new(0));
    let _c =
        start_gated_connector(&connectors, "slow", registration(1, &["slow"], &[]), gate).await?;
    assert_eq!(
        h1(&ingress, get("/slow/x")?).await?.0,
        StatusCode::GATEWAY_TIMEOUT
    );
    Ok(())
}

#[tokio::test]
async fn a_kept_route_with_no_connector_is_503_with_retry_after() -> Res<()> {
    let (gateway, connectors, ingress) = start_ingress(ingress_config(|_| {})?).await?;
    drop(
        register(&connector_config(
            &connectors,
            registration(2, &["gone"], &[]),
        )?)
        .await?,
    );
    eventually("the gone route to go", || {
        !gateway.routes().contains(&"gone".to_owned())
    })
    .await?;
    let (status, headers, _) = h1(&ingress, get("/gone/x")?).await?;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a kept route waits, then 503"
    );
    assert!(headers.contains_key("retry-after"));
    Ok(())
}
