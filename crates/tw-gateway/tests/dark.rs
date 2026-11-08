// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Dark mode (G14): a dark connection stays connected but takes no new
//! request, until it is turned back on.

mod common;

use std::time::Duration;

use hyper::StatusCode;
use tunnelward_gateway::{Config, DrainTarget, Gateway, SendError};
use tunnelward_proto::ConnectorId;

use common::{Res, eventually, gateway_config, get, registration, send, start, start_connector};

/// A gateway that lets requests wait 300 ms for a slot.
async fn gateway() -> Res<(Gateway, String)> {
    start(Config {
        max_wait: Duration::from_millis(300),
        ..gateway_config()?
    })
    .await
}

async fn unavailable(gateway: &Gateway, uri: &str) -> Res<bool> {
    Ok(matches!(
        send(gateway, uri).await?,
        Err(SendError::Unavailable { .. })
    ))
}

#[tokio::test]
async fn a_dark_route_waits_then_is_unavailable_and_comes_back() -> Res<()> {
    let (gateway, addr) = gateway().await?;
    let _c = start_connector(&addr, "a", registration(1, &["mcp"], &[])).await?;
    eventually("registered", || gateway.routes().len() == 1).await?;
    assert!(gateway.set_dark(DrainTarget::Route("mcp".into()), true));
    assert!(unavailable(&gateway, "http://x/mcp/1").await?);
    assert_eq!(gateway.routes(), ["mcp"], "still connected");
    assert!(
        !gateway.set_dark(DrainTarget::Route("mcp".into()), true),
        "already dark"
    );

    assert!(gateway.set_dark(DrainTarget::Route("mcp".into()), false));
    assert_eq!(
        get(&gateway, "http://x/mcp/2").await?,
        (StatusCode::OK, "a GET /mcp/2".into())
    );
    Ok(())
}

#[tokio::test]
async fn a_request_waiting_on_a_dark_route_is_served_when_it_comes_back() -> Res<()> {
    let (gateway, addr) = gateway().await?;
    let _c = start_connector(&addr, "a", registration(1, &["mcp"], &[])).await?;
    eventually("registered", || gateway.routes().len() == 1).await?;
    let _changed = gateway.set_dark(DrainTarget::Route("mcp".into()), true);
    let g = gateway.clone();
    let waiting = tokio::spawn(async move { get(&g, "http://x/mcp/held").await });
    eventually("the request waiting", || gateway.waiting() == 1).await?;
    let _changed = gateway.set_dark(DrainTarget::Route("mcp".into()), false);
    assert_eq!(waiting.await??.1, "a GET /mcp/held");
    Ok(())
}

#[tokio::test]
async fn a_dark_connector_leaves_the_work_to_the_others() -> Res<()> {
    let (gateway, addr) = gateway().await?;
    let _a = start_connector(&addr, "a", registration(1, &["mcp"], &[])).await?;
    let _b = start_connector(&addr, "b", registration(2, &["mcp"], &[])).await?;
    eventually("both registered", || gateway.routes().len() == 2).await?;
    let _changed = gateway.set_dark(DrainTarget::Connector(ConnectorId([1; 16])), true);
    for n in 0..20 {
        let (_, body) = get(&gateway, &format!("http://x/mcp/{n}")).await?;
        assert!(body.starts_with("b "), "request {n} reached {body}");
    }
    Ok(())
}

#[tokio::test]
async fn a_connection_that_arrives_later_is_dark_too() -> Res<()> {
    let (gateway, addr) = gateway().await?;
    let _changed = gateway.set_dark(DrainTarget::Connector(ConnectorId([1; 16])), true);
    let _a = start_connector(&addr, "a", registration(1, &["mcp"], &[])).await?;
    eventually("registered", || gateway.routes().len() == 1).await?;
    assert!(unavailable(&gateway, "http://x/mcp/1").await?);
    assert_eq!(
        gateway.dark(),
        [DrainTarget::Connector(ConnectorId([1; 16]))]
    );
    Ok(())
}
