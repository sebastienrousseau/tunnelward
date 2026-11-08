// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Certificates replaced without a restart (G16): the next handshake uses
//! the new configuration, and established connections keep theirs.

mod common;

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use tunnelward_connector::register;
use tunnelward_crypto::{ClientAuth, KeyExchange, server_config};
use tunnelward_proto::ALPN;
use tunnelward_testpki as pki;

use common::ingress::{get as get_request, h1, h1_over_tls, ingress_config, start_ingress};
use common::{Res, connector_config, gateway_config, get, registration, start, start_connector};

#[tokio::test]
async fn new_connector_handshakes_use_the_replaced_configuration() -> Res<()> {
    let (gateway, addr) = start(gateway_config()?).await?;
    let _first = start_connector(&addr, "a", registration(1, &["mcp"], &[])).await?;
    assert_eq!(get(&gateway, "http://x/mcp/1").await?.1, "a GET /mcp/1");

    // Trust only the other CA from now on: the test connector's
    // certificate no longer passes.
    let stricter = server_config(
        pki::identity(pki::GATEWAY),
        ClientAuth::Required(pki::roots(pki::OTHER_CA)?),
        KeyExchange::default(),
        &[ALPN],
    )?;
    gateway.set_tls(Arc::new(stricter));
    let refused = register(&connector_config(&addr, registration(2, &["mcp"], &[]))?).await;
    assert!(
        refused.is_err(),
        "a handshake after the reload used the old roots"
    );
    assert_eq!(
        get(&gateway, "http://x/mcp/2").await?.1,
        "a GET /mcp/2",
        "the established connection is untouched"
    );
    Ok(())
}

#[tokio::test]
async fn the_ingress_follows_its_replaced_configuration() -> Res<()> {
    let tls = server_config(
        pki::identity(pki::GATEWAY),
        ClientAuth::None,
        KeyExchange::default(),
        &[b"http/1.1"],
    )?;
    let config = ingress_config(|i| i.tls = Some(Arc::new(tls)))?;
    let (gateway, connectors, ingress) = start_ingress(config).await?;
    let _c = start_connector(&connectors, "echo", registration(1, &["mcp"], &[])).await?;
    let over_tls = h1_over_tls(&ingress, get_request("/mcp/tls")?).await?;
    assert_eq!(over_tls.2, "echo GET /mcp/tls");

    gateway.set_ingress_tls(None);
    let plain = Request::get("/mcp/plain")
        .header("host", "h")
        .body(Full::new(Bytes::new()))?;
    assert_eq!(h1(&ingress, plain).await?.0, StatusCode::OK);
    assert!(
        h1_over_tls(&ingress, get_request("/mcp/tls")?)
            .await
            .is_err()
    );
    Ok(())
}
