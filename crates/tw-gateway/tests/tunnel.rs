// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! End to end over loopback: a connector dials the gateway, registers,
//! and serves a request the gateway sends back through that connection.

mod common;

use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tw_connector::{Error as ConnectorError, register};
use tw_crypto::rustls::pki_types::ServerName;
use tw_gateway::{Config, SendError};
use tw_proto::io::read_frame;
use tw_proto::{ALPN, Frame, Limits, RejectCode};
use tw_testpki as pki;

use common::{
    Res, WAIT, connector_config, eventually, gateway_config, get, get_request, registration, start,
    start_connector, tls_client,
};

/// A gateway that forgets a route as soon as its connector leaves.
async fn start_gateway(registration_timeout: Duration) -> Res<(tw_gateway::Gateway, String)> {
    let config = Config {
        registration_timeout,
        routes_keep_time: Duration::ZERO,
        ..gateway_config()?
    };
    start(config).await
}

#[tokio::test]
async fn a_request_crosses_the_tunnel() -> Res<()> {
    let (gateway, addr) = start_gateway(WAIT).await?;
    let _c = start_connector(&addr, "echo", registration(1, &["mcp/echo"], &[])).await?;
    assert_eq!(gateway.routes(), vec!["mcp/echo".to_owned()]);
    let (status, body) = get(&gateway, "http://any.host/mcp/echo/hello").await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "echo GET /mcp/echo/hello")
    );
    // A relative URI is made absolute from the Host header.
    let request = Request::post("/mcp/echo")
        .header("host", "a.b")
        .body(Full::new(Bytes::new()))?;
    assert_eq!(gateway.send(request).await?.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn routing_prefers_domain_then_longest_route_then_catch_all() -> Res<()> {
    let (gateway, addr) = start_gateway(WAIT).await?;
    let _a = start_connector(&addr, "catch-all", registration(1, &["*"], &[])).await?;
    let _b = start_connector(&addr, "mcp", registration(2, &["mcp"], &[])).await?;
    let _c = start_connector(
        &addr,
        "payments",
        registration(3, &["mcp/payments"], &["*.bank.example"]),
    )
    .await?;
    let body = |uri: &'static str| {
        let g = gateway.clone();
        async move { get(&g, uri).await.map(|(_, b)| b) }
    };
    assert_eq!(body("http://x.org/other").await?, "catch-all GET /other");
    assert_eq!(body("http://x.org/mcp/tools").await?, "mcp GET /mcp/tools");
    assert_eq!(
        body("http://pay.bank.example/mcp/payments/1").await?,
        "payments GET /mcp/payments/1"
    );
    // The payments claim is for its domain only.
    assert_eq!(
        body("http://x.org/mcp/payments/1").await?,
        "mcp GET /mcp/payments/1"
    );
    Ok(())
}

#[tokio::test]
async fn no_connector_means_no_route() -> Res<()> {
    let (gateway, _) = start_gateway(WAIT).await?;
    let sent = gateway.send(get_request("http://x.org/mcp")?).await;
    assert!(matches!(sent, Err(SendError::NoRoute)), "{sent:?}");
    Ok(())
}

#[tokio::test]
async fn a_closed_connector_stops_being_routable() -> Res<()> {
    let (gateway, addr) = start_gateway(WAIT).await?;
    let serving = start_connector(&addr, "echo", registration(1, &["mcp/echo"], &[])).await?;
    serving.abort();
    eventually("the route to go", || gateway.routes().is_empty()).await?;
    let sent = gateway.send(get_request("http://x.org/mcp/echo")?).await;
    assert!(matches!(sent, Err(SendError::NoRoute)), "{sent:?}");
    Ok(())
}

/// A raw TLS connection to the gateway, to send bytes no connector would.
async fn raw(addr: &str, alpn: &[&[u8]]) -> Res<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from(pki::GATEWAY_NAME)?.to_owned();
    Ok(TlsConnector::from(tls_client(alpn)?)
        .connect(name, tcp)
        .await?)
}

/// A valid register frame's body with its version byte changed to 2. The
/// codec refuses to encode an invalid frame, so this patches valid CBOR.
fn version_2_body() -> Res<Vec<u8>> {
    let frame = Frame::Register(registration(1, &["mcp"], &[]));
    let valid = tw_proto::encode(&frame, &Limits::default())?;
    let mut body = valid[tw_proto::LENGTH_PREFIX_LEN..].to_vec();
    // CBOR text "version" followed by the unsigned integer 1.
    let at = body
        .windows(8)
        .position(|w| w == b"version\x01")
        .ok_or("version not found")?;
    body[at + 7] = 0x02;
    Ok(body)
}

async fn send_body(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    body: &[u8],
) -> Res<()> {
    stream
        .write_all(&u32::try_from(body.len())?.to_be_bytes())
        .await?;
    stream.write_all(body).await?;
    Ok(stream.flush().await?)
}

#[tokio::test]
async fn an_invalid_register_frame_is_answered_with_reject() -> Res<()> {
    let (gateway, addr) = start_gateway(WAIT).await?;
    let mut stream = raw(&addr, &[ALPN]).await?;
    send_body(&mut stream, &version_2_body()?).await?;
    match read_frame(&mut stream, &Limits::default()).await? {
        Frame::Reject(r) => assert_eq!(r.code, RejectCode::UnsupportedVersion),
        other => panic!("expected Reject, got {other:?}"),
    }
    assert_eq!(gateway.routes(), Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn a_client_offering_no_alpn_is_closed_without_an_answer() -> Res<()> {
    let (gateway, addr) = start_gateway(WAIT).await?;
    let mut stream = raw(&addr, &[]).await?;
    let frame = Frame::Register(registration(1, &["mcp"], &[]));
    let bytes = tw_proto::encode(&frame, &Limits::default())?;
    send_body(&mut stream, &bytes[tw_proto::LENGTH_PREFIX_LEN..]).await?;
    let read = tokio::time::timeout(WAIT, read_frame(&mut stream, &Limits::default())).await?;
    assert!(
        read.is_err(),
        "expected the connection closed, got {read:?}"
    );
    assert_eq!(gateway.routes(), Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn an_oversized_length_is_rejected_without_reading_the_body() -> Res<()> {
    let (_gateway, addr) = start_gateway(WAIT).await?;
    let mut stream = raw(&addr, &[ALPN]).await?;
    stream.write_all(&u32::MAX.to_be_bytes()).await?;
    stream.flush().await?;
    match tokio::time::timeout(WAIT, read_frame(&mut stream, &Limits::default())).await?? {
        Frame::Reject(r) => assert_eq!(r.code, RejectCode::Malformed),
        other => panic!("expected Reject, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn a_silent_connector_is_dropped_after_the_registration_timeout() -> Res<()> {
    let (_gateway, addr) = start_gateway(Duration::from_millis(200)).await?;
    let mut stream = raw(&addr, &[ALPN]).await?;
    let read = tokio::time::timeout(WAIT, read_frame(&mut stream, &Limits::default())).await?;
    assert!(
        read.is_err(),
        "the gateway should close, not answer: {read:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_connector_without_alpn_tw1_is_refused() -> Res<()> {
    let (gateway, addr) = start_gateway(WAIT).await?;
    let mut config = connector_config(&addr, registration(1, &["mcp"], &[]))?;
    config.tls = tls_client(&[b"h2"])?;
    let err = register(&config).await;
    assert!(
        matches!(err, Err(ConnectorError::Connect(_) | ConnectorError::Alpn)),
        "{err:?}"
    );
    assert_eq!(gateway.routes(), Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn the_connector_allowlist_refuses_unlisted_sources() -> Res<()> {
    let elsewhere = Config {
        connector_allow: vec!["10.0.0.0/8".parse()?],
        ..gateway_config()?
    };
    let (gateway, addr) = start(elsewhere).await?;
    let refused = register(&connector_config(&addr, registration(1, &["mcp"], &[]))?).await;
    assert!(
        refused.is_err(),
        "loopback is not in 10.0.0.0/8: {refused:?}"
    );
    assert_eq!(gateway.routes(), Vec::<String>::new());

    let loopback = Config {
        connector_allow: vec!["10.0.0.0/8".parse()?, "127.0.0.0/8".parse()?],
        ..gateway_config()?
    };
    let (gateway, addr) = start(loopback).await?;
    let _c = start_connector(&addr, "echo", registration(1, &["mcp"], &[])).await?;
    assert_eq!(gateway.routes(), vec!["mcp".to_owned()]);
    Ok(())
}

#[tokio::test]
async fn a_connector_that_goes_silent_is_dropped_by_keep_alive() -> Res<()> {
    let config = Config {
        keep_alive: Duration::from_millis(300),
        routes_keep_time: Duration::ZERO,
        ..gateway_config()?
    };
    let (gateway, addr) = start(config).await?;
    // Register over raw TLS, read Accept, then never speak HTTP/2: a peer
    // whose process hung but whose socket stayed open.
    let mut stream = raw(&addr, &[ALPN]).await?;
    let frame = Frame::Register(registration(1, &["mcp"], &[]));
    let bytes = tw_proto::encode(&frame, &Limits::default())?;
    send_body(&mut stream, &bytes[tw_proto::LENGTH_PREFIX_LEN..]).await?;
    assert!(matches!(
        read_frame(&mut stream, &Limits::default()).await?,
        Frame::Accept(_)
    ));
    assert_eq!(gateway.routes(), vec!["mcp".to_owned()]);
    eventually("the silent connector to be dropped", || {
        gateway.routes().is_empty()
    })
    .await?;
    drop(stream);
    Ok(())
}
