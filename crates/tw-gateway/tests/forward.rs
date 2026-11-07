// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The connector's `Forward` service (G5): requests travel gateway ->
//! connector -> a local HTTP/1.1 server, over TCP, TLS or a Unix socket.

mod common;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tw_connector::{Forward, Target, register};
use tw_crypto::rustls::pki_types::ServerName;
use tw_crypto::{ClientAuth, KeyExchange, client_config, server_config};
use tw_gateway::Gateway;
use tw_testpki as pki;

use common::{Res, WAIT, connector_config, gateway_config, registration, start};

/// Answers `<method> <path?query> host=<Host> x=<X-Test> body=<body>`, with
/// hop-by-hop headers the forwarder must drop; `/slow` waits 2 s first.
async fn backend(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() == "/slow" {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_owned()
    };
    let (host, x) = (header("host"), header("x-test"));
    let line = format!("{} {} host={host} x={x}", req.method(), req.uri());
    let body = req
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let text = format!("{line} body={}", String::from_utf8_lossy(&body));
    let mut response = Response::new(Full::new(Bytes::from(text)));
    response
        .headers_mut()
        .insert("keep-alive", HeaderValue::from_static("timeout=5"));
    response
        .headers_mut()
        .insert("x-ok", HeaderValue::from_static("1"));
    // A header the target marks as hop-by-hop through `Connection`.
    let headers = response.headers_mut();
    headers.insert("connection", HeaderValue::from_static("x-secret"));
    headers.insert("x-secret", HeaderValue::from_static("1"));
    Ok(response)
}

/// Serves `backend` over HTTP/1.1 on every stream `accept` yields.
fn serve_backend<S, F>(mut accept: impl FnMut() -> F + Send + 'static)
where
    F: std::future::Future<Output = Option<S>> + Send,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(stream) = accept().await {
            tokio::spawn(
                http1::Builder::new().serve_connection(TokioIo::new(stream), service_fn(backend)),
            );
        }
    });
}

async fn tcp_backend() -> Res<String> {
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await?);
    let addr = listener.local_addr()?.to_string();
    serve_backend(move || {
        let l = listener.clone();
        async move { l.accept().await.ok().map(|(s, _)| s) }
    });
    Ok(addr)
}

async fn tls_backend() -> Res<String> {
    let tls = server_config(
        pki::identity(pki::GATEWAY),
        ClientAuth::None,
        KeyExchange::default(),
        &[b"http/1.1"],
    )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await?);
    let addr = listener.local_addr()?.to_string();
    serve_backend(move || {
        let (l, a) = (listener.clone(), acceptor.clone());
        async move {
            let (tcp, _) = l.accept().await.ok()?;
            a.accept(tcp).await.ok()
        }
    });
    Ok(addr)
}

/// A gateway and one connector forwarding `mcp` to `target`.
async fn tunnel_to(target: Target, timeout: Duration) -> Res<Gateway> {
    let (gateway, addr) = start(gateway_config()?).await?;
    let session = register(&connector_config(
        &addr,
        registration(1, &["mcp", "slow"], &[]),
    )?)
    .await?;
    tokio::spawn(async move {
        let _ended = session.serve(Forward::new(target, timeout)).await;
    });
    Ok(gateway)
}

async fn call(
    gateway: &Gateway,
    request: Request<Full<Bytes>>,
) -> Res<(StatusCode, Option<String>, Option<String>, String)> {
    let response = tokio::time::timeout(WAIT, gateway.send(request)).await??;
    let header = |n: &str| {
        response
            .headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let hop = header("keep-alive").or_else(|| header("x-secret"));
    let (status, keep_alive, ok) = (response.status(), hop, header("x-ok"));
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, keep_alive, ok, String::from_utf8(body.to_vec())?))
}

fn get(uri: &str) -> Res<Request<Full<Bytes>>> {
    Ok(Request::get(uri).body(Full::new(Bytes::new()))?)
}

#[tokio::test]
async fn requests_reach_a_tcp_target_with_host_query_headers_and_body() -> Res<()> {
    let gateway = tunnel_to(
        Target::Http {
            addr: tcp_backend().await?,
        },
        WAIT,
    )
    .await?;
    let (status, keep_alive, ok, body) =
        call(&gateway, get("http://app.example/mcp/x?q=1")?).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "GET /mcp/x?q=1 host=app.example x=- body=");
    assert_eq!(
        (keep_alive, ok.as_deref()),
        (None, Some("1")),
        "hop-by-hop dropped, others kept"
    );
    let post = Request::post("http://app.example/mcp/tools")
        .header("x-test", "yes")
        .header("te", "trailers")
        .body(Full::new(Bytes::from_static(b"{\"a\":1}")))?;
    let (_, _, _, body) = call(&gateway, post).await?;
    assert_eq!(
        body,
        "POST /mcp/tools host=app.example x=yes body={\"a\":1}"
    );
    Ok(())
}

#[tokio::test]
async fn an_unreachable_target_is_502_and_the_tunnel_stays_up() -> Res<()> {
    let closed = TcpListener::bind("127.0.0.1:0")
        .await?
        .local_addr()?
        .to_string();
    let gateway = tunnel_to(Target::Http { addr: closed }, WAIT).await?;
    for _ in 0..3 {
        assert_eq!(
            call(&gateway, get("http://x/mcp")?).await?.0,
            StatusCode::BAD_GATEWAY
        );
    }
    assert_eq!(gateway.routes(), vec!["mcp".to_owned(), "slow".to_owned()]);
    Ok(())
}

#[tokio::test]
async fn a_slow_target_is_504() -> Res<()> {
    let gateway = tunnel_to(
        Target::Http {
            addr: tcp_backend().await?,
        },
        Duration::from_millis(300),
    )
    .await?;
    assert_eq!(
        call(&gateway, get("http://x/slow")?).await?.0,
        StatusCode::GATEWAY_TIMEOUT
    );
    Ok(())
}

fn https_target(addr: String, ca: &[u8]) -> Res<Target> {
    let tls = client_config(
        pki::roots(ca)?,
        None,
        KeyExchange::default(),
        &[b"http/1.1"],
    )?;
    Ok(Target::Https {
        addr,
        server_name: ServerName::try_from(pki::GATEWAY_NAME)?.to_owned(),
        tls: Arc::new(tls),
    })
}

#[tokio::test]
async fn an_https_target_is_verified_against_its_pinned_ca() -> Res<()> {
    let addr = tls_backend().await?;
    let gateway = tunnel_to(https_target(addr.clone(), pki::CA)?, WAIT).await?;
    let (status, _, _, body) = call(&gateway, get("http://app.example/mcp/tls")?).await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "GET /mcp/tls host=app.example x=- body=")
    );
    let wrong = tunnel_to(https_target(addr, pki::OTHER_CA)?, WAIT).await?;
    assert_eq!(
        call(&wrong, get("http://app.example/mcp/tls")?).await?.0,
        StatusCode::BAD_GATEWAY
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_unix_socket_target_works() -> Res<()> {
    let dir = std::env::temp_dir().join(format!("tw-forward-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("backend.sock");
    let _ = std::fs::remove_file(&path);
    let listener = Arc::new(tokio::net::UnixListener::bind(&path)?);
    serve_backend(move || {
        let l = listener.clone();
        async move { l.accept().await.ok().map(|(s, _)| s) }
    });
    let gateway = tunnel_to(Target::Unix { path: path.clone() }, WAIT).await?;
    let (status, _, _, body) = call(&gateway, get("http://app.example/mcp/uds")?).await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "GET /mcp/uds host=app.example x=- body=")
    );
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
