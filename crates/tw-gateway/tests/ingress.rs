// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The agent-facing ingress end to end: an HTTP client in front, a
//! connector behind (FR-2, FR-11, G11 to G13).

mod common;

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tunnelward_connector::register;
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{ClientAuth, KeyExchange, client_config, server_config};
use tunnelward_gateway::{Config, Gateway, IngressConfig, ProxyObserver, RateLimit, RequestInfo};
use tunnelward_testpki as pki;

use common::{
    Res, WAIT, connector_config, eventually, gateway_config, registration, start, start_connector,
    start_gated_connector,
};

/// A gateway with its ingress on a loopback port: (gateway, connector address, ingress address).
async fn start_ingress(config: Config) -> Res<(Gateway, String, String)> {
    let (gateway, connectors) = start(config).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let ingress = listener.local_addr()?.to_string();
    let serving = gateway.clone();
    tokio::spawn(async move { serving.serve_ingress(listener).await });
    Ok((gateway, connectors, ingress))
}

/// 127.0.0.0/8, where the tests' clients connect from.
fn loopback() -> tunnelward_gateway::Cidr {
    "127.0.0.0/8"
        .parse()
        .unwrap_or_else(|_| unreachable!("a valid range"))
}

fn ingress_config(change: impl FnOnce(&mut IngressConfig)) -> Res<Config> {
    let mut config = gateway_config()?;
    config.max_wait = Duration::from_millis(100);
    change(&mut config.ingress);
    Ok(config)
}

/// One HTTP/1.1 request over plain TCP.
async fn h1(
    addr: &str,
    request: Request<Full<Bytes>>,
) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    let tcp = TcpStream::connect(addr).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(conn);
    read(tokio::time::timeout(WAIT, sender.send_request(request)).await??).await
}

async fn read(response: Response<Incoming>) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    let (parts, body) = response.into_parts();
    let bytes = tokio::time::timeout(WAIT, body.collect())
        .await??
        .to_bytes();
    Ok((
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

fn get(path: &str) -> Res<Request<Full<Bytes>>> {
    Ok(Request::get(path)
        .header("host", "mcp.example.org")
        .body(Full::new(Bytes::new()))?)
}

#[tokio::test]
async fn plain_http1_reaches_the_connector() -> Res<()> {
    let (_gateway, connectors, ingress) = start_ingress(ingress_config(|_| {})?).await?;
    let _c = start_connector(&connectors, "echo", registration(1, &["mcp"], &[])).await?;
    let (status, _, body) = h1(&ingress, get("/mcp/hello?x=1")?).await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "echo GET /mcp/hello")
    );
    Ok(())
}

async fn tls_stream(ingress: &str, alpn: &[u8]) -> Res<tokio_rustls::client::TlsStream<TcpStream>> {
    let tls = client_config(pki::roots(pki::CA)?, None, KeyExchange::default(), &[alpn])?;
    let tcp = TcpStream::connect(ingress).await?;
    let name = ServerName::try_from(pki::GATEWAY_NAME)?.to_owned();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await?)
}

async fn h2_over_tls(
    ingress: &str,
    request: Request<Full<Bytes>>,
) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    let stream = tls_stream(ingress, b"h2").await?;
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await?;
    tokio::spawn(conn);
    read(sender.send_request(request).await?).await
}

async fn h1_over_tls(
    ingress: &str,
    request: Request<Full<Bytes>>,
) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    let stream = tls_stream(ingress, b"http/1.1").await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(conn);
    read(sender.send_request(request).await?).await
}

#[tokio::test]
async fn tls_ingress_speaks_h2_and_http1_by_alpn() -> Res<()> {
    let tls = server_config(
        pki::identity(pki::GATEWAY),
        ClientAuth::None,
        KeyExchange::default(),
        &[b"h2", b"http/1.1"],
    )?;
    let config = ingress_config(|i| i.tls = Some(Arc::new(tls)))?;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    let _c = start_connector(&connectors, "echo", registration(1, &["mcp"], &[])).await?;
    let h2 = Request::get("https://mcp.example.org/mcp/two").body(Full::new(Bytes::new()))?;
    assert_eq!(h2_over_tls(&ingress, h2).await?.2, "echo GET /mcp/two");
    assert_eq!(
        h1_over_tls(&ingress, get("/mcp/one")?).await?.2,
        "echo GET /mcp/one"
    );
    Ok(())
}

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

/// A connector that answers with the forwarding headers it received.
async fn start_header_echo(connectors: &str) -> Res<()> {
    let session = register(&connector_config(
        connectors,
        registration(9, &["hdr"], &[]),
    )?)
    .await?;
    tokio::spawn(async move {
        let service = service_fn(|req: Request<Incoming>| {
            let h = |n: &str| {
                req.headers()
                    .get(n)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-")
                    .to_owned()
            };
            let text = format!(
                "forwarded={} xff={} via={}",
                h("forwarded"),
                h("x-forwarded-for"),
                h("via")
            );
            std::future::ready(Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                text,
            )))))
        });
        let _ended = session.serve(service).await;
    });
    Ok(())
}

fn spoofed() -> Res<Request<Full<Bytes>>> {
    Ok(Request::get("/hdr")
        .header("host", "mcp.example.org")
        .header("x-forwarded-for", "203.0.113.7")
        .header("forwarded", "for=203.0.113.7")
        .body(Full::new(Bytes::new()))?)
}

#[tokio::test]
async fn an_untrusted_client_cannot_spoof_its_address() -> Res<()> {
    let (_gateway, connectors, ingress) = start_ingress(ingress_config(|_| {})?).await?;
    start_header_echo(&connectors).await?;
    let body = h1(&ingress, spoofed()?).await?.2;
    assert_eq!(
        body,
        "forwarded=for=127.0.0.1;proto=http;host=\"mcp.example.org\" xff=127.0.0.1 via=1.1 tunnelward"
    );
    Ok(())
}

#[tokio::test]
async fn a_trusted_proxy_is_believed() -> Res<()> {
    let config = ingress_config(|i| i.trusted_proxies = vec![loopback()])?;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    start_header_echo(&connectors).await?;
    let body = h1(&ingress, spoofed()?).await?.2;
    assert!(body.starts_with("forwarded=for=203.0.113.7;"), "{body}");
    Ok(())
}

/// Sends `prefix` and a GET in one write and returns whatever comes back.
/// A gateway that refuses may close mid-exchange; that reads as an empty
/// or partial reply, not as an error.
async fn raw_http(ingress: &str, prefix: &[u8]) -> Res<String> {
    let mut tcp = TcpStream::connect(ingress).await?;
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(b"GET /hdr HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n");
    let mut out = Vec::new();
    if tcp.write_all(&bytes).await.is_ok() {
        let read = tokio::time::timeout(
            WAIT,
            tokio::io::AsyncReadExt::read_to_end(&mut tcp, &mut out),
        )
        .await?;
        let _closed_early = read.is_err();
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[tokio::test]
async fn a_proxy_header_from_a_trusted_proxy_names_the_client() -> Res<()> {
    let config = ingress_config(|i| {
        i.proxy_protocol = true;
        i.trusted_proxies = vec![loopback()];
    })?;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    start_header_echo(&connectors).await?;
    let reply = raw_http(&ingress, b"PROXY TCP4 198.51.100.4 10.0.0.1 40000 443\r\n").await?;
    assert!(reply.contains("forwarded=for=198.51.100.4;"), "{reply}");
    Ok(())
}

#[tokio::test]
async fn a_proxy_header_from_anyone_else_is_not_believed() -> Res<()> {
    // PROXY protocol on, but loopback is not a trusted proxy.
    let config = ingress_config(|i| i.proxy_protocol = true)?;
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    start_header_echo(&connectors).await?;
    let reply = raw_http(&ingress, b"PROXY TCP4 198.51.100.4 10.0.0.1 40000 443\r\n").await?;
    // The connector was never reached: refused with 400, or closed.
    assert!(
        !reply.contains("forwarded="),
        "the request reached the connector: {reply}"
    );
    assert!(
        reply.is_empty() || reply.starts_with("HTTP/1.1 400"),
        "{reply}"
    );
    Ok(())
}

#[derive(Debug, Default)]
struct Counting {
    requests: AtomicU64,
    responses: AtomicU64,
    completed_bytes: AtomicU64,
    failures: AtomicU64,
}

impl ProxyObserver for Counting {
    fn on_request(&self, _: &RequestInfo) {
        self.requests.fetch_add(1, Ordering::SeqCst);
    }
    fn on_response(&self, _: &RequestInfo, _: StatusCode, _: Duration) {
        self.responses.fetch_add(1, Ordering::SeqCst);
    }
    fn on_complete(&self, _: &RequestInfo, bytes: u64, _: Duration) {
        self.completed_bytes.fetch_add(bytes, Ordering::SeqCst);
    }
    fn on_failure(&self, _: &RequestInfo, _: StatusCode, _: &str) {
        self.failures.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn observers_see_requests_responses_completion_and_failures() -> Res<()> {
    let counting = Arc::new(Counting::default());
    let observer: Arc<dyn ProxyObserver> = counting.clone();
    let (_gateway, connectors, ingress) =
        start_ingress(ingress_config(|i| i.observers = vec![observer])?).await?;
    let _c = start_connector(&connectors, "echo", registration(1, &["mcp"], &[])).await?;
    assert_eq!(h1(&ingress, get("/mcp/abc")?).await?.2, "echo GET /mcp/abc");
    assert_eq!(h1(&ingress, get("/none")?).await?.0, StatusCode::NOT_FOUND);
    eventually("completion to be reported", || {
        counting.completed_bytes.load(Ordering::SeqCst) > 0
    })
    .await?;
    assert_eq!(counting.requests.load(Ordering::SeqCst), 2);
    assert_eq!(counting.responses.load(Ordering::SeqCst), 2);
    assert_eq!(counting.failures.load(Ordering::SeqCst), 1);
    assert_eq!(
        counting.completed_bytes.load(Ordering::SeqCst),
        "echo GET /mcp/abc".len() as u64
    );
    Ok(())
}

/// An endless response body, counting the bytes it has produced. It only
/// produces when polled, so the count shows how far flow control lets it run.
struct Endless {
    produced: Arc<AtomicU64>,
}

const CHUNK: usize = 16 * 1024;

impl Body for Endless {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.produced.fetch_add(CHUNK as u64, Ordering::SeqCst);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'.'; CHUNK])))))
    }
}

/// A connector on `sse` answering every request with an [`Endless`]
/// body; returns its production counter.
async fn start_endless(connectors: &str) -> Res<Arc<AtomicU64>> {
    let produced = Arc::new(AtomicU64::new(0));
    let session = register(&connector_config(
        connectors,
        registration(1, &["sse"], &[]),
    )?)
    .await?;
    let counter = produced.clone();
    tokio::spawn(async move {
        let service = service_fn(move |_req: Request<Incoming>| {
            let body = Endless {
                produced: counter.clone(),
            };
            std::future::ready(Ok::<_, Infallible>(Response::new(body)))
        });
        let _ended = session.serve(service).await;
    });
    Ok(produced)
}

/// Opens the endless stream and returns it without reading the body.
async fn open_unread(ingress: &str) -> Res<Response<Incoming>> {
    let tcp = TcpStream::connect(ingress).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(conn);
    Ok(sender.send_request(get("/sse/events")?).await?)
}

/// Reads until the producer runs again; at most `buffered` bytes plus 1 MiB.
async fn read_until_resumed(
    mut body: Incoming,
    produced: &AtomicU64,
    before: u64,
    buffered: u64,
) -> Res<()> {
    let mut read_bytes: u64 = 0;
    while produced.load(Ordering::SeqCst) == before {
        if read_bytes > buffered + 1024 * 1024 {
            return Err(format!("read {read_bytes} bytes and production never resumed").into());
        }
        let frame = tokio::time::timeout(WAIT, body.frame())
            .await?
            .ok_or("stream ended")??;
        read_bytes += frame.data_ref().map_or(0, Bytes::len) as u64;
    }
    Ok(())
}

#[tokio::test]
async fn a_slow_client_holds_back_an_endless_stream() -> Res<()> {
    let (_gateway, connectors, ingress) = start_ingress(ingress_config(|_| {})?).await?;
    let produced = start_endless(&connectors).await?;
    let response = open_unread(&ingress).await?;
    assert_eq!(response.status(), StatusCode::OK);
    // Read nothing for a second: the stream must stall, not fill memory.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let stalled = produced.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        stalled,
        produced.load(Ordering::SeqCst),
        "production stopped while the client was not reading"
    );
    assert!(
        stalled < 32 * 1024 * 1024,
        "{stalled} bytes buffered for a client that read nothing"
    );
    // Draining what is buffered makes the producer run again.
    read_until_resumed(response.into_body(), &produced, stalled, stalled).await
}
