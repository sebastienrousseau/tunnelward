// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The stdio bridge (FR-6) in front of the `stdio-echo` example: sessions,
//! requests and notifications, the event stream and its resumption with
//! `Last-Event-ID`, and the limits.

use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tunnelward_connector::{StdioBridge, StdioConfig};

type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const WAIT: Duration = Duration::from_secs(10);

/// The `stdio-echo` example, which `cargo test` builds beside the tests.
fn echo_server() -> Res<PathBuf> {
    let exe = std::env::current_exe()?;
    let debug = exe
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("no target directory")?;
    let path = debug
        .join("examples")
        .join(format!("stdio-echo{}", std::env::consts::EXE_SUFFIX));
    path.is_file()
        .then_some(path)
        .ok_or_else(|| "the stdio-echo example is not built: run `cargo test` without --test, or `cargo build --example stdio-echo`".into())
}

/// The bridge on a loopback port.
async fn serve(config: StdioConfig) -> Res<(String, StdioBridge)> {
    let bridge = StdioBridge::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    let service = bridge.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let service = service.clone();
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service),
            );
        }
    });
    Ok((addr, bridge))
}

async fn bridge() -> Res<(String, StdioBridge)> {
    serve(StdioConfig::new(
        echo_server()?.to_string_lossy(),
        Vec::new(),
    ))
    .await
}

async fn send(addr: &str, request: Request<Full<Bytes>>) -> Res<Response<Incoming>> {
    let tcp = TcpStream::connect(addr).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(conn);
    Ok(tokio::time::timeout(WAIT, sender.send_request(request)).await??)
}

/// POSTs `body`, in `session` when given: status, session header, body.
async fn post(
    addr: &str,
    session: Option<&str>,
    body: &Value,
) -> Res<(StatusCode, Option<String>, String)> {
    let mut request = Request::post("/mcp").header("content-type", "application/json");
    if let Some(s) = session {
        request = request.header("mcp-session-id", s);
    }
    let response = send(
        addr,
        request.body(Full::new(Bytes::from(body.to_string())))?,
    )
    .await?;
    let status = response.status();
    let id = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let text = response.into_body().collect().await?.to_bytes();
    Ok((status, id, String::from_utf8_lossy(&text).into_owned()))
}

fn initialize() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
           "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                      "clientInfo": {"name": "test", "version": "1"}}})
}

fn echo(id: u32, text: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": "echo", "arguments": {"text": text}}})
}

async fn open(addr: &str) -> Res<String> {
    let (status, id, body) = post(addr, None, &initialize()).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("stdio-echo"), "{body}");
    id.ok_or_else(|| "no Mcp-Session-Id".into())
}

/// The first event on the session's stream, after `last` if given.
async fn first_event(addr: &str, session: &str, last: Option<u64>) -> Res<String> {
    let mut request = Request::get("/mcp")
        .header("accept", "text/event-stream")
        .header("mcp-session-id", session);
    if let Some(n) = last {
        request = request.header("last-event-id", n.to_string());
    }
    let response = send(addr, request.body(Full::new(Bytes::new()))?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let mut text = String::new();
    while !text.contains("\n\n") {
        let frame = tokio::time::timeout(WAIT, body.frame())
            .await?
            .ok_or("stream ended")??;
        if let Some(data) = frame.data_ref() {
            text.push_str(&String::from_utf8_lossy(data));
        }
    }
    Ok(text)
}

#[tokio::test]
async fn a_session_starts_answers_and_streams_what_the_server_sends() -> Res<()> {
    let (addr, bridge) = bridge().await?;
    let session = open(&addr).await?;
    let (status, _, body) = post(&addr, Some(&session), &echo(2, "hello")).await?;
    assert_eq!(status, StatusCode::OK);
    let answer: Value = serde_json::from_str(&body)?;
    assert_eq!(answer["id"], 2);
    assert_eq!(answer["result"]["content"][0]["text"], "hello");
    let event = first_event(&addr, &session, None).await?;
    assert!(event.starts_with("id: 1\ndata: "), "{event}");
    assert!(event.contains("echoing hello"), "{event}");
    assert_eq!(bridge.sessions(), 1);
    Ok(())
}

#[tokio::test]
async fn a_reconnecting_stream_resumes_after_its_last_event() -> Res<()> {
    let (addr, _) = bridge().await?;
    let session = open(&addr).await?;
    post(&addr, Some(&session), &echo(2, "one")).await?;
    post(&addr, Some(&session), &echo(3, "two")).await?;
    let resumed = first_event(&addr, &session, Some(1)).await?;
    assert!(
        resumed.starts_with("id: 2\n") && resumed.contains("echoing two"),
        "{resumed}"
    );
    Ok(())
}

#[tokio::test]
async fn notifications_are_accepted_and_batches_answered_in_order() -> Res<()> {
    let (addr, _) = bridge().await?;
    let session = open(&addr).await?;
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    assert_eq!(
        post(&addr, Some(&session), &note).await?.0,
        StatusCode::ACCEPTED
    );
    let batch = json!([echo(5, "a"), echo(6, "b")]);
    let (status, _, body) = post(&addr, Some(&session), &batch).await?;
    assert_eq!(status, StatusCode::OK);
    let answers: Vec<Value> = serde_json::from_str(&body)?;
    let ids: Vec<&Value> = answers.iter().map(|a| &a["id"]).collect();
    assert_eq!(ids, [&json!(5), &json!(6)]);
    Ok(())
}

#[tokio::test]
async fn sessions_are_named_ended_and_forgotten() -> Res<()> {
    let (addr, bridge) = bridge().await?;
    assert_eq!(
        post(&addr, None, &echo(1, "x")).await?.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(&addr, Some("nope"), &echo(1, "x")).await?.0,
        StatusCode::NOT_FOUND
    );
    let session = open(&addr).await?;
    let delete = Request::delete("/mcp")
        .header("mcp-session-id", &session)
        .body(Full::new(Bytes::new()))?;
    assert_eq!(send(&addr, delete).await?.status(), StatusCode::NO_CONTENT);
    assert_eq!(bridge.sessions(), 0);
    let (status, _, _) = post(&addr, Some(&session), &echo(2, "x")).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an ended session is not found"
    );
    Ok(())
}

#[tokio::test]
async fn the_session_limit_and_a_server_that_will_not_start() -> Res<()> {
    let mut one = StdioConfig::new(echo_server()?.to_string_lossy(), Vec::new());
    one.max_sessions = 1;
    let (addr, _) = serve(one).await?;
    open(&addr).await?;
    assert_eq!(
        post(&addr, None, &initialize()).await?.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let (missing, _) = serve(StdioConfig::new("/nonexistent/stdio-server", Vec::new())).await?;
    let (status, _, body) = post(&missing, None, &initialize()).await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(body.contains("cannot start"), "{body}");
    Ok(())
}

#[tokio::test]
async fn an_idle_session_ends() -> Res<()> {
    let mut config = StdioConfig::new(echo_server()?.to_string_lossy(), Vec::new());
    config.idle = Duration::from_millis(200);
    let (addr, bridge) = serve(config).await?;
    let session = open(&addr).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let (status, _, _) = post(&addr, Some(&session), &echo(2, "late")).await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "ended after 200 ms unused");
    assert_eq!(bridge.sessions(), 0);
    Ok(())
}

/// A reference MCP server, not ours: `TW_STDIO_REFERENCE` is its command
/// line, split on whitespace. CI runs `@modelcontextprotocol/server-everything`
/// in a container with no network (`scripts/stdio-reference.sh`).
fn reference_server() -> Res<StdioConfig> {
    let line = std::env::var("TW_STDIO_REFERENCE")
        .map_err(|_| "set TW_STDIO_REFERENCE to a stdio MCP server's command")?;
    let mut words = line.split_whitespace().map(str::to_owned);
    let program = words.next().ok_or("TW_STDIO_REFERENCE is empty")?;
    Ok(StdioConfig::new(program, words.collect()))
}

/// Lists the reference server's tools and calls its `echo`.
async fn reference_tools(addr: &str, session: &str) -> Res<()> {
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let (_, _, body) = post(addr, Some(session), &list).await?;
    assert!(body.contains("\"echo\""), "{body}");
    let call = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                      "params": {"name": "echo", "arguments": {"message": "through the bridge"}}});
    let (_, _, body) = post(addr, Some(session), &call).await?;
    assert!(body.contains("through the bridge"), "{body}");
    Ok(())
}

/// Log messages the reference server sends on its own arrive on the
/// event stream.
async fn reference_events(addr: &str, session: &str) -> Res<()> {
    let level = json!({"jsonrpc": "2.0", "id": 4, "method": "logging/setLevel",
                       "params": {"level": "debug"}});
    post(addr, Some(session), &level).await?;
    let trigger = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                         "params": {"name": "trigger-log-messages", "arguments": {}}});
    post(addr, Some(session), &trigger).await?;
    let event = first_event(addr, session, None).await?;
    assert!(event.contains("notifications/message"), "{event}");
    Ok(())
}

#[tokio::test]
#[ignore = "needs TW_STDIO_REFERENCE, a reference stdio MCP server (scripts/stdio-reference.sh)"]
async fn a_reference_server_works_end_to_end() -> Res<()> {
    let (addr, bridge) = serve(reference_server()?).await?;
    let (status, session, body) = post(&addr, None, &initialize()).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session = session.ok_or("no Mcp-Session-Id")?;
    let started: Value = serde_json::from_str(&body)?;
    println!("reference server: {}", started["result"]["serverInfo"]);
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    assert_eq!(
        post(&addr, Some(&session), &note).await?.0,
        StatusCode::ACCEPTED
    );
    reference_tools(&addr, &session).await?;
    reference_events(&addr, &session).await?;
    let delete = Request::delete("/mcp")
        .header("mcp-session-id", &session)
        .body(Full::new(Bytes::new()))?;
    assert_eq!(send(&addr, delete).await?.status(), StatusCode::NO_CONTENT);
    assert_eq!(bridge.sessions(), 0);
    Ok(())
}
