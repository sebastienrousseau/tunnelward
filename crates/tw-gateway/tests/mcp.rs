// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! MCP Streamable HTTP through the gateway (FR-2): JSON answers, SSE
//! streams and the session header pass through unchanged; observers see
//! each call's envelope; every response carries its request id.

mod common;

use std::convert::Infallible;
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tunnelward_connector::register;
use tunnelward_gateway::{ProxyObserver, RequestInfo};
use tunnelward_mcp::Envelope;

use common::ingress::{h1, ingress_config, start_ingress};
use common::{Res, connector_config, registration};

const SSE: &str = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n\
                   event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[]}}\n\n";
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;

/// A minimal MCP server: `initialize` answers JSON and opens a session;
/// anything else answers an SSE stream. It reports the request id and
/// traceparent it was given in response headers.
async fn mcp_server(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let seen = |name: &str| request.headers().get(name).cloned();
    let (request_id, traceparent) = (seen("tw-request-id"), seen("traceparent"));
    let body = request
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let initialize = body.windows(10).any(|w| w == b"initialize");
    let mut response = if initialize {
        let mut r = Response::new(Full::new(Bytes::from_static(INITIALIZED.as_bytes())));
        r.headers_mut().insert(
            "content-type",
            "application/json"
                .parse()
                .unwrap_or_else(|_| unreachable!()),
        );
        r.headers_mut().insert(
            "mcp-session-id",
            "session-1".parse().unwrap_or_else(|_| unreachable!()),
        );
        r
    } else {
        let mut r = Response::new(Full::new(Bytes::from_static(SSE.as_bytes())));
        r.headers_mut().insert(
            "content-type",
            "text/event-stream"
                .parse()
                .unwrap_or_else(|_| unreachable!()),
        );
        r
    };
    for (name, value) in [
        ("x-seen-request-id", request_id),
        ("x-seen-traceparent", traceparent),
    ] {
        if let Some(value) = value {
            response.headers_mut().insert(name, value);
        }
    }
    Ok(response)
}

/// Keeps every envelope and request it sees.
#[derive(Debug, Default)]
struct Recorder {
    seen: Mutex<Vec<(RequestInfo, Envelope)>>,
}

impl ProxyObserver for Recorder {
    fn on_envelope(&self, info: &RequestInfo, envelope: &Envelope) {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.push((info.clone(), envelope.clone()));
    }
}

impl Recorder {
    fn calls(&self) -> Vec<(RequestInfo, Envelope)> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

async fn rig() -> Res<(Arc<Recorder>, String)> {
    let recorder = Arc::new(Recorder::default());
    let observer: Arc<dyn ProxyObserver> = recorder.clone();
    let (_gateway, connectors, ingress) =
        start_ingress(ingress_config(|i| i.observers = vec![observer])?).await?;
    let session = register(&connector_config(
        &connectors,
        registration(1, &["mcp"], &[]),
    )?)
    .await?;
    tokio::spawn(async move { session.serve(service_fn(mcp_server)).await });
    Ok((recorder, ingress))
}

fn post(body: &'static str, extra: &[(&str, &str)]) -> Res<Request<Full<Bytes>>> {
    let mut request = Request::post("/mcp")
        .header("host", "mcp.example.org")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    Ok(request.body(Full::new(Bytes::from_static(body.as_bytes())))?)
}

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"claude-ai","version":"0.1.0"}}}"#;
const CALL: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":"Paris"}}}"#;
const TRACE: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

#[tokio::test]
async fn initialize_and_a_tool_call_pass_through_unchanged() -> Res<()> {
    let (recorder, ingress) = rig().await?;
    let (status, headers, body) = h1(
        &ingress,
        post(INITIALIZE, &[("user-agent", "claude-ai/0.1")])?,
    )
    .await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, INITIALIZED));
    assert_eq!(
        headers.get("mcp-session-id").and_then(|v| v.to_str().ok()),
        Some("session-1")
    );

    let call = post(
        CALL,
        &[("mcp-session-id", "session-1"), ("traceparent", TRACE)],
    )?;
    let (status, headers, body) = h1(&ingress, call).await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, SSE),
        "the SSE stream, byte for byte"
    );
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(
        headers
            .get("x-seen-traceparent")
            .and_then(|v| v.to_str().ok()),
        Some(TRACE)
    );

    let calls = recorder.calls();
    assert_eq!(calls.len(), 2);
    let (init_info, init) = &calls[0];
    let client = init.messages[0].client.as_ref().ok_or("no clientInfo")?;
    assert_eq!(
        (client.name.as_str(), init_info.user_agent.as_deref()),
        ("claude-ai", Some("claude-ai/0.1"))
    );
    let (call_info, call) = &calls[1];
    assert_eq!(call.messages[0].tool.as_deref(), Some("get_weather"));
    assert_eq!(call_info.mcp_session.as_deref(), Some("session-1"));
    assert_eq!(call_info.traceparent.as_deref(), Some(TRACE));
    Ok(())
}

#[tokio::test]
async fn every_response_carries_its_request_id() -> Res<()> {
    let (recorder, ingress) = rig().await?;
    let spoofed = post(CALL, &[("tw-request-id", "chosen-by-client")])?;
    let (_, headers, _) = h1(&ingress, spoofed).await?;
    let id = headers
        .get("tw-request-id")
        .and_then(|v| v.to_str().ok())
        .ok_or("no id")?;
    assert_eq!(id.len(), 26, "{id}");
    assert_eq!(
        headers
            .get("x-seen-request-id")
            .and_then(|v| v.to_str().ok()),
        Some(id),
        "the connector saw the gateway's id, not the client's"
    );
    assert_eq!(recorder.calls()[0].0.request_id, id);

    let refused = Request::get("/nowhere")
        .header("host", "h")
        .body(Full::new(Bytes::new()))?;
    let (status, headers, _) = h1(&ingress, refused).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        headers.get("tw-request-id").is_some(),
        "refusals carry an id too"
    );
    Ok(())
}

#[tokio::test]
async fn a_malformed_traceparent_is_not_recorded() -> Res<()> {
    let (recorder, ingress) = rig().await?;
    let call = post(CALL, &[("traceparent", "00-not-a-trace-01")])?;
    h1(&ingress, call).await?;
    assert_eq!(recorder.calls()[0].0.traceparent, None);
    Ok(())
}

#[tokio::test]
async fn a_body_that_is_not_json_rpc_has_no_envelope() -> Res<()> {
    let (recorder, ingress) = rig().await?;
    h1(&ingress, post(r#"{"hello":"world"}"#, &[])?).await?;
    assert!(recorder.calls().is_empty());
    Ok(())
}
