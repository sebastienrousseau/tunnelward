// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Asking the local MCP server who it is (ADR 0017): `initialize`, then
//! `notifications/initialized`, then every page of `tools/list`, then
//! the session ends. Over HTTP this is MCP Streamable HTTP, JSON or an
//! event stream; the stdio bridge runs the same exchange on a process of
//! its own.

use core::future::Future;

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE};
use http::{Method, Request};
use http_body_util::{BodyExt, Limited};
use serde_json::{Value, json};

use crate::Described;
use crate::blind::full;
use crate::forward::Forward;
use crate::tools::{answers, server_info};

/// The MCP revision the connector asks for.
pub(crate) const PROTOCOL: &str = "2025-06-18";

/// Most `tools/list` pages read: a server that pages forever is refused.
const MAX_PAGES: u64 = 64;

/// The `initialize` request the connector sends.
pub(crate) fn initialize() -> Value {
    json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": { "name": "tunnelward-connector", "version": env!("CARGO_PKG_VERSION") }
        }
    })
}

pub(crate) fn initialized() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
}

/// One MCP session: sends a request and returns its `result`.
pub(crate) trait Ask {
    fn ask(&mut self, request: Value) -> impl Future<Output = Result<Value, String>> + Send;
}

/// Every tool, asking for one page after another.
pub(crate) async fn tools(session: &mut impl Ask) -> Result<Vec<Value>, String> {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    for id in 1..=MAX_PAGES {
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |c| json!({ "cursor": c }));
        let result = session
            .ask(json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list", "params": params }))
            .await?;
        let page = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or("tools/list has no tools")?;
        all.extend(page.iter().cloned());
        cursor = result
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if cursor.is_none() {
            return Ok(all);
        }
    }
    Err(format!("tools/list has more than {MAX_PAGES} pages"))
}

/// The `result` of the answer to `id` among `found`, or its error.
pub(crate) fn result_of(found: &[Value], id: &Value) -> Result<Value, String> {
    let answer = found
        .iter()
        .find(|a| a.get("id") == Some(id))
        .ok_or("no answer to the request")?;
    if let Some(error) = answer.get("error") {
        return Err(format!("the server answered with an error: {error}"));
    }
    answer
        .get("result")
        .cloned()
        .ok_or_else(|| "an answer without a result".into())
}

/// One MCP session over HTTP.
struct Http<'a> {
    forward: &'a Forward,
    path: &'a str,
    session: Option<String>,
}

impl Http<'_> {
    fn request(
        &self,
        method: Method,
        body: Option<&Value>,
    ) -> Result<crate::forward::Outgoing, String> {
        let mut builder = Request::builder()
            .method(method)
            .uri(self.path)
            .header(ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL);
        if body.is_some() {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        if let Some(id) = &self.session {
            builder = builder.header(tunnelward_mcp::SESSION_HEADER, id);
        }
        let bytes = body.map_or_else(Bytes::new, |b| Bytes::from(b.to_string()));
        builder.body(full(bytes)).map_err(|e| e.to_string())
    }

    /// Sends `message`; returns the JSON-RPC messages that came back.
    async fn post(&mut self, message: &Value) -> Result<Vec<Value>, String> {
        let request = self.request(Method::POST, Some(message))?;
        let answer = self.forward.send_unguarded(request).await;
        let status = answer.status();
        if !status.is_success() {
            return Err(format!("{} answered {status}", self.path));
        }
        if let Some(id) = answer.headers().get(tunnelward_mcp::SESSION_HEADER) {
            self.session = id.to_str().ok().map(str::to_owned);
        }
        let event_stream = (answer.headers().get(CONTENT_TYPE))
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.starts_with(tunnelward_mcp::EVENT_STREAM));
        let body = Limited::new(answer.into_body(), tunnelward_mcp::MAX_BODY)
            .collect()
            .await
            .map_err(|_| "the answer is too large or failed".to_owned())?
            .to_bytes();
        Ok(answers(event_stream, &body))
    }
}

impl Ask for Http<'_> {
    async fn ask(&mut self, message: Value) -> Result<Value, String> {
        let found = self.post(&message).await?;
        result_of(&found, &message["id"])
    }
}

/// [`Forward::describe`].
pub(crate) async fn http(forward: &Forward, path: &str) -> Result<Described, String> {
    let mut mcp = Http {
        forward,
        path,
        session: None,
    };
    let init = mcp.ask(initialize()).await?;
    let (name, version) = server_info(&init);
    let (name, version) = (name.to_owned(), version.to_owned());
    let _accepted = mcp.post(&initialized()).await?;
    let listed = tools(&mut mcp).await;
    if mcp.session.is_some()
        && let Ok(end) = mcp.request(Method::DELETE, None)
    {
        let _ended = forward.send_unguarded(end).await;
    }
    Described::new(&name, &version, &listed?)
}
