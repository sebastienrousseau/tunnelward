// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The stdio bridge (FR-6): a local MCP server that speaks JSON-RPC over
//! stdio, served to agents as MCP Streamable HTTP through the tunnel.
//!
//! A stdio server serves one client, so each MCP session gets its own
//! process. An `initialize` POST with no `Mcp-Session-Id` starts the
//! configured command and answers with a new session id; later requests
//! must carry it.
//!
//! - `POST`: the JSON-RPC messages go to the server, one per line.
//!   Requests are answered with their responses as JSON; notifications
//!   and responses alone get 202.
//! - `GET` (`Accept: text/event-stream`): what the server sends on its
//!   own, as server-sent events with ids. A client that reconnects with
//!   `Last-Event-ID` gets what it missed (session resumption).
//! - `DELETE`: ends the session and the process.
//!
//! A session ends when its process exits, when it has been idle for
//! [`StdioConfig::idle`], or on `DELETE`; its id then gets 404, as the
//! specification asks, so the client starts a new one.

mod session;
mod sse;

use core::future::Future;
use core::pin::Pin;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use serde_json::Value;

use session::Session;
use sse::EventStream;

/// The header naming the session.
const SESSION: &str = "mcp-session-id";
/// The header a reconnecting event stream names its last event in.
const LAST_EVENT: &str = "last-event-id";

/// The body [`StdioBridge`] answers with.
pub type StdioBody = BoxBody<Bytes, Infallible>;

/// What to run, and the bridge's limits.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StdioConfig {
    /// The server's program.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// Variables added to its environment.
    pub env: Vec<(String, String)>,
    /// Most sessions (processes) at once; more get 503.
    pub max_sessions: usize,
    /// How long a session may sit unused before it is ended.
    pub idle: Duration,
    /// How long a request waits for its response.
    pub timeout: Duration,
    /// Longest message, either way, in bytes.
    pub max_line: usize,
    /// Events kept for a reconnecting stream.
    pub replay: usize,
}

impl StdioConfig {
    /// Runs `program` with `args`: 16 sessions, ended after 10 idle
    /// minutes, 60 s per request, messages of up to 4 MiB, 256 events
    /// kept for replay.
    #[must_use]
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            env: Vec::new(),
            max_sessions: 16,
            idle: Duration::from_secs(600),
            timeout: Duration::from_secs(60),
            max_line: 4 * 1024 * 1024,
            replay: 256,
        }
    }
}

/// Serves a stdio MCP server as Streamable HTTP. Cloning is cheap.
#[derive(Clone)]
pub struct StdioBridge {
    config: Arc<StdioConfig>,
    sessions: Arc<Mutex<HashMap<String, Arc<Session>>>>,
}

impl std::fmt::Debug for StdioBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioBridge")
            .field("program", &self.config.program)
            .field("sessions", &self.sessions())
            .finish_non_exhaustive()
    }
}

/// Why a request is refused: its status and a sentence.
type Refused = (StatusCode, String);

fn refused(status: StatusCode, reason: &str) -> Refused {
    (status, reason.to_owned())
}

fn answer(status: StatusCode, text: &str) -> Response<StdioBody> {
    let mut response = Response::new(Full::new(Bytes::from(format!("{text}\n"))).boxed());
    *response.status_mut() = status;
    response
}

fn json(body: &Value) -> Response<StdioBody> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())).boxed());
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// A new session id: 128 random bits in hex.
fn new_id() -> Result<String, String> {
    use std::fmt::Write as _;
    let mut bytes = [0_u8; 16];
    aws_lc_rs::rand::SecureRandom::fill(&aws_lc_rs::rand::SystemRandom::new(), &mut bytes)
        .map_err(|_| "no randomness for a session id".to_owned())?;
    Ok(bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    }))
}

/// The messages in a POST body, and whether it was a batch.
fn messages(body: &[u8]) -> Result<(Vec<Value>, bool), String> {
    match serde_json::from_slice::<Value>(body).map_err(|e| format!("not JSON: {e}"))? {
        Value::Array(all) if !all.is_empty() => Ok((all, true)),
        Value::Object(one) => Ok((vec![Value::Object(one)], false)),
        _ => Err("not a JSON-RPC message or batch".into()),
    }
}

/// A body that opens a session: one `initialize` request.
fn is_initialize(messages: &[Value]) -> bool {
    matches!(messages, [one] if one.get("method").and_then(Value::as_str) == Some("initialize"))
}

/// The answer to a POST: 202 with no request in it, else the responses,
/// as a batch when the request was one. A new session's id goes with it.
fn reply(answers: &[Value], batch: bool, new: Option<&str>) -> Response<StdioBody> {
    let mut response = match (answers, batch) {
        ([], _) => answer(StatusCode::ACCEPTED, ""),
        ([one], false) => json(one),
        (all, _) => json(&Value::Array(all.to_vec())),
    };
    if let Some(value) = new.and_then(|s| HeaderValue::from_str(s).ok()) {
        response.headers_mut().insert(SESSION, value);
    }
    response
}

fn is_request(m: &Value) -> bool {
    m.get("method").is_some() && m.get("id").is_some_and(|id| !id.is_null())
}

impl StdioBridge {
    /// A bridge to the server `config` describes. Nothing starts until
    /// the first `initialize`.
    #[must_use]
    pub fn new(config: StdioConfig) -> Self {
        Self {
            config: Arc::new(config),
            sessions: Arc::default(),
        }
    }

    /// Sessions open now.
    #[must_use]
    pub fn sessions(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn table(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Session>>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The live session `request` names, ending idle and dead ones first.
    fn session<B>(&self, request: &Request<B>) -> Result<(String, Arc<Session>), Refused> {
        let idle = self.config.idle;
        let mut table = self.table();
        table.retain(|_, s| {
            let keep = s.is_alive() && s.idle_since().elapsed() < idle;
            if !keep {
                s.end();
            }
            keep
        });
        let id = request
            .headers()
            .get(SESSION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| refused(StatusCode::BAD_REQUEST, "missing Mcp-Session-Id"))?;
        let session = table
            .get(id)
            .cloned()
            .ok_or_else(|| refused(StatusCode::NOT_FOUND, "no such session; initialize again"))?;
        session.touch();
        Ok((id.to_owned(), session))
    }

    /// The session `request` names, if it names one.
    fn named<B>(&self, request: &Request<B>) -> Result<Option<(String, Arc<Session>)>, Refused> {
        if request.headers().contains_key(SESSION) {
            self.session(request).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Starts a session for an `initialize`.
    fn open(&self) -> Result<(String, Arc<Session>), Refused> {
        if self.table().len() >= self.config.max_sessions {
            return Err(refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many sessions",
            ));
        }
        let fail = |e: String| (StatusCode::BAD_GATEWAY, e);
        let id = new_id().map_err(fail)?;
        let session = Session::start(&self.config).map_err(fail)?;
        self.table().insert(id.clone(), session.clone());
        Ok((id, session))
    }

    async fn handle(&self, request: Request<Incoming>) -> Response<StdioBody> {
        let outcome = match *request.method() {
            Method::POST => self.post(request).await,
            Method::GET => self.get(&request),
            Method::DELETE => self.delete(&request),
            _ => Err(refused(
                StatusCode::METHOD_NOT_ALLOWED,
                "use POST, GET or DELETE",
            )),
        };
        outcome.unwrap_or_else(|(status, reason)| answer(status, &reason))
    }

    async fn post(&self, request: Request<Incoming>) -> Result<Response<StdioBody>, Refused> {
        let named = self.named(&request)?;
        let (messages, batch) = self.read(request.into_body()).await?;
        let opened = named.is_none();
        let (id, session) = match named {
            Some(found) => found,
            None if is_initialize(&messages) => self.open()?,
            None => return Err(refused(StatusCode::BAD_REQUEST, "missing Mcp-Session-Id")),
        };
        let answers = self.exchange(&session, &messages).await?;
        Ok(reply(&answers, batch, opened.then_some(id.as_str())))
    }

    /// The messages in a POST body of at most `max_line` bytes.
    async fn read(&self, body: Incoming) -> Result<(Vec<Value>, bool), Refused> {
        let bytes = Limited::new(body, self.config.max_line)
            .collect()
            .await
            .map_err(|_| {
                refused(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "the body is too large or failed",
                )
            })?
            .to_bytes();
        messages(&bytes).map_err(|e| (StatusCode::BAD_REQUEST, e))
    }

    /// Sends `messages` and gathers the responses to the requests among
    /// them, in order.
    async fn exchange(&self, session: &Session, messages: &[Value]) -> Result<Vec<Value>, Refused> {
        let waits: Vec<_> = messages
            .iter()
            .filter(|m| is_request(m))
            .filter_map(|m| m.get("id"))
            .map(|id| session.expect(id))
            .collect();
        for m in messages {
            session
                .send(m)
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
        }
        let mut answers = Vec::with_capacity(waits.len());
        for wait in waits {
            answers.push(self.response(wait).await?);
        }
        Ok(answers)
    }

    /// One response, within the timeout.
    async fn response(
        &self,
        wait: tokio::sync::oneshot::Receiver<Value>,
    ) -> Result<Value, Refused> {
        match tokio::time::timeout(self.config.timeout, wait).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(refused(StatusCode::BAD_GATEWAY, "the server ended")),
            Err(_) => Err(refused(
                StatusCode::GATEWAY_TIMEOUT,
                "the server did not answer in time",
            )),
        }
    }

    fn get(&self, request: &Request<Incoming>) -> Result<Response<StdioBody>, Refused> {
        let wants_events = request
            .headers()
            .get(ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("text/event-stream"));
        if !wants_events {
            return Err(refused(
                StatusCode::NOT_ACCEPTABLE,
                "accept text/event-stream",
            ));
        }
        let (_, session) = self.session(request)?;
        let last = request
            .headers()
            .get(LAST_EVENT)
            .and_then(|v| v.to_str().ok()?.parse().ok());
        let (missed, live) = session.subscribe(last);
        let mut response = Response::new(EventStream::new(missed, live).boxed());
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
        Ok(response)
    }

    fn delete(&self, request: &Request<Incoming>) -> Result<Response<StdioBody>, Refused> {
        let (id, session) = self.session(request)?;
        self.table().remove(&id);
        session.end();
        Ok(answer(StatusCode::NO_CONTENT, ""))
    }
}

impl hyper::service::Service<Request<Incoming>> for StdioBridge {
    type Response = Response<StdioBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { Ok(this.handle(request).await) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_are_one_message_or_a_batch() {
        assert_eq!(
            messages(br#"{"jsonrpc":"2.0","method":"ping","id":1}"#).map(|m| m.1),
            Ok(false)
        );
        assert_eq!(
            messages(br#"[{"jsonrpc":"2.0","method":"x"}]"#).map(|m| m.1),
            Ok(true)
        );
        assert!(messages(b"[]").is_err());
        assert!(messages(b"42").is_err());
        assert!(messages(b"nope").is_err());
    }

    #[test]
    fn requests_have_a_method_and_an_id() {
        assert!(is_request(&serde_json::json!({"method": "x", "id": 1})));
        assert!(!is_request(&serde_json::json!({"method": "x"})));
        assert!(!is_request(&serde_json::json!({"method": "x", "id": null})));
        assert!(!is_request(&serde_json::json!({"id": 1, "result": {}})));
    }

    #[test]
    fn session_ids_are_128_bits_of_hex() -> Result<(), String> {
        let (a, b) = (new_id()?, new_id()?);
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        Ok(())
    }
}
