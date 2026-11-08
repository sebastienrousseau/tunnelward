// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JSON-RPC 2.0 envelopes, read without their arguments.

use core::fmt;

use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::{MAX_BATCH, MAX_BODY};

/// Longest method, tool, client name or version kept, in bytes. Longer
/// values are refused: no MCP name comes close.
const MAX_FIELD: usize = 256;

/// A JSON-RPC message id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Id {
    /// A numeric id, as its JSON text.
    Number(String),
    /// A string id.
    String(String),
}

/// What a message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A method call that expects an answer.
    Request,
    /// A method call without an id: no answer.
    Notification,
    /// An answer, with `result` or `error`.
    Response,
}

/// The client's self-description from `initialize`. Declared, not proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    /// `clientInfo.name`.
    pub name: String,
    /// `clientInfo.version`.
    pub version: String,
}

/// One JSON-RPC message's envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Message {
    /// Request, notification or response.
    pub kind: Kind,
    /// The id, absent for a notification.
    pub id: Option<Id>,
    /// The method, absent for a response.
    pub method: Option<String>,
    /// `params.name` of a `tools/call`.
    pub tool: Option<String>,
    /// `params.clientInfo` of an `initialize`.
    pub client: Option<ClientInfo>,
    /// `params._meta.traceparent`, when the client sent one.
    pub traceparent: Option<String>,
}

/// A body's messages: one, or a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Envelope {
    /// The messages, in order.
    pub messages: Vec<Message>,
    /// Whether the body was a JSON array.
    pub batch: bool,
}

/// Why a body is not an MCP envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The body is over [`MAX_BODY`].
    TooLarge(usize),
    /// The body is not valid JSON of the expected shape.
    Json(String),
    /// A message lacks `"jsonrpc": "2.0"`.
    NotJsonRpc,
    /// A message is neither a request, a notification nor a response.
    Shape,
    /// A batch is empty or over [`MAX_BATCH`].
    Batch(usize),
    /// A method, tool or client field is over 256 bytes.
    FieldTooLong,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(n) => write!(f, "body of {n} bytes is over {MAX_BODY}"),
            Self::Json(e) => write!(f, "not a JSON-RPC body: {e}"),
            Self::NotJsonRpc => f.write_str("a message lacks \"jsonrpc\": \"2.0\""),
            Self::Shape => f.write_str("a message is neither request, notification nor response"),
            Self::Batch(n) => write!(f, "a batch of {n} messages (1 to {MAX_BATCH} allowed)"),
            Self::FieldTooLong => f.write_str("a method, tool or client field is over 256 bytes"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

#[derive(Deserialize)]
struct Raw {
    jsonrpc: Option<String>,
    id: Option<serde_json::Value>,
    method: Option<String>,
    params: Option<serde_json::Value>,
    result: Option<IgnoredAny>,
    error: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Body {
    Batch(Vec<Raw>),
    One(Box<Raw>),
}

fn id(value: Option<serde_json::Value>) -> Result<Option<Id>, EnvelopeError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => Ok(Some(Id::Number(n.to_string()))),
        Some(serde_json::Value::String(s)) => Ok(Some(Id::String(s))),
        Some(_) => Err(EnvelopeError::Shape),
    }
}

fn kind(raw: &Raw, id: Option<&Id>) -> Result<Kind, EnvelopeError> {
    let answered = raw.result.is_some() || raw.error.is_some();
    match (&raw.method, id, answered) {
        (Some(_), Some(_), false) => Ok(Kind::Request),
        (Some(_), None, false) => Ok(Kind::Notification),
        (None, _, true) => Ok(Kind::Response),
        _ => Err(EnvelopeError::Shape),
    }
}

fn short(field: Option<String>) -> Result<Option<String>, EnvelopeError> {
    match field {
        Some(f) if f.len() > MAX_FIELD => Err(EnvelopeError::FieldTooLong),
        other => Ok(other),
    }
}

/// A string field of `params`, if present and a string.
fn text<'a>(params: Option<&'a serde_json::Value>, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(params?, |value, key| value.get(key))?
        .as_str()
}

/// The tool a `tools/call` names. Its `params.name` must be a string:
/// a call that hides its tool would slip past per-tool policy.
fn tool(
    method: Option<&str>,
    params: Option<&serde_json::Value>,
) -> Result<Option<String>, EnvelopeError> {
    if method != Some("tools/call") {
        return Ok(None);
    }
    let name = text(params, &["name"]).ok_or(EnvelopeError::Shape)?;
    short(Some(name.to_owned()))
}

/// The client's self-description, from `initialize` only.
fn client(
    method: Option<&str>,
    params: Option<&serde_json::Value>,
) -> Result<Option<ClientInfo>, EnvelopeError> {
    if method != Some("initialize") {
        return Ok(None);
    }
    let name = text(params, &["clientInfo", "name"]);
    let version = text(params, &["clientInfo", "version"]);
    let (Some(name), Some(version)) = (name, version) else {
        return Ok(None);
    };
    Ok(Some(ClientInfo {
        name: short(Some(name.to_owned()))?.unwrap_or_default(),
        version: short(Some(version.to_owned()))?.unwrap_or_default(),
    }))
}

fn message(raw: Raw) -> Result<Message, EnvelopeError> {
    if raw.jsonrpc.as_deref() != Some("2.0") {
        return Err(EnvelopeError::NotJsonRpc);
    }
    let id = id(raw.id.clone())?;
    let kind = kind(&raw, id.as_ref())?;
    let method = short(raw.method)?;
    let params = raw.params.as_ref().filter(|p| p.is_object());
    let traceparent = short(text(params, &["_meta", "traceparent"]).map(str::to_owned))?;
    Ok(Message {
        kind,
        tool: tool(method.as_deref(), params)?,
        client: client(method.as_deref(), params)?,
        id,
        method,
        traceparent,
    })
}

/// Reads the envelope of an MCP POST body.
///
/// # Errors
///
/// The body is over [`MAX_BODY`], is not JSON, or holds a message that is
/// not JSON-RPC 2.0.
pub fn parse(body: &[u8]) -> Result<Envelope, EnvelopeError> {
    if body.len() > MAX_BODY {
        return Err(EnvelopeError::TooLarge(body.len()));
    }
    let parsed: Body =
        serde_json::from_slice(body).map_err(|e| EnvelopeError::Json(e.to_string()))?;
    let (raws, batch) = match parsed {
        Body::Batch(raws) => (raws, true),
        Body::One(raw) => (vec![*raw], false),
    };
    if batch && !(1..=MAX_BATCH).contains(&raws.len()) {
        return Err(EnvelopeError::Batch(raws.len()));
    }
    let messages = raws.into_iter().map(message).collect::<Result<_, _>>()?;
    Ok(Envelope { messages, batch })
}
