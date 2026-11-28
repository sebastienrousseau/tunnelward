// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The server a connector registered with, and the guard that holds it
//! there (ADR 0017).
//!
//! At start the connector asks its MCP server who it is (`initialize`)
//! and what tools it has (`tools/list`), and registers with that
//! [`McpDescriptor`]: the gateway checks the name and version against
//! the route's attestation and records all three in its audit log.
//!
//! The guard then reads every `initialize` and `tools/list` answer on
//! its way back to an agent. An answer that names another server or
//! version, or a tool that is new or whose definition changed (a rug
//! pull: a tool rewritten after it was reviewed), is replaced with a
//! JSON-RPC error. With [`OnChange::Block`] it stays refused until the
//! connector restarts; with [`OnChange::Reregister`] the connector takes
//! the new set and registers again, so the gateway admits it afresh. A
//! tool that disappears is not a change the guard stops.
//!
//! A tool's digest is SHA-256 over its JSON with keys sorted and no
//! whitespace; the list's digest is SHA-256 over every tool's name and
//! digest, in name order.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use aws_lc_rs::digest::{SHA256, digest};
use serde_json::{Value, json};
use tokio::sync::watch;
use tunnelward_proto::McpDescriptor;

/// The JSON-RPC error code of an answer the guard refuses (in the range
/// JSON-RPC leaves to servers).
pub(crate) const CHANGED: i64 = -32001;

/// What the guard does when the server changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OnChange {
    /// Refuse the changed answers until the connector restarts.
    #[default]
    Block,
    /// Take the change and register again, so the gateway decides.
    Reregister,
}

/// A server as it described itself: its name, version and tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Described {
    name: String,
    version: String,
    tools: BTreeMap<String, [u8; 32]>,
}

impl Described {
    /// `name` and `version` (from `serverInfo`) with `tools` (every
    /// `tools/list` page together).
    ///
    /// # Errors
    ///
    /// A tool without a string `name`, or two tools with the same one.
    pub fn new(name: &str, version: &str, tools: &[Value]) -> Result<Self, String> {
        let mut digests = BTreeMap::new();
        for tool in tools {
            let (name, d) = tool_digest(tool)?;
            if digests.insert(name.clone(), d).is_some() {
                return Err(format!("the server lists tool {name:?} twice"));
            }
        }
        Ok(Self {
            name: name.to_owned(),
            version: version.to_owned(),
            tools: digests,
        })
    }

    /// The register frame's descriptor.
    #[must_use]
    pub fn descriptor(&self) -> McpDescriptor {
        let mut all = Vec::new();
        for (name, d) in &self.tools {
            let len = u32::try_from(name.len()).unwrap_or(u32::MAX);
            all.extend_from_slice(&len.to_be_bytes());
            all.extend_from_slice(name.as_bytes());
            all.extend_from_slice(d);
        }
        let mut tools_digest = [0; 32];
        tools_digest.copy_from_slice(digest(&SHA256, &all).as_ref());
        McpDescriptor {
            name: self.name.clone(),
            version: self.version.clone(),
            tools_digest,
        }
    }

    /// Why `answer` differs from this server, if it does.
    fn differs(&self, asked: Asked, result: &Value) -> Option<String> {
        match asked {
            Asked::Initialize => {
                let (name, version) = server_info(result);
                (name != self.name || version != self.version).then(|| {
                    format!(
                        "the server is now {name} {version}, registered as {} {}",
                        self.name, self.version
                    )
                })
            }
            Asked::Tools => {
                let tools = result.get("tools").and_then(Value::as_array)?;
                tools.iter().find_map(|tool| match tool_digest(tool) {
                    Ok((name, d)) if self.tools.get(&name) == Some(&d) => None,
                    Ok((name, _)) if self.tools.contains_key(&name) => {
                        Some(format!("tool {name:?} changed since registration"))
                    }
                    Ok((name, _)) => Some(format!("tool {name:?} is new since registration")),
                    Err(e) => Some(e),
                })
            }
        }
    }

    /// This server with what `result` says merged in.
    fn merged(&self, asked: Asked, result: &Value) -> Self {
        let mut next = self.clone();
        match asked {
            Asked::Initialize => {
                let (name, version) = server_info(result);
                (next.name, next.version) = (name.to_owned(), version.to_owned());
            }
            Asked::Tools => {
                let tools = result.get("tools").and_then(Value::as_array);
                for (name, d) in tools
                    .into_iter()
                    .flatten()
                    .filter_map(|t| tool_digest(t).ok())
                {
                    next.tools.insert(name, d);
                }
            }
        }
        next
    }
}

/// `serverInfo`'s name and version in an `initialize` result.
pub(crate) fn server_info(result: &Value) -> (&str, &str) {
    let info = result.get("serverInfo");
    let field = |k| {
        info.and_then(|i| i.get(k))
            .and_then(Value::as_str)
            .unwrap_or("")
    };
    (field("name"), field("version"))
}

/// A tool's name and digest.
fn tool_digest(tool: &Value) -> Result<(String, [u8; 32]), String> {
    let name = tool
        .get("name")
        .and_then(Value::as_str)
        .ok_or("a tool without a name")?;
    // serde_json's map is ordered by key, so this text is canonical.
    let mut d = [0; 32];
    d.copy_from_slice(digest(&SHA256, tool.to_string().as_bytes()).as_ref());
    Ok((name.to_owned(), d))
}

/// The two requests the guard reads the answers of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Asked {
    Initialize,
    Tools,
}

/// The guarded requests among `messages`, by id.
pub(crate) fn asked(messages: &[Value]) -> Vec<(Value, Asked)> {
    messages
        .iter()
        .filter_map(|m| {
            let asked = match m.get("method").and_then(Value::as_str)? {
                "initialize" => Asked::Initialize,
                "tools/list" => Asked::Tools,
                _ => return None,
            };
            m.get("id")
                .filter(|id| !id.is_null())
                .map(|id| (id.clone(), asked))
        })
        .collect()
}

/// The registered server, shared by the guard and every connection.
/// Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Pinned {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    described: Mutex<Described>,
    on_change: OnChange,
    /// Bumped when the server changes under [`OnChange::Reregister`]:
    /// every connection registers again.
    generation: watch::Sender<u64>,
}

impl Pinned {
    /// Holds the connector to `described`.
    #[must_use]
    pub fn new(described: Described, on_change: OnChange) -> Self {
        Self {
            inner: Arc::new(Inner {
                described: Mutex::new(described),
                on_change,
                generation: watch::Sender::new(0),
            }),
        }
    }

    /// The descriptor to register with now.
    #[must_use]
    pub fn descriptor(&self) -> McpDescriptor {
        self.lock().descriptor()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Described> {
        self.inner
            .described
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes that ask every connection to register again.
    pub(crate) fn changes(&self) -> watch::Receiver<u64> {
        self.inner.generation.subscribe()
    }

    /// The guard for a service of your own: checks `answers` to the
    /// `initialize` and `tools/list` requests among `requests`, as
    /// [`Forward::with_pinned`](crate::Forward::with_pinned) does.
    ///
    /// # Errors
    ///
    /// What changed: the answers must not reach the agent.
    pub fn check_exchange(&self, requests: &[Value], answers: &[Value]) -> Result<(), String> {
        self.check(&asked(requests), answers)
    }

    /// Checks the answers to the guarded requests `asked` among
    /// `answers`. On a change, under [`OnChange::Reregister`], takes it
    /// and asks for a new registration; either way says what changed.
    pub(crate) fn check(&self, asked: &[(Value, Asked)], answers: &[Value]) -> Result<(), String> {
        for (id, what) in asked {
            let Some(result) = answers
                .iter()
                .find(|a| a.get("id") == Some(id))
                .and_then(|a| a.get("result"))
            else {
                continue;
            };
            let mut described = self.lock();
            if let Some(why) = described.differs(*what, result) {
                if self.inner.on_change == OnChange::Reregister {
                    *described = described.merged(*what, result);
                    self.inner.generation.send_modify(|g| *g += 1);
                }
                return Err(why);
            }
        }
        Ok(())
    }
}

/// The guard's JSON-RPC errors for `asked`: one, or a batch.
pub(crate) fn refusal(asked: &[(Value, Asked)], why: &str, batch: bool) -> Value {
    let message = format!("tunnelward: {why} (ADR 0017)");
    let errors: Vec<Value> = asked
        .iter()
        .map(|(id, _)| {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": CHANGED, "message": message } })
        })
        .collect();
    match (batch, errors.as_slice()) {
        (false, [one]) => one.clone(),
        _ => Value::Array(errors),
    }
}

/// The JSON-RPC messages in an answer: a JSON body, or the `data` of
/// each server-sent event.
pub(crate) fn answers(event_stream: bool, body: &[u8]) -> Vec<Value> {
    let parsed = |text: &str| match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(all)) => all,
        Ok(one) => vec![one],
        Err(_) => Vec::new(),
    };
    if !event_stream {
        return std::str::from_utf8(body).map(parsed).unwrap_or_default();
    }
    let text = String::from_utf8_lossy(body).replace("\r\n", "\n");
    text.split("\n\n")
        .map(|event| {
            event
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(str::trim_start)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|data| !data.is_empty())
        .flat_map(|data| parsed(&data))
        .collect()
}

#[cfg(test)]
#[path = "tools_tests.rs"]
mod tests;
