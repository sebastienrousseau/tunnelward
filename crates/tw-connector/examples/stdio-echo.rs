// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A small MCP server over stdio, for trying the stdio bridge and for its
//! tests: one JSON-RPC message per line. It offers one tool, `echo`,
//! which first sends a `notifications/message` on its own (so the bridge
//! has an event to stream) and then answers with its `text`. The tool's
//! description is `STDIO_ECHO_DESCRIPTION` when set, so a test can start
//! a server whose tool changed (ADR 0017).
//!
//! ```sh
//! cargo run -p tunnelward-connector --example stdio-echo
//! ```

use std::io::{BufRead, Write};

use serde_json::{Value, json};

fn result(id: &Value, result: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// The answer to one request, and any message to send before it.
fn answer(method: &str, id: &Value, params: &Value) -> (Option<Value>, Value) {
    match method {
        "initialize" => (
            None,
            result(
                id,
                &json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "stdio-echo", "version": "1.0.0"},
                }),
            ),
        ),
        "ping" => (None, result(id, &json!({}))),
        "tools/list" => (None, result(id, &json!({"tools": [tool()]}))),
        "tools/call" => call(id, params),
        _ => (
            None,
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unknown method"}}),
        ),
    }
}

/// The one tool, `echo`, with its schemas and annotations.
fn tool() -> Value {
    let description = std::env::var("STDIO_ECHO_DESCRIPTION")
        .unwrap_or_else(|_| "Answers with the text it is given, unchanged.".to_owned());
    json!({
        "name": "echo",
        "title": "Echo",
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "The text to answer with."}},
            "required": ["text"],
        },
        "outputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "The text, unchanged."}},
            "required": ["text"],
        },
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false,
        },
    })
}

/// `tools/call`: `echo` with a string `text`, else invalid params.
fn call(id: &Value, params: &Value) -> (Option<Value>, Value) {
    let invalid =
        |why: &str| json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": why}});
    match params["name"].as_str() {
        Some("echo") => {}
        Some(other) => return (None, invalid(&format!("unknown tool: {other}"))),
        None => return (None, invalid("tools/call needs a tool name")),
    }
    let Some(text) = params["arguments"]["text"].as_str() else {
        return (None, invalid("echo needs a string argument text"));
    };
    let note = json!({
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": {"level": "info", "data": format!("echoing {text}")},
    });
    let reply = result(
        id,
        &json!({
            "content": [{"type": "text", "text": text}],
            "structuredContent": {"text": text},
        }),
    );
    (Some(note), reply)
}

fn main() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(message) = serde_json::from_str::<Value>(&line?) else {
            continue;
        };
        let (Some(method), Some(id)) = (message["method"].as_str(), message.get("id")) else {
            // A notification or a response: nothing to answer.
            continue;
        };
        let (before, reply) = answer(method, id, &message["params"]);
        for m in before.iter().chain([&reply]) {
            writeln!(out, "{m}")?;
        }
        out.flush()?;
    }
    Ok(())
}
