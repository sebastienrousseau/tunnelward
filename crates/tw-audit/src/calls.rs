// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The MCP calls in a request body, with digests of their arguments in
//! place of the arguments themselves.

use serde_json::Value;

use crate::Call;

/// Most calls recorded from one body.
const MAX_CALLS: usize = 100;
/// Longest method or tool name kept, in bytes.
const MAX_NAME: usize = 256;

/// The JSON-RPC calls in `body` (one message or a batch): each method,
/// the tool of a `tools/call`, and the SHA-256 of `params.arguments`
/// written back by `serde_json` with its keys sorted, so the digest does
/// not depend on the client's key order or spacing. A body that is not
/// JSON has none.
#[must_use]
pub fn calls(body: &[u8]) -> Vec<Call> {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    let messages = match value {
        Value::Array(items) => items,
        single => vec![single],
    };
    messages.iter().filter_map(call).take(MAX_CALLS).collect()
}

fn call(message: &Value) -> Option<Call> {
    let method = message.get("method")?.as_str()?;
    let params = message.get("params");
    let tool = params
        .filter(|_| method == "tools/call")
        .and_then(|p| p.get("name")?.as_str())
        .map(cut);
    let arguments = params
        .and_then(|p| p.get("arguments"))
        .and_then(|a| serde_json::to_vec(a).ok())
        .map(|bytes| crate::digest(&bytes));
    Some(Call {
        method: cut(method),
        tool,
        arguments,
    })
}

/// `text` cut to [`MAX_NAME`] bytes on a character boundary.
fn cut(text: &str) -> String {
    let mut end = text.len().min(MAX_NAME);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_call_records_its_tool_and_a_digest_of_its_arguments() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"b":2,"a":"secret"}}}"#;
        let got = calls(body);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].method, "tools/call");
        assert_eq!(got[0].tool.as_deref(), Some("pay"));
        let digest = got[0].arguments.clone().unwrap();
        assert_eq!(digest, crate::digest(br#"{"a":"secret","b":2}"#));
        let reordered =
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{ "a" : "secret", "b":2 }}}"#;
        assert_eq!(calls(reordered)[0].arguments, Some(digest));
        assert!(!format!("{got:?}").contains("secret"));
    }

    #[test]
    fn batches_responses_and_non_json() {
        let batch = br#"[{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"result":{}},{"jsonrpc":"2.0","id":3,"method":"tools/list"}]"#;
        let methods: Vec<_> = calls(batch).into_iter().map(|c| c.method).collect();
        assert_eq!(methods, ["notifications/initialized", "tools/list"]);
        assert_eq!(calls(b"not json"), []);
        assert_eq!(calls(b""), []);
    }

    #[test]
    fn long_names_are_cut() {
        let name = "é".repeat(200);
        let body = format!(r#"{{"method":"tools/call","params":{{"name":"{name}"}}}}"#);
        let tool = calls(body.as_bytes())[0].tool.clone().unwrap();
        assert!(tool.len() <= 256 && tool.len() >= 254);
    }
}
