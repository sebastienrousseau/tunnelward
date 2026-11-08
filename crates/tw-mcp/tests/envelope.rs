// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the envelope parser accepts, what it refuses, and that it never
//! panics.

use proptest::prelude::*;
use tunnelward_mcp::{ClientInfo, EnvelopeError, Id, Kind, MAX_BATCH, MAX_BODY, is_json, parse};

type Res = Result<(), EnvelopeError>;

#[test]
fn requests_notifications_and_responses() -> Res {
    let request = parse(br#"{"jsonrpc":"2.0","id":"a","method":"tools/list"}"#)?;
    assert_eq!(request.messages[0].kind, Kind::Request);
    assert_eq!(request.messages[0].id, Some(Id::String("a".into())));
    let note = parse(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)?;
    assert_eq!(
        (note.messages[0].kind, note.messages[0].id.clone()),
        (Kind::Notification, None)
    );
    let answer = parse(br#"{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}"#)?;
    assert_eq!(answer.messages[0].kind, Kind::Response);
    assert_eq!(answer.messages[0].id, Some(Id::Number("3".into())));
    let failure = parse(br#"{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"no"}}"#)?;
    assert_eq!(failure.messages[0].kind, Kind::Response);
    Ok(())
}

#[test]
fn tool_names_come_only_from_tools_call() -> Res {
    let call = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"export","arguments":{"all":true}}}"#;
    assert_eq!(parse(call)?.messages[0].tool.as_deref(), Some("export"));
    let prompt = br#"{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"export"}}"#;
    assert_eq!(parse(prompt)?.messages[0].tool, None);
    Ok(())
}

#[test]
fn initialize_declares_the_client_and_meta_carries_a_traceparent() -> Res {
    let body = br#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{
        "protocolVersion":"2025-06-18","capabilities":{},
        "clientInfo":{"name":"claude-ai","version":"0.1.0"},
        "_meta":{"traceparent":"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}}}"#;
    let message = &parse(body)?.messages[0];
    let declared = ClientInfo {
        name: "claude-ai".into(),
        version: "0.1.0".into(),
    };
    assert_eq!(message.client.as_ref(), Some(&declared));
    assert_eq!(
        message.traceparent.as_deref(),
        Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
    );
    Ok(())
}

#[test]
fn client_info_counts_only_on_initialize() -> Res {
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"clientInfo":{"name":"x","version":"1"}}}"#;
    assert_eq!(parse(body)?.messages[0].client, None);
    Ok(())
}

#[test]
fn batches_keep_their_order() -> Res {
    let body = br#"[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","method":"b"}]"#;
    let envelope = parse(body)?;
    assert!(envelope.batch);
    let methods: Vec<_> = envelope
        .messages
        .iter()
        .map(|m| m.method.as_deref())
        .collect();
    assert_eq!(methods, [Some("a"), Some("b")]);
    Ok(())
}

#[test]
fn a_tools_call_must_name_its_tool() {
    // Each would otherwise reach policy as a tools/call with no tool.
    for body in [
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[1,2]}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":42}}"#,
    ] {
        assert_eq!(
            parse(body),
            Err(EnvelopeError::Shape),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn a_malformed_sibling_does_not_hide_the_tool() -> Res {
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"export","clientInfo":5,"_meta":7}}"#;
    assert_eq!(parse(body)?.messages[0].tool.as_deref(), Some("export"));
    Ok(())
}

#[test]
fn other_methods_may_have_any_params() -> Res {
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[1,2]}"#;
    assert_eq!(
        parse(body)?.messages[0].method.as_deref(),
        Some("tools/list")
    );
    Ok(())
}

/// Which error a refused body must give.
#[derive(Debug, Clone, Copy)]
enum Why {
    Json,
    JsonRpc,
    Shape,
    Batch,
}

#[test]
fn refusals() {
    let cases: [(&[u8], Why); 9] = [
        (b"not json", Why::Json),
        (br#"{"id":1,"method":"a"}"#, Why::JsonRpc),
        (br#"{"jsonrpc":"1.0","id":1,"method":"a"}"#, Why::JsonRpc),
        (br#"{"jsonrpc":"2.0","id":1}"#, Why::Shape),
        (br#"{"jsonrpc":"2.0","id":true,"method":"a"}"#, Why::Shape),
        (
            br#"{"jsonrpc":"2.0","id":1,"method":"a","result":{}}"#,
            Why::Shape,
        ),
        // Two methods in one message: a smuggling attempt, not JSON-RPC.
        (
            br#"{"jsonrpc":"2.0","id":1,"method":"a","method":"b"}"#,
            Why::Json,
        ),
        (b"[]", Why::Batch),
        (
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":42}}"#,
            Why::Shape,
        ),
    ];
    for (body, why) in cases {
        let refused = parse(body);
        let matches = matches!(
            (&refused, why),
            (Err(EnvelopeError::Json(_)), Why::Json)
                | (Err(EnvelopeError::NotJsonRpc), Why::JsonRpc)
                | (Err(EnvelopeError::Shape), Why::Shape)
                | (Err(EnvelopeError::Batch(_)), Why::Batch)
        );
        assert!(matches, "{}: {refused:?}", String::from_utf8_lossy(body));
    }
}

#[test]
fn limits_are_enforced() {
    let big = vec![b' '; MAX_BODY + 1];
    assert_eq!(parse(&big), Err(EnvelopeError::TooLarge(MAX_BODY + 1)));
    let one = r#"{"jsonrpc":"2.0","method":"a"}"#;
    let batch = format!("[{}]", vec![one; MAX_BATCH + 1].join(","));
    assert_eq!(
        parse(batch.as_bytes()),
        Err(EnvelopeError::Batch(MAX_BATCH + 1))
    );
    let long = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}"}}"#,
        "m".repeat(257)
    );
    assert_eq!(parse(long.as_bytes()), Err(EnvelopeError::FieldTooLong));
}

#[test]
fn json_content_types() {
    assert!(is_json("application/json"));
    assert!(is_json("Application/JSON; charset=utf-8"));
    assert!(!is_json("text/event-stream"));
    assert!(!is_json("application/jsonx"));
}

proptest! {
    #[test]
    fn never_panics(body in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _outcome = parse(&body);
    }

    #[test]
    fn a_tools_call_names_its_tool(tool in "[a-zA-Z0-9_.-]{1,64}", id in any::<i64>()) {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}"}}}}"#
        );
        let envelope = parse(body.as_bytes()).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(envelope.messages[0].tool.as_deref(), Some(tool.as_str()));
        prop_assert_eq!(envelope.messages[0].id.clone(), Some(Id::Number(id.to_string())));
    }
}
