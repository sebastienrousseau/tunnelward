// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Feeds arbitrary bytes to the MCP envelope parser. It must never panic,
//! every message it accepts has a method or is a response, and a
//! `tools/call` it accepts always names its tool.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tunnelward_mcp::{Kind, parse};

fuzz_target!(|data: &[u8]| {
    let Ok(envelope) = parse(data) else {
        return;
    };
    assert!(!envelope.messages.is_empty());
    for message in &envelope.messages {
        assert!(message.method.is_some() || message.kind == Kind::Response);
        if message.method.as_deref() == Some("tools/call") {
            assert!(message.tool.is_some(), "a tools/call without a tool");
        }
    }
});
