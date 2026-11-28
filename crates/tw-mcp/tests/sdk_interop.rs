// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The gateway-blind SDK helpers against this crate (ADR 0016): each one
//! seals a call that the connector side here opens, and opens the answer
//! this side seals. They need their runtimes (Node 24.7 or later, JDK 25
//! or later), so they are ignored by default; `scripts/sdk-interop.sh`
//! runs them.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use tunnelward_crypto::xwing::PrivateKeyXWing;
use tunnelward_mcp::blind::{open_call, seal_answer};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

/// The connector side of one exchange: opens what the agent sealed and
/// seals the answer, returning it and the answer as sent.
fn connector_side(sealed: &str, key: &PrivateKeyXWing, call: &Value) -> Res<(String, Value)> {
    assert!(!sealed.contains("alice"), "sealed: {sealed}");
    let (opened, response_key) =
        open_call(sealed.trim().as_bytes(), key)?.ok_or("not a sealed call")?;
    let opened: Value = serde_json::from_slice(&opened)?;
    assert_eq!(&opened, call, "the connector side opens exactly the call");
    let answer = json!({"jsonrpc":"2.0","id":11,"result":{"content":[{"type":"text","text":"sent 5 to alice"}]}});
    let sealed_answer = seal_answer(answer.to_string().as_bytes(), &response_key)?;
    Ok((String::from_utf8(sealed_answer)?, answer))
}

/// Runs `command` as the agent: it seals a call, this side opens it and
/// seals an answer, the agent opens that.
fn exchange(mut command: Command) -> Res<()> {
    let key = PrivateKeyXWing::generate()?;
    let mut child = command
        .arg(b64url(key.public_key()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let mut stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
    let call = json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"transfer","arguments":{"to":"alice","amount":5}}});
    writeln!(stdin, "{call}")?;
    let mut sealed = String::new();
    stdout.read_line(&mut sealed)?;
    let (sealed_answer, answer) = connector_side(&sealed, &key, &call)?;
    writeln!(stdin, "{sealed_answer}")?;
    let mut back = String::new();
    stdout.read_line(&mut back)?;
    assert_eq!(
        serde_json::from_str::<Value>(&back)?,
        answer,
        "the agent opens exactly the answer"
    );
    drop(stdin);
    assert!(child.wait()?.success());
    Ok(())
}

#[test]
#[ignore = "needs Node 24.7 or later: scripts/sdk-interop.sh"]
fn the_typescript_helper_on_node() -> Res<()> {
    let mut node = Command::new(std::env::var("NODE").unwrap_or_else(|_| "node".into()));
    node.arg(repo().join("sdk/typescript/blind/interop.ts"));
    exchange(node)
}

#[test]
#[ignore = "needs JDK 25 or later: scripts/sdk-interop.sh"]
fn the_java_helper() -> Res<()> {
    let dir =
        repo().join("sdk/java/blind/src/main/java/io/github/sebastienrousseau/tunnelward/blind");
    let mut java = Command::new(std::env::var("JAVA").unwrap_or_else(|_| "java".into()));
    java.arg(dir.join("Interop.java"));
    exchange(java)
}
