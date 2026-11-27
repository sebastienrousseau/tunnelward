// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward crypto report --admin <addr>`: the TLS each live connector
//! connection negotiated, from a gateway's admin API, as a post-quantum
//! migration inventory wants it: protocol, key exchange, cipher suite
//! and the connector's key. The admin token, when the gateway needs one,
//! comes from `TUNNELWARD_ADMIN_TOKEN`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::Value;

use crate::Outcome;
use crate::args::{Args, UsageError};

/// Longest answer read from the admin API.
const MAX_ANSWER: u64 = 4 * 1024 * 1024;
/// Longest the admin API may take to connect or answer.
const TIMEOUT: Duration = Duration::from_secs(10);

/// `crypto report --admin <addr>`.
pub(crate) fn command(args: &[String]) -> Result<(), Outcome> {
    if args.first().map(String::as_str) != Some("report") {
        return Err(UsageError("crypto needs 'report'".into()).into());
    }
    let args = Args::parse(&args[1..], &["admin"])?;
    let admin = args
        .get("admin")
        .ok_or_else(|| UsageError("crypto report needs '--admin <addr>'".into()))?;
    let token = std::env::var("TUNNELWARD_ADMIN_TOKEN").ok();
    let inventory = fetch(admin, token.as_deref()).map_err(Outcome::Failed)?;
    print!("{}", report(&inventory).map_err(Outcome::Failed)?);
    Ok(())
}

/// The admin API's internal inventory at `admin`, as JSON.
fn fetch(admin: &str, token: Option<&str>) -> Result<Value, String> {
    let failed = |e: std::io::Error| format!("{admin}: {e}");
    let mut tcp = TcpStream::connect(admin).map_err(failed)?;
    tcp.set_read_timeout(Some(TIMEOUT)).map_err(failed)?;
    let auth = token.map_or_else(String::new, |t| format!("authorization: Bearer {t}\r\n"));
    write!(
        tcp,
        "GET /inventory?redaction=internal HTTP/1.1\r\nhost: {admin}\r\n{auth}connection: close\r\n\r\n"
    )
    .map_err(failed)?;
    let mut answer = Vec::new();
    tcp.take(MAX_ANSWER)
        .read_to_end(&mut answer)
        .map_err(failed)?;
    let answer = String::from_utf8_lossy(&answer);
    let (head, body) = answer.split_once("\r\n\r\n").unwrap_or((&answer, ""));
    let status = head.split(' ').nth(1).unwrap_or_default();
    if status != "200" {
        return Err(format!("{admin}: the admin API answered {status:?}"));
    }
    serde_json::from_str(body).map_err(|e| format!("{admin}: {e}"))
}

/// One line per connection, then how many used a hybrid post-quantum
/// key exchange.
fn report(inventory: &Value) -> Result<String, String> {
    let connections = inventory
        .get("detail")
        .and_then(Value::as_array)
        .ok_or("the inventory lists no connections")?;
    let field = |c: &Value, key: &str| {
        c.pointer(&format!("/tls/{key}"))
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_owned()
    };
    let row = |c: [&str; 6]| {
        format!(
            "{:<32}  {:<15}  {:<8}  {:<15}  {:<26}  {}",
            c[0], c[1], c[2], c[3], c[4], c[5]
        )
    };
    let mut lines = vec![row([
        "CONNECTOR",
        "PEER",
        "TLS",
        "KEY EXCHANGE",
        "CIPHER SUITE",
        "PEER KEY",
    ])];
    let mut hybrid = 0;
    for c in connections {
        let key_exchange = field(c, "key_exchange");
        hybrid += usize::from(key_exchange.contains("MLKEM"));
        lines.push(row([
            c.get("connector").and_then(Value::as_str).unwrap_or("-"),
            c.get("peer").and_then(Value::as_str).unwrap_or("-"),
            &field(c, "version"),
            &key_exchange,
            &field(c, "cipher_suite"),
            &field(c, "peer_key"),
        ]));
    }
    let total = connections.len();
    lines.push(format!(
        "connections {total}, hybrid post-quantum {hybrid}, classical {}",
        total - hybrid
    ));
    Ok(lines.join("\n") + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn each_connection_is_a_line_and_hybrids_are_counted() {
        let inventory = json!({"connections": 2, "detail": [
            {"connector": "ab", "peer": "10.0.0.4", "tls": {
                "version": "TLSv1_3", "key_exchange": "X25519MLKEM768",
                "cipher_suite": "TLS13_AES_256_GCM_SHA384", "peer_key": "ECDSA P-256"}},
            {"connector": "cd", "tls": {"version": "TLSv1_3", "key_exchange": "X25519"}},
        ]});
        let text = report(&inventory).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert!(lines[1].contains("X25519MLKEM768") && lines[1].ends_with("ECDSA P-256"));
        assert!(
            lines[2].starts_with("cd ") && lines[2].contains(" - "),
            "{text}"
        );
        assert_eq!(
            lines[3],
            "connections 2, hybrid post-quantum 1, classical 1"
        );
        assert!(report(&json!({"connections": 0})).is_err());
    }
}
