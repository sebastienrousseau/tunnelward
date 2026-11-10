// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! What a signed receipt costs (FR-15, ADR 0008): issuing one is on the
//! request path when receipts are on, so its time counts against
//! NFR-1's budget.

use std::time::Instant;

use tunnelward_audit::receipt::{Receipt, issue, verify};
use tunnelward_crypto::composite::SigningKey;

use crate::setup::Res;

/// Receipts per run.
const PER_RUN: u32 = 1000;
/// Runs.
const RUNS: usize = 5;

/// A receipt like the gateway's for one `tools/call`.
fn sample() -> Receipt {
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_balance","arguments":{"account":"A-1"}}}"#;
    let mut entry = tunnelward_audit::RequestEntry::default();
    entry.request_id = "01JC0000000000000000000000".into();
    entry.method = "POST".into();
    entry.path = "/mcp".into();
    entry.evidence = "cryptographic".into();
    entry.calls = tunnelward_audit::calls(body);
    entry.request_digest = Some(tunnelward_audit::digest(body));
    entry.decision = "forwarded".into();
    entry.status = 200;
    Receipt::from_entry(&entry)
}

/// Per run: microseconds to issue one, to verify one, and the receipt's
/// length in bytes.
pub(crate) fn run() -> Res<Vec<(f64, f64, usize)>> {
    let (key, _) = SigningKey::generate()?;
    let public = key.public_key();
    let id = tunnelward_audit::key_id(&public);
    let body = sample();
    let mut text = issue(&key, &id, &body)?;
    let mut rows = Vec::new();
    for _ in 0..RUNS {
        let started = Instant::now();
        for _ in 0..PER_RUN {
            text = issue(&key, &id, &body)?;
        }
        let signing = started.elapsed() / PER_RUN;
        let started = Instant::now();
        for _ in 0..PER_RUN {
            verify(&public, &text)?;
        }
        let checking = started.elapsed() / PER_RUN;
        rows.push((micros(signing), micros(checking), text.len()));
    }
    Ok(rows)
}

fn micros(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

/// The rows as Markdown.
pub(crate) fn report(rows: &[(f64, f64, usize)]) {
    println!("## Receipts: signing and checking one (FR-15)\n");
    println!("| Run | Issue | Verify | Header |");
    println!("| ---: | ---: | ---: | ---: |");
    for (i, (issue, verify, len)) in rows.iter().enumerate() {
        println!("| {} | {issue:.0} µs | {verify:.0} µs | {len} B |", i + 1);
    }
    println!();
}
