// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Checks an audit log offline: every line names the hash of the one
//! before it, `seq` counts up from 0 without gaps, and every checkpoint
//! is signed by one of the given keys. Fields it does not know are
//! ignored, so newer entries still verify.

use std::io::BufRead;

use serde_json::Value;

use crate::{b64, chain};

/// What [`verify`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// Lines read.
    pub lines: u64,
    /// Request and admin entries.
    pub entries: u64,
    /// Signed checkpoints.
    pub checkpoints: u64,
    /// Entries the writer recorded as dropped, from its gap lines.
    pub dropped: u64,
    /// The `seq` of the last checkpoint: every line before it is signed.
    pub signed_through: Option<u64>,
    /// Lines after the last checkpoint, which nothing signs yet: they
    /// could be cut off without trace.
    pub unsigned: u64,
    /// The first line that fails, if one does; nothing after it is read.
    pub problem: Option<Problem>,
}

/// A line that fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Its line number, from 1.
    pub line: u64,
    /// Why.
    pub what: String,
}

impl Report {
    /// Whether every line passed.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.problem.is_none()
    }
}

/// Checks the log in `reader` against the checkpoint keys `keys` (each a
/// composite public key).
///
/// # Errors
///
/// Reading failed.
pub fn verify(mut reader: impl BufRead, keys: &[Vec<u8>]) -> std::io::Result<Report> {
    let mut walk = Walk {
        keys: keys
            .iter()
            .map(|k| (chain::key_id(k), k.as_slice()))
            .collect(),
        prev: chain::GENESIS.to_owned(),
        report: Report::default(),
    };
    let mut bytes = Vec::new();
    loop {
        bytes.clear();
        if reader.read_until(b'\n', &mut bytes)? == 0 {
            return Ok(walk.report);
        }
        walk.report.lines += 1;
        let checked = match bytes.strip_suffix(b"\n") {
            Some(line) => walk.line(line),
            None => Err("the last line is incomplete".to_owned()),
        };
        if let Err(what) = checked {
            walk.report.problem = Some(Problem {
                line: walk.report.lines,
                what,
            });
            return Ok(walk.report);
        }
    }
}

struct Walk<'k> {
    keys: Vec<(String, &'k [u8])>,
    prev: String,
    report: Report,
}

impl Walk<'_> {
    fn line(&mut self, line: &[u8]) -> Result<(), String> {
        let value: Value = serde_json::from_slice(line).map_err(|_| "not JSON".to_owned())?;
        let expected = self.report.lines - 1;
        let seq = value.get("seq").and_then(Value::as_u64);
        if seq != Some(expected) {
            return Err(format!("seq is {seq:?}, expected {expected}"));
        }
        if value.get("prev").and_then(Value::as_str) != Some(&self.prev) {
            return Err("prev does not match the line before".to_owned());
        }
        match value.get("kind").and_then(Value::as_str) {
            Some("checkpoint") => self.checkpoint(&value, expected)?,
            Some("gap") => {
                self.report.dropped += value.get("dropped").and_then(Value::as_u64).unwrap_or(0);
                self.report.unsigned += 1;
            }
            _ => {
                self.report.entries += 1;
                self.report.unsigned += 1;
            }
        }
        self.prev = chain::hash_line(line);
        Ok(())
    }

    fn checkpoint(&mut self, value: &Value, seq: u64) -> Result<(), String> {
        let id = value.get("key").and_then(Value::as_str).unwrap_or("");
        let public = self
            .keys
            .iter()
            .find(|(k, _)| k == id)
            .map(|(_, p)| *p)
            .ok_or_else(|| format!("checkpoint signed by key {id}, which was not given"))?;
        let time = value.get("time").and_then(Value::as_u64).unwrap_or(0);
        let signature = value
            .get("sig")
            .and_then(Value::as_str)
            .and_then(b64::decode)
            .unwrap_or_default();
        if !chain::verify(public, seq, &self.prev, time, &signature) {
            return Err("checkpoint signature does not verify".to_owned());
        }
        self.report.checkpoints += 1;
        self.report.signed_through = Some(seq);
        self.report.unsigned = 0;
        Ok(())
    }
}
