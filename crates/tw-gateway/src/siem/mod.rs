// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Audit export to a SIEM (ADR 0013). The audit writer hands each line
//! it wrote to a [`Forwarder`]; a bounded queue takes it to one task,
//! which turns entries into OCSF events and sends them as RFC 5424
//! syslog, as OTLP logs, or both. A full queue drops the line and counts
//! it, so export never holds up the log; the chained file stays the
//! record, and a SIEM that missed an event can be filled from
//! `tunnelward audit export`.

mod logs;
mod syslog;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc;

pub use logs::OtlpLogSettings;
pub use syslog::SyslogSettings;

/// Where and how audit events are exported. [`SiemSettings::new`] gives
/// the defaults, with no destination.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SiemSettings {
    /// Send each event as an RFC 5424 syslog message.
    pub syslog: Option<SyslogSettings>,
    /// Send events as OTLP/HTTP JSON logs.
    pub otlp: Option<OtlpLogSettings>,
    /// Most lines waiting to be sent; more are dropped and counted.
    pub queue: usize,
    /// Most events in one send.
    pub batch: usize,
    /// Longest an event waits for its batch to fill.
    pub every: Duration,
}

impl SiemSettings {
    /// No destination yet; a queue of 4,096, batches of 256, sent at
    /// least every second.
    #[must_use]
    pub fn new() -> Self {
        Self {
            syslog: None,
            otlp: None,
            queue: 4096,
            batch: 256,
            every: Duration::from_secs(1),
        }
    }

    /// Whether the settings can export.
    ///
    /// # Errors
    ///
    /// A sentence for each problem: no destination, a destination that
    /// is not allowed, or a limit of 0.
    pub fn check(&self) -> Result<(), Vec<String>> {
        let mut problems = Vec::new();
        if self.syslog.is_none() && self.otlp.is_none() {
            problems.push("name a syslog or an OTLP destination".to_owned());
        }
        problems.extend(self.syslog.as_ref().and_then(|s| s.check().err()));
        problems.extend(self.otlp.as_ref().and_then(|o| o.check().err()));
        if self.queue == 0 || self.batch == 0 || self.every.is_zero() {
            problems.push("queue, batch and every_ms are at least 1".to_owned());
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }
}

impl Default for SiemSettings {
    fn default() -> Self {
        Self::new()
    }
}

/// Takes audit lines and exports their events. Install it as the audit
/// log's `forward`.
#[derive(Debug)]
pub struct Forwarder {
    queue: mpsc::Sender<Vec<u8>>,
    dropped: AtomicU64,
    failed: Arc<AtomicU64>,
}

impl Forwarder {
    /// A forwarder sending as `settings` say. Must be called inside a
    /// Tokio runtime: it spawns the sending task.
    ///
    /// # Errors
    ///
    /// What [`SiemSettings::check`] finds, joined.
    pub fn start(settings: SiemSettings) -> Result<Arc<Self>, String> {
        settings.check().map_err(|p| p.join("; "))?;
        let (queue, lines) = mpsc::channel(settings.queue);
        let failed = Arc::new(AtomicU64::new(0));
        let task = Task {
            syslog: settings.syslog.map(syslog::Client::new),
            otlp: settings.otlp.map(logs::Client::new).transpose()?,
            batch: settings.batch,
            every: settings.every,
            failed: failed.clone(),
        };
        tokio::spawn(task.run(lines));
        Ok(Arc::new(Self {
            queue,
            dropped: AtomicU64::new(0),
            failed,
        }))
    }

    /// Lines dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Sends a destination did not take.
    #[must_use]
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }
}

impl tunnelward_audit::Forward for Forwarder {
    fn line(&self, line: &[u8]) {
        if self.queue.try_send(line.to_vec()).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Whether `event` records a failure (OCSF `status_id` 2): syslog and
/// OTLP mark those as warnings.
fn is_failure(event: &Value) -> bool {
    event.get("status_id").and_then(Value::as_u64) == Some(2)
}

/// The task that sends batches.
struct Task {
    syslog: Option<syslog::Client>,
    otlp: Option<logs::Client>,
    batch: usize,
    every: Duration,
    failed: Arc<AtomicU64>,
}

impl Task {
    async fn run(mut self, mut lines: mpsc::Receiver<Vec<u8>>) {
        let mut batch = Vec::with_capacity(self.batch);
        loop {
            let next = tokio::time::timeout(self.every, lines.recv()).await;
            let closed = matches!(next, Ok(None));
            if let Ok(Some(line)) = &next {
                batch.extend(event(line));
            }
            let due = closed || next.is_err() || batch.len() >= self.batch;
            if due && !batch.is_empty() {
                self.send(&std::mem::take(&mut batch)).await;
            }
            if closed {
                return;
            }
        }
    }

    async fn send(&mut self, events: &[Value]) {
        let mut failures = 0;
        if let Some(syslog) = &mut self.syslog {
            failures += u64::from(syslog.send(events).await.is_err());
        }
        if let Some(otlp) = &self.otlp {
            failures += u64::from(otlp.send(events).await.is_err());
        }
        self.failed.fetch_add(failures, Ordering::Relaxed);
    }
}

/// The OCSF event for an audit line, if it is an entry.
fn event(line: &[u8]) -> Option<Value> {
    tunnelward_audit::ocsf::event(std::str::from_utf8(line).ok()?)
}
