// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway file's `[risk]` (FR-16, ADR 0011) and `[telemetry]`
//! (ADR 0010). Both are read when the gateway starts; a change needs a
//! restart, since the risk baselines and the exporter's queue live in it.
//!
//! ```toml
//! [risk]                          # every key optional; defaults shown
//! window_secs = 60                # velocity is counted over this window
//! per_subject = 120               # calls by one client (else address)
//! per_tool = 60                   # calls by one client to one tool
//! per_prefix = 600                # calls from one /24 or /48
//! velocity_weight = 35            # what each limit crossed adds
//! warmup = 20                     # calls before a new step is drift
//! drift_weight = 25
//! max_steps = 256                 # steps remembered per subject
//! max_subjects = 10000            # subjects remembered
//! canary_tools = ["export_all_customers"]
//! canary_records = ["CANARY-4417"]
//! alert_at = 70                   # the score that alerts observers
//! block_secs = 3600               # how long a canary ends a session
//! max_blocked = 10000
//!
//! [telemetry]
//! otlp_endpoint = "http://127.0.0.1:4318"   # https://, or http:// to
//!                                           # loopback; spans go to
//!                                           # <endpoint>/v1/traces
//! service_name = "tunnelward-gateway"       # optional
//! ca = "collector-ca.crt"                   # optional: roots for https
//! queue = 2048                              # optional limits
//! batch = 512
//! every_ms = 5000
//! ```
//!
//! RED metrics are on the admin API's `/metrics` with or without
//! `[telemetry]`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_gateway::{OtlpExporter, OtlpSettings};
use tunnelward_risk::{Risk, Settings};

use crate::config::{Problems, resolve};

/// The gateway file's `[risk]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RiskSection {
    window_secs: Option<u64>,
    per_subject: Option<u64>,
    per_tool: Option<u64>,
    per_prefix: Option<u64>,
    velocity_weight: Option<u8>,
    warmup: Option<u32>,
    drift_weight: Option<u8>,
    max_steps: Option<usize>,
    max_subjects: Option<usize>,
    #[serde(default)]
    canary_tools: Vec<String>,
    #[serde(default)]
    canary_records: Vec<String>,
    alert_at: Option<u8>,
    block_secs: Option<u64>,
    max_blocked: Option<usize>,
}

/// The gateway file's `[telemetry]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TelemetrySection {
    otlp_endpoint: String,
    service_name: Option<String>,
    ca: Option<PathBuf>,
    queue: Option<usize>,
    batch: Option<usize>,
    every_ms: Option<u64>,
}

/// A checked `[telemetry]`: the exporter to start with the gateway.
pub(crate) struct Otlp {
    settings: OtlpSettings,
    roots: Arc<RootCertStore>,
}

impl Otlp {
    /// Starts the exporter; inside the gateway's runtime.
    pub(crate) fn start(self) -> Result<Arc<OtlpExporter>, String> {
        OtlpExporter::start(self.settings, self.roots).map_err(|e| format!("[telemetry] {e}"))
    }
}

/// The risk score `section` describes, every problem noted.
pub(crate) fn risk(section: &RiskSection, problems: &mut Problems) -> Option<Arc<Risk>> {
    let settings = risk_settings(section);
    let before = problems.len();
    let positive = [
        ("window_secs", settings.window.as_secs()),
        ("per_subject", settings.per_subject),
        ("per_tool", settings.per_tool),
        ("per_prefix", settings.per_prefix),
        ("block_secs", settings.block.as_secs()),
    ];
    for (key, value) in positive.iter().filter(|(_, v)| *v == 0) {
        problems.push(format!("[risk] {key} {value}: give at least 1"));
    }
    let sizes = [
        settings.max_steps,
        settings.max_subjects,
        settings.max_blocked,
    ];
    if sizes.contains(&0) {
        problems.push("[risk]: max_steps, max_subjects and max_blocked are at least 1".into());
    }
    let scores = [
        settings.velocity_weight,
        settings.drift_weight,
        settings.alert_at,
    ];
    if scores.iter().any(|s| *s > 100) || settings.alert_at == 0 {
        problems.push("[risk]: weights are 0 to 100, alert_at 1 to 100".into());
    }
    let blank = settings.canary_tools.iter().chain(&settings.canary_records);
    if blank.into_iter().any(|c| c.trim().is_empty()) {
        problems.push("[risk]: a canary cannot be empty".into());
    }
    (problems.len() == before).then(|| Arc::new(Risk::new(settings)))
}

fn risk_settings(section: &RiskSection) -> Settings {
    let d = Settings::default();
    Settings {
        window: section.window_secs.map_or(d.window, Duration::from_secs),
        per_subject: section.per_subject.unwrap_or(d.per_subject),
        per_tool: section.per_tool.unwrap_or(d.per_tool),
        per_prefix: section.per_prefix.unwrap_or(d.per_prefix),
        velocity_weight: section.velocity_weight.unwrap_or(d.velocity_weight),
        warmup: section.warmup.unwrap_or(d.warmup),
        drift_weight: section.drift_weight.unwrap_or(d.drift_weight),
        max_steps: section.max_steps.unwrap_or(d.max_steps),
        max_subjects: section.max_subjects.unwrap_or(d.max_subjects),
        canary_tools: section.canary_tools.clone(),
        canary_records: section.canary_records.clone(),
        alert_at: section.alert_at.unwrap_or(d.alert_at),
        block: section.block_secs.map_or(d.block, Duration::from_secs),
        max_blocked: section.max_blocked.unwrap_or(d.max_blocked),
    }
}

/// The exporter `section` describes, every problem noted.
pub(crate) fn telemetry(
    base: &Path,
    section: &TelemetrySection,
    problems: &mut Problems,
) -> Option<Otlp> {
    let d = OtlpSettings::new(section.otlp_endpoint.clone());
    let settings = OtlpSettings {
        service: section.service_name.clone().unwrap_or(d.service.clone()),
        queue: section.queue.unwrap_or(d.queue),
        batch: section.batch.unwrap_or(d.batch),
        every: section.every_ms.map_or(d.every, Duration::from_millis),
        ..d
    };
    let before = problems.len();
    if let Err(e) = settings.check() {
        problems.push(format!("[telemetry] {e}"));
    }
    if settings.queue == 0 || settings.batch == 0 || settings.every.is_zero() {
        problems.push("[telemetry]: queue, batch and every_ms are at least 1".into());
    }
    // Roots only for https://: a collector on loopback over plain HTTP
    // needs no CA bundle, and a machine may have none.
    let roots = if settings.endpoint.starts_with("https://") {
        crate::agents::system_roots(section.ca.as_ref().map(|c| resolve(base, c)))
            .map_err(|e| problems.push(format!("[telemetry] ca: {e}")))
            .ok()?
    } else {
        Arc::new(RootCertStore::empty())
    };
    (problems.len() == before).then_some(Otlp { settings, roots })
}
