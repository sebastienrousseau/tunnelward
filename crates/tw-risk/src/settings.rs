// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! What the risk score counts, and how much each signal weighs.

use std::time::Duration;

/// Every limit and weight of the risk score, each configurable
/// (`[risk]` in the gateway file); [`Settings::default`] gives the
/// documented defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The window velocity is counted over.
    pub window: Duration,
    /// Most calls one subject may make in a window.
    pub per_subject: u64,
    /// Most calls one subject may make to one tool in a window.
    pub per_tool: u64,
    /// Most calls from one IP prefix (/24, /48) in a window.
    pub per_prefix: u64,
    /// What each velocity limit crossed adds to the score.
    pub velocity_weight: u8,
    /// Calls a subject makes before a new step between tools counts as
    /// drift.
    pub warmup: u32,
    /// What a drift adds to the score.
    pub drift_weight: u8,
    /// Most distinct steps remembered per subject.
    pub max_steps: usize,
    /// Most subjects whose steps are remembered; the oldest goes first.
    pub max_subjects: usize,
    /// Tools no legitimate agent calls: a call scores 100.
    pub canary_tools: Vec<String>,
    /// Planted values no legitimate request contains: a request body
    /// holding one scores 100.
    pub canary_records: Vec<String>,
    /// The score at which observers are alerted.
    pub alert_at: u8,
    /// How long a canary blocks its subject and MCP session.
    pub block: Duration,
    /// Most subjects and sessions blocked at once.
    pub max_blocked: usize,
}

impl Default for Settings {
    /// A 60 s window; 120 calls per subject, 60 per tool, 600 per
    /// prefix, each worth 35; drift after 20 calls, worth 25, 256 steps
    /// per subject, 10,000 subjects; no canaries; alerts at 70; a canary
    /// blocks for an hour, 10,000 blocks at most.
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60),
            per_subject: 120,
            per_tool: 60,
            per_prefix: 600,
            velocity_weight: 35,
            warmup: 20,
            drift_weight: 25,
            max_steps: 256,
            max_subjects: 10_000,
            canary_tools: Vec::new(),
            canary_records: Vec::new(),
            alert_at: 70,
            block: Duration::from_secs(3600),
            max_blocked: 10_000,
        }
    }
}
