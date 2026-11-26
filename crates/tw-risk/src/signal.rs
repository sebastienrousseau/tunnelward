// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! What raised a score.

use core::fmt;

/// What a velocity limit counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Calls by one subject.
    Subject,
    /// Calls by one subject to one tool.
    Tool,
    /// Calls from one IP prefix.
    Prefix,
}

/// One reason a score rose.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Signal {
    /// More calls in the window than `limit`.
    Velocity {
        /// What was counted.
        scope: Scope,
        /// How many calls, this one included.
        count: u64,
        /// The limit crossed.
        limit: u64,
    },
    /// A step between tools the subject had not taken before.
    Drift {
        /// The tool before.
        from: String,
        /// The tool now.
        to: String,
    },
    /// A call to a canary tool.
    CanaryTool(String),
    /// A request body holding a canary record.
    CanaryRecord,
}

impl Signal {
    /// Whether this is a canary.
    #[must_use]
    pub fn is_canary(&self) -> bool {
        matches!(self, Self::CanaryTool(_) | Self::CanaryRecord)
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Velocity {
                scope,
                count,
                limit,
            } => {
                let scope = match scope {
                    Scope::Subject => "subject",
                    Scope::Tool => "tool",
                    Scope::Prefix => "prefix",
                };
                write!(f, "velocity:{scope}:{count}>{limit}")
            }
            Self::Drift { from, to } => write!(f, "drift:{from}->{to}"),
            Self::CanaryTool(tool) => write!(f, "canary-tool:{tool}"),
            Self::CanaryRecord => f.write_str("canary-record"),
        }
    }
}

/// A request's score and what raised it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assessment {
    /// 0 to 100.
    pub score: u8,
    /// Every signal that fired.
    pub signals: Vec<Signal>,
}

impl Assessment {
    /// Whether a canary fired.
    #[must_use]
    pub fn canary(&self) -> bool {
        self.signals.iter().any(Signal::is_canary)
    }

    /// Adds `signal`, worth `weight`; a canary sets the score to 100.
    pub(crate) fn add(&mut self, signal: Signal, weight: u8) {
        self.score = if signal.is_canary() {
            100
        } else {
            self.score.saturating_add(weight).min(100)
        };
        self.signals.push(signal);
    }
}
