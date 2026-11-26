// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Each subject's steps between tools, for drift.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// One subject's history.
#[derive(Debug, Default)]
struct History {
    /// When the subject was last seen, in calls to [`Baselines::step`].
    seen: u64,
    calls: u32,
    last: Option<String>,
    steps: HashSet<(String, String)>,
    /// The last drift, and when it happened.
    drift: Option<(String, String, Instant)>,
}

/// Steps per subject, at most `max_subjects` of them; the subject seen
/// least recently goes first.
#[derive(Debug, Default)]
pub(crate) struct Baselines {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    subjects: HashMap<String, History>,
    clock: u64,
}

/// How [`Baselines::step`] is bounded.
pub(crate) struct Bounds {
    pub(crate) warmup: u32,
    pub(crate) max_steps: usize,
    pub(crate) max_subjects: usize,
}

impl Baselines {
    /// Records `subject` calling `tool`; returns the tool before it when
    /// the step is new and the subject is past its warm-up.
    pub(crate) fn step(&self, subject: &str, tool: &str, bounds: &Bounds) -> Option<String> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let history = inner.history(subject, bounds.max_subjects);
        history.calls = history.calls.saturating_add(1);
        let from = history.last.replace(tool.to_owned())?;
        let step = (from.clone(), tool.to_owned());
        let known = history.steps.contains(&step);
        if !known && history.steps.len() < bounds.max_steps {
            history.steps.insert(step);
        }
        let drifted = !known && history.calls > bounds.warmup;
        if drifted {
            history.drift = Some((from.clone(), tool.to_owned(), now));
        }
        drifted.then_some(from)
    }

    /// `subject`'s last drift, if it happened less than `window` ago.
    pub(crate) fn recent(&self, subject: &str, window: Duration) -> Option<(String, String)> {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let (from, to, at) = inner.subjects.get(subject)?.drift.as_ref()?;
        (at.elapsed() < window).then(|| (from.clone(), to.clone()))
    }

    /// Subjects remembered now.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .subjects
            .len()
    }
}

impl Inner {
    /// `subject`'s history, marked most recent. A subject not yet known
    /// at `max` subjects first evicts the one seen least recently: the
    /// only step that scans.
    fn history(&mut self, subject: &str, max: usize) -> &mut History {
        self.clock = self.clock.wrapping_add(1);
        if !self.subjects.contains_key(subject) && self.subjects.len() >= max.max(1) {
            let oldest = self.subjects.iter().min_by_key(|(_, h)| h.seen);
            if let Some(old) = oldest.map(|(k, _)| k.clone()) {
                self.subjects.remove(&old);
            }
        }
        let history = self.subjects.entry(subject.to_owned()).or_default();
        history.seen = self.clock;
        history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUNDS: Bounds = Bounds {
        warmup: 2,
        max_steps: 8,
        max_subjects: 2,
    };

    #[test]
    fn a_new_step_after_the_warmup_is_drift() {
        let b = Baselines::default();
        assert_eq!(b.step("s", "search", &BOUNDS), None);
        assert_eq!(b.step("s", "search", &BOUNDS), None, "within the warm-up");
        assert_eq!(b.step("s", "search", &BOUNDS), None, "a known step");
        assert_eq!(b.step("s", "export", &BOUNDS), Some("search".into()));
        assert_eq!(b.step("s", "search", &BOUNDS), Some("export".into()));
        assert_eq!(b.step("s", "export", &BOUNDS), None, "now known");
        assert_eq!(
            b.recent("s", Duration::from_secs(60)),
            Some(("export".into(), "search".into()))
        );
        assert_eq!(b.recent("s", Duration::ZERO), None, "the window passed");
        assert_eq!(b.recent("t", Duration::from_secs(60)), None);
    }

    #[test]
    fn the_oldest_subject_is_forgotten() {
        let b = Baselines::default();
        for s in ["a", "b", "a", "c"] {
            b.step(s, "t", &BOUNDS);
        }
        assert_eq!(b.len(), 2);
        let inner = b.inner.lock().unwrap();
        assert!(inner.subjects.contains_key("a") && inner.subjects.contains_key("c"));
    }
}
