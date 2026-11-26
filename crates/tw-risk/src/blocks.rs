// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Subjects and sessions a canary ended, until their block runs out.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

/// Blocked keys and when each block ends, at most `max` of them; at
/// capacity, the block ending soonest gives way.
#[derive(Debug, Default)]
pub(crate) struct Blocks {
    until: Mutex<HashMap<String, Instant>>,
}

impl Blocks {
    /// Blocks `key` until `until`.
    pub(crate) fn block(&self, key: String, until: Instant, max: usize) {
        let mut map = self.until.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        map.retain(|_, end| *end > now);
        if !map.contains_key(&key) && map.len() >= max.max(1) {
            let soonest = map.iter().min_by_key(|(_, end)| **end);
            if let Some(k) = soonest.map(|(k, _)| k.clone()) {
                map.remove(&k);
            }
        }
        map.insert(key, until);
    }

    /// Whether `key` is blocked at `now`.
    pub(crate) fn is_blocked(&self, key: &str, now: Instant) -> bool {
        let map = self.until.lock().unwrap_or_else(PoisonError::into_inner);
        map.get(key).is_some_and(|end| *end > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_block_ends_and_the_soonest_gives_way() {
        let blocks = Blocks::default();
        let now = Instant::now();
        let hour = now + Duration::from_secs(3600);
        blocks.block("a".into(), hour, 2);
        blocks.block("b".into(), hour + Duration::from_secs(1), 2);
        assert!(blocks.is_blocked("a", now));
        assert!(!blocks.is_blocked("a", hour), "ended");
        blocks.block("c".into(), hour + Duration::from_secs(2), 2);
        assert!(!blocks.is_blocked("a", now), "gave way at capacity");
        assert!(blocks.is_blocked("b", now) && blocks.is_blocked("c", now));
    }
}
