// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reconnect delays: decorrelated jitter (FR-1).
//!
//! Each delay is random between `base` and three times the previous one,
//! capped at `cap`. Connectors that lost the same gateway at the same
//! moment spread out instead of reconnecting in lockstep.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::time::Duration;

/// Decorrelated-jitter backoff.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    previous: Duration,
}

impl Backoff {
    /// Delays start near `base` and never exceed `cap`.
    #[must_use]
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap: cap.max(base),
            previous: base,
        }
    }

    /// The next delay.
    pub fn next_delay(&mut self) -> Duration {
        let upper = (self.previous * 3).min(self.cap);
        let span = upper.saturating_sub(self.base);
        let delay = (self.base + span.mul_f64(unit_random())).min(self.cap);
        self.previous = delay;
        delay
    }

    /// Starts again from `base`, after a connection that worked.
    pub fn reset(&mut self) {
        self.previous = self.base;
    }
}

/// A random fraction in `[0, 1)` from the standard library's randomly
/// keyed hasher; jitter needs spread, not secrecy.
fn unit_random() -> f64 {
    let bits = u32::try_from(RandomState::new().hash_one(0_u8) >> 32).unwrap_or(0);
    f64::from(bits) / 4_294_967_296.0
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: Duration = Duration::from_millis(250);
    const CAP: Duration = Duration::from_secs(30);

    #[test]
    fn delays_stay_between_base_and_cap() {
        let mut b = Backoff::new(BASE, CAP);
        for _ in 0..1000 {
            let d = b.next_delay();
            assert!(d >= BASE && d <= CAP, "{d:?}");
        }
    }

    #[test]
    fn delays_grow_towards_the_cap_then_reset() {
        let mut b = Backoff::new(BASE, CAP);
        let early: Duration = (0..3).map(|_| b.next_delay()).max().unwrap_or_default();
        assert!(
            early <= BASE * 27,
            "three steps grow at most 3x each: {early:?}"
        );
        for _ in 0..200 {
            b.next_delay();
        }
        let late: Duration = (0..20).map(|_| b.next_delay()).max().unwrap_or_default();
        assert!(
            late > CAP / 2,
            "after many failures delays approach the cap: {late:?}"
        );
        b.reset();
        assert!(b.next_delay() <= BASE * 3);
    }

    #[test]
    fn delays_are_spread_not_fixed() {
        let mut b = Backoff::new(BASE, CAP);
        let delays: std::collections::BTreeSet<Duration> = (0..20)
            .map(|_| {
                b.reset();
                b.next_delay()
            })
            .collect();
        assert!(
            delays.len() > 10,
            "jitter gives different delays: {delays:?}"
        );
    }

    #[test]
    fn unit_random_is_in_range() {
        for _ in 0..1000 {
            let r = unit_random();
            assert!((0.0..1.0).contains(&r));
        }
    }
}
