// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Per-client token buckets for the ingress (G13).
//!
//! Each client address gets `burst` tokens, refilled at `per_second`; a
//! request takes one, and with none left gets 429 and how long to wait.
//! At most `max_clients` addresses are tracked. When the table is full,
//! buckets that have refilled completely are dropped first; if it is still
//! full, an unknown address is let through untracked. Rate limiting cannot
//! stop a distributed flood, so it must not become the way to exhaust the
//! gateway's memory either.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Rate-limit settings. `per_second` of zero turns limiting off.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimit {
    /// Tokens added per second.
    pub per_second: f64,
    /// Bucket size: the burst a client may send at once.
    pub burst: u32,
    /// Most client addresses tracked at once.
    pub max_clients: usize,
}

impl Default for RateLimit {
    /// 50 requests a second per address, bursts of 100, 100,000 addresses.
    fn default() -> Self {
        Self {
            per_second: 50.0,
            burst: 100,
            max_clients: 100_000,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// The buckets.
#[derive(Debug)]
pub(crate) struct Limiter {
    config: RateLimit,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl Limiter {
    pub(crate) fn new(config: RateLimit) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// `count` attempts per address per minute, all usable at once, for
    /// the default number of addresses; zero turns limiting off.
    pub(crate) fn per_minute(count: u32) -> Self {
        Self::new(RateLimit {
            per_second: f64::from(count) / 60.0,
            burst: count,
            ..RateLimit::default()
        })
    }

    /// Takes a token for `ip` at `now`, or says how long until one is free.
    pub(crate) fn check(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        if self.config.per_second <= 0.0 {
            return Ok(());
        }
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.has_room_for(&mut buckets, ip, now) {
            return Ok(());
        }
        let burst = f64::from(self.config.burst);
        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: burst,
            at: now,
        });
        self.take(bucket, now)
    }

    /// Whether `ip` has or can get a bucket; when the table is full,
    /// refilled buckets are pruned first.
    fn has_room_for(
        &self,
        buckets: &mut HashMap<IpAddr, Bucket>,
        ip: IpAddr,
        now: Instant,
    ) -> bool {
        if buckets.contains_key(&ip) || buckets.len() < self.config.max_clients {
            return true;
        }
        self.prune(buckets, now);
        buckets.len() < self.config.max_clients
    }

    fn take(&self, bucket: &mut Bucket, now: Instant) -> Result<(), Duration> {
        bucket.tokens = self.refill(*bucket, now);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }
        Err(Duration::from_secs_f64(
            (1.0 - bucket.tokens) / self.config.per_second,
        ))
    }

    fn refill(&self, bucket: Bucket, now: Instant) -> f64 {
        let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
        (bucket.tokens + elapsed * self.config.per_second).min(f64::from(self.config.burst))
    }

    fn prune(&self, buckets: &mut HashMap<IpAddr, Bucket>, now: Instant) {
        let burst = f64::from(self.config.burst);
        buckets.retain(|_, b| self.refill(*b, now) < burst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, last])
    }

    fn limiter(per_second: f64, burst: u32, max_clients: usize) -> Limiter {
        Limiter::new(RateLimit {
            per_second,
            burst,
            max_clients,
        })
    }

    #[test]
    fn a_burst_passes_then_the_rate_applies() {
        let l = limiter(2.0, 3, 10);
        let t = Instant::now();
        for _ in 0..3 {
            assert_eq!(l.check(ip(1), t), Ok(()));
        }
        let wait = l.check(ip(1), t).err().unwrap_or_default();
        assert!(
            wait > Duration::from_millis(400) && wait <= Duration::from_millis(500),
            "{wait:?}"
        );
        assert_eq!(
            l.check(ip(1), t + Duration::from_millis(500)),
            Ok(()),
            "one token after 0.5 s at 2/s"
        );
        assert!(l.check(ip(1), t + Duration::from_millis(500)).is_err());
    }

    #[test]
    fn clients_have_separate_buckets() {
        let l = limiter(1.0, 1, 10);
        let t = Instant::now();
        assert_eq!(l.check(ip(1), t), Ok(()));
        assert!(l.check(ip(1), t).is_err());
        assert_eq!(l.check(ip(2), t), Ok(()));
    }

    #[test]
    fn a_full_table_drops_refilled_buckets_then_fails_open() {
        let l = limiter(1.0, 1, 2);
        let t = Instant::now();
        assert_eq!(l.check(ip(1), t), Ok(()));
        assert_eq!(l.check(ip(2), t), Ok(()));
        // Both buckets are empty, so nothing can be pruned: ip(3) is let through untracked.
        assert_eq!(l.check(ip(3), t), Ok(()));
        assert_eq!(l.check(ip(3), t), Ok(()), "untracked, so never limited");
        // A second later both buckets have refilled and are pruned; ip(3) is tracked now.
        let later = t + Duration::from_secs(1);
        assert_eq!(l.check(ip(3), later), Ok(()));
        assert!(l.check(ip(3), later).is_err());
    }

    #[test]
    fn a_zero_rate_turns_limiting_off() {
        let l = limiter(0.0, 0, 0);
        for _ in 0..100 {
            assert_eq!(l.check(ip(1), Instant::now()), Ok(()));
        }
    }
}
