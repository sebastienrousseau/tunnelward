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
//!
//! With a store shared by several gateways (ADR 0004) the limit is
//! counted there instead, in fixed windows of `burst / per_second`
//! seconds, so a client cannot multiply its rate by spreading requests.
//! If the store fails, each gateway falls back to a local bucket of the
//! limit divided by `gateways` (fail open, approximately).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use crate::SharedState;

/// Rate-limit settings. `per_second` of zero turns limiting off.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimit {
    /// Tokens added per second.
    pub per_second: f64,
    /// Bucket size: the burst a client may send at once.
    pub burst: u32,
    /// Most client addresses tracked at once.
    pub max_clients: usize,
    /// How many gateways share the limit through a shared store; each
    /// falls back to its share when the store fails.
    pub gateways: u32,
}

impl Default for RateLimit {
    /// 50 requests a second per address, bursts of 100, 100,000
    /// addresses, one gateway.
    fn default() -> Self {
        Self {
            per_second: 50.0,
            burst: 100,
            max_clients: 100_000,
            gateways: 1,
        }
    }
}

/// The ingress limit: shared when the store is, local otherwise.
#[derive(Debug)]
pub(crate) struct IngressLimit {
    config: RateLimit,
    local: Limiter,
    /// This gateway's share, for when the shared store fails.
    fallback: Limiter,
}

impl IngressLimit {
    pub(crate) fn new(config: RateLimit) -> Self {
        let gateways = config.gateways.max(1);
        let fallback = RateLimit {
            per_second: config.per_second / f64::from(gateways),
            burst: config.burst.div_ceil(gateways),
            ..config
        };
        Self {
            config,
            local: Limiter::new(config),
            fallback: Limiter::new(fallback),
        }
    }

    /// Counts a request from `ip`, or says how long until one is allowed.
    pub(crate) async fn check(
        &self,
        state: &dyn SharedState,
        ip: IpAddr,
        now: Instant,
    ) -> Result<(), Duration> {
        if !state.is_shared() || self.config.per_second <= 0.0 {
            return self.local.check(ip, now);
        }
        let window = window_ms(&self.config);
        let at = crate::state::millis(SystemTime::now());
        let key = format!("rate:{ip}:{}", at / window);
        let left = Duration::from_millis(window - at % window);
        match state.count(&key, left).await {
            Ok(n) if n <= u64::from(self.config.burst) => Ok(()),
            Ok(_) => Err(left),
            Err(_) => self.fallback.check(ip, now),
        }
    }
}

/// The shared window, `burst / per_second`, at least one second.
fn window_ms(config: &RateLimit) -> u64 {
    let window = Duration::try_from_secs_f64(f64::from(config.burst) / config.per_second)
        .unwrap_or(Duration::MAX);
    u64::try_from(window.as_millis())
        .unwrap_or(u64::MAX)
        .max(1000)
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
            gateways: 1,
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

    /// A store other gateways see: an [`InMemory`] that says it is shared,
    /// or one that always fails.
    #[derive(Debug)]
    struct Shared(Option<crate::InMemory>);

    impl SharedState for Shared {
        fn first_use<'a>(&'a self, _: &'a str, _: Duration) -> crate::StateFuture<'a, bool> {
            Box::pin(std::future::ready(Ok(true)))
        }
        fn claim<'a>(&'a self, _: &'a str, _: Duration) -> crate::StateFuture<'a, crate::Claim> {
            Box::pin(std::future::ready(Ok(crate::Claim::First)))
        }
        fn complete<'a>(
            &'a self,
            _: &'a str,
            _: bytes::Bytes,
            _: Duration,
        ) -> crate::StateFuture<'a, ()> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn release<'a>(&'a self, _: &'a str) -> crate::StateFuture<'a, ()> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn count<'a>(&'a self, key: &'a str, ttl: Duration) -> crate::StateFuture<'a, u64> {
            match &self.0 {
                Some(inner) => inner.count(key, ttl),
                None => Box::pin(std::future::ready(Err(crate::StateError("down".into())))),
            }
        }
    }

    fn shared_limit(gateways: u32) -> IngressLimit {
        IngressLimit::new(RateLimit {
            per_second: 1.0,
            burst: 4,
            max_clients: 10,
            gateways,
        })
    }

    #[tokio::test]
    async fn gateways_sharing_a_store_share_one_limit() {
        let store = Shared(Some(crate::InMemory::default()));
        let (a, b) = (shared_limit(2), shared_limit(2));
        let now = Instant::now();
        for limit in [&a, &b, &a, &b] {
            assert_eq!(limit.check(&store, ip(1), now).await, Ok(()));
        }
        assert!(
            a.check(&store, ip(1), now).await.is_err(),
            "the fifth, at either"
        );
        assert!(b.check(&store, ip(1), now).await.is_err());
        assert_eq!(a.check(&store, ip(2), now).await, Ok(()), "per address");
    }

    #[tokio::test]
    async fn a_failed_store_falls_back_to_this_gateways_share() {
        let down = Shared(None);
        let limit = shared_limit(2);
        let now = Instant::now();
        assert_eq!(limit.check(&down, ip(1), now).await, Ok(()));
        assert_eq!(limit.check(&down, ip(1), now).await, Ok(()));
        assert!(limit.check(&down, ip(1), now).await.is_err(), "half of 4");
    }

    #[tokio::test]
    async fn an_unshared_store_keeps_the_exact_local_bucket() {
        let local = crate::InMemory::default();
        let limit = shared_limit(2);
        let now = Instant::now();
        for _ in 0..4 {
            assert_eq!(limit.check(&local, ip(1), now).await, Ok(()));
        }
        assert!(limit.check(&local, ip(1), now).await.is_err());
    }
}
