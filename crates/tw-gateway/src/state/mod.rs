// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! State shared across gateways (ADR 0004): the replay caches, the
//! idempotency keys and the rate counters every gateway must see alike.
//!
//! [`SharedState`] is the one interface; [`InMemory`] serves a single
//! gateway, and [`RedisState`] (any store that speaks RESP) serves
//! several. Each caller decides in
//! advance what it does when the store fails: the replay and idempotency
//! checks refuse (fail closed), the rate limits fall back to a local
//! bucket (fail open), as the ADR's table says.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

mod redis;
mod resp;

pub use redis::RedisState;

/// What a [`SharedState`] call returns.
pub type StateFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StateError>> + Send + 'a>>;

/// The store could not answer: unreachable, full, or a reply that does
/// not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateError(pub String);

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "shared state: {}", self.0)
    }
}

impl std::error::Error for StateError {}

/// Where an idempotency key stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// The caller is first: run the call, then [`SharedState::complete`]
    /// or [`SharedState::release`] it.
    First,
    /// Another call with the key is still running.
    Pending,
    /// A call with the key finished; this is what it answered.
    Done(Bytes),
}

/// State every gateway sees alike. Keys are namespaced by their caller
/// (`nonce:`, `jti:`, `idem:`, `rate:`); each lives for its `ttl`, counted
/// on the store's clock, so gateways need not agree on the time.
pub trait SharedState: Send + Sync + std::fmt::Debug {
    /// Records `key`; `true` the first time, `false` if it is already
    /// recorded (a replay).
    fn first_use<'a>(&'a self, key: &'a str, ttl: Duration) -> StateFuture<'a, bool>;

    /// Claims the idempotency key `key` for a call, or says why not.
    fn claim<'a>(&'a self, key: &'a str, ttl: Duration) -> StateFuture<'a, Claim>;

    /// Records what the call holding `key` answered.
    fn complete<'a>(&'a self, key: &'a str, answer: Bytes, ttl: Duration) -> StateFuture<'a, ()>;

    /// Gives `key` up, so a retry can run the call.
    fn release<'a>(&'a self, key: &'a str) -> StateFuture<'a, ()>;

    /// Adds one to the counter `key` and returns its new value.
    fn count<'a>(&'a self, key: &'a str, ttl: Duration) -> StateFuture<'a, u64>;

    /// Whether other gateways see this state. A store only this gateway
    /// sees leaves the rate limit to its exact local buckets.
    fn is_shared(&self) -> bool {
        true
    }
}

/// Milliseconds since 1970, saturating.
pub(crate) fn millis(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// When an entry living `ttl` from now expires, in milliseconds.
fn expiry(ttl: Duration) -> u64 {
    millis(SystemTime::now()).saturating_add(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX))
}

#[derive(Debug, Clone)]
enum Value {
    Used,
    Pending,
    Done(Bytes),
    Count(u64),
}

/// Most keys [`InMemory`] holds before it refuses new ones.
const DEFAULT_CAPACITY: usize = 1_000_000;

/// State in this process: for one gateway, or for gateways that share
/// one process (as the tests do).
#[derive(Debug)]
pub struct InMemory {
    entries: Mutex<HashMap<String, (Value, u64)>>,
    capacity: usize,
}

impl Default for InMemory {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl InMemory {
    /// A store that holds at most `capacity` live keys. When full, after
    /// dropping expired keys, a new key is an error, so the checks that
    /// depend on it refuse rather than forget.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Runs `change` on the live entry for `key` (`None` when absent or
    /// expired), under the lock.
    fn with<T>(
        &self,
        key: &str,
        change: impl FnOnce(Option<&mut (Value, u64)>) -> Result<(T, Option<(Value, u64)>), StateError>,
    ) -> Result<T, StateError> {
        let now = millis(SystemTime::now());
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let live = entries.get_mut(key).filter(|(_, until)| *until > now);
        let (out, insert) = change(live)?;
        if let Some(entry) = insert {
            if !entries.contains_key(key) && entries.len() >= self.capacity {
                entries.retain(|_, (_, until)| *until > now);
                if entries.len() >= self.capacity {
                    return Err(StateError("the in-memory store is full".into()));
                }
            }
            entries.insert(key.to_owned(), entry);
        }
        Ok(out)
    }
}

fn ready<'a, T: Send + 'a>(result: Result<T, StateError>) -> StateFuture<'a, T> {
    Box::pin(std::future::ready(result))
}

impl SharedState for InMemory {
    /// Only gateways in this process see it.
    fn is_shared(&self) -> bool {
        false
    }

    fn first_use<'a>(&'a self, key: &'a str, ttl: Duration) -> StateFuture<'a, bool> {
        ready(self.with(key, |live| match live {
            Some(_) => Ok((false, None)),
            None => Ok((true, Some((Value::Used, expiry(ttl))))),
        }))
    }

    fn claim<'a>(&'a self, key: &'a str, ttl: Duration) -> StateFuture<'a, Claim> {
        ready(self.with(key, |live| match live {
            Some((Value::Done(answer), _)) => Ok((Claim::Done(answer.clone()), None)),
            Some(_) => Ok((Claim::Pending, None)),
            None => Ok((Claim::First, Some((Value::Pending, expiry(ttl))))),
        }))
    }

    fn complete<'a>(&'a self, key: &'a str, answer: Bytes, ttl: Duration) -> StateFuture<'a, ()> {
        ready(self.with(key, |_| Ok(((), Some((Value::Done(answer), expiry(ttl)))))))
    }

    fn release<'a>(&'a self, key: &'a str) -> StateFuture<'a, ()> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.remove(key);
        ready(Ok(()))
    }

    fn count<'a>(&'a self, key: &'a str, ttl: Duration) -> StateFuture<'a, u64> {
        ready(self.with(key, |live| match live {
            Some((Value::Count(n), _)) => {
                *n += 1;
                Ok((*n, None))
            }
            _ => Ok((1, Some((Value::Count(1), expiry(ttl))))),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn later(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    #[tokio::test]
    async fn a_key_is_first_used_once_until_it_expires() -> Result<(), StateError> {
        let state = InMemory::default();
        assert!(state.first_use("nonce:a", later(60)).await?);
        assert!(!state.first_use("nonce:a", later(60)).await?);
        assert!(state.first_use("nonce:b", later(60)).await?);
        let past = Duration::ZERO;
        assert!(state.first_use("nonce:c", past).await?);
        assert!(
            state.first_use("nonce:c", later(60)).await?,
            "expired keys count as new"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_idempotency_key_runs_once_and_replays_its_answer() -> Result<(), StateError> {
        let state = InMemory::default();
        assert_eq!(state.claim("idem:k", later(60)).await?, Claim::First);
        assert_eq!(state.claim("idem:k", later(60)).await?, Claim::Pending);
        state
            .complete("idem:k", Bytes::from_static(b"ok"), later(60))
            .await?;
        assert_eq!(
            state.claim("idem:k", later(60)).await?,
            Claim::Done(Bytes::from_static(b"ok"))
        );
        assert_eq!(state.claim("idem:r", later(60)).await?, Claim::First);
        state.release("idem:r").await?;
        assert_eq!(
            state.claim("idem:r", later(60)).await?,
            Claim::First,
            "released"
        );
        Ok(())
    }

    #[tokio::test]
    async fn counters_count_up_from_one() -> Result<(), StateError> {
        let state = InMemory::default();
        assert_eq!(state.count("rate:x", later(60)).await?, 1);
        assert_eq!(state.count("rate:x", later(60)).await?, 2);
        assert_eq!(state.count("rate:y", later(60)).await?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_full_store_drops_expired_keys_then_refuses() -> Result<(), StateError> {
        let state = InMemory::with_capacity(2);
        let past = Duration::ZERO;
        assert!(state.first_use("a", past).await?);
        assert!(state.first_use("b", later(60)).await?);
        assert!(
            state.first_use("c", later(60)).await?,
            "the expired key made room"
        );
        assert!(state.first_use("d", later(60)).await.is_err(), "full");
        assert!(
            !state.first_use("b", later(60)).await?,
            "known keys still answer"
        );
        Ok(())
    }
}
