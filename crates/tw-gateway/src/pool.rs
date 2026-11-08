// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Connectors as slots: in-flight counts, capacity, and the choice of
//! connector within a pool.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http2::SendRequest;
use tokio::sync::Notify;

use crate::kill::KillSwitch;
use tunnelward_proto::ConnectorId;

/// One admitted connector.
pub(crate) struct Entry {
    /// One connection; a connector with several connections has several.
    pub(crate) session: u64,
    pub(crate) id: ConnectorId,
    /// The SPIFFE ID its certificate proved.
    pub(crate) spiffe_id: String,
    /// The connector's address, when the listener knew it.
    pub(crate) peer: Option<IpAddr>,
    /// Set by a drain or an expired lease: no new requests.
    pub(crate) draining: bool,
    /// Cuts the connection, resetting whatever is still open.
    pub(crate) kill: Arc<KillSwitch>,
    pub(crate) routes: Vec<String>,
    pub(crate) domains: Vec<String>,
    /// Most concurrent requests: the smaller of the connector's capacity
    /// and the gateway's stream grant.
    pub(crate) capacity: u32,
    pub(crate) in_flight: Arc<AtomicU32>,
    pub(crate) sender: SendRequest<Full<Bytes>>,
}

impl Entry {
    pub(crate) fn load(&self) -> u32 {
        self.in_flight.load(Ordering::Acquire)
    }

    /// A draining connector stays in its pool, so requests wait for a
    /// replacement instead of failing, but it never takes a new one.
    pub(crate) fn has_room(&self) -> bool {
        !self.draining && self.load() < self.capacity
    }

    /// Takes a slot. The caller holds the registry lock, so the check in
    /// [`Entry::has_room`] and this increment cannot interleave with
    /// another taker; a release only lowers the count.
    pub(crate) fn lease(&self, changed: Arc<Notify>) -> Lease {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        Lease {
            session: self.session,
            sender: self.sender.clone(),
            slot: Slot {
                count: self.in_flight.clone(),
                changed,
            },
        }
    }
}

/// A connection with one slot taken on it.
pub(crate) struct Lease {
    pub(crate) session: u64,
    pub(crate) sender: SendRequest<Full<Bytes>>,
    pub(crate) slot: Slot,
}

/// One in-flight request. Dropping it frees the slot and wakes waiters.
pub(crate) struct Slot {
    count: Arc<AtomicU32>,
    changed: Arc<Notify>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
        self.changed.notify_waiters();
    }
}

/// Power of two choices: two different connectors picked at random, the
/// less loaded one wins. With one candidate it is that one; with two it
/// always compares both.
pub(crate) fn choose<'a>(candidates: &[&'a Entry]) -> Option<&'a Entry> {
    match candidates {
        [] => None,
        [only] => Some(only),
        _ => {
            let len = candidates.len();
            let first = random_below(len);
            let second = (first + 1 + random_below(len - 1)) % len;
            let (one, other) = (candidates[first], candidates[second]);
            Some(if other.load() < one.load() {
                other
            } else {
                one
            })
        }
    }
}

/// A random index below `n` (`n` > 0), from the standard library's
/// randomly keyed hasher. Load balancing needs spread, not secrecy.
fn random_below(n: usize) -> usize {
    let r = RandomState::new().hash_one(0_u8);
    let n64 = u64::try_from(n).unwrap_or(u64::MAX);
    usize::try_from(r % n64).unwrap_or(0)
}

/// A response body that holds its request's slot until the body ends or
/// is dropped, so a long stream (SSE) counts as in flight for its whole
/// life.
pub struct ResponseBody {
    inner: Incoming,
    slot: Option<Slot>,
}

impl ResponseBody {
    pub(crate) fn new(inner: Incoming, slot: Slot) -> Self {
        Self {
            inner,
            slot: Some(slot),
        }
    }
}

impl core::fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResponseBody")
            .field("open", &self.slot.is_some())
            .finish_non_exhaustive()
    }
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(polled, Poll::Ready(None | Some(Err(_)))) {
            self.slot = None;
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
