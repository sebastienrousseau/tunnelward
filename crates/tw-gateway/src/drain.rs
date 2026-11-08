// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Draining connections (FR-7), by request or when a lease ends.

use std::net::IpAddr;
use std::time::Duration;

use tokio::time::{Instant, timeout_at};
use tunnelward_proto::ConnectorId;

use crate::Gateway;
use crate::pool::Entry;

/// Which connections to drain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DrainTarget {
    /// Every connection of one connector.
    Connector(ConnectorId),
    /// Every connection that claims this route.
    Route(String),
    /// Every connection from this address.
    Peer(IpAddr),
}

impl DrainTarget {
    pub(crate) fn matches(&self, entry: &Entry) -> bool {
        match self {
            Self::Connector(id) => entry.id == *id,
            Self::Route(route) => entry.routes.iter().any(|r| r == route),
            Self::Peer(ip) => entry.peer == Some(*ip),
        }
    }
}

/// What a drain did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrainReport {
    /// Connections drained.
    pub sessions: usize,
    /// Of those, the ones whose requests all finished before the deadline.
    pub finished: usize,
    /// Of those, the ones with requests still open at the deadline, which
    /// were reset.
    pub reset: usize,
}

impl Gateway {
    /// Drains every connection `target` matches: no new request reaches
    /// them, in-flight requests get until `deadline` to finish, then the
    /// connections close and anything still open is reset. Requests for a
    /// route whose only connections are draining wait for a replacement.
    pub async fn drain(&self, target: &DrainTarget, deadline: Duration) -> DrainReport {
        let sessions = self.inner.registry.mark_draining(|e| target.matches(e));
        self.finish(&sessions, deadline).await
    }

    /// Turns connections matching `target` dark (G14), or back on. A dark
    /// connection stays connected and finishes what it has, but takes no
    /// new request; requests for a route with only dark connections wait
    /// for `max_wait`, then get `Unavailable`. Connections that arrive
    /// later and match are dark too. Returns whether anything changed.
    #[must_use = "false means the target was already in that state"]
    pub fn set_dark(&self, target: DrainTarget, dark: bool) -> bool {
        self.inner.registry.set_dark(target, dark)
    }

    /// The dark targets, in the order they were set.
    #[must_use]
    pub fn dark(&self) -> Vec<DrainTarget> {
        self.inner.registry.dark()
    }

    /// Connections draining now.
    #[must_use]
    pub fn draining(&self) -> u32 {
        self.inner.registry.draining()
    }

    /// Waits for `sessions` to go idle or `deadline` to pass, then closes them.
    pub(crate) async fn finish(&self, sessions: &[u64], deadline: Duration) -> DrainReport {
        let registry = &self.inner.registry;
        let until = Instant::now() + deadline;
        let changed = registry.changed();
        loop {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.busy(sessions) == 0 || timeout_at(until, notified).await.is_err() {
                break;
            }
        }
        let reset = self.busy(sessions);
        for session in sessions {
            registry.abort(*session);
        }
        DrainReport {
            sessions: sessions.len(),
            finished: sessions.len() - reset,
            reset,
        }
    }

    fn busy(&self, sessions: &[u64]) -> usize {
        let registry = &self.inner.registry;
        sessions
            .iter()
            .filter(|s| registry.session_load(**s).is_some_and(|load| load > 0))
            .count()
    }
}
