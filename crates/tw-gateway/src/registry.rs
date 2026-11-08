// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Live connectors and what they serve.

use std::sync::{Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http2::SendRequest;
use tw_proto::{ConnectorId, Register};

use crate::route::{Target, domain_matches, route_score};

struct Entry {
    id: ConnectorId,
    routes: Vec<String>,
    domains: Vec<String>,
    sender: SendRequest<Full<Bytes>>,
}

/// Every admitted connector whose connection is open. v0.0.4 keeps a flat
/// list; pools and selection by load arrive in v0.0.5.
#[derive(Default)]
pub(crate) struct Registry {
    entries: Mutex<Vec<Entry>>,
}

impl Registry {
    fn lock(&self) -> MutexGuard<'_, Vec<Entry>> {
        // A panic while holding the lock cannot leave the list half-edited:
        // every edit is one push or one retain.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn insert(&self, register: Register, sender: SendRequest<Full<Bytes>>) {
        self.lock().push(Entry {
            id: register.connector_id,
            routes: register.routes,
            domains: register.domains,
            sender,
        });
    }

    pub(crate) fn remove(&self, id: ConnectorId) {
        self.lock().retain(|e| e.id != id);
    }

    pub(crate) fn routes(&self) -> Vec<String> {
        let mut routes: Vec<String> = self.lock().iter().flat_map(|e| e.routes.clone()).collect();
        routes.sort_unstable();
        routes
    }

    /// The open connection whose claim fits `target` best: domain first,
    /// then the longest route. Closed connections are dropped on the way.
    pub(crate) fn pick(&self, target: &Target) -> Option<SendRequest<Full<Bytes>>> {
        let mut entries = self.lock();
        entries.retain(|e| !e.sender.is_closed());
        entries
            .iter()
            .filter(|e| domain_matches(&e.domains, target.host.as_deref()))
            .filter_map(|e| best_score(&e.routes, &target.path).map(|s| (s, e)))
            .max_by_key(|(score, _)| *score)
            .map(|(_, e)| e.sender.clone())
    }
}

fn best_score(routes: &[String], path: &str) -> Option<usize> {
    routes.iter().filter_map(|r| route_score(r, path)).max()
}
