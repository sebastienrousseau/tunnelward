// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Live connectors, routes kept after their connectors leave, and how
//! many requests wait for each route.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http2::SendRequest;
use tokio::sync::Notify;
use tunnelward_proto::Register;

use crate::kill::KillSwitch;
use crate::pool::{Entry, Lease, choose};
use crate::{RouteResolver, Target};

/// A route remembered after its last connector left (G4).
struct Kept {
    routes: Vec<String>,
    domains: Vec<String>,
    until: Instant,
}

#[derive(Default)]
struct State {
    entries: Vec<Entry>,
    kept: Vec<Kept>,
    waiting: HashMap<String, u32>,
}

/// What a request can do now.
pub(crate) enum Pick {
    /// A slot on a connector.
    Ready(Lease),
    /// Its route exists but has no free slot, or is kept with no
    /// connector: wait in the queue named here.
    Wait(String),
    /// Nothing serves it.
    None,
}

/// A connection as the registry needs it.
pub(crate) struct Link {
    pub(crate) sender: SendRequest<Full<Bytes>>,
    /// The gateway's stream grant, capping the connector's capacity.
    pub(crate) grant: u32,
    pub(crate) peer: Option<IpAddr>,
    pub(crate) kill: Arc<KillSwitch>,
}

#[derive(Default)]
pub(crate) struct Registry {
    state: Mutex<State>,
    next_session: AtomicU64,
    /// Notified when a slot frees or a connector arrives.
    changed: Arc<Notify>,
}

/// The best rank any of `routes` gets for `target`, and that route.
fn best<'a>(
    resolver: &dyn RouteResolver,
    routes: &'a [String],
    domains: &[String],
    target: &Target,
) -> Option<(u32, &'a str)> {
    routes
        .iter()
        .filter_map(|r| {
            resolver
                .rank(r, domains, target)
                .map(|rank| (rank, r.as_str()))
        })
        .max_by_key(|(rank, _)| *rank)
}

impl Registry {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Every edit is a push, a retain or a counter change, so a panic
        // while holding the lock cannot leave the state half-edited.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn changed(&self) -> Arc<Notify> {
        self.changed.clone()
    }

    /// Adds one connection and returns its session number.
    pub(crate) fn insert(&self, register: Register, link: Link) -> u64 {
        let session = self.next_session.fetch_add(1, Ordering::Relaxed);
        self.lock().entries.push(Entry {
            session,
            id: register.connector_id,
            peer: link.peer,
            draining: false,
            kill: link.kill,
            capacity: register.capacity.min(link.grant),
            routes: register.routes,
            domains: register.domains,
            in_flight: Arc::new(AtomicU32::new(0)),
            sender: link.sender,
        });
        self.changed.notify_waiters();
        session
    }

    /// Marks every session `select` picks as draining; returns them.
    pub(crate) fn mark_draining(&self, select: impl Fn(&Entry) -> bool) -> Vec<u64> {
        let mut state = self.lock();
        let picked: Vec<u64> = state
            .entries
            .iter_mut()
            .filter(|e| select(e))
            .map(|e| {
                e.draining = true;
                e.session
            })
            .collect();
        picked
    }

    /// Requests in flight on `session`, or `None` once it is gone.
    pub(crate) fn session_load(&self, session: u64) -> Option<u32> {
        self.lock()
            .entries
            .iter()
            .find(|e| e.session == session)
            .map(Entry::load)
    }

    /// Ends `session`'s connection, resetting what is still open.
    pub(crate) fn abort(&self, session: u64) {
        if let Some(e) = self.lock().entries.iter().find(|e| e.session == session) {
            e.kill.kill();
        }
    }

    pub(crate) fn draining(&self) -> u32 {
        let count = self.lock().entries.iter().filter(|e| e.draining).count();
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Forgets connector `id`, keeping its routes for `keep`.
    /// Forgets `session`, keeping its routes for `keep`.
    pub(crate) fn remove(&self, session: u64, keep: Duration) {
        let mut state = self.lock();
        let (gone, live): (Vec<Entry>, Vec<Entry>) =
            state.entries.drain(..).partition(|e| e.session == session);
        state.entries = live;
        let until = Instant::now() + keep;
        state.kept.extend(gone.into_iter().map(|e| Kept {
            routes: e.routes,
            domains: e.domains,
            until,
        }));
        drop(state);
        self.changed.notify_waiters();
    }

    pub(crate) fn routes(&self) -> Vec<String> {
        let mut routes: Vec<String> = self
            .lock()
            .entries
            .iter()
            .flat_map(|e| e.routes.clone())
            .collect();
        routes.sort_unstable();
        routes
    }

    pub(crate) fn in_flight(&self) -> u32 {
        self.lock().entries.iter().map(Entry::load).sum()
    }

    pub(crate) fn waiting(&self) -> u32 {
        self.lock().waiting.values().sum()
    }

    /// Finds a slot for `target` among the connectors whose claim ranks
    /// highest, or says where to wait.
    pub(crate) fn pick(&self, resolver: &dyn RouteResolver, target: &Target) -> Pick {
        let mut state = self.lock();
        let now = Instant::now();
        state.entries.retain(|e| !e.sender.is_closed());
        state.kept.retain(|k| k.until > now);
        let top = top_pool(resolver, &state.entries, target);
        match top {
            None => kept_queue(resolver, &state.kept, target),
            Some((route, pool)) => {
                let room: Vec<&Entry> = pool.into_iter().filter(|e| e.has_room()).collect();
                choose(&room).map_or(Pick::Wait(route), |e| {
                    Pick::Ready(e.lease(self.changed.clone()))
                })
            }
        }
    }

    /// Joins the wait queue for `route` if it holds fewer than `max`.
    pub(crate) fn enqueue(&self, route: &str, max: u32) -> Option<Queued<'_>> {
        let mut state = self.lock();
        let count = state.waiting.entry(route.to_owned()).or_insert(0);
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(Queued {
            registry: self,
            route: route.to_owned(),
        })
    }
}

/// The connectors whose claim ranks highest for `target`, and the route
/// that ranked (the name of its wait queue).
fn top_pool<'a>(
    resolver: &dyn RouteResolver,
    entries: &'a [Entry],
    target: &Target,
) -> Option<(String, Vec<&'a Entry>)> {
    let ranked: Vec<(u32, &str, &Entry)> = entries
        .iter()
        .filter_map(|e| {
            best(resolver, &e.routes, &e.domains, target).map(|(r, route)| (r, route, e))
        })
        .collect();
    let top = ranked.iter().map(|(r, ..)| *r).max()?;
    let route = ranked
        .iter()
        .find(|(r, ..)| *r == top)
        .map(|(_, route, _)| (*route).to_owned())?;
    let pool = ranked
        .into_iter()
        .filter(|(r, ..)| *r == top)
        .map(|(.., e)| e)
        .collect();
    Some((route, pool))
}

fn kept_queue(resolver: &dyn RouteResolver, kept: &[Kept], target: &Target) -> Pick {
    kept.iter()
        .filter_map(|k| best(resolver, &k.routes, &k.domains, target))
        .max_by_key(|(rank, _)| *rank)
        .map_or(Pick::None, |(_, route)| Pick::Wait(route.to_owned()))
}

/// A place in a route's wait queue, given back on drop.
pub(crate) struct Queued<'a> {
    registry: &'a Registry,
    route: String,
}

impl Drop for Queued<'_> {
    fn drop(&mut self) {
        let mut state = self.registry.lock();
        if let Some(count) = state.waiting.get_mut(&self.route) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.waiting.remove(&self.route);
            }
        }
    }
}
