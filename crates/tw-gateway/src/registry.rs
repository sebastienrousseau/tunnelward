// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Live connectors, routes kept after their connectors leave, and how
//! many requests wait for each route.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http2::SendRequest;
use tokio::sync::Notify;
use tunnelward_proto::{ConnectorId, Register};

use crate::claims::{Holding, Refusal, Rules, check};
use crate::kill::KillSwitch;
use crate::pool::{Entry, Lease, choose};
use crate::{DrainTarget, RouteResolver, Target};

/// A route remembered after its last connector left (G4).
struct Kept {
    spiffe_id: String,
    routes: Vec<String>,
    domains: Vec<String>,
    until: Instant,
}

#[derive(Default)]
struct State {
    entries: Vec<Entry>,
    kept: Vec<Kept>,
    /// Each route's wait queue, as tickets in arrival order.
    waiting: HashMap<String, VecDeque<u64>>,
    next_ticket: u64,
    /// Dark targets (G14): matching connections stay connected but take
    /// no new request.
    dark: Vec<DrainTarget>,
    /// Claims of registrations being admitted, by ticket.
    reserved: HashMap<u64, Reserved>,
}

impl State {
    /// Everything held or promised: live connections, kept routes and
    /// admissions in progress. Drops what has closed or expired first.
    fn holdings(&mut self) -> Vec<Holding<'_>> {
        let now = Instant::now();
        self.entries.retain(|e| !e.sender.is_closed());
        self.kept.retain(|k| k.until > now);
        let live = self.entries.iter().map(|e| Holding {
            spiffe_id: &e.spiffe_id,
            routes: &e.routes,
            domains: &e.domains,
            live: true,
        });
        let kept = self.kept.iter().map(|k| Holding {
            spiffe_id: &k.spiffe_id,
            routes: &k.routes,
            domains: &k.domains,
            live: false,
        });
        let admitting = self.reserved.values().map(|r| Holding {
            spiffe_id: &r.spiffe_id,
            routes: &r.routes,
            domains: &r.domains,
            live: true,
        });
        live.chain(kept).chain(admitting).collect()
    }
}

/// What a registration being admitted holds until it is registered.
struct Reserved {
    spiffe_id: String,
    routes: Vec<String>,
    domains: Vec<String>,
}

/// What a request can do now.
pub(crate) enum Pick {
    /// A slot on a connector.
    Ready(Lease),
    /// Its route exists but has no free slot, is kept with no
    /// connector, or has a connector being admitted: wait in the queue
    /// named here.
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
    /// The digest of the attestation it was admitted with, if any.
    pub(crate) attested: Option<[u8; 32]>,
    pub(crate) tls: crate::admin::Tls,
}

/// One connection as the admin inventory reports it.
pub(crate) struct Snapshot {
    pub(crate) id: ConnectorId,
    pub(crate) peer: Option<IpAddr>,
    pub(crate) routes: Vec<String>,
    pub(crate) domains: Vec<String>,
    pub(crate) capacity: u32,
    pub(crate) in_flight: u32,
    pub(crate) draining: bool,
    pub(crate) dark: bool,
    pub(crate) tls: crate::admin::Tls,
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
            spiffe_id: register.spiffe_id,
            peer: link.peer,
            draining: false,
            kill: link.kill,
            capacity: register.capacity.min(link.grant),
            routes: register.routes,
            domains: register.domains,
            in_flight: Arc::new(AtomicU32::new(0)),
            sender: link.sender,
            attested: link.attested,
            tls: link.tls,
        });
        self.changed.notify_waiters();
        session
    }

    /// Promises `claim`'s routes and domains to its identity if they fit
    /// beside everything held ([`check`]). The promise lasts until the
    /// returned [`Reservation`] drops, by which time an admitted
    /// connector's claims are in the registry.
    pub(crate) fn reserve(
        &self,
        claim: &Register,
        rules: &Rules<'_>,
    ) -> Result<Reservation<'_>, Refusal> {
        let mut state = self.lock();
        check(&state.holdings(), claim, rules)?;
        let ticket = self.next_session.fetch_add(1, Ordering::Relaxed);
        let reserved = Reserved {
            spiffe_id: claim.spiffe_id.clone(),
            routes: claim.routes.clone(),
            domains: claim.domains.clone(),
        };
        state.reserved.insert(ticket, reserved);
        Ok(Reservation {
            registry: self,
            ticket,
        })
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

    /// Forgets `session`, keeping its routes for `keep`.
    pub(crate) fn remove(&self, session: u64, keep: Duration) {
        let mut state = self.lock();
        let (gone, live): (Vec<Entry>, Vec<Entry>) =
            state.entries.drain(..).partition(|e| e.session == session);
        state.entries = live;
        let until = Instant::now() + keep;
        state.kept.extend(gone.into_iter().map(|e| Kept {
            spiffe_id: e.spiffe_id,
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

    /// Every live connection, for the admin inventory.
    pub(crate) fn snapshot(&self) -> Vec<Snapshot> {
        let state = self.lock();
        state
            .entries
            .iter()
            .filter(|e| !e.sender.is_closed())
            .map(|e| Snapshot {
                id: e.id,
                peer: e.peer,
                routes: e.routes.clone(),
                domains: e.domains.clone(),
                capacity: e.capacity,
                in_flight: e.load(),
                draining: e.draining,
                dark: state.dark.iter().any(|d| d.matches(e)),
                tls: e.tls.clone(),
            })
            .collect()
    }

    /// Turns `target` dark or back; returns whether that changed anything.
    pub(crate) fn set_dark(&self, target: DrainTarget, dark: bool) -> bool {
        let mut state = self.lock();
        let had = state.dark.contains(&target);
        match (had, dark) {
            (false, true) => state.dark.push(target),
            (true, false) => state.dark.retain(|d| *d != target),
            _ => return false,
        }
        drop(state);
        // Requests waiting for a slot may find one now.
        self.changed.notify_waiters();
        true
    }

    pub(crate) fn dark(&self) -> Vec<DrainTarget> {
        self.lock().dark.clone()
    }

    pub(crate) fn in_flight(&self) -> u32 {
        self.lock().entries.iter().map(Entry::load).sum()
    }

    pub(crate) fn waiting(&self) -> u32 {
        let state = self.lock();
        let count: usize = state.waiting.values().map(VecDeque::len).sum();
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// The claim that ranks highest for `target` now, if any.
    pub(crate) fn route_for(
        &self,
        resolver: &dyn RouteResolver,
        target: &Target,
    ) -> Option<String> {
        top_pool(resolver, &self.lock().entries, target).map(|(route, _)| route)
    }

    /// Finds a slot for `target` among the connectors whose claim ranks
    /// highest, or says where to wait. A request that is not queued comes
    /// after every request already waiting for that route.
    pub(crate) fn pick(&self, resolver: &dyn RouteResolver, target: &Target) -> Pick {
        self.pick_at(resolver, target, None)
    }

    /// [`Registry::pick`] for a request holding `queued`: it may take a
    /// free slot only when fewer requests wait ahead of it than there are
    /// free slots, so slots go out in arrival order.
    pub(crate) fn pick_queued(
        &self,
        resolver: &dyn RouteResolver,
        target: &Target,
        queued: &Queued<'_>,
    ) -> Pick {
        self.pick_at(resolver, target, Some(queued.ticket))
    }

    fn pick_at(&self, resolver: &dyn RouteResolver, target: &Target, ticket: Option<u64>) -> Pick {
        let mut state = self.lock();
        let now = Instant::now();
        state.entries.retain(|e| !e.sender.is_closed());
        state.kept.retain(|k| k.until > now);
        match top_pool(resolver, &state.entries, target) {
            None => coming_queue(resolver, &state, target),
            Some((route, pool)) => self.take(&state, route, pool, ticket),
        }
    }

    /// A slot among `pool`'s lit connectors with room, unless as many
    /// requests wait ahead of `ticket` as there are free slots.
    fn take(&self, state: &State, route: String, pool: Vec<&Entry>, ticket: Option<u64>) -> Pick {
        let lit = |e: &&Entry| !state.dark.iter().any(|d| d.matches(e));
        let room: Vec<&Entry> = pool
            .into_iter()
            .filter(|e| e.has_room() && lit(e))
            .collect();
        if ahead(state, &route, ticket) >= free_slots(&room) {
            return Pick::Wait(route);
        }
        choose(&room).map_or(Pick::Wait(route), |e| {
            Pick::Ready(e.lease(self.changed.clone()))
        })
    }

    /// Joins the wait queue for `route` if it holds fewer than `max`.
    pub(crate) fn enqueue(&self, route: &str, max: u32) -> Option<Queued<'_>> {
        let mut state = self.lock();
        let ticket = state.next_ticket;
        let queue = state.waiting.entry(route.to_owned()).or_default();
        if queue.len() >= usize::try_from(max).unwrap_or(usize::MAX) {
            return None;
        }
        queue.push_back(ticket);
        state.next_ticket += 1;
        Some(Queued {
            registry: self,
            route: route.to_owned(),
            ticket,
        })
    }
}

/// How many requests wait for `route` ahead of `ticket`: all of them
/// for a request that is not in that queue.
fn ahead(state: &State, route: &str, ticket: Option<u64>) -> usize {
    let Some(queue) = state.waiting.get(route) else {
        return 0;
    };
    ticket
        .and_then(|t| queue.iter().position(|q| *q == t))
        .unwrap_or(queue.len())
}

/// Free slots across `room`.
fn free_slots(room: &[&Entry]) -> usize {
    room.iter()
        .map(|e| usize::try_from(e.capacity.saturating_sub(e.load())).unwrap_or(0))
        .sum()
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

/// With no live connector for `target`, where to wait: a route kept
/// after its connectors left, or one a connector is being admitted for
/// (it has read `Accept`, and its claims reach the registry when the
/// gateway's side of the connection is ready).
fn coming_queue(resolver: &dyn RouteResolver, state: &State, target: &Target) -> Pick {
    let kept = state.kept.iter().map(|k| (&k.routes, &k.domains));
    let admitting = state.reserved.values().map(|r| (&r.routes, &r.domains));
    kept.chain(admitting)
        .filter_map(|(routes, domains)| best(resolver, routes, domains, target))
        .max_by_key(|(rank, _)| *rank)
        .map_or(Pick::None, |(_, route)| Pick::Wait(route.to_owned()))
}

/// Claims promised to one registration, given back on drop.
pub(crate) struct Reservation<'a> {
    registry: &'a Registry,
    ticket: u64,
}

impl Drop for Reservation<'_> {
    /// Gives the claims back and wakes waiting requests: an admission
    /// that failed leaves them to learn that nothing serves the route.
    fn drop(&mut self) {
        self.registry.lock().reserved.remove(&self.ticket);
        self.registry.changed.notify_waiters();
    }
}

/// A place in a route's wait queue, given back on drop.
pub(crate) struct Queued<'a> {
    registry: &'a Registry,
    route: String,
    ticket: u64,
}

impl Drop for Queued<'_> {
    /// Leaves the queue and wakes the others: the request behind may now
    /// be close enough to the front to take a free slot.
    fn drop(&mut self) {
        let mut state = self.registry.lock();
        if let Some(queue) = state.waiting.get_mut(&self.route) {
            queue.retain(|t| *t != self.ticket);
            if queue.is_empty() {
                state.waiting.remove(&self.route);
            }
        }
        drop(state);
        self.registry.changed.notify_waiters();
    }
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
