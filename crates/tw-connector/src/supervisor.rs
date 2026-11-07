// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A connector that stays connected: several connections to each of
//! several gateways, renewed before their leases end, re-established when
//! they fail, and shut down gracefully (FR-1, G6 to G8).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use hyper::body::{Body, Incoming};
use hyper::service::HttpService;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};

use crate::backoff::Backoff;
use crate::slot::{Slot, Stop, wait_for_stop};
use crate::{Config, ConnectorEvent};

/// Where the gateways are.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Gateways {
    /// A fixed list of addresses.
    Static(Vec<SocketAddr>),
    /// Every address a DNS name resolves to, looked up again every
    /// `refresh`. Gateways that appear get connections; gateways that
    /// disappear drain theirs. TLS still verifies the configured server
    /// name, never the IP address.
    Dns {
        /// The DNS name.
        name: String,
        /// The port on every address.
        port: u16,
        /// How often to look the name up again.
        refresh: Duration,
    },
}

/// How a [`Connector`] runs.
#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    /// Where the gateways are.
    pub gateways: Gateways,
    /// The connection settings; its `gateway` field is replaced by each
    /// gateway's address in turn.
    pub session: Config,
    /// Connections kept to each gateway (FR-1 default: 2).
    pub connections_per_gateway: usize,
    /// First reconnect delay (FR-1 default: 250 ms).
    pub backoff_base: Duration,
    /// Longest reconnect delay (FR-1 default: 30 s).
    pub backoff_cap: Duration,
    /// How long a gateway that leaves DNS gets to finish its requests.
    pub drain_deadline: Duration,
}

impl ConnectorConfig {
    /// The FR-1 defaults: 2 connections per gateway, backoff from 250 ms
    /// to 30 s, 30 s to drain a gateway that leaves DNS.
    #[must_use]
    pub fn new(gateways: Gateways, session: Config) -> Self {
        Self {
            gateways,
            session,
            connections_per_gateway: 2,
            backoff_base: Duration::from_millis(250),
            backoff_cap: Duration::from_secs(30),
            drain_deadline: Duration::from_secs(30),
        }
    }
}

/// A running connector. Dropping it stops every connection at once; call
/// [`Connector::shutdown`] to let requests finish first.
#[derive(Debug)]
pub struct Connector {
    stop: watch::Sender<Option<Instant>>,
    events: broadcast::Sender<ConnectorEvent>,
    task: Option<JoinHandle<bool>>,
}

impl Connector {
    /// Starts connecting, serving every request with `service`.
    #[must_use]
    pub fn start<S>(config: ConnectorConfig, service: S) -> Self
    where
        S: HttpService<Incoming> + Clone + Send + Sync + 'static,
        S::Future: Send + 'static,
        S::ResBody: Send + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        <S::ResBody as Body>::Data: Send,
        <S::ResBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (stop, stop_rx) = watch::channel(None);
        let (events, _) = broadcast::channel(256);
        let supervisor = Supervisor {
            config,
            service,
            events: events.clone(),
            stop: stop_rx,
            slots: BTreeMap::new(),
        };
        let task = tokio::spawn(supervisor.run());
        Self {
            stop,
            events,
            task: Some(task),
        }
    }

    /// A stream of what happens from now on.
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<ConnectorEvent> {
        self.events.subscribe()
    }

    /// Stops: every connection sends GOAWAY, so the gateways route nothing
    /// new to it, and requests in flight get until `deadline` to finish.
    /// Returns whether they all did (G7).
    pub async fn shutdown(mut self, deadline: Duration) -> bool {
        let _sent = self.stop.send(Some(Instant::now() + deadline));
        let completed = match self.task.take() {
            Some(task) => task.await.unwrap_or(false),
            None => false,
        };
        let _sent = self.events.send(ConnectorEvent::Stopped { completed });
        completed
    }
}

impl Drop for Connector {
    fn drop(&mut self) {
        if self.stop.borrow().is_none() {
            let _sent = self.stop.send(Some(Instant::now()));
        }
    }
}

/// The slots of one gateway, and how to stop them.
struct Group {
    stop: watch::Sender<Option<Instant>>,
    slots: Vec<JoinHandle<bool>>,
}

struct Supervisor<S> {
    config: ConnectorConfig,
    service: S,
    events: broadcast::Sender<ConnectorEvent>,
    stop: Stop,
    slots: BTreeMap<SocketAddr, Group>,
}

impl<S> Supervisor<S>
where
    S: HttpService<Incoming> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
    S::ResBody: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    <S::ResBody as Body>::Data: Send,
    <S::ResBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    async fn run(mut self) -> bool {
        loop {
            let addrs = self.resolve().await;
            self.reconcile(&addrs);
            let refresh = match &self.config.gateways {
                Gateways::Dns { refresh, .. } => *refresh,
                Gateways::Static(_) => Duration::MAX,
            };
            tokio::select! {
                () = sleep(refresh) => {}
                deadline = wait_for_stop(&mut self.stop) => return self.stop_all(deadline).await,
            }
        }
    }

    async fn resolve(&self) -> Vec<SocketAddr> {
        match &self.config.gateways {
            Gateways::Static(addrs) => addrs.clone(),
            Gateways::Dns { name, port, .. } => {
                match tokio::net::lookup_host((name.as_str(), *port)).await {
                    Ok(found) => found.collect(),
                    // A failed lookup keeps the gateways already known.
                    Err(_) => self.slots.keys().copied().collect(),
                }
            }
        }
    }

    /// Starts slots for new gateways and drains those that went away.
    fn reconcile(&mut self, addrs: &[SocketAddr]) {
        let gone: Vec<SocketAddr> = self
            .slots
            .keys()
            .filter(|a| !addrs.contains(a))
            .copied()
            .collect();
        for addr in &gone {
            if let Some(group) = self.slots.remove(addr) {
                let _sent = group
                    .stop
                    .send(Some(Instant::now() + self.config.drain_deadline));
            }
        }
        let new: Vec<SocketAddr> = addrs
            .iter()
            .filter(|a| !self.slots.contains_key(a))
            .copied()
            .collect();
        for addr in &new {
            let group = self.start_group(*addr);
            self.slots.insert(*addr, group);
        }
        if !gone.is_empty() || !new.is_empty() {
            let _sent = self.events.send(ConnectorEvent::Resolved {
                gateways: self.slots.keys().copied().collect(),
            });
        }
    }

    fn start_group(&self, gateway: SocketAddr) -> Group {
        let (stop, stop_rx) = watch::channel(None);
        let mut session = self.config.session.clone();
        session.gateway = gateway.to_string();
        let slots = (0..self.config.connections_per_gateway)
            .map(|_| {
                let slot = Slot {
                    gateway,
                    config: session.clone(),
                    service: self.service.clone(),
                    events: self.events.clone(),
                    backoff: Backoff::new(self.config.backoff_base, self.config.backoff_cap),
                    stop: stop_rx.clone(),
                };
                tokio::spawn(slot.run())
            })
            .collect();
        Group { stop, slots }
    }

    /// Passes the deadline to every slot and waits for them.
    async fn stop_all(self, deadline: Instant) -> bool {
        let mut completed = true;
        for group in self.slots.into_values() {
            let _sent = group.stop.send(Some(deadline));
            for slot in group.slots {
                completed &= slot.await.unwrap_or(false);
            }
        }
        completed
    }
}
