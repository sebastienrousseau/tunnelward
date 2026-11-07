// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One slot: a connection to one gateway, kept up for the connector's life.
//!
//! A slot registers, serves until the lease nears its end, then dials a
//! successor before letting the old connection finish (make before break,
//! ADR 0005). A failed or closed connection is retried after a
//! decorrelated-jitter delay.

use std::net::SocketAddr;
use std::time::Duration;

use hyper::body::{Body, Incoming};
use hyper::service::HttpService;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout_at};

use crate::backoff::{Backoff, unit_random};
use crate::session::ServerConnection;
use crate::{Config, ConnectorEvent, Error, register};

/// When the slot must stop: `None` while running, then the deadline.
pub(crate) type Stop = watch::Receiver<Option<Instant>>;

/// Everything a slot needs.
pub(crate) struct Slot<S> {
    pub(crate) gateway: SocketAddr,
    pub(crate) config: Config,
    pub(crate) service: S,
    pub(crate) events: broadcast::Sender<ConnectorEvent>,
    pub(crate) backoff: Backoff,
    pub(crate) stop: Stop,
}

/// How serving one connection ended.
enum Ended {
    /// The lease is ending: dial a successor at once.
    Renew,
    /// The connection closed or failed: retry after a delay.
    Closed,
    /// The connector is stopping; whether in-flight requests finished.
    Stopped(bool),
}

impl<S> Slot<S>
where
    S: HttpService<Incoming> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
    S::ResBody: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    <S::ResBody as Body>::Data: Send,
    <S::ResBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    /// Runs until stopped. Returns whether every request in flight at the
    /// stop finished before the deadline.
    pub(crate) async fn run(mut self) -> bool {
        let mut finishing: Vec<JoinHandle<()>> = Vec::new();
        loop {
            // Replaced connections that already ended say nothing about the
            // requests in flight at a later stop, and must not pile up over
            // weeks of renewals.
            finishing.retain(|handle| !handle.is_finished());
            let stopping = *self.stop.borrow();
            if let Some(deadline) = stopping {
                break finish_all(finishing, deadline).await;
            }
            match self.connect_and_serve(&mut finishing).await {
                Ended::Renew => {}
                Ended::Closed => self.pause().await,
                Ended::Stopped(done) => {
                    let deadline = self.stop.borrow().unwrap_or_else(Instant::now);
                    break done & finish_all(finishing, deadline).await;
                }
            }
        }
    }

    async fn connect_and_serve(&mut self, finishing: &mut Vec<JoinHandle<()>>) -> Ended {
        let gateway = self.gateway;
        let registered = match register(&self.config).await {
            Ok(registered) => registered,
            Err(error) => {
                self.emit(failure(gateway, error));
                return Ended::Closed;
            }
        };
        let lease = registered.accept().lease_secs;
        self.emit(ConnectorEvent::Registered {
            gateway,
            lease_secs: lease,
        });
        self.backoff.reset();
        let conn = registered.into_connection(self.service.clone());
        self.serve(conn, renew_after(lease), finishing).await
    }

    async fn serve(
        &mut self,
        conn: ServerConnection<S>,
        renew_after: Duration,
        finishing: &mut Vec<JoinHandle<()>>,
    ) -> Ended {
        let mut conn = Box::pin(conn);
        let ended = tokio::select! {
            _ = conn.as_mut() => Ended::Closed,
            () = sleep(renew_after) => {
                self.emit(ConnectorEvent::Renewing { gateway: self.gateway });
                conn.as_mut().graceful_shutdown();
                finishing.push(tokio::spawn(async move {
                    // However it ends: a cut the gateway chose is not a missed deadline.
                    let _ended = conn.await;
                }));
                return Ended::Renew;
            }
            deadline = wait_for_stop(&mut self.stop) => {
                conn.as_mut().graceful_shutdown();
                Ended::Stopped(timeout_at(deadline, conn.as_mut()).await.is_ok())
            }
        };
        self.emit(ConnectorEvent::Disconnected {
            gateway: self.gateway,
        });
        ended
    }

    /// Waits a backoff delay, or less if the connector stops meanwhile.
    async fn pause(&mut self) {
        let delay = self.backoff.next_delay();
        tokio::select! {
            () = sleep(delay) => {}
            _ = wait_for_stop(&mut self.stop) => {}
        }
    }

    fn emit(&self, event: ConnectorEvent) {
        // No subscriber is fine: events are for whoever listens.
        let _sent = self.events.send(event);
    }
}

fn failure(gateway: SocketAddr, error: Error) -> ConnectorEvent {
    match error {
        Error::Rejected(reject) => ConnectorEvent::Rejected {
            gateway,
            code: reject.code,
            reason: reject.reason,
        },
        other => ConnectorEvent::Failed {
            gateway,
            error: other.to_string(),
        },
    }
}

/// Renews at a random point between 70% and 90% of the lease, so the
/// connections of one connector do not all renew at once.
fn renew_after(lease_secs: u32) -> Duration {
    Duration::from_secs(u64::from(lease_secs)).mul_f64(0.7 + 0.2 * unit_random())
}

/// Resolves when a stop is asked for, with its deadline.
pub(crate) async fn wait_for_stop(stop: &mut Stop) -> Instant {
    loop {
        if let Some(deadline) = *stop.borrow_and_update() {
            return deadline;
        }
        if stop.changed().await.is_err() {
            // The connector was dropped without a stop: stop now.
            return Instant::now();
        }
    }
}

/// Waits for connections being replaced to end, until `deadline`.
/// Returns whether they all ended in time; those that did not are cut.
async fn finish_all(finishing: Vec<JoinHandle<()>>, deadline: Instant) -> bool {
    let mut completed = true;
    for handle in finishing {
        let abort = handle.abort_handle();
        if timeout_at(deadline, handle).await.is_err() {
            abort.abort();
            completed = false;
        }
    }
    completed
}
