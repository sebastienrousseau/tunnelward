// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! NFR-1: the latency the gateway and tunnel add to a 1 KiB MCP call on
//! a warm connection. Open loop: calls are due at a fixed rate and each
//! is timed from when it was due, not from when it went out, so a slow
//! call's delay to the next is counted (no coordinated omission).

use std::time::Duration;

use tokio::time::{Instant, sleep_until};

/// How early the timer wakes the series before a call is due; the rest
/// is spun, because the timer is only good to a millisecond.
const SPIN: Duration = Duration::from_millis(2);

/// Waits until `due`: sleeps most of the way, then spins.
async fn wait_until(due: Instant) {
    if let Some(early) = due.checked_sub(SPIN) {
        sleep_until(early).await;
    }
    while Instant::now() < due {
        std::hint::spin_loop();
    }
}

use crate::setup::{Res, call, client, connector, direct, gateway};

/// Calls in one series, after warming up.
const CALLS: u32 = 5_000;
/// Calls a second.
const RATE: u32 = 1_000;
/// Series per path.
pub(crate) const RUNS: usize = 5;

/// Latencies of `CALLS` calls to `addr`, each from when it was due.
async fn series(addr: &str) -> Res<Vec<Duration>> {
    let mut sender = client(addr).await?;
    for _ in 0..2_000 {
        call(&mut sender).await?;
    }
    let interval = Duration::from_secs(1) / RATE;
    let start = Instant::now();
    let mut out = Vec::with_capacity(CALLS as usize);
    for i in 0..CALLS {
        let due = start + interval * i;
        wait_until(due).await;
        call(&mut sender).await?;
        out.push(due.elapsed());
    }
    Ok(out)
}

/// The `q` quantile of `values`, in microseconds.
fn quantile(values: &mut [Duration], q: f64) -> f64 {
    values.sort_unstable();
    let last = values.len().saturating_sub(1);
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "an index into a few thousand samples"
    )]
    let at = ((last as f64) * q).round() as usize;
    values.get(at).map_or(0.0, |d| d.as_secs_f64() * 1e6)
}

/// p50 and p99 of one series, in microseconds.
fn p50_p99(mut values: Vec<Duration>) -> (f64, f64) {
    (quantile(&mut values, 0.50), quantile(&mut values, 0.99))
}

/// One row per run: direct and through the gateway, p50 and p99, and
/// what the gateway adds.
pub(crate) async fn run() -> Res<Vec<[f64; 6]>> {
    let baseline = direct().await?;
    let (connectors, ingress) = gateway().await?;
    connector(&connectors, 1, Duration::ZERO).await?;
    let mut rows = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let (d50, d99) = p50_p99(series(&baseline).await?);
        let (g50, g99) = p50_p99(series(&ingress).await?);
        rows.push([d50, d99, g50, g99, g50 - d50, g99 - d99]);
    }
    Ok(rows)
}
