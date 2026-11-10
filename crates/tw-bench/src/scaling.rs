// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! NFR-3: gateway throughput by worker threads. The gateway runs in a
//! child process with a runtime of N workers; connectors and a closed
//! loop of clients run here, so the gateway's threads are the only
//! limit that changes.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::setup::{Res, call, client, connector, gateway};

/// Clients calling at once.
const CLIENTS: usize = 64;
/// How long each measurement runs.
const SPAN: Duration = Duration::from_secs(5);
/// Connectors serving the route.
const CONNECTORS: u16 = 4;

/// The child: a gateway on `workers` threads, printing its addresses.
pub(crate) fn serve(workers: usize) -> Res<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let (connectors, ingress) = gateway().await?;
        println!("{connectors} {ingress}");
        tokio::time::sleep(Duration::from_secs(600)).await;
        Ok(())
    })
}

/// The CPU the process `pid` used, in percent of one core, as `ps`
/// reports it (averaged over its life).
fn cpu_percent(pid: u32) -> Res<f64> {
    let out = Command::new("ps")
        .args(["-o", "%cpu=", "-p", &pid.to_string()])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().parse()?)
}

/// Calls a second through a gateway on `workers` threads, and the CPU
/// the gateway used meanwhile (percent of one core).
pub(crate) async fn measure(workers: usize) -> Res<(f64, f64)> {
    let (mut child, connectors, ingress) = spawn_gateway(workers)?;
    for n in 0..CONNECTORS {
        connector(&connectors, n, Duration::ZERO).await?;
    }
    let rate = load(&ingress).await?;
    let cpu = cpu_percent(child.id())?;
    let _killed = child.kill();
    let _reaped = child.wait();
    Ok((rate, cpu))
}

/// The child gateway on `workers` threads, and its two addresses.
fn spawn_gateway(workers: usize) -> Res<(std::process::Child, String, String)> {
    let mut child = Command::new(std::env::current_exe()?)
        .args(["gateway", &workers.to_string()])
        .stdout(Stdio::piped())
        .spawn()?;
    let first = BufReader::new(child.stdout.take().ok_or("no stdout")?)
        .lines()
        .next()
        .ok_or("the gateway printed nothing")??;
    let (connectors, ingress) = first.split_once(' ').ok_or("no addresses")?;
    Ok((child, connectors.to_owned(), ingress.to_owned()))
}

/// `CLIENTS` connections calling back to back for `SPAN`.
async fn load(ingress: &str) -> Res<f64> {
    let done = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::with_capacity(CLIENTS);
    let until = tokio::time::Instant::now() + SPAN;
    for _ in 0..CLIENTS {
        let mut sender = client(ingress).await?;
        let done = done.clone();
        tasks.push(tokio::spawn(async move {
            while tokio::time::Instant::now() < until && call(&mut sender).await.is_ok() {
                done.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for task in tasks {
        task.await?;
    }
    #[expect(clippy::cast_precision_loss, reason = "a count of calls")]
    let calls = done.load(Ordering::Relaxed) as f64;
    Ok(calls / SPAN.as_secs_f64())
}
