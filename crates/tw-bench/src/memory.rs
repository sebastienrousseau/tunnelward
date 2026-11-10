// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! NFR-2: the gateway's memory per idle connector connection and per
//! in-flight request. The gateway runs in this process; connectors and
//! clients run in a child, so only the gateway's own growth is counted.
//! Measured as the growth of the bytes live on the heap, counted by the
//! global allocator (`alloc.rs`): exact, without the allocator's own
//! slack or the pages it keeps.
//!
//! The child moves through three phases, each only when told on its
//! stdin, so each reading sees only that phase's connections: connectors
//! registered and idle; client connections open, no request sent; one
//! request on each, held by its connector.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::Duration;

use crate::setup::{Res, call, client, connector, gateway};

/// Idle connector connections opened.
pub(crate) const IDLE: u16 = 500;
/// Client connections opened, then requests held in flight on them.
pub(crate) const HELD: u16 = 500;

/// Bytes per idle connector connection, per idle client connection and
/// per request in flight, at the gateway.
pub(crate) struct Usage {
    pub(crate) connector: u64,
    pub(crate) client: u64,
    pub(crate) request: u64,
}

/// The bytes live on this process's heap.
fn live() -> u64 {
    crate::alloc::live() as u64
}

/// Waits for the child to print `wanted`.
fn wait_for(lines: &mut impl Iterator<Item = std::io::Result<String>>, wanted: &str) -> Res<()> {
    for line in lines {
        if line?.contains(wanted) {
            return Ok(());
        }
    }
    Err(format!("the child ended before {wanted:?}").into())
}

/// The heap after the child reports `phase` and things settle.
async fn after(lines: &mut impl Iterator<Item = std::io::Result<String>>, phase: &str) -> Res<u64> {
    // A blocking read, off the runtime's workers.
    tokio::task::block_in_place(|| wait_for(lines, phase))?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(live())
}

/// The child that opens the connections, with its stdin and its lines.
type Peers = (
    Child,
    ChildStdin,
    std::io::Lines<BufReader<std::process::ChildStdout>>,
);

/// Starts the child against the gateway's two addresses.
fn spawn_peers(connectors: &str, ingress: &str) -> Res<Peers> {
    let mut child = Command::new(std::env::current_exe()?)
        .args(["peers", connectors, ingress])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let go = child.stdin.take().ok_or("no stdin")?;
    let lines = BufReader::new(child.stdout.take().ok_or("no stdout")?).lines();
    Ok((child, go, lines))
}

/// Runs the child through its phases and divides each phase's growth.
pub(crate) async fn run() -> Res<Usage> {
    let (connectors, ingress) = gateway().await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = live();
    let (mut child, mut go, mut lines) = spawn_peers(&connectors, &ingress)?;
    let idle = after(&mut lines, "idle").await?;
    writeln!(go, "connect")?;
    let connected = after(&mut lines, "connected").await?;
    writeln!(go, "hold")?;
    let held = after(&mut lines, "held").await?;
    let _killed = child.kill();
    let _reaped = child.wait();
    Ok(Usage {
        connector: idle.saturating_sub(before) / u64::from(IDLE),
        client: connected.saturating_sub(idle) / u64::from(HELD),
        request: held.saturating_sub(connected) / u64::from(HELD),
    })
}

/// Waits for the parent's word on stdin.
fn told() -> Res<()> {
    let mut line = String::new();
    tokio::task::block_in_place(|| std::io::stdin().read_line(&mut line))?;
    Ok(())
}

/// The child: `IDLE` connectors; then `HELD` client connections; then a
/// request on each, its answer held by a connector for a minute.
pub(crate) async fn peers(connectors: &str, ingress: &str) -> Res<()> {
    for n in 0..IDLE {
        connector(connectors, n, Duration::from_secs(60)).await?;
    }
    println!("idle");
    told()?;
    let mut senders = Vec::new();
    for _ in 0..HELD {
        senders.push(client(ingress).await?);
    }
    println!("connected");
    told()?;
    for mut sender in senders {
        tokio::spawn(async move {
            let _answered = call(&mut sender).await;
        });
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("held");
    tokio::time::sleep(Duration::from_secs(120)).await;
    Ok(())
}
