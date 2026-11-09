// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! NFR-2: the gateway's memory per idle connector connection and per
//! in-flight request. The gateway runs in this process; connectors and
//! clients run in a child, so only the gateway's own growth is counted.
//! Measured as the growth of the process's resident memory, which is
//! coarser than an allocator profile: an upper bound, rounded to pages.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::setup::{Res, call, client, connector, gateway};

/// Idle connector connections opened.
pub(crate) const IDLE: u16 = 500;
/// Requests held in flight.
pub(crate) const HELD: u16 = 500;

/// This process's resident memory, in KiB.
fn rss_kib() -> Res<u64> {
    let pid = std::process::id().to_string();
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().parse()?)
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

/// Bytes per idle connection and per held request, at the gateway.
pub(crate) async fn run() -> Res<(u64, u64)> {
    let (connectors, ingress) = gateway().await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = rss_kib()?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["peers", &connectors, &ingress])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut lines = BufReader::new(child.stdout.take().ok_or("no stdout")?).lines();
    wait_for(&mut lines, "idle")?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let idle = rss_kib()?;
    wait_for(&mut lines, "held")?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let held = rss_kib()?;
    let _killed = child.kill();
    let _reaped = child.wait();
    let per_idle = idle.saturating_sub(before) * 1024 / u64::from(IDLE);
    let per_held = held.saturating_sub(idle) * 1024 / u64::from(HELD);
    Ok((per_idle, per_held))
}

/// The child: `IDLE` connectors, then `HELD` requests that each hold a
/// connector's answer for a minute.
pub(crate) async fn peers(connectors: &str, ingress: &str) -> Res<()> {
    for n in 0..IDLE {
        connector(connectors, n, Duration::from_secs(60)).await?;
    }
    println!("idle");
    for _ in 0..HELD {
        let mut sender = client(ingress).await?;
        tokio::spawn(async move {
            let _answered = call(&mut sender).await;
        });
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("held");
    tokio::time::sleep(Duration::from_secs(120)).await;
    Ok(())
}
