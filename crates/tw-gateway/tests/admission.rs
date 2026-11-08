// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Gateway-wide admission limits: registrations per source per minute
//! (TW-R009) and domains per gateway (TW-R010).

mod common;

use std::time::Duration;

use tunnelward_connector::{Error, Registered, register};
use tunnelward_proto::{Register, RejectCode};

use common::{Res, WAIT, connector_config, gateway_config, registration, start};

/// Registers `as_` with the gateway at `addr`.
async fn try_register(addr: &str, as_: Register) -> Res<Result<Registered, Error>> {
    Ok(register(&connector_config(addr, as_)?).await)
}

/// The code a refused registration carried, or a failure if it was not
/// refused.
fn refused(outcome: Result<Registered, Error>) -> Res<RejectCode> {
    match outcome {
        Err(Error::Rejected(reject)) => Ok(reject.code),
        Err(other) => Err(format!("failed without a Reject: {other}").into()),
        Ok(_) => Err("registered".into()),
    }
}

#[tokio::test]
async fn a_source_over_its_registrations_per_minute_is_refused() -> Res<()> {
    let mut config = gateway_config()?;
    config.limits.registrations_per_minute = 2;
    let (_gateway, addr) = start(config).await?;
    let _first = try_register(&addr, registration(1, &["a"], &[])).await??;
    let _second = try_register(&addr, registration(2, &["b"], &[])).await??;
    let third = try_register(&addr, registration(3, &["c"], &[])).await?;
    assert_eq!(refused(third)?, RejectCode::RateLimited);
    Ok(())
}

#[tokio::test]
async fn zero_registrations_per_minute_turns_the_limit_off() -> Res<()> {
    let mut config = gateway_config()?;
    config.limits.registrations_per_minute = 0;
    let (_gateway, addr) = start(config).await?;
    for id in 1..=5 {
        let _session = try_register(&addr, registration(id, &["a"], &[])).await??;
    }
    Ok(())
}

#[tokio::test]
async fn the_gateway_serves_at_most_max_domains() -> Res<()> {
    let mut config = gateway_config()?;
    config.limits.max_domains = 3;
    let (gateway, addr) = start(config).await?;
    let both = ["a.example.com", "b.example.com"];
    let _a = try_register(&addr, registration(1, &["a"], &both)).await??;
    // b.example.com is already served: only c.example.com is new.
    let shared = ["b.example.com", "c.example.com"];
    let _b = try_register(&addr, registration(2, &["b"], &shared)).await??;
    let fourth = try_register(&addr, registration(3, &["c"], &["d.example.com"])).await?;
    assert_eq!(refused(fourth)?, RejectCode::Overloaded);
    // A domain already served still joins its pool at the cap.
    let _pool = try_register(&addr, registration(4, &["a"], &["a.example.com"])).await??;
    assert_eq!(gateway.routes(), ["a", "a", "b"]);
    Ok(())
}

#[tokio::test]
async fn a_refused_registration_frees_nothing_it_did_not_hold() -> Res<()> {
    let mut config = gateway_config()?;
    config.limits.max_domains = 1;
    let (_gateway, addr) = start(config).await?;
    let over = ["x.example.com", "y.example.com"];
    let refusal = try_register(&addr, registration(1, &["x"], &over)).await?;
    assert_eq!(refused(refusal)?, RejectCode::Overloaded);
    // The refused claim reserved nothing, so one domain still fits.
    let _fits = try_register(&addr, registration(2, &["x"], &["x.example.com"])).await??;
    Ok(())
}

#[tokio::test]
async fn a_departed_connectors_domains_are_freed() -> Res<()> {
    let mut config = gateway_config()?;
    config.limits.max_domains = 1;
    config.limits.registrations_per_minute = 0;
    config.routes_keep_time = Duration::ZERO;
    let (_gateway, addr) = start(config).await?;
    let first = try_register(&addr, registration(1, &["x"], &["x.example.com"])).await??;
    drop(first);
    // Once the gateway sees the connection close, y.example.com fits.
    register_once_free(&addr, registration(2, &["y"], &["y.example.com"])).await
}

/// Registers `as_`, retrying while the gateway answers Overloaded, until
/// [`WAIT`] passes.
async fn register_once_free(addr: &str, as_: Register) -> Res<()> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        match try_register(addr, as_.clone()).await? {
            Ok(_registered) => return Ok(()),
            Err(Error::Rejected(r)) if r.code == RejectCode::Overloaded => {}
            Err(other) => return Err(format!("refused otherwise: {other}").into()),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("still over max_domains".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
