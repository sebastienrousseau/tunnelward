// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Identity at registration: the claimed SPIFFE ID must be the
//! certificate's (TW-R003), a route belongs to one identity (FR-3,
//! TW-R004), and an identity claims at most `max_routes_per_identity`.

mod common;

use std::time::Duration;

use tunnelward_connector::{Error, Registered, register};
use tunnelward_gateway::{Config, RouteOwner};
use tunnelward_proto::{Register, RejectCode};
use tunnelward_testpki as pki;

use common::{Res, WAIT, connector_config_as, gateway_config, registration, start};

/// Registers `as_` with `pair`'s certificate; the claimed SPIFFE ID is
/// `as_`'s.
async fn try_as(addr: &str, as_: Register, pair: pki::Pair) -> Res<Result<Registered, Error>> {
    Ok(register(&connector_config_as(addr, as_, pair)?).await)
}

/// A registration claiming `routes` as `spiffe_id`.
fn claim(id: u8, spiffe_id: &str, routes: &[&str]) -> Register {
    Register {
        spiffe_id: spiffe_id.to_owned(),
        ..registration(id, routes, &[])
    }
}

fn refused(outcome: Result<Registered, Error>) -> Res<RejectCode> {
    match outcome {
        Err(Error::Rejected(reject)) => Ok(reject.code),
        Err(other) => Err(format!("failed without a Reject: {other}").into()),
        Ok(_) => Err("registered".into()),
    }
}

async fn gateway(edit: impl FnOnce(&mut Config)) -> Res<String> {
    let mut config = gateway_config()?;
    config.limits.registrations_per_minute = 0;
    edit(&mut config);
    let (gateway, addr) = start(config).await?;
    // The gateway lives as long as its serving task; the handle can go.
    drop(gateway);
    Ok(addr)
}

#[tokio::test]
async fn the_claimed_spiffe_id_must_be_the_certificates() -> Res<()> {
    let addr = gateway(|_| {}).await?;
    let ok = try_as(&addr, claim(1, pki::CONNECTOR_ID, &["a"]), pki::CONNECTOR).await?;
    assert!(ok.is_ok(), "the certificate's own identity registers");
    let lie = try_as(&addr, claim(2, pki::RIVAL_ID, &["b"]), pki::CONNECTOR).await?;
    assert_eq!(refused(lie)?, RejectCode::IdentityMismatch);
    Ok(())
}

#[tokio::test]
async fn a_certificate_without_a_spiffe_id_cannot_register() -> Res<()> {
    let addr = gateway(|_| {}).await?;
    let plain = try_as(&addr, claim(1, pki::CONNECTOR_ID, &["a"]), pki::PLAIN).await?;
    assert_eq!(refused(plain)?, RejectCode::IdentityMismatch);
    Ok(())
}

#[tokio::test]
async fn a_configured_owner_alone_may_claim_its_route() -> Res<()> {
    let addr = gateway(|c| {
        c.route_owners = vec![RouteOwner {
            route: "pay".into(),
            identities: vec![pki::CONNECTOR_ID.into()],
        }];
    })
    .await?;
    let rival = try_as(&addr, claim(1, pki::RIVAL_ID, &["pay"]), pki::RIVAL).await?;
    assert_eq!(refused(rival)?, RejectCode::RouteOwned);
    let owner = try_as(&addr, claim(2, pki::CONNECTOR_ID, &["pay"]), pki::CONNECTOR).await?;
    assert!(owner.is_ok(), "the owner registers");
    Ok(())
}

#[tokio::test]
async fn a_held_route_belongs_to_its_holder() -> Res<()> {
    let addr = gateway(|_| {}).await?;
    let _held = try_as(&addr, claim(1, pki::CONNECTOR_ID, &["a"]), pki::CONNECTOR).await??;
    let rival = try_as(&addr, claim(2, pki::RIVAL_ID, &["a"]), pki::RIVAL).await?;
    assert_eq!(refused(rival)?, RejectCode::RouteOwned);
    let own = try_as(&addr, claim(3, pki::RIVAL_ID, &["b"]), pki::RIVAL).await?;
    assert!(own.is_ok(), "a route nobody holds is free");
    let pool = try_as(&addr, claim(4, pki::CONNECTOR_ID, &["a"]), pki::CONNECTOR).await?;
    assert!(pool.is_ok(), "the holder adds connections to its pool");
    Ok(())
}

#[tokio::test]
async fn a_kept_route_stays_owned_until_it_expires() -> Res<()> {
    let addr = gateway(|c| c.routes_keep_time = Duration::from_millis(300)).await?;
    let held = try_as(&addr, claim(1, pki::CONNECTOR_ID, &["a"]), pki::CONNECTOR).await??;
    drop(held);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let early = try_as(&addr, claim(2, pki::RIVAL_ID, &["a"]), pki::RIVAL).await?;
    assert_eq!(
        refused(early)?,
        RejectCode::RouteOwned,
        "kept for its owner"
    );
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let later = try_as(&addr, claim(3, pki::RIVAL_ID, &["a"]), pki::RIVAL).await?;
        if later.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("the kept route never expired".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn an_identity_claims_at_most_its_route_limit() -> Res<()> {
    let addr = gateway(|c| c.limits.max_routes_per_identity = 2).await?;
    let _two = try_as(
        &addr,
        claim(1, pki::CONNECTOR_ID, &["a", "b"]),
        pki::CONNECTOR,
    )
    .await??;
    let third = try_as(&addr, claim(2, pki::CONNECTOR_ID, &["c"]), pki::CONNECTOR).await?;
    assert_eq!(refused(third)?, RejectCode::Invalid);
    let again = try_as(&addr, claim(3, pki::CONNECTOR_ID, &["a"]), pki::CONNECTOR).await?;
    assert!(
        again.is_ok(),
        "a route the identity holds does not count twice"
    );
    let other = try_as(&addr, claim(4, pki::RIVAL_ID, &["c", "d"]), pki::RIVAL).await?;
    assert!(other.is_ok(), "the limit is per identity");
    Ok(())
}
