// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Admission by passmcp attestation (FR-5, ADR 0009), end to end: a
//! route that requires one refuses a connector without it (TW-R006) or
//! with a bad one (TW-R007), admits one with a cosign-signed statement,
//! and drains it when the statement is revoked.

mod common;

use std::sync::Arc;
use std::time::Duration;

use tunnelward_attest::{Admission, Revoked, Rule, Target, TrustedKey};
use tunnelward_connector::{Error, Registered, register};
use tunnelward_gateway::Gateway;
use tunnelward_proto::{Register, RejectCode};

use common::{Res, connector_config, gateway_config, get, registration, start, start_connector};

const KEY: &[u8] = include_bytes!("../../tw-attest/tests/vectors/cosign-p256.pub");
const BUNDLE: &[u8] = include_bytes!("../../tw-attest/tests/vectors/cosign-bundle.json");
const TAMPERED: &[u8] = include_bytes!("../../tw-attest/tests/vectors/tampered-bundle.json");

/// `pay` needs a statement about passmcp's fixture target; its run is
/// from 2026-09-22, so the rule accepts old ones (freshness is tested in
/// tunnelward-attest) and its one failed check.
fn admission(revoked: Revoked) -> Res<Arc<Admission>> {
    let mut rule = Rule::new("pay", vec![Target::http("https://mcp.example.com/mcp")]);
    rule.max_age = Duration::from_secs(100 * 365 * 86_400);
    rule.max_fail = 1;
    let key = TrustedKey::from_pem(KEY)?;
    Ok(Arc::new(Admission::new(vec![key], vec![rule], revoked)))
}

async fn gateway() -> Res<(Gateway, String)> {
    let mut config = gateway_config()?;
    config.limits.registrations_per_minute = 0;
    config.attestation = Some(admission(Revoked::default())?);
    start(config).await
}

fn claim(id: u8, routes: &[&str], attestation: Option<&[u8]>) -> Register {
    Register {
        attestation: attestation.map(<[u8]>::to_vec),
        ..registration(id, routes, &[])
    }
}

async fn refusal(addr: &str, register_as: Register) -> Res<(RejectCode, String)> {
    match register(&connector_config(addr, register_as)?).await {
        Err(Error::Rejected(r)) => Ok((r.code, r.reason)),
        Err(other) => Err(format!("failed without a Reject: {other}").into()),
        Ok(Registered { .. }) => Err("registered".into()),
    }
}

/// The hex SHA-256 of the statement the bundle signs.
fn statement_digest() -> String {
    let statement = include_bytes!("../../tw-attest/tests/vectors/statement.json");
    tunnelward_audit::digest(statement)
}

#[tokio::test]
async fn a_ruled_route_needs_a_valid_signed_statement() -> Res<()> {
    let (_gateway, addr) = gateway().await?;
    let (code, reason) = refusal(&addr, claim(1, &["pay"], None)).await?;
    assert_eq!(code, RejectCode::AttestationRequired, "{reason}");
    let (code, reason) = refusal(&addr, claim(2, &["pay"], Some(TAMPERED))).await?;
    assert_eq!(code, RejectCode::AttestationInvalid);
    assert!(reason.contains("trusted key"), "{reason}");
    let (code, _) = refusal(&addr, claim(3, &["pay"], Some(b"{}"))).await?;
    assert_eq!(code, RejectCode::AttestationInvalid);
    Ok(())
}

#[tokio::test]
async fn an_attested_connector_serves_its_route() -> Res<()> {
    let (gateway, addr) = gateway().await?;
    let _pay = start_connector(&addr, "pay", claim(1, &["pay"], Some(BUNDLE))).await?;
    let _open = start_connector(&addr, "open", claim(2, &["open"], None)).await?;
    assert_eq!(get(&gateway, "/pay/x").await?.1, "pay GET /pay/x");
    assert_eq!(get(&gateway, "/open/x").await?.1, "open GET /open/x");
    Ok(())
}

#[tokio::test]
async fn revoking_a_statement_drains_its_connectors() -> Res<()> {
    let (gateway, addr) = gateway().await?;
    let _pay = start_connector(&addr, "pay", claim(1, &["pay"], Some(BUNDLE))).await?;
    let _open = start_connector(&addr, "open", claim(2, &["open"], None)).await?;
    let revoked = Revoked::parse(&statement_digest())?;
    let report = gateway.set_admission(Some(admission(revoked)?)).await;
    assert_eq!(report.sessions, 1, "only the attested connection drains");
    let (code, reason) = refusal(&addr, claim(3, &["pay"], Some(BUNDLE))).await?;
    assert_eq!(code, RejectCode::AttestationInvalid);
    assert!(reason.contains("revoked"), "{reason}");
    assert_eq!(get(&gateway, "/open/x").await?.1, "open GET /open/x");
    Ok(())
}

#[tokio::test]
async fn turning_admission_off_admits_without_a_statement() -> Res<()> {
    let (gateway, addr) = gateway().await?;
    let report = gateway.set_admission(None).await;
    assert_eq!(report.sessions, 0);
    let _pay = start_connector(&addr, "pay", claim(1, &["pay"], None)).await?;
    assert_eq!(get(&gateway, "/pay/x").await?.1, "pay GET /pay/x");
    Ok(())
}
