// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Admission rules against statements signed here, one demand at a time.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use tunnelward_attest::{Admission, Limits, PAYLOAD_TYPE, Revoked, Rule, Target, TrustedKey};
use tunnelward_audit::b64;
use tunnelward_proto::{McpDescriptor, RejectCode};

const FIXTURE: &str = include_str!("vectors/statement.json");
const ROUTE: &str = "mcp/payments";
const ENDPOINT: &str = "https://mcp.example.com/mcp";
const DAY: u64 = 86_400;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// A key pair and the time the tests call now.
struct Signer {
    pair: Ed25519KeyPair,
    now: SystemTime,
}

impl Signer {
    fn new() -> Res<Self> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
        Ok(Self {
            pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())?,
            now: UNIX_EPOCH + Duration::from_secs(1_790_078_400 + DAY),
        })
    }

    fn key(&self) -> Res<TrustedKey> {
        let der = AsDer::<aws_lc_rs::encoding::PublicKeyX509Der>::as_der(self.pair.public_key())?;
        Ok(TrustedKey::from_spki(der.as_ref())?)
    }

    /// passmcp's fixture, run `age` before now, with `edit` applied.
    fn statement(&self, age: i64, edit: impl FnOnce(&mut Value)) -> Res<Vec<u8>> {
        let mut value: Value = serde_json::from_str(FIXTURE)?;
        let now = self.now.duration_since(UNIX_EPOCH)?.as_secs();
        let ran = now.checked_add_signed(-age).ok_or("before 1970")?;
        value["predicate"]["ranAt"] = rfc3339(ran).into();
        edit(&mut value);
        self.sign(&serde_json::to_vec(&value)?)
    }

    fn sign(&self, payload: &[u8]) -> Res<Vec<u8>> {
        let pae = [
            format!(
                "DSSEv1 {} {PAYLOAD_TYPE} {} ",
                PAYLOAD_TYPE.len(),
                payload.len()
            )
            .as_bytes(),
            payload,
        ]
        .concat();
        let sig = self.pair.sign(&pae);
        Ok(serde_json::to_vec(&json!({
            "payloadType": PAYLOAD_TYPE,
            "payload": b64::encode(payload),
            "signatures": [{ "keyid": "", "sig": b64::encode(sig.as_ref()) }],
        }))?)
    }

    fn admission(&self, rule: Rule) -> Res<Admission> {
        Ok(Admission::new(
            vec![self.key()?],
            vec![rule],
            Revoked::default(),
            Limits::default(),
        ))
    }
}

/// Seconds since 1970 as `YYYY-MM-DDTHH:MM:SSZ` (days by Hinnant's
/// `civil_from_days`).
fn rfc3339(secs: u64) -> String {
    let z = secs / DAY + 719_468;
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    let rest = secs % DAY;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// The fixture's route rule, with its one failed check allowed.
fn rule() -> Rule {
    let mut rule = Rule::new(ROUTE, vec![Target::http(ENDPOINT)]);
    rule.max_fail = 1;
    rule
}

fn routes() -> Vec<String> {
    vec![ROUTE.to_owned(), "mcp/other".to_owned()]
}

fn reason(
    admission: &Admission,
    bundle: &[u8],
    mcp: Option<&McpDescriptor>,
    now: SystemTime,
) -> Res<String> {
    let refusal = admission
        .admit(&routes(), Some(bundle), mcp, now)
        .err()
        .ok_or("admitted")?;
    assert_eq!(refusal.code, RejectCode::AttestationInvalid);
    Ok(refusal.reason)
}

#[test]
fn a_fresh_signed_statement_for_the_target_is_admitted() -> Res<()> {
    let signer = Signer::new()?;
    let bundle = signer.statement(60, |_| {})?;
    let admitted = signer
        .admission(rule())?
        .admit(&routes(), Some(&bundle), None, signer.now);
    assert!(matches!(admitted, Ok(Some(_))));
    Ok(())
}

#[test]
fn a_route_with_no_rule_ignores_what_is_sent() -> Res<()> {
    let signer = Signer::new()?;
    let admission = signer.admission(rule())?;
    let other = ["mcp/other".to_owned()];
    assert_eq!(
        admission.admit(&other, Some(b"junk"), None, signer.now),
        Ok(None)
    );
    assert_eq!(admission.admit(&other, None, None, signer.now), Ok(None));
    Ok(())
}

#[test]
fn a_ruled_route_without_one_is_required() -> Res<()> {
    let signer = Signer::new()?;
    let refusal = signer
        .admission(rule())?
        .admit(&routes(), None, None, signer.now)
        .unwrap_err();
    assert_eq!(refusal.code, RejectCode::AttestationRequired);
    assert!(refusal.reason.contains(ROUTE), "{}", refusal.reason);
    Ok(())
}

#[test]
fn a_statement_is_fresh_for_max_age_after_its_run() -> Res<()> {
    let signer = Signer::new()?;
    let admission = signer.admission(rule())?;
    let thirty_days = i64::try_from(30 * DAY)?;
    let edge = signer.statement(thirty_days, |_| {})?;
    let admitted = admission.admit(&routes(), Some(&edge), None, signer.now);
    assert!(admitted.is_ok());
    let old = signer.statement(thirty_days + 1, |_| {})?;
    assert!(reason(&admission, &old, None, signer.now)?.contains("older"));
    Ok(())
}

#[test]
fn a_run_may_be_dated_at_most_five_minutes_ahead() -> Res<()> {
    let signer = Signer::new()?;
    let admission = signer.admission(rule())?;
    let soon = signer.statement(-300, |_| {})?;
    let admitted = admission.admit(&routes(), Some(&soon), None, signer.now);
    assert!(admitted.is_ok());
    let ahead = signer.statement(-301, |_| {})?;
    assert!(reason(&admission, &ahead, None, signer.now)?.contains("future"));
    Ok(())
}

#[test]
fn the_future_skew_is_the_gateways_to_set() -> Res<()> {
    let signer = Signer::new()?;
    let limits = Limits {
        future_skew: std::time::Duration::from_secs(60),
        ..Limits::default()
    };
    let admission = Admission::new(
        vec![signer.key()?],
        vec![rule()],
        Revoked::default(),
        limits,
    );
    let within = signer.statement(-60, |_| {})?;
    let admitted = admission.admit(&routes(), Some(&within), None, signer.now);
    assert!(admitted.is_ok());
    let ahead = signer.statement(-61, |_| {})?;
    assert!(reason(&admission, &ahead, None, signer.now)?.contains("future"));
    Ok(())
}

#[test]
fn a_statement_about_another_target_is_refused() -> Res<()> {
    let signer = Signer::new()?;
    let mut rule = rule();
    rule.targets = vec![
        Target::http("https://mcp.example.com/other"),
        Target::stdio(ENDPOINT),
    ];
    let bundle = signer.statement(60, |_| {})?;
    let why = reason(&signer.admission(rule)?, &bundle, None, signer.now)?;
    assert!(why.contains("another server"), "{why}");
    Ok(())
}

#[test]
fn the_server_must_be_the_one_the_connector_reports() -> Res<()> {
    let signer = Signer::new()?;
    let admission = signer.admission(rule())?;
    let bundle = signer.statement(60, |v| {
        v["predicate"]["target"]["server"] = json!({ "name": "payments", "version": "1.2.0" });
    })?;
    let mut mcp = McpDescriptor {
        name: "payments".into(),
        version: "1.2.0".into(),
        tools_digest: [0; 32],
    };
    assert!(
        admission
            .admit(&routes(), Some(&bundle), Some(&mcp), signer.now)
            .is_ok()
    );
    mcp.version = "1.3.0".into();
    let why = reason(&admission, &bundle, Some(&mcp), signer.now)?;
    assert!(why.contains("1.3.0") && why.contains("1.2.0"), "{why}");
    Ok(())
}

#[test]
fn verdicts_are_held_to_the_rule() -> Res<()> {
    let signer = Signer::new()?;
    let bundle = signer.statement(60, |_| {})?;
    let check = |edit: &dyn Fn(&mut Rule)| {
        let mut rule = rule();
        edit(&mut rule);
        signer
            .admission(rule)
            .map_err(|e| e.to_string())?
            .admit(&routes(), Some(&bundle), None, signer.now)
            .map_err(|r| r.reason)
    };
    assert!(check(&|r| r.max_fail = 0).unwrap_err().contains("1 failed"));
    assert!(check(&|r| r.require = vec!["auth.unauthenticated_tools".into()]).is_ok());
    assert!(
        check(&|r| r.require = vec!["protocol.origin".into()])
            .unwrap_err()
            .contains("is fail")
    );
    assert!(
        check(&|r| r.require = vec!["no.such".into()])
            .unwrap_err()
            .contains("not assessed")
    );
    assert!(check(&|r| r.min_score = Some(88.0)).is_ok());
    assert!(
        check(&|r| r.min_score = Some(90.0))
            .unwrap_err()
            .contains("under 90")
    );
    Ok(())
}

#[test]
fn a_statement_with_no_score_fails_a_minimum() -> Res<()> {
    let signer = Signer::new()?;
    let bundle = signer.statement(60, |v| {
        if let Some(p) = v["predicate"].as_object_mut() {
            p.remove("score");
        }
    })?;
    let mut rule = rule();
    rule.min_score = Some(1.0);
    let why = reason(&signer.admission(rule)?, &bundle, None, signer.now)?;
    assert!(why.contains("no score"), "{why}");
    Ok(())
}

#[test]
fn every_rule_for_a_claimed_route_applies() -> Res<()> {
    let signer = Signer::new()?;
    let mut strict = rule();
    strict.route = "mcp/other".into();
    strict.max_fail = 0;
    let admission = Admission::new(
        vec![signer.key()?],
        vec![rule(), strict],
        Revoked::default(),
        Limits::default(),
    );
    let bundle = signer.statement(60, |_| {})?;
    assert!(reason(&admission, &bundle, None, signer.now)?.contains("1 failed"));
    Ok(())
}

#[test]
fn a_revoked_statement_is_refused() -> Res<()> {
    let signer = Signer::new()?;
    let bundle = signer.statement(60, |_| {})?;
    let digest = signer
        .admission(rule())?
        .admit(&routes(), Some(&bundle), None, signer.now)
        .unwrap()
        .unwrap();
    let revoked = Revoked::parse(&tunnelward_audit::hex(&digest), 1).unwrap();
    let admission = Admission::new(
        vec![signer.key()?],
        vec![rule()],
        revoked,
        Limits::default(),
    );
    assert!(admission.is_revoked(&digest));
    assert!(reason(&admission, &bundle, None, signer.now)?.contains("revoked"));
    Ok(())
}

#[test]
fn a_statement_by_an_unknown_signer_is_invalid() -> Res<()> {
    let (signer, stranger) = (Signer::new()?, Signer::new()?);
    let bundle = stranger.statement(60, |_| {})?;
    let why = reason(&signer.admission(rule())?, &bundle, None, signer.now)?;
    assert!(why.contains("trusted key"), "{why}");
    Ok(())
}

#[test]
fn a_signed_but_broken_statement_is_invalid() -> Res<()> {
    let signer = Signer::new()?;
    let admission = signer.admission(rule())?;
    let edited = signer.statement(60, |v| v["predicate"]["counts"]["fail"] = 0.into())?;
    let why = reason(&admission, &edited, None, signer.now)?;
    assert!(why.contains("counts disagree"), "{why}");
    let undated = signer.statement(60, |v| v["predicate"]["ranAt"] = "yesterday".into())?;
    assert!(reason(&admission, &undated, None, signer.now)?.contains("RFC 3339"));
    Ok(())
}
