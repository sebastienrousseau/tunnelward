// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `AgentAuth::bearer`, the token check an API other than the ingress
//! uses (the control plane's, ADR 0012): it names the caller and its
//! claims, and refuses what the ingress refuses.

mod common;

use std::sync::Arc;
use std::time::SystemTime;

use http::HeaderMap;
use tunnelward_gateway::{AgentAuth, Issuer, KeySet};

use common::Res;
use common::jwt::{Signer, claims, now};

const ISSUER: &str = "https://idp.example.org";
const RESOURCE: &str = "https://control.example.org";

fn auth(signer: &Signer) -> Res<AgentAuth> {
    let keys = KeySet::from_jwks(Signer::jwks(&[signer]).as_bytes())?;
    let issuer = Issuer {
        issuer: ISSUER.into(),
        keys: Arc::new(keys),
    };
    Ok(AgentAuth::new(RESOURCE, vec![issuer]))
}

fn bearer(token: &str) -> Res<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("Bearer {token}").parse()?);
    Ok(headers)
}

#[test]
fn a_valid_token_names_its_subject_and_keeps_its_other_claims() -> Res<()> {
    let signer = Signer::es256("k1")?;
    let text = format!(
        r#"{{"iss":"{ISSUER}","aud":"{RESOURCE}","sub":"ops-7","groups":["tw-operators"],"exp":{}}}"#,
        now() + 600
    );
    let caller = auth(&signer)?.bearer(&bearer(&signer.token(&text)?)?, SystemTime::now())?;
    assert_eq!(caller.subject.as_deref(), Some("ops-7"));
    assert_eq!(caller.claims["groups"][0], "tw-operators");
    assert!(
        !caller.claims.contains_key("iss"),
        "registered claims stay typed"
    );
    Ok(())
}

#[test]
fn tokens_the_ingress_refuses_are_refused() -> Res<()> {
    let signer = Signer::es256("k1")?;
    let other = Signer::es256("k1")?;
    let auth = auth(&signer)?;
    let now = SystemTime::now();
    let elsewhere = signer.token(&claims(ISSUER, "https://other.example.org", ""))?;
    let forged = other.token(&claims(ISSUER, RESOURCE, ""))?;
    let expired = signer.token(&format!(
        r#"{{"iss":"{ISSUER}","aud":"{RESOURCE}","exp":{}}}"#,
        now_secs_ago(3600)
    ))?;
    for (token, why) in [
        (elsewhere, "not for this resource"),
        (forged, "does not verify"),
        (expired, "expired"),
    ] {
        let refused = auth.bearer(&bearer(&token)?, now).err().ok_or("accepted")?;
        assert!(refused.contains(why), "{refused}");
    }
    Ok(())
}

#[test]
fn a_missing_token_or_another_scheme_is_refused() -> Res<()> {
    let auth = auth(&Signer::es256("k1")?)?;
    let now = SystemTime::now();
    let refused = auth
        .bearer(&HeaderMap::new(), now)
        .err()
        .ok_or("accepted")?;
    assert_eq!(refused, "no bearer token");
    let mut dpop = HeaderMap::new();
    dpop.insert("authorization", "DPoP abc".parse()?);
    assert!(auth.bearer(&dpop, now).is_err());
    Ok(())
}

fn now_secs_ago(secs: u64) -> u64 {
    now().saturating_sub(secs)
}
