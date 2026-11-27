// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The approver's sign-in: an OIDC authorization code with PKCE
//! (RFC 7636, S256). The ID token is checked by the gateway's own JWT
//! verifier, with `client_id` as its audience.

use std::time::SystemTime;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use tunnelward_audit::b64;

use super::Approvals;
use super::form::{encode, field};
use crate::Caller;

/// Largest token endpoint answer read.
const MAX_TOKEN_ANSWER: usize = 64 * 1024;

/// `n` random bytes as unpadded base64url.
pub(super) fn random(n: usize) -> Result<String, String> {
    let mut bytes = vec![0; n];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "no randomness".to_owned())?;
    Ok(b64::encode(&bytes))
}

/// The S256 challenge for `verifier`.
pub(super) fn challenge(verifier: &str) -> String {
    b64::encode(digest(&SHA256, verifier.as_bytes()).as_ref())
}

/// Where the provider sends the approver back.
pub(super) fn redirect_uri(approvals: &Approvals) -> String {
    format!("{}{}", approvals.public_url, super::CALLBACK)
}

/// The provider URL that starts a sign-in for `state`.
pub(super) fn authorize_url(
    approvals: &Approvals,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> String {
    let separator = if approvals.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!(
        "{}{separator}response_type=code&scope=openid&client_id={}&redirect_uri={}\
         &state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        approvals.authorization_endpoint,
        encode(&approvals.client_id),
        encode(&redirect_uri(approvals)),
        encode(state),
        encode(nonce),
        challenge(verifier),
    )
}

/// Exchanges `code` for the approver's ID token and checks it, with its
/// `nonce`, at `now`.
pub(super) async fn approver(
    approvals: &Approvals,
    (code, verifier, nonce): (&str, &str, &str),
    now: SystemTime,
) -> Result<Caller, String> {
    let mut body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        encode(code),
        encode(&redirect_uri(approvals)),
        encode(&approvals.client_id),
        encode(verifier),
    );
    if let Some(secret) = &approvals.client_secret {
        body.push_str("&client_secret=");
        body.push_str(&encode(secret));
    }
    let answer = crate::https::https_post_form(
        &approvals.token_endpoint,
        body,
        approvals.roots.clone(),
        MAX_TOKEN_ANSWER,
    )
    .await
    .map_err(|e| format!("token endpoint: {e}"))?;
    let answer: Value =
        serde_json::from_slice(&answer).map_err(|e| format!("token endpoint: {e}"))?;
    let id_token = answer
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or("the token endpoint sent no id_token")?;
    let caller = approvals.verifier.token(id_token, now)?;
    if caller.claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Err("the ID token's nonce is not this sign-in's".into());
    }
    Ok(caller)
}

/// The `code` and `state` of a callback's query.
pub(super) fn callback(query: &str) -> Option<(String, String)> {
    Some((field(query, "code")?, field(query, "state")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_is_rfc_7636s_example() {
        // RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(random(32).unwrap().len(), 43);
        assert_ne!(random(16).unwrap(), random(16).unwrap());
    }
}
