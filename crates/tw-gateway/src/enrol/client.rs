// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The connector's side of enrolment, beside the gateway's so the two
//! share one wire format.

use std::sync::Arc;

use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_identity::enrol;

use super::{ENROL_PATH, EnrolRequest, Issued, RENEW_PATH, RenewRequest};
use crate::auth::b64;
use crate::https_post;

/// Largest answer read.
const MAX_ANSWER: usize = 64 * 1024;

fn endpoint(gateway: &str, path: &str) -> String {
    format!("{}{path}", gateway.trim_end_matches('/'))
}

async fn send(url: String, body: Vec<u8>, roots: Arc<RootCertStore>) -> Result<Vec<u8>, String> {
    let answer = https_post(&url, body, roots, MAX_ANSWER).await?;
    let issued: Issued =
        serde_json::from_slice(&answer).map_err(|e| format!("the gateway's answer: {e}"))?;
    b64::decode(&issued.svid).ok_or_else(|| "the gateway's answer: svid is not base64url".into())
}

/// Redeems `token` at the gateway whose ingress is `gateway` (an
/// `https://` URL), asking it to certify the PKCS#8 key `key`; returns
/// the SVID, DER.
///
/// # Errors
///
/// A sentence: the key, the connection, or the gateway's refusal.
pub async fn request_enrolment(
    gateway: &str,
    token: &str,
    key: &[u8],
    roots: Arc<RootCertStore>,
) -> Result<Vec<u8>, String> {
    let csr = enrol::request(key).map_err(|e| e.to_string())?;
    let body = EnrolRequest {
        token: token.to_owned(),
        csr: b64::encode(&csr),
    };
    let json = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    send(endpoint(gateway, ENROL_PATH), json, roots).await
}

/// Renews `svid`, held with the PKCS#8 key `current`, for the new key
/// `next`; returns the new SVID, DER.
///
/// # Errors
///
/// As [`request_enrolment`].
pub async fn request_renewal(
    gateway: &str,
    (svid, current): (&[u8], &[u8]),
    next: &[u8],
    roots: Arc<RootCertStore>,
) -> Result<Vec<u8>, String> {
    let csr = enrol::request(next).map_err(|e| e.to_string())?;
    let proof = enrol::sign(current, &csr).map_err(|e| e.to_string())?;
    let body = RenewRequest {
        svid: b64::encode(svid),
        csr: b64::encode(&csr),
        proof: b64::encode(&proof),
    };
    let json = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    send(endpoint(gateway, RENEW_PATH), json, roots).await
}
