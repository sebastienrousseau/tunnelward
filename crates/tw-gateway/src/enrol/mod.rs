// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Enrolment: connectors with no SVID get one from the gateway.
//!
//! An operator issues a one-time token bound to a SPIFFE ID
//! ([`Tokens::issue`]). The connector POSTs the token and a signing
//! request to `/.well-known/tunnelward/enrol` on the ingress and gets a
//! short-lived X.509-SVID for that ID from the gateway's CA. Before it
//! expires the connector POSTs its current SVID, a new signing request,
//! and the request signed with the current key to
//! `/.well-known/tunnelward/renew`: holding the key of a valid SVID is
//! the proof, as it would be over mutual TLS. Revoking an identity
//! ([`Tokens::revoke`]) stops its renewals; the SVID it holds lapses
//! within one lifetime.
//!
//! The token store is a directory shared with `tunnelward enrol`
//! ([`Tokens`]). The connector's side of the exchange is
//! [`request_enrolment`] and [`request_renewal`].

mod client;
mod tokens;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use tunnelward_crypto::rustls::pki_types::{CertificateDer, UnixTime};
use tunnelward_crypto::rustls::server::WebPkiClientVerifier;
use tunnelward_crypto::rustls::server::danger::ClientCertVerifier;
use tunnelward_crypto::rustls::{RootCertStore, crypto::CryptoProvider};
use tunnelward_crypto::{KeyExchange, provider};
use tunnelward_identity::enrol::{self, Ca};

pub use client::{request_enrolment, request_renewal};
pub(crate) use tokens::TokenError;
pub use tokens::Tokens;

use crate::auth::b64;
use crate::refusal::Refusal;

/// Where a connector enrols with a token.
pub(crate) const ENROL_PATH: &str = "/.well-known/tunnelward/enrol";
/// Where a connector renews with its current SVID.
pub(crate) const RENEW_PATH: &str = "/.well-known/tunnelward/renew";
/// Largest enrolment request body.
pub(crate) const MAX_BODY: usize = 64 * 1024;
pub(crate) fn unix(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A gateway's enrolment: its CA, its tokens, and how long an SVID lasts.
pub struct Enrolment {
    ca: Ca,
    tokens: Tokens,
    lifetime: Duration,
    issued_by_us: Arc<dyn ClientCertVerifier>,
}

impl std::fmt::Debug for Enrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrolment")
            .field("tokens", &self.tokens)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

impl Enrolment {
    /// Enrolment issuing from `ca`, redeeming `tokens`, each SVID valid
    /// for `lifetime`. The connector listener must trust `ca`'s
    /// certificate for the SVIDs it issues to be accepted.
    ///
    /// # Errors
    ///
    /// The CA certificate is not one rustls can use as a root.
    pub fn new(ca: Ca, tokens: Tokens, lifetime: Duration) -> Result<Self, String> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.certificate().to_vec()))
            .map_err(|e| format!("the enrolment CA certificate: {e}"))?;
        let provider: Arc<CryptoProvider> = provider(KeyExchange::default());
        let issued_by_us = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|e| format!("the enrolment CA certificate: {e}"))?;
        Ok(Self {
            ca,
            tokens,
            lifetime,
            issued_by_us,
        })
    }

    /// The CA certificate, DER.
    #[must_use]
    pub fn ca_certificate(&self) -> &[u8] {
        self.ca.certificate()
    }

    fn issue(&self, spiffe_id: &str, csr: &[u8], now: SystemTime) -> Result<Issued, Refusal> {
        let key = enrol::requested_key(csr).map_err(|e| bad_request(&e))?;
        let svid = self
            .ca
            .issue(spiffe_id, &key, self.lifetime, now)
            .map_err(|e| Refusal::new(ID, StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        Ok(Issued {
            not_after: enrol::validity(&svid).map_or(0, |v| v.1),
            svid: b64::encode(&svid),
            ca: b64::encode(self.ca.certificate()),
        })
    }

    fn enrol(&self, request: &EnrolRequest, now: SystemTime) -> Result<Issued, Refusal> {
        let csr = decode(&request.csr, "csr")?;
        let spiffe_id = self
            .tokens
            .redeem(&request.token, now)
            .map_err(token_refusal)?;
        self.issue(&spiffe_id, &csr, now)
    }

    fn renew(&self, request: &RenewRequest, now: SystemTime) -> Result<Issued, Refusal> {
        let svid = decode(&request.svid, "svid")?;
        let csr = decode(&request.csr, "csr")?;
        let proof = decode(&request.proof, "proof")?;
        let at = UnixTime::since_unix_epoch(Duration::from_secs(unix(now)));
        self.issued_by_us
            .verify_client_cert(&CertificateDer::from(svid.as_slice()), &[], at)
            .map_err(|e| {
                forbidden(format!(
                    "the SVID is not a current one from this gateway: {e}"
                ))
            })?;
        let spiffe_id = tunnelward_identity::spiffe_id(&svid)
            .map_err(|e| forbidden(format!("the SVID: {e}")))?;
        if !self.tokens.is_enrolled(&spiffe_id) {
            return Err(forbidden(format!(
                "{spiffe_id} is not enrolled, or was revoked"
            )));
        }
        if !enrol::verify(&svid, &csr, &proof) {
            return Err(forbidden("the proof does not verify with the SVID's key"));
        }
        self.issue(&spiffe_id, &csr, now)
    }
}

/// The error id for every enrolment refusal.
const ID: &str = "TW-I011";

/// An enrolment body over [`MAX_BODY`], or one that failed to arrive.
fn body_refused() -> Refusal {
    Refusal::new(
        ID,
        StatusCode::PAYLOAD_TOO_LARGE,
        "enrolment body over 64 KiB, or it failed",
    )
}

fn forbidden(reason: impl Into<String>) -> Refusal {
    Refusal::new(ID, StatusCode::FORBIDDEN, reason)
}

fn bad_request(reason: &dyn std::fmt::Display) -> Refusal {
    Refusal::new(ID, StatusCode::BAD_REQUEST, reason.to_string())
}

fn token_refusal(error: TokenError) -> Refusal {
    match error {
        TokenError::Unknown => forbidden("the token is unknown or already used"),
        TokenError::Expired => forbidden("the token has expired"),
        TokenError::Store => Refusal::new(
            ID,
            StatusCode::INTERNAL_SERVER_ERROR,
            "the token store cannot be read or written",
        ),
    }
}

fn decode(text: &str, field: &str) -> Result<Vec<u8>, Refusal> {
    b64::decode(text).ok_or_else(|| bad_request(&format!("{field}: not base64url")))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrolRequest {
    token: String,
    csr: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewRequest {
    svid: String,
    csr: String,
    proof: String,
}

/// What enrolment and renewal answer: the SVID, the CA, and when the
/// SVID expires (seconds since 1970). DER in base64url.
#[derive(Debug, Serialize, Deserialize)]
struct Issued {
    svid: String,
    ca: String,
    not_after: u64,
}

/// Whether `path` is one of the enrolment endpoints.
pub(crate) fn is_enrolment_path(path: &str) -> bool {
    path == ENROL_PATH || path == RENEW_PATH
}

fn parse<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, Refusal> {
    serde_json::from_slice(body).map_err(|e| bad_request(&format!("the request body: {e}")))
}

/// Reads `request`'s body, up to [`MAX_BODY`], and answers it.
pub(crate) async fn respond(
    enrolment: &Enrolment,
    request: http::Request<hyper::body::Incoming>,
) -> Result<Bytes, Refusal> {
    use http_body_util::{BodyExt, Limited};
    let (parts, body) = request.into_parts();
    let body = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map_err(|_| body_refused())?;
    answer(
        enrolment,
        &parts.method,
        parts.uri.path(),
        &body.to_bytes(),
        SystemTime::now(),
    )
}

/// The JSON answer to a POST of `body` to the enrolment endpoint `path`.
pub(crate) fn answer(
    enrolment: &Enrolment,
    method: &Method,
    path: &str,
    body: &[u8],
    now: SystemTime,
) -> Result<Bytes, Refusal> {
    if method != Method::POST {
        return Err(Refusal::new(ID, StatusCode::METHOD_NOT_ALLOWED, "use POST"));
    }
    let issued = if path == ENROL_PATH {
        enrolment.enrol(&parse(body)?, now)?
    } else {
        enrolment.renew(&parse(body)?, now)?
    };
    serde_json::to_vec(&issued)
        .map(Bytes::from)
        .map_err(|e| Refusal::new(ID, StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    type Res = Result<(), Box<dyn std::error::Error>>;

    const ID: &str = "spiffe://example.org/connector";

    fn post(enrolment: &Enrolment, path: &str, body: &str, now: SystemTime) -> Result<Bytes, u16> {
        answer(enrolment, &Method::POST, path, body.as_bytes(), now).map_err(|r| r.status.as_u16())
    }

    /// An enrolment whose SVIDs last 600 s, and one enrolled at `now`:
    /// its answer and its key.
    fn enrolled(
        now: SystemTime,
    ) -> Result<(Enrolment, Issued, Vec<u8>), Box<dyn std::error::Error>> {
        let (cert, key) = Ca::generate("CA", Duration::from_secs(86_400), now)?;
        let dir = std::env::temp_dir().join(format!("tw-enrol-expiry-{}", std::process::id()));
        let _fresh = std::fs::remove_dir_all(&dir);
        let tokens = Tokens::new(dir);
        let lifetime = Duration::from_secs(600);
        let enrolment = Enrolment::new(Ca::load(&cert, &key)?, tokens.clone(), lifetime)?;
        let token = tokens.issue(ID, Duration::from_secs(60), now)?;
        let key = enrol::new_key()?;
        let csr = b64::encode(&enrol::request(&key)?);
        let body = format!(r#"{{"token":"{token}","csr":"{csr}"}}"#);
        let answer = post(&enrolment, ENROL_PATH, &body, now).map_err(|s| format!("{s}"))?;
        Ok((enrolment, serde_json::from_slice(&answer)?, key))
    }

    /// A renewal body for `issued`, proven with `key`.
    fn renewal(issued: &Issued, key: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let csr = enrol::request(&enrol::new_key()?)?;
        Ok(format!(
            r#"{{"svid":"{}","csr":"{}","proof":"{}"}}"#,
            issued.svid,
            b64::encode(&csr),
            b64::encode(&enrol::sign(key, &csr)?)
        ))
    }

    #[test]
    fn an_expired_svid_does_not_renew() -> Res {
        let now = SystemTime::now();
        let (enrolment, issued, key) = enrolled(now)?;
        assert_eq!(issued.not_after, unix(now) + 600);
        let body = renewal(&issued, &key)?;
        let in_time = now + Duration::from_secs(590);
        assert!(post(&enrolment, RENEW_PATH, &body, in_time).is_ok());
        let late = now + Duration::from_secs(601);
        assert_eq!(post(&enrolment, RENEW_PATH, &body, late), Err(403));
        Ok(())
    }
}
