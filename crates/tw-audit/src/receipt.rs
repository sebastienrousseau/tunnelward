// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Signed call receipts (FR-15): what the gateway saw and decided about
//! one request, signed so the caller can prove it later, offline.
//!
//! A receipt is `<payload>.<signature>`, both unpadded base64url: the
//! payload is JSON, the signature a composite ML-DSA-65 + Ed25519 one
//! over a receipt label and the payload's bytes. Changing any byte of
//! the payload, so any field, makes it fail.

use serde::{Deserialize, Serialize};
use tunnelward_crypto::composite;

use crate::{Call, RequestEntry, b64};

/// What a receipt signature covers, before the payload.
const LABEL: &[u8] = b"tunnelward receipt v1\0";
/// The receipt format version.
const VERSION: u8 = 1;
/// Longest receipt [`verify`] reads, in characters.
const MAX_LEN: usize = 64 * 1024;

/// A receipt's fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Receipt {
    /// The format version, 1.
    pub v: u8,
    /// When it was signed, in milliseconds since 1970.
    pub issued: u64,
    /// The signing key's id ([`crate::key_id`]).
    pub key: String,
    /// The request's id (`tw-request-id`).
    pub request_id: String,
    /// The method.
    pub method: String,
    /// The host the client asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The path, without the query.
    pub path: String,
    /// The OAuth client the token named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The AI provider the gateway saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// How well the sender was known.
    pub evidence: String,
    /// Claims the evidence did not back.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatches: Vec<String>,
    /// The MCP calls, with argument digests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<Call>,
    /// SHA-256 of the request body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    /// `forwarded`, `refused` or `answered`.
    pub decision: String,
    /// The refusal's error id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The response status.
    pub status: u16,
}

impl Receipt {
    /// The receipt fields of `entry`: all but what is known only after
    /// the answer is sent (bytes, result digest, time taken).
    #[must_use]
    pub fn from_entry(entry: &RequestEntry) -> Self {
        Self {
            request_id: entry.request_id.clone(),
            method: entry.method.clone(),
            host: entry.host.clone(),
            path: entry.path.clone(),
            client_id: entry.client_id.clone(),
            provider: entry.provider.clone(),
            evidence: entry.evidence.clone(),
            mismatches: entry.mismatches.clone(),
            calls: entry.calls.clone(),
            request_digest: entry.request_digest.clone(),
            decision: entry.decision.clone(),
            error: entry.error.clone(),
            status: entry.status,
            ..Self::default()
        }
    }
}

/// Why a receipt does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Not two base64url parts, or too long.
    Malformed,
    /// The signature does not verify under the key.
    Signature,
    /// The payload is not a receipt of a known version.
    Payload,
    /// Signed by a key other than the one given.
    Key,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "not a receipt",
            Self::Signature => "the signature does not verify",
            Self::Payload => "the payload is not a version 1 receipt",
            Self::Key => "signed by another key",
        })
    }
}

impl std::error::Error for Error {}

/// `body` signed by `key` (whose id is `key_id`), as a receipt. Sets the
/// version and key, and the time when it is 0.
///
/// # Errors
///
/// The payload could not be written or signed.
pub fn issue(key: &composite::SigningKey, key_id: &str, body: &Receipt) -> Result<String, String> {
    let mut body = body.clone();
    body.v = VERSION;
    key_id.clone_into(&mut body.key);
    if body.issued == 0 {
        body.issued = crate::now_ms();
    }
    let payload = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    let signature = key
        .sign(&[LABEL, &payload].concat())
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{}.{}",
        b64::encode(&payload),
        b64::encode(&signature)
    ))
}

/// The receipt in `text`, if `public` signed it.
///
/// # Errors
///
/// See [`Error`].
pub fn verify(public: &[u8], text: &str) -> Result<Receipt, Error> {
    let text = text.trim();
    if text.len() > MAX_LEN {
        return Err(Error::Malformed);
    }
    let (payload, signature) = text.split_once('.').ok_or(Error::Malformed)?;
    let payload = b64::decode(payload).ok_or(Error::Malformed)?;
    let signature = b64::decode(signature).ok_or(Error::Malformed)?;
    if !composite::verify(public, &[LABEL, &payload].concat(), &signature) {
        return Err(Error::Signature);
    }
    let receipt: Receipt = serde_json::from_slice(&payload).map_err(|_| Error::Payload)?;
    if receipt.v != VERSION {
        return Err(Error::Payload);
    }
    if receipt.key != crate::key_id(public) {
        return Err(Error::Key);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Receipt {
        Receipt {
            request_id: "01JC0000000000000000000000".into(),
            method: "POST".into(),
            path: "/mcp".into(),
            evidence: "cryptographic".into(),
            calls: vec![Call {
                method: "tools/call".into(),
                tool: Some("pay".into()),
                arguments: Some(crate::digest(b"{}")),
            }],
            decision: "forwarded".into(),
            status: 200,
            ..Receipt::default()
        }
    }

    #[test]
    fn a_receipt_verifies_offline_and_any_change_breaks_it() {
        let (key, _) = composite::SigningKey::generate().unwrap();
        let public = key.public_key();
        let text = issue(&key, &crate::key_id(&public), &sample()).unwrap();
        let got = verify(&public, &text).unwrap();
        assert_eq!(got.v, 1);
        assert_eq!(got.calls, sample().calls);
        assert!(got.issued > 0);

        let (payload, signature) = text.split_once('.').unwrap();
        let json = String::from_utf8(b64::decode(payload).unwrap()).unwrap();
        for (from, to) in [
            ("200", "201"),
            ("forwarded", "refused"),
            ("\"pay\"", "\"pax\""),
        ] {
            let changed = b64::encode(json.replacen(from, to, 1).as_bytes());
            assert_eq!(
                verify(&public, &format!("{changed}.{signature}")),
                Err(Error::Signature),
                "{from}"
            );
        }
    }

    #[test]
    fn other_keys_and_garbage_are_refused() {
        let (key, _) = composite::SigningKey::generate().unwrap();
        let (other, _) = composite::SigningKey::generate().unwrap();
        let text = issue(&key, &crate::key_id(&key.public_key()), &sample()).unwrap();
        assert_eq!(verify(&other.public_key(), &text), Err(Error::Signature));
        let lying = issue(&key, "0000000000000000", &sample()).unwrap();
        assert_eq!(verify(&key.public_key(), &lying), Err(Error::Key));
        assert_eq!(verify(&key.public_key(), "x"), Err(Error::Malformed));
        assert_eq!(verify(&key.public_key(), "!.!"), Err(Error::Malformed));
    }
}
