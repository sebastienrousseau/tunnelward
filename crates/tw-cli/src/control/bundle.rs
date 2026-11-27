// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! A policy bundle and its signed envelope (ADR 0012). The signature
//! covers the payload bytes exactly as sent, so nothing is canonicalised.

use serde::{Deserialize, Serialize};
use tunnelward_audit::{b64, key_id};
use tunnelward_crypto::composite::{self, SigningKey};

/// Longest envelope a gateway reads.
pub(crate) const MAX_ENVELOPE: usize = 1024 * 1024;

/// What a gateway applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bundle {
    /// Goes up by one with every publish, rollbacks included.
    pub(crate) version: u64,
    /// Milliseconds since 1970.
    pub(crate) issued_ms: u64,
    /// The operator token's subject.
    pub(crate) publisher: String,
    /// The policy file's TOML, as published.
    pub(crate) policy: String,
}

/// A bundle as stored and served.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    key: String,
    sig: String,
}

/// `bundle` signed with `key`, as the JSON text of its envelope.
pub(crate) fn seal(bundle: &Bundle, key: &SigningKey) -> Result<String, String> {
    let payload = serde_json::to_vec(bundle).map_err(|e| e.to_string())?;
    let sig = key.sign(&payload).map_err(|e| e.to_string())?;
    let envelope = Envelope {
        payload: b64::encode(&payload),
        key: key_id(&key.public_key()),
        sig: b64::encode(&sig),
    };
    serde_json::to_string(&envelope).map_err(|e| e.to_string())
}

/// The bundle in `envelope`, if its signature verifies under `public`.
pub(crate) fn open(envelope: &[u8], public: &[u8]) -> Result<Bundle, String> {
    let envelope: Envelope =
        serde_json::from_slice(envelope).map_err(|e| format!("not an envelope: {e}"))?;
    let payload = b64::decode(&envelope.payload).ok_or("the payload does not decode")?;
    let sig = b64::decode(&envelope.sig).ok_or("the signature does not decode")?;
    if !composite::verify(public, &payload, &sig) {
        return Err("the signature does not verify under the control's key".into());
    }
    serde_json::from_slice(&payload).map_err(|e| format!("not a bundle: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> Bundle {
        Bundle {
            version: 3,
            issued_ms: 1,
            publisher: "ops-7".into(),
            policy: "default = \"deny\"\n".into(),
        }
    }

    #[test]
    fn a_sealed_bundle_opens_only_under_its_key() {
        let key = SigningKey::generate().unwrap().0;
        let public = key.public_key();
        let other = SigningKey::generate().unwrap().0.public_key();
        let text = seal(&bundle(), &key).unwrap();
        assert_eq!(open(text.as_bytes(), &public).unwrap(), bundle());
        assert!(open(text.as_bytes(), &other).is_err());
    }

    #[test]
    fn a_changed_payload_or_signature_does_not_open() {
        let key = SigningKey::generate().unwrap().0;
        let public = key.public_key();
        let text = seal(&bundle(), &key).unwrap();
        let mut envelope: Envelope = serde_json::from_str(&text).unwrap();
        let mut forged = bundle();
        forged.policy = "default = \"allow\"\n".into();
        envelope.payload = b64::encode(&serde_json::to_vec(&forged).unwrap());
        let tampered = serde_json::to_vec(&envelope).unwrap();
        assert!(
            open(&tampered, &public)
                .unwrap_err()
                .contains("does not verify")
        );
        assert!(open(b"{}", &public).is_err());
    }
}
