// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Approval records in the shared state (ADR 0004, ADR 0014), so any
//! gateway behind a load balancer can serve the page and honour an
//! approval. A record is written once and read back; one-time use goes
//! through the store's atomic first use.

use std::time::Duration;

use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{Claim, SharedState};

/// A call waiting for approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Request {
    pub(super) id: String,
    /// What an approval of it binds (ADR 0014).
    pub(super) digest: String,
    pub(super) tool: String,
    pub(super) arguments: serde_json::Value,
    /// The agent token's `sub` and client.
    pub(super) sub: Option<String>,
    pub(super) client_id: Option<String>,
    pub(super) path: String,
    pub(super) at_ms: u64,
}

/// A sign-in under way, by its `state`.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Login {
    pub(super) id: String,
    pub(super) verifier: String,
    pub(super) nonce: String,
}

/// A signed-in approver's form, by its token.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Form {
    pub(super) id: String,
    pub(super) approver: String,
}

/// Writes `value` under `key` for `ttl`.
pub(super) async fn put<T: Serialize>(
    state: &dyn SharedState,
    key: &str,
    value: &T,
    ttl: Duration,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    (state.complete(key, Bytes::from(bytes), ttl).await).map_err(|e| e.to_string())
}

/// The value under `key`, if there is one.
pub(super) async fn get<T: DeserializeOwned>(
    state: &dyn SharedState,
    key: &str,
    ttl: Duration,
) -> Result<Option<T>, String> {
    match state.claim(key, ttl).await.map_err(|e| e.to_string())? {
        Claim::Done(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
        Claim::First => {
            // Reading claimed the empty key; give it back.
            state.release(key).await.map_err(|e| e.to_string())?;
            Ok(None)
        }
        Claim::Pending => Ok(None),
    }
}

/// Whether this is the first use of `key`.
pub(super) async fn first(
    state: &dyn SharedState,
    key: &str,
    ttl: Duration,
) -> Result<bool, String> {
    state.first_use(key, ttl).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemory;

    #[tokio::test]
    async fn a_value_reads_back_and_a_missing_one_leaves_no_trace() {
        let state = InMemory::default();
        let ttl = Duration::from_secs(60);
        let login = Login {
            id: "a".into(),
            verifier: "v".into(),
            nonce: "n".into(),
        };
        put(&state, "approval-login:s", &login, ttl).await.unwrap();
        let back: Login = get(&state, "approval-login:s", ttl).await.unwrap().unwrap();
        assert_eq!((back.id, back.nonce), ("a".to_owned(), "n".to_owned()));
        assert!(
            get::<Login>(&state, "approval-login:x", ttl)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            first(&state, "approval-login:x", ttl).await.unwrap(),
            "read left nothing"
        );
        assert!(!first(&state, "approval-login:x", ttl).await.unwrap());
    }
}
