// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! An issuer's verification keys: a fixed JWK Set, or one fetched from
//! its `jwks_uri` over HTTPS and kept fresh.

use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use http::Uri;
use tokio::sync::Notify;
use tunnelward_crypto::rustls::RootCertStore;

use super::jwk::{Alg, Key, parse_set};

/// Largest JWK Set read, in bytes.
const MAX_JWKS: usize = 64 * 1024;
/// Least time between fetches asked for by an unknown key id.
const MIN_REFETCH: Duration = Duration::from_secs(30);

/// Why keys could not be set up or fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The `jwks_uri` is not an `https://` URL with a host.
    Url(String),
    /// The fetch failed: connection, TLS, status, size or timeout.
    Fetch(String),
    /// The document is not a JWK Set.
    NotAJwkSet,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(why) => write!(f, "jwks_uri: {why}"),
            Self::Fetch(why) => write!(f, "fetching the JWK Set: {why}"),
            Self::NotAJwkSet => f.write_str("the document is not a JWK Set"),
        }
    }
}

impl std::error::Error for KeyError {}

enum Source {
    Fixed,
    Url { uri: Uri, roots: Arc<RootCertStore> },
}

/// One issuer's verification keys. Cheap to read on every request; a
/// fetched set is replaced whole on each refresh.
pub struct KeySet {
    keys: RwLock<Vec<Key>>,
    source: Source,
    /// Asked for when a token names a key id the set lacks.
    wanted: Notify,
    last_fetch: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySet")
            .field("keys", &self.len())
            .finish_non_exhaustive()
    }
}

impl KeySet {
    /// The keys in the JWK Set `json`, never refreshed.
    ///
    /// # Errors
    ///
    /// [`KeyError::NotAJwkSet`].
    pub fn from_jwks(json: &[u8]) -> Result<Self, KeyError> {
        let keys = parse_set(json).ok_or(KeyError::NotAJwkSet)?;
        Ok(Self::with(keys, Source::Fixed))
    }

    /// An empty set that [`KeySet::refresh`] fills from `url`, trusting
    /// `roots` for its TLS certificate.
    ///
    /// # Errors
    ///
    /// [`KeyError::Url`] unless `url` is `https://` with a host.
    pub fn from_url(url: &str, roots: Arc<RootCertStore>) -> Result<Self, KeyError> {
        let uri: Uri = url.parse().map_err(|e| KeyError::Url(format!("{e}")))?;
        if uri.scheme_str() != Some("https") || uri.host().is_none() {
            return Err(KeyError::Url(format!("{url:?} is not an https:// URL")));
        }
        Ok(Self::with(Vec::new(), Source::Url { uri, roots }))
    }

    fn with(keys: Vec<Key>, source: Source) -> Self {
        Self {
            keys: RwLock::new(keys),
            source,
            wanted: Notify::new(),
            last_fetch: Mutex::new(None),
        }
    }

    /// How many keys the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether the set holds no key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fetches the set again (a fixed set is left as it is) and returns
    /// how many keys it now holds. On failure the old keys stay.
    ///
    /// # Errors
    ///
    /// [`KeyError::Fetch`] or [`KeyError::NotAJwkSet`].
    pub async fn refresh(&self) -> Result<usize, KeyError> {
        let Source::Url { uri, roots } = &self.source else {
            return Ok(self.len());
        };
        *self
            .last_fetch
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        let body = crate::https_get(&uri.to_string(), roots.clone(), MAX_JWKS)
            .await
            .map_err(KeyError::Fetch)?;
        let keys = parse_set(&body).ok_or(KeyError::NotAJwkSet)?;
        let count = keys.len();
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = keys;
        Ok(count)
    }

    /// Refreshes now, then every `every`, and sooner (at most every 30 s)
    /// when a token names a key id the set lacks. Runs until dropped;
    /// failures keep the old keys and are retried at the next turn.
    pub async fn keep_fresh(&self, every: Duration) {
        loop {
            let _kept_old_keys_on_failure = self.refresh().await;
            let _woken = tokio::time::timeout(every, self.wanted.notified()).await;
            tokio::time::sleep(self.until_refetch()).await;
        }
    }

    fn until_refetch(&self) -> Duration {
        let last = *self
            .last_fetch
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        last.map_or(Duration::ZERO, |at| {
            MIN_REFETCH.saturating_sub(at.elapsed())
        })
    }

    /// The Ed25519 key whose thumbprint is `thumbprint`. A miss asks
    /// [`KeySet::keep_fresh`] to refetch.
    pub(crate) fn ed25519(&self, thumbprint: &str) -> Option<Key> {
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        let found = keys
            .iter()
            .find(|k| k.ed25519_thumbprint().as_deref() == Some(thumbprint))
            .cloned();
        if found.is_none() {
            self.wanted.notify_one();
        }
        found
    }

    /// The keys that may verify a token signed with `alg` and naming
    /// `kid`. An unknown `kid` asks [`KeySet::keep_fresh`] to refetch.
    pub(crate) fn candidates(&self, alg: Alg, name: &str, kid: Option<&str>) -> Vec<Key> {
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        let found: Vec<Key> = keys
            .iter()
            .filter(|k| k.fits(alg, name) && (kid.is_none() || k.kid.as_deref() == kid))
            .cloned()
            .collect();
        if found.is_empty() && kid.is_some() {
            self.wanted.notify_one();
        }
        found
    }
}
