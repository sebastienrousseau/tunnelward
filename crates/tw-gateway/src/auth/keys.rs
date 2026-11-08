// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! An issuer's verification keys: a fixed JWK Set, or one fetched from
//! its `jwks_uri` over HTTPS and kept fresh.

use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Uri;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::TlsConnector;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{KeyExchange, client_config};

use super::jwk::{Alg, Key, parse_set};

/// Largest JWK Set read, in bytes.
const MAX_JWKS: usize = 64 * 1024;
/// Longest a fetch may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
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
        let body = tokio::time::timeout(FETCH_TIMEOUT, fetch(uri, roots.clone()))
            .await
            .map_err(|_| KeyError::Fetch("timed out".into()))??;
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

fn fail(what: &str, e: &dyn std::fmt::Display) -> KeyError {
    KeyError::Fetch(format!("{what}: {e}"))
}

/// GETs `uri` over HTTPS (HTTP/1.1, TLS 1.3) and returns the body.
async fn fetch(uri: &Uri, roots: Arc<RootCertStore>) -> Result<Vec<u8>, KeyError> {
    let mut sender = connect(uri, roots).await?;
    let host = uri.host().unwrap_or_default();
    let authority = uri.authority().map_or(host, http::uri::Authority::as_str);
    let request = Request::get(uri.path_and_query().map_or("/", |p| p.as_str()))
        .header(http::header::HOST, authority)
        .header(http::header::ACCEPT, "application/json")
        .body(Full::new(Bytes::new()))
        .map_err(|e| fail("request", &e))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| fail("HTTP", &e))?;
    if response.status() != http::StatusCode::OK {
        return Err(KeyError::Fetch(format!("status {}", response.status())));
    }
    let body = Limited::new(response.into_body(), MAX_JWKS)
        .collect()
        .await
        .map_err(|e| fail("body", &*e))?;
    Ok(body.to_bytes().to_vec())
}

/// An HTTP/1.1 connection to `uri`'s host over TLS 1.3, trusting `roots`.
async fn connect(
    uri: &Uri,
    roots: Arc<RootCertStore>,
) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>, KeyError> {
    let stream = tls(uri, roots).await?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| fail("HTTP", &e))?;
    tokio::spawn(conn);
    Ok(sender)
}

/// A TLS 1.3 stream to `uri`'s host and port, trusting `roots`.
async fn tls(
    uri: &Uri,
    roots: Arc<RootCertStore>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, KeyError> {
    let host = uri.host().unwrap_or_default().trim_matches(['[', ']']);
    let config = client_config(roots, None, KeyExchange::default(), &[b"http/1.1"])
        .map_err(|e| fail("TLS", &e))?;
    let name = ServerName::try_from(host.to_owned()).map_err(|e| fail("host", &e))?;
    let tcp = TcpStream::connect((host, uri.port_u16().unwrap_or(443)))
        .await
        .map_err(|e| fail("connect", &e))?;
    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| fail("TLS", &e))
}
