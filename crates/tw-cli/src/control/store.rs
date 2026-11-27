// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The control's bundles: `<dir>/bundles/<version>.json`, one signed
//! envelope each, never rewritten (ADR 0012). Each is opened under the
//! control's own key when the store loads, so a file changed on disk
//! stops the control rather than reaching a gateway.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;
use tunnelward_crypto::composite::SigningKey;

use super::bundle::{self, Bundle};

/// What the API lists about a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Summary {
    pub(crate) version: u64,
    pub(crate) issued_ms: u64,
    pub(crate) publisher: String,
    /// SHA-256 of the policy, in hex.
    pub(crate) policy_digest: String,
}

impl Summary {
    fn of(bundle: &Bundle) -> Self {
        Self {
            version: bundle.version,
            issued_ms: bundle.issued_ms,
            publisher: bundle.publisher.clone(),
            policy_digest: tunnelward_audit::digest(bundle.policy.as_bytes()),
        }
    }
}

/// Every bundle's summary, oldest first, and the newest envelope.
#[derive(Default)]
struct State {
    history: Vec<Summary>,
    latest: Option<Arc<str>>,
}

pub(crate) struct Store {
    dir: PathBuf,
    key: SigningKey,
    public: Vec<u8>,
    state: Mutex<State>,
}

impl Store {
    /// The store in `dir`, signing with `key`; every bundle already there
    /// must open under it.
    pub(crate) fn open(dir: &Path, key: SigningKey) -> Result<Self, String> {
        let dir = dir.join("bundles");
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let public = key.public_key();
        let mut found = read_all(&dir, &public)?;
        found.sort_by_key(|(b, _)| b.version);
        let state = State {
            history: found.iter().map(|(b, _)| Summary::of(b)).collect(),
            latest: found.pop().map(|(_, text)| Arc::from(text)),
        };
        Ok(Self {
            dir,
            key,
            public,
            state: Mutex::new(state),
        })
    }

    /// The newest envelope, and its version.
    pub(crate) fn latest(&self) -> Option<(u64, Arc<str>)> {
        let state = self.lock();
        let version = state.history.last()?.version;
        state.latest.clone().map(|text| (version, text))
    }

    /// Every bundle's summary, oldest first.
    pub(crate) fn history(&self) -> Vec<Summary> {
        self.lock().history.clone()
    }

    /// Publishes `policy` as the next version.
    pub(crate) fn publish(&self, policy: String, publisher: &str) -> Result<Summary, String> {
        let mut state = self.lock();
        let version = state.history.last().map_or(1, |s| s.version + 1);
        let bundle = Bundle {
            version,
            issued_ms: tunnelward_audit::now_ms(),
            publisher: publisher.to_owned(),
            policy,
        };
        let text = bundle::seal(&bundle, &self.key)?;
        let path = self.dir.join(format!("{version}.json"));
        crate::providers::write_new(&path, text.as_bytes(), false)?;
        let summary = Summary::of(&bundle);
        state.history.push(summary.clone());
        state.latest = Some(Arc::from(text));
        Ok(summary)
    }

    /// The policy of `version`, read back and checked.
    pub(crate) fn policy(&self, version: u64) -> Result<String, String> {
        let path = self.dir.join(format!("{version}.json"));
        if !path.is_file() {
            return Err(format!("no bundle {version}"));
        }
        read(&path, &self.public).map(|(b, _)| b.policy)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Every bundle in `dir`, each opened under `public`, in no order.
fn read_all(dir: &Path, public: &[u8]) -> Result<Vec<(Bundle, String)>, String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|e| e == "json") {
            found.push(read(&path, public)?);
        }
    }
    Ok(found)
}

/// The bundle in `path`, opened under `public`, and the file's text.
fn read(path: &Path, public: &[u8]) -> Result<(Bundle, String), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bundle =
        bundle::open(text.as_bytes(), public).map_err(|e| format!("{}: {e}", path.display()))?;
    let named = path.file_stem().and_then(|s| s.to_str());
    if named != Some(bundle.version.to_string().as_str()) {
        return Err(format!(
            "{}: holds version {}",
            path.display(),
            bundle.version
        ));
    }
    Ok((bundle, text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tw-control-store-{name}-{}-{}",
            std::process::id(),
            tunnelward_audit::now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn key_bytes() -> Vec<u8> {
        SigningKey::generate().unwrap().1
    }

    #[test]
    fn versions_go_up_and_survive_a_restart() {
        let dir = dir("restart");
        let bytes = key_bytes();
        let store = Store::open(&dir, SigningKey::from_bytes(&bytes).unwrap()).unwrap();
        assert!(store.latest().is_none());
        store
            .publish("default = \"deny\"\n".into(), "ops-1")
            .unwrap();
        let second = store
            .publish("default = \"allow\"\n".into(), "ops-2")
            .unwrap();
        assert_eq!(second.version, 2);
        let again = Store::open(&dir, SigningKey::from_bytes(&bytes).unwrap()).unwrap();
        assert_eq!(again.history(), store.history());
        assert_eq!(again.latest().unwrap().0, 2);
        assert_eq!(again.policy(1).unwrap(), "default = \"deny\"\n");
        assert!(again.policy(9).is_err());
    }

    #[test]
    fn a_bundle_changed_on_disk_or_signed_by_another_key_stops_the_store() {
        let dir = dir("tamper");
        let store = Store::open(&dir, SigningKey::generate().unwrap().0).unwrap();
        store
            .publish("default = \"deny\"\n".into(), "ops-1")
            .unwrap();
        let err = Store::open(&dir, SigningKey::generate().unwrap().0)
            .err()
            .unwrap();
        assert!(err.contains("does not verify"), "{err}");
        let bytes = key_bytes();
        let fresh = self::dir("renamed");
        let store = Store::open(&fresh, SigningKey::from_bytes(&bytes).unwrap()).unwrap();
        store
            .publish("default = \"deny\"\n".into(), "ops-1")
            .unwrap();
        std::fs::copy(fresh.join("bundles/1.json"), fresh.join("bundles/2.json")).unwrap();
        let err = Store::open(&fresh, SigningKey::from_bytes(&bytes).unwrap())
            .err()
            .unwrap();
        assert!(err.contains("holds version 1"), "{err}");
    }
}
