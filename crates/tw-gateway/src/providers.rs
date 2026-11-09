// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Provider identification at the network level (FR-12): which AI
//! provider's published egress ranges a client address is in.
//!
//! The ranges come in a snapshot, JSON with a version, signed with
//! Ed25519 by a key the gateway trusts. A snapshot is accepted whole or
//! not at all, and never replaces a newer one, so an attacker who can
//! serve files cannot widen the ranges or roll them back.
//!
//! ```json
//! {"version": 3, "created": "2026-11-08T00:00:00Z", "providers": [
//!   {"provider": "anthropic", "agent": "outbound",
//!    "source": "https://platform.claude.com/docs/en/api/ip-addresses",
//!    "ranges": ["160.79.104.0/21", "153.61.208.0/20"]}]}
//! ```
//!
//! A tag says where a request came from, not who is calling: an address
//! in a provider's range is evidence at the `network` level only.

use std::net::IpAddr;
use std::sync::{Arc, PoisonError, RwLock};

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use serde::Deserialize;

use crate::Cidr;

/// The provider a request's address belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTag {
    /// The provider, for example `anthropic`.
    pub provider: String,
    /// Which of its published ranges, for example `outbound` or
    /// `chatgpt-user`.
    pub agent: String,
    /// How strong the evidence is: `network` for an address match.
    pub level: &'static str,
    /// The snapshot version that matched; `None` for a signature.
    pub snapshot: Option<u64>,
}

impl ProviderTag {
    /// The tag a verified Web Bot Auth signature from `signer` earns.
    #[must_use]
    pub fn signed(signer: &crate::Signer) -> Self {
        Self {
            provider: signer.provider.clone(),
            agent: signer.agent.clone(),
            level: "signature",
            snapshot: None,
        }
    }
}

/// Why a snapshot was not loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// No trusted key signed exactly these bytes.
    Signature,
    /// The snapshot is older than the one loaded.
    Rollback {
        /// The version loaded now.
        loaded: u64,
        /// The version offered.
        offered: u64,
    },
    /// Signed, but not a snapshot this gateway reads.
    Format(String),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signature => f.write_str("no trusted key signed the provider snapshot"),
            Self::Rollback { loaded, offered } => {
                write!(
                    f,
                    "provider snapshot {offered} is older than the loaded {loaded}"
                )
            }
            Self::Format(why) => write!(f, "provider snapshot: {why}"),
        }
    }
}

impl std::error::Error for ProviderError {}

#[derive(Deserialize)]
struct SnapshotFile {
    version: u64,
    providers: Vec<EntryFile>,
}

#[derive(Deserialize)]
struct EntryFile {
    provider: String,
    agent: String,
    ranges: Vec<String>,
}

struct Entry {
    provider: String,
    agent: String,
    ranges: Vec<Cidr>,
}

struct Snapshot {
    version: u64,
    entries: Vec<Entry>,
}

/// The loaded snapshot and the keys a new one must be signed with.
pub struct Providers {
    keys: Vec<Vec<u8>>,
    current: RwLock<Option<Arc<Snapshot>>>,
}

impl std::fmt::Debug for Providers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Providers")
            .field("keys", &self.keys.len())
            .field("version", &self.version())
            .finish_non_exhaustive()
    }
}

impl Providers {
    /// Nothing loaded yet; snapshots must be signed by one of `keys`
    /// (raw 32-byte Ed25519 public keys).
    #[must_use]
    pub fn new(keys: Vec<Vec<u8>>) -> Self {
        Self {
            keys,
            current: RwLock::new(None),
        }
    }

    /// The loaded snapshot's version.
    #[must_use]
    pub fn version(&self) -> Option<u64> {
        self.snapshot().map(|s| s.version)
    }

    fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Loads `snapshot` if `signature` (64 raw bytes) is a trusted key's
    /// Ed25519 signature over exactly those bytes, it parses, and it is
    /// not older than the loaded one. Returns its version.
    ///
    /// # Errors
    ///
    /// [`ProviderError`]; the loaded snapshot stays.
    pub fn load(&self, snapshot: &[u8], signature: &[u8]) -> Result<u64, ProviderError> {
        let signed = self.keys.iter().any(|k| {
            UnparsedPublicKey::new(&ED25519, k)
                .verify(snapshot, signature)
                .is_ok()
        });
        if !signed {
            return Err(ProviderError::Signature);
        }
        let next = parse(snapshot)?;
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(loaded) = current.as_ref().map(|s| s.version)
            && next.version < loaded
        {
            return Err(ProviderError::Rollback {
                loaded,
                offered: next.version,
            });
        }
        let version = next.version;
        *current = Some(Arc::new(next));
        Ok(version)
    }

    /// The provider whose ranges hold `ip`, if any; the first listed wins.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<ProviderTag> {
        let snapshot = self.snapshot()?;
        let entry = snapshot
            .entries
            .iter()
            .find(|e| e.ranges.iter().any(|r| r.contains(ip)))?;
        Some(ProviderTag {
            provider: entry.provider.clone(),
            agent: entry.agent.clone(),
            level: "network",
            snapshot: Some(snapshot.version),
        })
    }
}

fn parse(bytes: &[u8]) -> Result<Snapshot, ProviderError> {
    let file: SnapshotFile =
        serde_json::from_slice(bytes).map_err(|e| ProviderError::Format(e.to_string()))?;
    let entries = file
        .providers
        .into_iter()
        .map(entry)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Snapshot {
        version: file.version,
        entries,
    })
}

fn entry(file: EntryFile) -> Result<Entry, ProviderError> {
    let ranges = file
        .ranges
        .iter()
        .map(|r| {
            r.parse::<Cidr>()
                .map_err(|e| ProviderError::Format(format!("{}: {e}", file.provider)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Entry {
        provider: file.provider,
        agent: file.agent,
        ranges,
    })
}
