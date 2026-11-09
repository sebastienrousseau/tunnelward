// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The token store: a directory shared by `tunnelward enrol` and the
//! gateway. `tokens/` holds one file per unused token, named by the
//! SHA-256 of the token so the directory holds no secret; `enrolled/`
//! one file per enrolled identity. Redeeming renames the token's file
//! into `enrolled/`; the rename is atomic, so a token works once even
//! when two gateways share the directory.

use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use super::unix;
use crate::auth::b64;

/// What every token starts with, so one is recognisable in a log or a
/// secret scanner.
const TOKEN_PREFIX: &str = "twe1_";

fn hex_sha256(text: &str) -> String {
    use std::fmt::Write as _;
    digest(&SHA256, text.as_bytes())
        .as_ref()
        .iter()
        .fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// One token or enrolment on disk.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    spiffe_id: String,
    expires: u64,
}

/// Why a token was not redeemed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenError {
    /// Never issued, already used, or not a token.
    Unknown,
    /// Issued, but its time ran out; it is gone now.
    Expired,
    /// The directory could not be read or written.
    Store,
}

/// The token store: a directory shared by the CLI and the gateway.
#[derive(Debug, Clone)]
pub struct Tokens {
    dir: PathBuf,
}

impl Tokens {
    /// The store in `dir`; its `tokens/` and `enrolled/` directories are
    /// made when first needed.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn token_file(&self, token: &str) -> PathBuf {
        self.dir.join("tokens").join(hex_sha256(token))
    }

    fn enrolled_file(&self, spiffe_id: &str) -> PathBuf {
        self.dir.join("enrolled").join(hex_sha256(spiffe_id))
    }

    /// A new one-time token that enrols `spiffe_id`, valid for `ttl`
    /// from `now`. Only its hash is stored; the token itself is returned
    /// once, for the operator to hand to the connector.
    ///
    /// # Errors
    ///
    /// `spiffe_id` is not a SPIFFE ID, there is no randomness, or the
    /// store cannot be written.
    pub fn issue(
        &self,
        spiffe_id: &str,
        ttl: Duration,
        now: SystemTime,
    ) -> std::io::Result<String> {
        if !tunnelward_proto::is_spiffe_id(spiffe_id) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("{spiffe_id:?} is not a SPIFFE ID"),
            ));
        }
        let mut secret = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| std::io::Error::other("no randomness for the token"))?;
        let token = format!("{TOKEN_PREFIX}{}", b64::encode(&secret));
        let record = Record {
            spiffe_id: spiffe_id.to_owned(),
            expires: unix(now) + ttl.as_secs(),
        };
        write_new(&self.token_file(&token), &record)?;
        Ok(token)
    }

    /// The SPIFFE ID `token` enrols, using the token up.
    pub(crate) fn redeem(&self, token: &str, now: SystemTime) -> Result<String, TokenError> {
        if !token.starts_with(TOKEN_PREFIX) || token.len() > 128 {
            return Err(TokenError::Unknown);
        }
        let path = self.token_file(token);
        let record = read_record(&path)?;
        if record.expires <= unix(now) {
            let _gone = std::fs::remove_file(&path);
            return Err(TokenError::Expired);
        }
        let enrolled = self.enrolled_file(&record.spiffe_id);
        ensure_parent(&enrolled).map_err(|_| TokenError::Store)?;
        // Atomic: of two requests with one token, one finds it gone.
        std::fs::rename(&path, &enrolled).map_err(|e| store_error(&e))?;
        Ok(record.spiffe_id)
    }

    /// Whether `spiffe_id` enrolled and was not revoked since.
    #[must_use]
    pub fn is_enrolled(&self, spiffe_id: &str) -> bool {
        self.enrolled_file(spiffe_id).is_file()
    }

    /// Stops `spiffe_id`'s renewals; `false` when it was not enrolled.
    ///
    /// # Errors
    ///
    /// The store cannot be written.
    pub fn revoke(&self, spiffe_id: &str) -> std::io::Result<bool> {
        match std::fs::remove_file(self.enrolled_file(spiffe_id)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// A missing file is an unknown token; anything else, a store failure.
fn store_error(e: &std::io::Error) -> TokenError {
    if e.kind() == ErrorKind::NotFound {
        TokenError::Unknown
    } else {
        TokenError::Store
    }
}

fn read_record(path: &std::path::Path) -> Result<Record, TokenError> {
    let bytes = std::fs::read(path).map_err(|e| store_error(&e))?;
    serde_json::from_slice(&bytes).map_err(|_| TokenError::Store)
}

fn ensure_parent(path: &std::path::Path) -> std::io::Result<()> {
    match path.parent() {
        Some(dir) => std::fs::create_dir_all(dir),
        None => Ok(()),
    }
}

/// Writes `record` to `path` whole or not at all: a temporary file, then
/// a rename.
fn write_new(path: &std::path::Path, record: &Record) -> std::io::Result<()> {
    ensure_parent(path)?;
    let json = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    let temporary = path.with_extension("new");
    std::fs::write(&temporary, json)?;
    std::fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "spiffe://example.org/connector";

    fn store(name: &str) -> Tokens {
        let dir = std::env::temp_dir().join(format!("tw-tokens-{name}-{}", std::process::id()));
        let _fresh = std::fs::remove_dir_all(&dir);
        Tokens::new(dir)
    }

    #[test]
    fn a_token_works_once_and_enrols_its_identity() -> std::io::Result<()> {
        let tokens = store("once");
        let now = SystemTime::now();
        let token = tokens.issue(ID, Duration::from_secs(60), now)?;
        assert!(!tokens.is_enrolled(ID));
        assert_eq!(tokens.redeem(&token, now), Ok(ID.to_owned()));
        assert!(tokens.is_enrolled(ID));
        assert_eq!(tokens.redeem(&token, now), Err(TokenError::Unknown));
        assert!(tokens.revoke(ID)?);
        assert!(!tokens.is_enrolled(ID));
        assert!(!tokens.revoke(ID)?);
        Ok(())
    }

    #[test]
    fn an_expired_token_is_refused_and_removed() -> std::io::Result<()> {
        let tokens = store("expired");
        let now = SystemTime::now();
        let token = tokens.issue(ID, Duration::from_secs(60), now)?;
        let later = now + Duration::from_secs(61);
        assert_eq!(tokens.redeem(&token, later), Err(TokenError::Expired));
        assert_eq!(tokens.redeem(&token, now), Err(TokenError::Unknown));
        assert!(!tokens.is_enrolled(ID));
        Ok(())
    }

    #[test]
    fn the_store_holds_no_token() -> std::io::Result<()> {
        let tokens = store("hashed");
        let token = tokens.issue(ID, Duration::from_secs(60), SystemTime::now())?;
        for entry in std::fs::read_dir(tokens.dir.join("tokens"))? {
            let entry = entry?;
            let text = std::fs::read_to_string(entry.path())?;
            let secret = &token[TOKEN_PREFIX.len()..];
            assert!(!text.contains(secret));
            assert!(!entry.file_name().to_string_lossy().contains(secret));
        }
        Ok(())
    }

    #[test]
    fn only_spiffe_ids_get_tokens_and_only_tokens_are_looked_up() {
        let tokens = store("shape");
        assert!(
            tokens
                .issue("https://x", Duration::from_secs(1), SystemTime::now())
                .is_err()
        );
        assert_eq!(
            tokens.redeem("not-a-token", SystemTime::now()),
            Err(TokenError::Unknown)
        );
    }
}
