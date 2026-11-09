// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The keys that sign provider snapshots: `tunnelward providers keygen`
//! makes a composite ML-DSA-65 + Ed25519 one, and `sign` uses it, or an
//! Ed25519 key made before 0.0.12.

use std::path::{Path, PathBuf};

use aws_lc_rs::signature::Ed25519KeyPair;
use tunnelward_crypto::composite;

use super::{hex, signature_path};

/// Writes `bytes` to a new file `path`, never over an existing one;
/// owner-only when `private`.
fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    std::io::Write::write_all(&mut file, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// Writes a new composite ML-DSA-65 + Ed25519 key to `out` (owner-only)
/// and its public key, in hex, to `<out>.pub`, never over existing
/// files; returns the public key file's path.
pub(crate) fn keygen(out: &Path) -> Result<PathBuf, String> {
    let (key, encoded) = composite::SigningKey::generate().map_err(|e| e.to_string())?;
    let public = public_path(out);
    if public.exists() {
        return Err(format!("{}: already exists", public.display()));
    }
    write_new(out, &encoded, true)?;
    write_new(
        &public,
        format!("{}\n", hex(&key.public_key())).as_bytes(),
        false,
    )?;
    Ok(public)
}

/// Where a key's public half goes: beside it, with `.pub` added.
pub(crate) fn public_path(key: &Path) -> PathBuf {
    let mut name = key.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// Signs `snapshot` with the key in `key`, composite or (made before
/// 0.0.12) Ed25519; writes `<snapshot>.sig` and returns its path.
pub(crate) fn sign(key: &Path, snapshot: &Path) -> Result<PathBuf, String> {
    let bytes = std::fs::read(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let message = std::fs::read(snapshot).map_err(|e| format!("{}: {e}", snapshot.display()))?;
    let signature = signature(&bytes, &message).map_err(|e| format!("{}: {e}", key.display()))?;
    let out = signature_path(snapshot);
    std::fs::write(&out, signature).map_err(|e| format!("{}: {e}", out.display()))?;
    Ok(out)
}

/// `message` signed with the key encoded in `key`.
fn signature(key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok(composite) = composite::SigningKey::from_bytes(key) {
        return composite.sign(message).map_err(|e| e.to_string());
    }
    let ed25519 = Ed25519KeyPair::from_pkcs8(key).map_err(|_| "not a signing key".to_owned())?;
    Ok(ed25519.sign(message).as_ref().to_vec())
}
