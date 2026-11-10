// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway's `[audit]` section (FR-15, FR-18; ADR 0008), and the
//! `audit` and `receipt` commands.
//!
//! ```toml
//! [audit]
//! path = "audit.jsonl"          # the log, created or continued
//! key = "audit.key"             # from `tunnelward audit keygen`
//! pseudonym_key = "audit.key.pseudonym"   # default: <key>.pseudonym
//! checkpoint_every = 1000       # a signed checkpoint after this many lines
//! checkpoint_secs = 60          # or after this long
//! raw_days = 0                  # days to keep raw client addresses beside
//!                               # the log, at most 30; 0 keeps none
//! receipts = false              # sign a tw-receipt on every answer
//! ```

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use tunnelward_audit::{PSEUDONYM_KEY_LEN, Settings, hex, unhex, verify};
use tunnelward_crypto::composite;

use crate::config::{Problems, resolve};

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Section {
    path: PathBuf,
    key: PathBuf,
    pseudonym_key: Option<PathBuf>,
    checkpoint_every: Option<u64>,
    checkpoint_secs: Option<u64>,
    raw_days: Option<u32>,
    #[serde(default)]
    receipts: bool,
}

/// `<key>` with `suffix` added.
fn beside(key: &Path, suffix: &str) -> PathBuf {
    let mut name = key.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn signing_key(path: &Path) -> Result<composite::SigningKey, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    composite::SigningKey::from_bytes(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn pseudonym_key(path: &Path) -> Result<[u8; PSEUDONYM_KEY_LEN], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    unhex(text.trim())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{}: not {PSEUDONYM_KEY_LEN} bytes in hex", path.display()))
}

/// Checks `section` and reads its keys; the log itself is opened only
/// when the gateway starts, so checking a file never writes one.
pub(crate) fn check(base: &Path, section: &Section, problems: &mut Problems) -> Option<Settings> {
    let raw_days = section.raw_days.unwrap_or(0);
    if raw_days > tunnelward_audit::MAX_RAW_DAYS {
        problems.push(format!(
            "[audit] raw_days: at most {}",
            tunnelward_audit::MAX_RAW_DAYS
        ));
    }
    let key_path = resolve(base, &section.key);
    let pseudonym_path = section
        .pseudonym_key
        .as_ref()
        .map_or_else(|| beside(&key_path, ".pseudonym"), |p| resolve(base, p));
    let key = signing_key(&key_path).map_err(|e| problems.push(format!("[audit] key: {e}")));
    let pseudonyms = pseudonym_key(&pseudonym_path)
        .map_err(|e| problems.push(format!("[audit] pseudonym_key: {e}")));
    let (Ok(key), Ok(pseudonyms)) = (key, pseudonyms) else {
        return None;
    };
    let mut settings = Settings::new(resolve(base, &section.path), key, pseudonyms);
    settings.checkpoint_every = section.checkpoint_every.unwrap_or(1000).max(1);
    settings.checkpoint_interval =
        std::time::Duration::from_secs(section.checkpoint_secs.unwrap_or(60).max(1));
    settings.raw_days = raw_days;
    settings.receipts = section.receipts;
    Some(settings)
}

/// Writes a new signing key to `out` (owner-only), its public key in hex
/// to `<out>.pub`, and a pseudonym key to `<out>.pseudonym` (owner-only),
/// never over existing files. Returns the two new paths beside `out`.
pub(crate) fn keygen(out: &Path) -> Result<(PathBuf, PathBuf), String> {
    let pseudonym = beside(out, ".pseudonym");
    if pseudonym.exists() {
        return Err(format!("{}: already exists", pseudonym.display()));
    }
    let public = crate::providers::keygen(out)?;
    let key = tunnelward_audit::Pseudonyms::generate_key()?;
    crate::providers::write_new(&pseudonym, format!("{}\n", hex(&key)).as_bytes(), true)?;
    Ok((public, pseudonym))
}

/// The composite public keys in the files `paths`, in hex.
fn public_keys(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>, String> {
    paths
        .iter()
        .map(|path| {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            unhex(text.trim())
                .filter(|k| k.len() == composite::PUBLIC_LEN)
                .ok_or_else(|| format!("{}: not a composite public key", path.display()))
        })
        .collect()
}

/// Checks the log at `log` against the public keys in `keys`; the
/// report, or why it fails.
pub(crate) fn verify_log(log: &Path, keys: &[PathBuf]) -> Result<String, String> {
    let keys = public_keys(keys)?;
    let file = std::fs::File::open(log).map_err(|e| format!("{}: {e}", log.display()))?;
    let report = verify::verify(BufReader::new(file), &keys)
        .map_err(|e| format!("{}: {e}", log.display()))?;
    let signed = report
        .signed_through
        .map_or_else(|| "nothing".to_owned(), |s| format!("seq {s}"));
    let summary = format!(
        "{}: {} lines, {} entries, {} checkpoints, {} dropped; signed through {signed}, {} unsigned after",
        log.display(),
        report.lines,
        report.entries,
        report.checkpoints,
        report.dropped,
        report.unsigned
    );
    match report.problem {
        None => Ok(summary),
        Some(p) => Err(format!("{summary}\nline {}: {}", p.line, p.what)),
    }
}

/// Writes each entry of the log at `log` as an OCSF event, one JSON
/// object per line, to standard output.
pub(crate) fn export(log: &Path) -> Result<(), String> {
    let file = std::fs::File::open(log).map_err(|e| format!("{}: {e}", log.display()))?;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| format!("{}: {e}", log.display()))?;
        if let Some(event) = tunnelward_audit::ocsf::event(&line) {
            println!("{event}");
        }
    }
    Ok(())
}

/// The receipt `arg` names: from standard input for `-`, from the file
/// it names, or `arg` itself.
fn receipt_text(arg: &str) -> Result<String, String> {
    if arg == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| e.to_string())?;
        Ok(text)
    } else if Path::new(arg).is_file() {
        std::fs::read_to_string(arg).map_err(|e| format!("{arg}: {e}"))
    } else {
        Ok(arg.to_owned())
    }
}

/// Checks a receipt (`text`, a file holding one, or `-` for standard
/// input) against the public key in `key`; the receipt's fields as JSON.
pub(crate) fn verify_receipt(key: &Path, receipt: &str) -> Result<String, String> {
    let public = public_keys(&[key.to_owned()])?.remove(0);
    let text = receipt_text(receipt)?;
    let got = tunnelward_audit::receipt::verify(&public, &text).map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&got).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tw-cli-audit-{name}-{}-{}",
            std::process::id(),
            tunnelward_audit::now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn keygen_then_check_then_verify() {
        let dir = dir("keys");
        let key = dir.join("audit.key");
        let (public, pseudonym) = keygen(&key).unwrap();
        assert!(public.exists() && pseudonym.exists());
        assert!(keygen(&key).is_err(), "never over existing files");
        let toml = "path = \"audit.jsonl\"\nkey = \"audit.key\"\nreceipts = true\n";
        let section: Section = toml::from_str(toml).unwrap();
        let mut problems = Problems::new();
        let settings = check(&dir, &section, &mut problems).unwrap();
        assert!(problems.is_empty(), "{problems:?}");
        assert!(!dir.join("audit.jsonl").exists(), "checking writes nothing");
        let sink = tunnelward_audit::Sink::open(settings).unwrap();
        sink.close();
        let report = verify_log(&dir.join("audit.jsonl"), &[public]).unwrap();
        assert!(report.contains("0 entries"), "{report}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bad_sections_are_listed() {
        let dir = dir("bad");
        let toml = "path = \"a\"\nkey = \"missing.key\"\nraw_days = 31\n";
        let section: Section = toml::from_str(toml).unwrap();
        let mut problems = Problems::new();
        assert!(check(&dir, &section, &mut problems).is_none());
        assert_eq!(problems.len(), 3, "{problems:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
