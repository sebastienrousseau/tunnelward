// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward providers`: make and sign the provider snapshot a gateway
//! tags requests with (FR-12).
//!
//! ```text
//! tunnelward providers keygen --out signing.key   # prints the public key (hex)
//! tunnelward providers build --out providers.json [--version N]
//! tunnelward providers sign --key signing.key providers.json   # writes providers.json.sig
//! ```
//!
//! `build` fetches each provider's own published list, nothing else:
//! Anthropic's outbound ranges from its IP addresses page, and the JSON
//! range files `OpenAI` publishes. A source that yields no range fails
//! the build.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use serde::Deserialize;
use tunnelward_gateway::Cidr;

/// How a source lists its ranges.
#[derive(Debug, Clone, Copy)]
enum Format {
    /// Anthropic's documentation page (Markdown): the CIDRs in backticks
    /// under "Outbound IP addresses", before "Phased out".
    AnthropicPage,
    /// `{"prefixes": [{"ipv4Prefix": ...} | {"ipv6Prefix": ...}]}`.
    Prefixes,
}

/// Every source: provider, agent, URL, format.
const SOURCES: &[(&str, &str, &str, Format)] = &[
    (
        "anthropic",
        "outbound",
        "https://platform.claude.com/docs/en/api/ip-addresses.md",
        Format::AnthropicPage,
    ),
    (
        "openai",
        "chatgpt-user",
        "https://openai.com/chatgpt-user.json",
        Format::Prefixes,
    ),
    (
        "openai",
        "chatgpt-actions",
        "https://openai.com/chatgpt-actions.json",
        Format::Prefixes,
    ),
    (
        "openai",
        "searchbot",
        "https://openai.com/searchbot.json",
        Format::Prefixes,
    ),
    (
        "openai",
        "gptbot",
        "https://openai.com/gptbot.json",
        Format::Prefixes,
    ),
];

/// Largest source document read.
const MAX_SOURCE: usize = 1024 * 1024;

/// The outbound CIDRs on Anthropic's IP addresses page.
pub(crate) fn anthropic_outbound(page: &str) -> Vec<String> {
    let Some((_, after)) = page.split_once("## Outbound IP addresses") else {
        return Vec::new();
    };
    let section = after
        .split("### Phased out")
        .next()
        .unwrap_or_default()
        .split("\n## ")
        .next()
        .unwrap_or_default();
    section
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|t| t.parse::<Cidr>().is_ok())
        .map(str::to_owned)
        .collect()
}

#[derive(Deserialize)]
struct PrefixList {
    prefixes: Vec<Prefix>,
}

#[derive(Deserialize)]
struct Prefix {
    #[serde(rename = "ipv4Prefix")]
    v4: Option<String>,
    #[serde(rename = "ipv6Prefix")]
    v6: Option<String>,
}

/// The CIDRs in a `prefixes` JSON list; `None` if it is not one or a
/// prefix does not parse.
pub(crate) fn prefixes(json: &[u8]) -> Option<Vec<String>> {
    let list: PrefixList = serde_json::from_slice(json).ok()?;
    list.prefixes
        .into_iter()
        .map(|p| p.v4.or(p.v6).filter(|c| c.parse::<Cidr>().is_ok()))
        .collect()
}

fn ranges(format: Format, body: &[u8]) -> Option<Vec<String>> {
    let found = match format {
        Format::AnthropicPage => Some(anthropic_outbound(&String::from_utf8_lossy(body))),
        Format::Prefixes => prefixes(body),
    }?;
    (!found.is_empty()).then_some(found)
}

/// Fetches every source and returns the snapshot, at `version`.
pub(crate) async fn build(
    version: u64,
    roots: std::sync::Arc<tunnelward_crypto::rustls::RootCertStore>,
) -> Result<Vec<u8>, String> {
    let mut providers = Vec::new();
    for &(provider, agent, url, format) in SOURCES {
        let body = tunnelward_gateway::https_get(url, roots.clone(), MAX_SOURCE)
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        let ranges = ranges(format, &body).ok_or_else(|| format!("{url}: no ranges found"))?;
        providers.push(serde_json::json!({
            "provider": provider, "agent": agent, "source": url, "ranges": ranges,
        }));
    }
    let created = humantime(SystemTime::now());
    let doc = serde_json::json!({ "version": version, "created": created, "providers": providers });
    serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())
}

/// A version that grows with time: seconds since the epoch.
pub(crate) fn default_version() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `at` as RFC 3339 UTC, to the second.
fn humantime(at: SystemTime) -> String {
    let secs = at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (y, m, d) = crate::devcert::civil(secs / 86_400);
    let rest = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// Lower-case hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 15)]])
        .map(char::from)
        .collect()
}

/// Bytes from hex; `None` for odd length or a non-hex character.
pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Writes a new Ed25519 key (PKCS#8) to `out`, never over an existing
/// file, readable by its owner only; returns the public key in hex.
pub(crate) fn keygen(out: &Path) -> Result<String, String> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "key generation failed".to_owned())?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| "the new key does not load".to_owned())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(out)
        .map_err(|e| format!("{}: {e}", out.display()))?;
    std::io::Write::write_all(&mut file, pkcs8.as_ref())
        .map_err(|e| format!("{}: {e}", out.display()))?;
    Ok(hex(pair.public_key().as_ref()))
}

/// Signs `snapshot` with the key in `key`; writes `<snapshot>.sig` and
/// returns its path.
pub(crate) fn sign(key: &Path, snapshot: &Path) -> Result<PathBuf, String> {
    let pkcs8 = std::fs::read(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let pair = Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|_| format!("{}: not an Ed25519 key", key.display()))?;
    let bytes = std::fs::read(snapshot).map_err(|e| format!("{}: {e}", snapshot.display()))?;
    let out = signature_path(snapshot);
    std::fs::write(&out, pair.sign(&bytes).as_ref())
        .map_err(|e| format!("{}: {e}", out.display()))?;
    Ok(out)
}

/// Where a snapshot's signature lives: beside it, with `.sig` added.
pub(crate) fn signature_path(snapshot: &Path) -> PathBuf {
    let mut name = snapshot.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "## Inbound IP addresses\n\n### IPv4\n\n`160.79.104.0/23`\n\n\
        ## Outbound IP addresses\n\nThese are used for outbound requests.\n\n### IPv4\n\n\
        `160.79.104.0/21`\n\n`153.61.208.0/20`\n\n### Phased out IP addresses\n\n`34.162.46.92/32`\n";

    #[test]
    fn the_anthropic_page_yields_its_outbound_ranges_only() {
        assert_eq!(
            anthropic_outbound(PAGE),
            ["160.79.104.0/21", "153.61.208.0/20"]
        );
        assert_eq!(anthropic_outbound("no such section"), Vec::<String>::new());
    }

    #[test]
    fn prefix_lists_yield_v4_and_v6_and_reject_junk() {
        let json = br#"{"creationTime":"x","prefixes":[{"ipv4Prefix":"192.0.2.0/28"},{"ipv6Prefix":"2001:db8::/32"}]}"#;
        assert_eq!(
            prefixes(json),
            Some(vec!["192.0.2.0/28".into(), "2001:db8::/32".into()])
        );
        assert_eq!(prefixes(br#"{"prefixes":[{"ipv4Prefix":"nope"}]}"#), None);
        assert_eq!(
            ranges(Format::Prefixes, br#"{"prefixes":[]}"#),
            None,
            "empty fails"
        );
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
        assert_eq!(unhex("00ab10"), Some(vec![0, 0xab, 0x10]));
        assert_eq!(unhex("0g"), None);
        assert_eq!(unhex("abc"), None);
    }

    /// Writes a snapshot at `version` into `dir` and signs it with `key`.
    fn publish(dir: &Path, key: &Path, version: u64) -> Result<(), String> {
        let snap = dir.join("providers.json");
        let json = format!(r#"{{"version":{version},"providers":[]}}"#);
        std::fs::write(&snap, json).map_err(|e| e.to_string())?;
        sign(key, &snap).map(drop)
    }

    #[tokio::test]
    async fn a_newer_snapshot_is_picked_up_and_a_rollback_is_not() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("tw-providers-{}", std::process::id()));
        let _fresh = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let key = dir.join("signing.key");
        let public = keygen(&key)?;
        publish(&dir, &key, 1)?;
        let section = Section {
            snapshot: PathBuf::from("providers.json"),
            keys: vec![public],
            reload_secs: Some(1),
        };
        let mut problems = Vec::new();
        let mut loaded = check(&dir, &section, &mut problems).ok_or(problems.join("; "))?;
        loaded.every = std::time::Duration::from_millis(20);
        let providers = loaded.providers.clone();
        let task = tokio::spawn(keep_fresh(loaded));
        let settle = || tokio::time::sleep(std::time::Duration::from_millis(1100));
        settle().await; // a new modification time on every file system
        publish(&dir, &key, 2)?;
        settle().await;
        assert_eq!(providers.version(), Some(2), "picked up");
        publish(&dir, &key, 1)?;
        settle().await;
        assert_eq!(providers.version(), Some(2), "a rollback is refused");
        task.abort();
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())
    }

    #[test]
    fn rfc_3339_times() {
        assert_eq!(
            humantime(UNIX_EPOCH + std::time::Duration::from_secs(1_794_000_000)),
            "2026-11-06T21:20:00Z"
        );
    }
}

/// The gateway file's `[providers]` section.
///
/// ```toml
/// [providers]
/// snapshot = "providers.json"   # its signature is providers.json.sig
/// keys = ["<hex Ed25519 public key>"]   # from `tunnelward providers keygen`
/// reload_secs = 300             # how often to look for a newer snapshot
/// ```
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Section {
    snapshot: PathBuf,
    keys: Vec<String>,
    reload_secs: Option<u64>,
}

/// A checked section: the loaded snapshot and how to keep it fresh.
pub(crate) struct Loaded {
    pub(crate) providers: std::sync::Arc<tunnelward_gateway::Providers>,
    snapshot: PathBuf,
    every: std::time::Duration,
}

/// Checks `section` (from a file in `base`) and loads its snapshot.
pub(crate) fn check(base: &Path, section: &Section, problems: &mut Vec<String>) -> Option<Loaded> {
    let keys: Vec<Vec<u8>> = section
        .keys
        .iter()
        .filter_map(|k| {
            let key = unhex(k).filter(|b| b.len() == 32);
            if key.is_none() {
                problems.push(format!("[providers] key {k:?}: give 64 hex characters"));
            }
            key
        })
        .collect();
    if section.keys.is_empty() {
        problems.push("[providers] keys: name at least one".into());
    }
    let providers = std::sync::Arc::new(tunnelward_gateway::Providers::new(keys));
    let snapshot = crate::config::resolve(base, &section.snapshot);
    load(&providers, &snapshot)
        .map_err(|e| problems.push(format!("[providers] {e}")))
        .ok()?;
    let every = std::time::Duration::from_secs(section.reload_secs.unwrap_or(300).max(1));
    Some(Loaded {
        providers,
        snapshot,
        every,
    })
}

/// Loads `snapshot` and its signature into `providers`.
fn load(providers: &tunnelward_gateway::Providers, snapshot: &Path) -> Result<u64, String> {
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let bytes = read(snapshot)?;
    let signature = read(&signature_path(snapshot))?;
    providers
        .load(&bytes, &signature)
        .map_err(|e| e.to_string())
}

/// Loads the snapshot again whenever it or its signature changes; a
/// refused one leaves the current snapshot in force.
pub(crate) async fn keep_fresh(loaded: Loaded) {
    let files = [loaded.snapshot.clone(), signature_path(&loaded.snapshot)];
    let stamp = |f: &PathBuf| std::fs::metadata(f).and_then(|m| m.modified()).ok();
    let mut seen: Vec<_> = files.iter().map(stamp).collect();
    loop {
        tokio::time::sleep(loaded.every).await;
        let now: Vec<_> = files.iter().map(stamp).collect();
        if now == seen {
            continue;
        }
        seen = now;
        match load(&loaded.providers, &loaded.snapshot) {
            Ok(v) => println!("tunnelward gateway: provider snapshot {v} loaded"),
            Err(e) => println!("tunnelward gateway: kept the current provider snapshot: {e}"),
        }
    }
}
