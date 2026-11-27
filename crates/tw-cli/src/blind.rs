// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: GPL-3.0-only

//! Gateway-blind mode (ADR 0016, experimental): the connector file's
//! `[blind]`, and `tunnelward blind keygen`.
//!
//! ```toml
//! [blind]
//! experimental = true             # required: the mode is experimental
//! key = "blind.key"               # from `tunnelward blind keygen`
//! require = false                 # true: refuse a tools/call not sealed
//! max_body = 1048576              # largest call or answer buffered
//! ```
//!
//! Agents seal to the public key in `blind.key.pub` (base64url), which
//! they must get from the connector's operator, not through the gateway.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use tunnelward_connector::Blind;
use tunnelward_crypto::xwing::PrivateKeyXWing;

use crate::Outcome;
use crate::args::{Args, UsageError};
use crate::config::{Problems, resolve};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Section {
    #[serde(default)]
    experimental: bool,
    key: PathBuf,
    #[serde(default)]
    require: bool,
    max_body: Option<usize>,
}

/// Checks `section`, read from a file in `base`, and loads the key.
pub(crate) fn check(base: &Path, section: &Section, problems: &mut Problems) -> Option<Blind> {
    if !section.experimental {
        problems
            .push("[blind]: gateway-blind mode is experimental; set experimental = true".into());
        return None;
    }
    let path = resolve(base, &section.key);
    let key = std::fs::read(&path)
        .map_err(|e| format!("{}: {e}", path.display()))
        .and_then(|bytes| {
            PrivateKeyXWing::from_bytes(&bytes).map_err(|e| format!("{}: {e}", path.display()))
        })
        .map_err(|e| problems.push(format!("[blind] key: {e}")))
        .ok()?;
    let mut blind = Blind::new(key);
    blind.require = section.require;
    if let Some(max) = section.max_body {
        if max == 0 {
            problems.push("[blind] max_body: at least 1".into());
            return None;
        }
        blind.max_body = max;
    }
    Some(blind)
}

/// `blind keygen --out <file>`: a new X-Wing key, owner-only, and its
/// public key in base64url beside it.
pub(crate) fn command(args: &[String]) -> Result<(), Outcome> {
    if args.first().map(String::as_str) != Some("keygen") {
        return Err(UsageError("blind needs 'keygen --out <file>'".into()).into());
    }
    let args = Args::parse(&args[1..], &["out"])?;
    let out = args
        .get("out")
        .ok_or_else(|| UsageError("blind keygen needs '--out <file>'".into()))?;
    let public = keygen(Path::new(out)).map_err(Outcome::Failed)?;
    println!(
        "{out}: gateway-blind key (experimental); agents seal to {}",
        public.display()
    );
    Ok(())
}

fn keygen(out: &Path) -> Result<PathBuf, String> {
    let mut public_path = out.as_os_str().to_owned();
    public_path.push(".pub");
    let public_path = PathBuf::from(public_path);
    if public_path.exists() {
        return Err(format!("{}: already exists", public_path.display()));
    }
    let key = PrivateKeyXWing::generate().map_err(|e| e.to_string())?;
    let private = key.to_bytes().map_err(|e| e.to_string())?;
    crate::providers::write_new(out, &private, true)?;
    let public = format!("{}\n", tunnelward_audit::b64::encode(key.public_key()));
    crate::providers::write_new(&public_path, public.as_bytes(), false)?;
    Ok(public_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_writes_a_key_the_section_loads_and_never_overwrites() {
        let dir = std::env::temp_dir().join(format!(
            "tw-blind-{}-{}",
            std::process::id(),
            tunnelward_audit::now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let public = keygen(&dir.join("blind.key")).unwrap();
        let text = std::fs::read_to_string(&public).unwrap();
        assert_eq!(
            tunnelward_audit::b64::decode(text.trim()).unwrap().len(),
            1216
        );
        assert!(keygen(&dir.join("blind.key")).is_err());
        let mut problems = Problems::new();
        let section: Section =
            toml::from_str("experimental = true\nkey = \"blind.key\"\nrequire = true\n").unwrap();
        let blind = check(&dir, &section, &mut problems).unwrap();
        assert!(problems.is_empty() && blind.require);
        assert_eq!(
            tunnelward_audit::b64::encode(blind.key.public_key()),
            text.trim()
        );
        let off: Section = toml::from_str("key = \"blind.key\"\n").unwrap();
        assert!(check(&dir, &off, &mut problems).is_none());
        assert!(problems[0].contains("experimental"), "{problems:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
