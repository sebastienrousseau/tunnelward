// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Raw values, kept only when an operator opts in (`raw_days`), in a
//! file beside the chain: pruning it never breaks the chain (ADR 0008).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The raw values behind an entry's pseudonyms.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Raw {
    /// The client address.
    pub client: String,
    /// SHA-256 of the client certificate, in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<String>,
}

/// One line of the raw file.
#[derive(Serialize, Deserialize)]
struct Line {
    seq: u64,
    time: u64,
    #[serde(flatten)]
    raw: Raw,
}

/// Where the raw values for the log at `log` go: beside it, `.raw`
/// added.
#[must_use]
pub(crate) fn path(log: &Path) -> PathBuf {
    let mut name = log.as_os_str().to_owned();
    name.push(".raw");
    PathBuf::from(name)
}

/// One line for the raw file.
pub(crate) fn line(seq: u64, time: u64, raw: &Raw) -> Result<String, serde_json::Error> {
    serde_json::to_string(&Line {
        seq,
        time,
        raw: raw.clone(),
    })
}

/// The lines of the raw file at `path` from `cutoff` on, and how many
/// were before it or did not parse; `None` when there is no file.
fn kept(path: &Path, cutoff: u64) -> std::io::Result<Option<(Vec<String>, usize)>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut kept = Vec::new();
    let mut removed = 0;
    for text in BufReader::new(file).lines() {
        let text = text?;
        match serde_json::from_str::<Line>(&text) {
            Ok(line) if line.time >= cutoff => kept.push(text),
            _ => removed += 1,
        }
    }
    Ok(Some((kept, removed)))
}

/// Replaces the file at `path` whole with `lines`.
fn replace(path: &Path, lines: &[String]) -> std::io::Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".prune");
    let temporary = PathBuf::from(temporary);
    let mut out = std::fs::File::create(&temporary)?;
    for text in lines {
        writeln!(out, "{text}")?;
    }
    out.sync_all()?;
    std::fs::rename(&temporary, path)
}

/// Rewrites the raw file at `path` without the lines from before
/// `cutoff` (milliseconds since 1970), or that do not parse. Returns how
/// many it removed. The new file replaces the old one whole.
pub(crate) fn prune(path: &Path, cutoff: u64) -> std::io::Result<usize> {
    let Some((lines, removed)) = kept(path, cutoff)? else {
        return Ok(0);
    };
    if removed > 0 {
        replace(path, &lines)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruning_drops_old_lines_only() {
        let dir = std::env::temp_dir().join(format!("tw-raw-{}", crate::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("audit.jsonl.raw");
        let raw = Raw {
            client: "192.0.2.1".into(),
            client_cert: None,
        };
        let text = [line(0, 100, &raw).unwrap(), line(1, 300, &raw).unwrap()].join("\n");
        std::fs::write(&file, text + "\n").unwrap();
        assert_eq!(prune(&file, 200).unwrap(), 1);
        let left = std::fs::read_to_string(&file).unwrap();
        assert!(left.contains("\"seq\":1") && !left.contains("\"seq\":0"));
        assert_eq!(prune(&file, 200).unwrap(), 0);
        assert_eq!(prune(&dir.join("absent"), 200).unwrap(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
