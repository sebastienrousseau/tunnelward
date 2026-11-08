// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Every error id in the code is explained in `docs/errors.md`, every id
//! there exists in the code, and no id names two errors.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// Every `TW-X000` literal in `text`, in order.
fn ids(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    (0..bytes.len().saturating_sub(6))
        .filter(|&i| bytes[i..].starts_with(b"TW-"))
        .filter_map(|i| {
            let id = bytes.get(i..i + 7)?;
            let well_formed = id[3].is_ascii_uppercase() && id[4..].iter().all(u8::is_ascii_digit);
            let ends = bytes.get(i + 7).is_none_or(|b| !b.is_ascii_alphanumeric());
            (well_formed && ends).then(|| String::from_utf8_lossy(id).into_owned())
        })
        .collect()
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) -> Res<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            sources(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn the_catalogue_and_the_code_name_the_same_ids() -> Res<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for krate in ["tw-proto", "tw-gateway", "tw-connector"] {
        sources(&root.join("crates").join(krate).join("src"), &mut files)?;
    }
    let mut in_code = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file)?;
        // Code only: not the tests, and not comments, which may cite an id.
        let body = text.split("#[cfg(test)]").next().unwrap_or_default();
        let code: String = body
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        in_code.extend(ids(&code).into_iter().filter(|id| id != "TW-R000"));
    }
    let unique: BTreeSet<_> = in_code.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        in_code.len(),
        "an id names two errors: {in_code:?}"
    );

    let docs = std::fs::read_to_string(root.join("docs/errors.md"))?;
    let headings: BTreeSet<String> = docs
        .lines()
        .filter_map(|l| l.strip_prefix("### "))
        .map(str::to_owned)
        .collect();
    assert_eq!(unique, headings, "code ids versus docs/errors.md headings");
    Ok(())
}
