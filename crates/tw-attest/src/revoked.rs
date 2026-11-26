// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Revoked statements.

use std::collections::HashSet;

/// Statements a gateway no longer accepts, by the SHA-256 of their signed
/// payload ([`crate::Attested::digest`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revoked(HashSet<[u8; 32]>);

impl Revoked {
    /// Most digests a list may hold.
    pub const MAX: usize = 100_000;

    /// A list from text: one hex SHA-256 per line; blank lines and text
    /// after `#` are ignored.
    ///
    /// # Errors
    ///
    /// The first line that is not a digest, by number, or more than
    /// [`Revoked::MAX`] digests.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut set = HashSet::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let digest = tunnelward_audit::unhex(line)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| format!("line {}: not a hex SHA-256", n + 1))?;
            if set.len() == Self::MAX {
                return Err(format!("more than {} digests", Self::MAX));
            }
            set.insert(digest);
        }
        Ok(Self(set))
    }

    /// Whether `digest` is revoked.
    #[must_use]
    pub fn contains(&self, digest: &[u8; 32]) -> bool {
        self.0.contains(digest)
    }

    /// How many statements are revoked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether none is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_digests_and_comments() {
        let one = "ab".repeat(32);
        let text = format!(
            "# revoked 2026-11-26\n\n{one}  # passmcp run 41\n{}\n",
            one.to_uppercase()
        );
        let revoked = Revoked::parse(&text).unwrap();
        assert_eq!(revoked.len(), 1);
        assert!(revoked.contains(&[0xab; 32]));
        assert!(!revoked.contains(&[0; 32]));
    }

    #[test]
    fn names_the_bad_line() {
        assert_eq!(
            Revoked::parse("\nabc\n"),
            Err("line 2: not a hex SHA-256".into())
        );
        assert!(Revoked::parse(&"0".repeat(62)).is_err());
    }
}
