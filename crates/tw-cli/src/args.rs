// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `--flag value` pairs and positional arguments, checked against what a
//! command accepts.

use std::collections::HashMap;

/// A command line that does not fit the command.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UsageError(pub(crate) String);

/// The parsed arguments of one command.
#[derive(Debug, Default)]
pub(crate) struct Args {
    flags: HashMap<String, String>,
    pub(crate) positional: Vec<String>,
}

impl Args {
    /// Parses `args`, accepting only the flags in `known`, each once and
    /// each with a value.
    pub(crate) fn parse(args: &[String], known: &[&str]) -> Result<Self, UsageError> {
        let mut parsed = Self::default();
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            let Some(flag) = arg.strip_prefix("--") else {
                parsed.positional.push(arg.clone());
                continue;
            };
            if !known.contains(&flag) {
                return Err(UsageError(format!("unknown option '--{flag}'")));
            }
            let value = rest
                .next()
                .ok_or_else(|| UsageError(format!("'--{flag}' needs a value")))?;
            if parsed
                .flags
                .insert(flag.to_owned(), value.clone())
                .is_some()
            {
                return Err(UsageError(format!("'--{flag}' given twice")));
            }
        }
        Ok(parsed)
    }

    /// The value of `--flag`, if given.
    pub(crate) fn get(&self, flag: &str) -> Option<&str> {
        self.flags.get(flag).map(String::as_str)
    }

    /// The value of `--flag` parsed as `T`.
    pub(crate) fn parsed<T: std::str::FromStr>(&self, flag: &str) -> Result<Option<T>, UsageError> {
        self.get(flag)
            .map(|v| {
                v.parse()
                    .map_err(|_| UsageError(format!("'--{flag}': cannot use {v:?}")))
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn flags_and_positionals_parse() -> Result<(), UsageError> {
        let args = Args::parse(&strings(&["check", "--to", "x", "file"]), &["to"])?;
        assert_eq!(args.get("to"), Some("x"));
        assert_eq!(args.positional, ["check", "file"]);
        Ok(())
    }

    #[test]
    fn bad_flags_are_usage_errors() {
        let known = &["to"];
        assert!(Args::parse(&strings(&["--from", "x"]), known).is_err());
        assert!(Args::parse(&strings(&["--to"]), known).is_err());
        assert!(Args::parse(&strings(&["--to", "a", "--to", "b"]), known).is_err());
    }

    #[test]
    fn values_parse_or_fail() -> Result<(), UsageError> {
        let args = Args::parse(&strings(&["--port", "80"]), &["port"])?;
        assert_eq!(args.parsed::<u16>("port")?, Some(80));
        let bad = Args::parse(&strings(&["--port", "x"]), &["port"])?;
        assert!(bad.parsed::<u16>("port").is_err());
        Ok(())
    }
}
