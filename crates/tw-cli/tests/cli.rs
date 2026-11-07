// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Black-box tests of the `tunnelward` binary's argument handling.

use std::io;
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn run(args: &[&str]) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_tunnelward"))
        .args(args)
        .output()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn version_prints_name_and_workspace_version() -> TestResult {
    for flag in ["--version", "-V"] {
        let out = run(&[flag])?;
        assert!(out.status.success(), "{flag} exits 0");
        assert_eq!(
            stdout(&out),
            format!("tunnelward {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
    Ok(())
}

#[test]
fn help_and_no_arguments_print_usage() -> TestResult {
    for args in [&["--help"][..], &["-h"][..], &[][..]] {
        let out = run(args)?;
        assert!(out.status.success(), "{args:?} exits 0");
        assert!(stdout(&out).starts_with("Usage: tunnelward"), "{args:?}");
    }
    Ok(())
}

#[test]
fn unknown_argument_fails_with_usage_error() -> TestResult {
    let out = run(&["--bogus"])?;
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), "");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unexpected argument '--bogus'"), "{err}");
    Ok(())
}
