// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Developer tasks for the Tunnelward workspace.
//!
//! `cargo xtask ci` runs every check CI runs, in the order CI runs them,
//! and stops at the first failure. CI calls this command and nothing
//! else, so a check added here is a check added to CI.
//!
//! `cargo xtask miri` and `cargo xtask fuzz [seconds] [target]` need a
//! nightly toolchain, so they are separate tasks with their own CI jobs.
//! `cargo xtask fuzz-targets` prints the targets as a JSON array, for the
//! weekly workflow's one job per target.

use std::env;
use std::fs;
use std::process::{Command, ExitCode};

/// One check: what it is called, the program, its arguments, and extra
/// environment variables.
struct Step {
    name: &'static str,
    program: &'static str,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
}

const STEPS: &[Step] = &[
    Step {
        name: "format",
        program: "cargo",
        args: &["fmt", "--all", "--check"],
        env: &[],
    },
    Step {
        name: "clippy",
        program: "cargo",
        args: &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        env: &[],
    },
    Step {
        name: "test",
        program: "cargo",
        args: &["test", "--workspace", "--locked"],
        env: &[],
    },
    Step {
        name: "docs",
        program: "cargo",
        args: &["doc", "--workspace", "--no-deps", "--locked"],
        env: &[("RUSTDOCFLAGS", "-D warnings")],
    },
    Step {
        name: "cargo-deny",
        program: "cargo",
        args: &["deny", "--locked", "check"],
        env: &[],
    },
    Step {
        name: "licence-boundary",
        program: "bash",
        args: &["scripts/licence-boundary.sh"],
        env: &[],
    },
    Step {
        name: "cargo-vet",
        program: "bash",
        args: &["scripts/vet.sh"],
        env: &[],
    },
    Step {
        name: "reuse",
        program: "reuse",
        args: &["lint"],
        env: &[],
    },
    Step {
        name: "readme",
        program: "bash",
        args: &["scripts/readme-check.sh"],
        env: &[],
    },
    Step {
        name: "semver",
        program: "bash",
        args: &["scripts/semver.sh"],
        env: &[],
    },
    Step {
        name: "complexity",
        program: "bash",
        args: &["scripts/complexity.sh"],
        env: &[],
    },
];

const MIRI: &[Step] = &[Step {
    name: "miri",
    program: "cargo",
    args: &[
        "+nightly",
        "miri",
        "test",
        "-p",
        "tunnelward-proto",
        "--locked",
    ],
    env: &[("MIRIFLAGS", "-Zmiri-strict-provenance")],
}];

/// Fuzz targets, each with a committed seed corpus in `fuzz/seeds/<name>`.
const FUZZ_TARGETS: &[&str] = &["decode", "envelope", "proxy", "svid"];

/// Seconds each target runs when `cargo xtask fuzz` is given no time.
const DEFAULT_FUZZ_SECS: u32 = 60;

/// Runs one step, returning a message on failure.
fn run(step: &Step) -> Result<(), String> {
    println!(
        "==> {}: {} {}",
        step.name,
        step.program,
        step.args.join(" ")
    );
    let status = Command::new(step.program)
        .args(step.args)
        .envs(step.env.iter().copied())
        .status()
        .map_err(|e| format!("{}: cannot start `{}`: {e}", step.name, step.program))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{}: failed ({status})", step.name))
    }
}

/// Runs every step in order, stopping at the first failure.
fn run_all(steps: &[Step]) -> Result<(), String> {
    steps.iter().try_for_each(run)?;
    println!("==> all {} checks passed", steps.len());
    Ok(())
}

/// The targets to run: `only` alone when given, which must be one of
/// [`FUZZ_TARGETS`], else all of them.
fn fuzz_targets(only: Option<&str>) -> Result<Vec<&'static str>, String> {
    match only {
        None => Ok(FUZZ_TARGETS.to_vec()),
        Some(name) => FUZZ_TARGETS
            .iter()
            .find(|t| **t == name)
            .map(|t| vec![*t])
            .ok_or_else(|| format!("fuzz: no target `{name}`; the targets are {FUZZ_TARGETS:?}")),
    }
}

/// [`FUZZ_TARGETS`] as a JSON array.
fn fuzz_targets_json() -> String {
    let quoted: Vec<String> = FUZZ_TARGETS.iter().map(|t| format!("\"{t}\"")).collect();
    format!("[{}]", quoted.join(","))
}

/// Replays each target's seeds, then fuzzes it for `secs` seconds. New
/// inputs go to the untracked `fuzz/corpus/<name>`; the seeds stay as
/// committed.
fn fuzz(secs: u32, targets: &[&str]) -> Result<(), String> {
    let host = host_triple()?;
    targets.iter().try_for_each(|target| {
        let corpus = format!("fuzz/corpus/{target}");
        fs::create_dir_all(&corpus).map_err(|e| format!("fuzz: cannot create {corpus}: {e}"))?;
        println!("==> fuzz {target} for {secs} s");
        let status = Command::new("cargo")
            .args([
                "+nightly", "fuzz", "run", "--target", &host, target, &corpus,
            ])
            .arg(format!("fuzz/seeds/{target}"))
            .args(["--", &format!("-max_total_time={secs}")])
            .status()
            .map_err(|e| format!("fuzz: cannot start cargo: {e}"))?;
        status
            .success()
            .then_some(())
            .ok_or(format!("fuzz {target}: failed ({status})"))
    })
}

/// The nightly toolchain's host triple. cargo-fuzz otherwise builds for
/// the triple it was itself built for, and a prebuilt musl `cargo-fuzz`
/// (as CI installs) then builds for musl, where `AddressSanitizer` cannot run.
fn host_triple() -> Result<String, String> {
    let out = Command::new("rustc")
        .args(["+nightly", "-vV"])
        .output()
        .map_err(|e| format!("fuzz: cannot run rustc: {e}"))?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "fuzz: rustc -vV printed no host".to_owned())
}

fn fuzz_secs(arg: Option<&str>) -> Result<u32, String> {
    arg.map_or(Ok(DEFAULT_FUZZ_SECS), |s| {
        s.parse()
            .map_err(|_| format!("fuzz: `{s}` is not a number of seconds"))
    })
}

const USAGE: &str = "usage: cargo xtask <ci | miri | fuzz [seconds] [target] | fuzz-targets>";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("ci") => run_all(STEPS),
        Some("miri") => run_all(MIRI),
        Some("fuzz") => fuzz_secs(args.get(1).map(String::as_str))
            .and_then(|secs| fuzz(secs, &fuzz_targets(args.get(2).map(String::as_str))?)),
        Some("fuzz-targets") => {
            println!("{}", fuzz_targets_json());
            Ok(())
        }
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("xtask: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_target_or_all_and_never_an_unknown_one() {
        assert_eq!(fuzz_targets(None), Ok(FUZZ_TARGETS.to_vec()));
        assert_eq!(fuzz_targets(Some("svid")), Ok(vec!["svid"]));
        assert!(fuzz_targets(Some("nope")).is_err());
    }

    #[test]
    fn the_targets_print_as_a_json_array() {
        assert_eq!(
            fuzz_targets_json(),
            r#"["decode","envelope","proxy","svid"]"#
        );
    }
}
