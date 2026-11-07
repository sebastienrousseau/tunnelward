// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Developer tasks for the Tunnelward workspace.
//!
//! `cargo xtask ci` runs every check CI runs, in the order CI runs them,
//! and stops at the first failure. CI calls this command and nothing
//! else, so a check added here is a check added to CI.

use std::env;
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
        name: "cargo-vet",
        program: "cargo",
        args: &["vet", "--locked"],
        env: &[],
    },
    Step {
        name: "reuse",
        program: "reuse",
        args: &["lint"],
        env: &[],
    },
    Step {
        name: "complexity",
        program: "bash",
        args: &["scripts/complexity.sh"],
        env: &[],
    },
];

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
fn ci() -> Result<(), String> {
    STEPS.iter().try_for_each(run)?;
    println!("==> all {} checks passed", STEPS.len());
    Ok(())
}

fn main() -> ExitCode {
    let task = env::args().nth(1);
    let result = match task.as_deref() {
        Some("ci") => ci(),
        _ => Err("usage: cargo xtask ci".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("xtask: {msg}");
            ExitCode::FAILURE
        }
    }
}
