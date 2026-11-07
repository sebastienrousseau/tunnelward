// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The `tunnelward` command-line tool.
//!
//! v0.0.1 only reports its version and usage; the `dev`, `audit verify`
//! and `crypto report` subcommands arrive with the crates they drive.

use std::env;
use std::process::ExitCode;

const USAGE: &str = "\
Usage: tunnelward [OPTIONS]

Tunnelward lets a service behind a firewall dial out to a gateway, prove
what it is, and serve AI agents with no inbound port.

Options:
  -h, --help     Print this help
  -V, --version  Print the version
";

/// Exit code for a usage error, as sysexits and most CLIs use it.
const USAGE_ERROR: u8 = 2;

fn main() -> ExitCode {
    let arg = env::args().nth(1);
    match arg.as_deref() {
        None | Some("-h" | "--help") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("-V" | "--version") => {
            println!("tunnelward {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("error: unexpected argument '{other}'\n\n{USAGE}");
            ExitCode::from(USAGE_ERROR)
        }
    }
}
