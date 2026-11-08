// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The `tunnelward` command-line tool.

mod agents;
mod args;
mod config;
mod connector;
mod dev;
mod devcert;
mod doctor;
mod gateway;
mod serve;

use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;

use args::{Args, UsageError};

const USAGE: &str = "\
Usage: tunnelward <COMMAND> [OPTIONS]

Tunnelward lets a service behind a firewall dial out to a gateway, prove
what it is, and serve AI agents with no inbound port.

Commands:
  dev --to <http://host:port> [--listen <addr>] [--route <route>] [--admin <addr>]
                 Run a gateway and a connector in front of a local service.
                 Defaults: --listen 127.0.0.1:8000, --route * (every request)
  gateway --config <file>
                 Run a gateway from its TOML configuration file
  connector --config <file>
                 Run a connector in front of a local service, from its TOML file
  config check <file>
                 Check a gateway's or a connector's file and list every problem
  doctor [--config <file>]
                 Check this machine and, given a file, its configuration

Options:
  -h, --help     Print this help
  -V, --version  Print the version

Errors are explained at https://github.com/sebastienrousseau/tunnelward/blob/main/docs/errors.md
";

/// Exit code for a usage error, as sysexits and most CLIs use it.
const USAGE_ERROR: u8 = 2;

/// What a command ended with.
enum Outcome {
    Done,
    Failed(String),
    Usage(UsageError),
}

impl From<UsageError> for Outcome {
    fn from(e: UsageError) -> Self {
        Self::Usage(e)
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, Outcome> {
    tokio::runtime::Runtime::new().map_err(|e| Outcome::Failed(format!("cannot start: {e}")))
}

fn dev(args: &[String]) -> Result<(), Outcome> {
    let args = Args::parse(args, &["to", "listen", "route", "admin"])?;
    let to = args
        .get("to")
        .ok_or_else(|| UsageError("dev needs '--to <http://host:port>'".into()))?;
    let default_listen = SocketAddr::from(([127, 0, 0, 1], 8000));
    let request = dev::Dev {
        to: to.to_owned(),
        listen: args.parsed("listen")?.unwrap_or(default_listen),
        route: args.get("route").unwrap_or("*").to_owned(),
        admin: args.parsed("admin")?,
    };
    runtime()?
        .block_on(dev::run(request))
        .map_err(|e| Outcome::Failed(e.to_string()))
}

fn gateway(args: &[String]) -> Result<(), Outcome> {
    let args = Args::parse(args, &["config"])?;
    let path = args
        .get("config")
        .ok_or_else(|| UsageError("gateway needs '--config <file>'".into()))?;
    runtime()?
        .block_on(gateway::run(Path::new(path)))
        .map_err(Outcome::Failed)
}

fn connector(args: &[String]) -> Result<(), Outcome> {
    let args = Args::parse(args, &["config"])?;
    let path = args
        .get("config")
        .ok_or_else(|| UsageError("connector needs '--config <file>'".into()))?;
    runtime()?
        .block_on(connector::run(Path::new(path)))
        .map_err(Outcome::Failed)
}

/// Checks a connector's file (one with `[target]`) or a gateway's.
fn check_file(path: &Path) -> Result<(), Outcome> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Outcome::Failed(format!("{}: {e}", path.display())))?;
    let problems = if connector::is_connector_file(&text) {
        let file = connector::load(path).map_err(Outcome::Failed)?;
        connector::check(path, &file).err()
    } else {
        let file = config::load(path).map_err(Outcome::Failed)?;
        config::check(path, file).err()
    };
    match problems {
        None => Ok(()),
        Some(problems) => Err(Outcome::Failed(problems.join("\n"))),
    }
}

fn config_check(args: &[String]) -> Result<(), Outcome> {
    let args = Args::parse(args, &[])?;
    let [command, path] = args.positional.as_slice() else {
        return Err(UsageError("usage: tunnelward config check <file>".into()).into());
    };
    if command != "check" {
        return Err(UsageError(format!("unknown config command '{command}'")).into());
    }
    let path = Path::new(path);
    check_file(path)?;
    println!("{}: ok", path.display());
    Ok(())
}

fn doctor(args: &[String]) -> Result<(), Outcome> {
    let args = Args::parse(args, &["config"])?;
    let findings = doctor::run(args.get("config").map(Path::new));
    for f in &findings {
        println!("{} {}", if f.ok { "ok  " } else { "FAIL" }, f.what);
    }
    let failed = findings.iter().filter(|f| !f.ok).count();
    if failed == 0 {
        Ok(())
    } else {
        Err(Outcome::Failed(format!("{failed} check(s) failed")))
    }
}

type Command = fn(&[String]) -> Result<(), Outcome>;

/// Every command, by the names that call it.
const COMMANDS: [(&[&str], Command); 7] = [
    (&["-h", "--help"], |_| {
        print!("{USAGE}");
        Ok(())
    }),
    (&["-V", "--version"], |_| {
        println!("tunnelward {}", env!("CARGO_PKG_VERSION"));
        Ok(())
    }),
    (&["dev"], dev),
    (&["gateway"], gateway),
    (&["connector"], connector),
    (&["config"], config_check),
    (&["doctor"], doctor),
];

fn dispatch(args: &[String]) -> Outcome {
    let (name, rest) = match args.split_first() {
        Some((name, rest)) => (name.as_str(), rest),
        None => ("--help", &[][..]),
    };
    let command = COMMANDS
        .iter()
        .find(|(names, _)| names.contains(&name))
        .map(|(_, command)| *command);
    let result = match command {
        Some(command) => command(rest),
        None => Err(UsageError(format!("unexpected argument '{name}'")).into()),
    };
    result.err().unwrap_or(Outcome::Done)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match dispatch(&args) {
        Outcome::Done => ExitCode::SUCCESS,
        Outcome::Failed(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
        Outcome::Usage(UsageError(message)) => {
            eprintln!("error: {message}\n\n{USAGE}");
            ExitCode::from(USAGE_ERROR)
        }
    }
}
