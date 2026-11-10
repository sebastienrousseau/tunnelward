// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The `tunnelward` command-line tool.

mod agents;
mod args;
mod audit;
mod backend;
mod config;
mod connector;
mod dev;
mod devcert;
mod doctor;
mod enrol;
mod enrolled;
mod gateway;
mod policy;
mod providers;
mod serve;
mod signers;
mod state;
mod svid;

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
      [--audit <key>]
                 Run a gateway and a connector in front of a local service.
                 Defaults: --listen 127.0.0.1:8000, --route * (every request).
                 --audit logs to audit.jsonl beside <key>, with receipts
  gateway --config <file>
                 Run a gateway from its TOML configuration file
  connector --config <file>
                 Run a connector in front of a local service, from its TOML file
  config check <file>
                 Check a gateway's or a connector's file and list every problem
  doctor [--config <file>]
                 Check this machine and, given a file, its configuration
  providers keygen --out <file>
                 Make a composite ML-DSA-65 + Ed25519 key for signing
                 provider snapshots; its public key goes to <file>.pub
  providers build --out <file> [--version <n>]
                 Fetch providers' published egress ranges into a snapshot
  providers sign --key <file> <snapshot>
                 Sign a snapshot; writes <snapshot>.sig
  enrol ca --cert <file> --key <file> [--name <cn>] [--days <n>]
                 Make the CA a gateway issues connector SVIDs from
                 Defaults: --name \"Tunnelward enrolment CA\", --days 3650
  enrol token --config <gateway file> --spiffe-id <id> [--ttl-secs <n>]
                 Print a one-time token that enrols <id> (default 3600 s)
  enrol revoke --config <gateway file> --spiffe-id <id>
                 Stop <id>'s renewals; its SVID lapses when it expires
  policy test --policy <file> <cases>
                 Run the calls in <cases> against a tool policy; fail on
                 any decision that is not the one expected
  audit keygen --out <file>
                 Make the audit log's signing key (public key to <file>.pub)
                 and pseudonym key (<file>.pseudonym)
  audit verify --key <file.pub>[,<file.pub>...] <log>
                 Check an audit log offline: chain, order and checkpoints
                 signed by any of the keys
  audit export <log>
                 Write the log's entries as OCSF 1.3.0 events (JSON Lines)
  receipt verify --key <file.pub> <receipt | file | ->
                 Check a tw-receipt offline and print what it says

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
    let args = Args::parse(args, &["to", "listen", "route", "admin", "audit"])?;
    let to = args
        .get("to")
        .ok_or_else(|| UsageError("dev needs '--to <http://host:port>'".into()))?;
    let default_listen = SocketAddr::from(([127, 0, 0, 1], 8000));
    let request = dev::Dev {
        to: to.to_owned(),
        listen: args.parsed("listen")?.unwrap_or(default_listen),
        route: args.get("route").unwrap_or("*").to_owned(),
        admin: args.parsed("admin")?,
        audit: args.get("audit").map(std::path::PathBuf::from),
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

fn providers(args: &[String]) -> Result<(), Outcome> {
    let args = Args::parse(args, &["out", "version", "key"])?;
    match args.positional.as_slice() {
        [command] if command == "keygen" => providers_keygen(&args),
        [command] if command == "build" => providers_build(&args),
        [command, snapshot] if command == "sign" => providers_sign(&args, snapshot),
        _ => Err(providers_usage().into()),
    }
}

fn providers_usage() -> UsageError {
    UsageError("usage: tunnelward providers keygen|build|sign (see --help)".into())
}

fn providers_keygen(args: &Args) -> Result<(), Outcome> {
    let out = args.get("out").ok_or_else(providers_usage)?;
    let public = providers::keygen(Path::new(out)).map_err(Outcome::Failed)?;
    println!("{out}\n{}", public.display());
    Ok(())
}

fn providers_build(args: &Args) -> Result<(), Outcome> {
    let out = args.get("out").ok_or_else(providers_usage)?;
    let version = args
        .parsed("version")?
        .unwrap_or_else(providers::default_version);
    let roots = agents::system_roots(None).map_err(Outcome::Failed)?;
    let snapshot = runtime()?
        .block_on(providers::build(version, roots))
        .map_err(Outcome::Failed)?;
    std::fs::write(out, snapshot).map_err(|e| Outcome::Failed(format!("{out}: {e}")))?;
    println!("{out}: version {version}");
    Ok(())
}

fn providers_sign(args: &Args, snapshot: &str) -> Result<(), Outcome> {
    let key = args.get("key").ok_or_else(providers_usage)?;
    let sig = providers::sign(Path::new(key), Path::new(snapshot)).map_err(Outcome::Failed)?;
    println!("{}", sig.display());
    Ok(())
}

fn enrol(args: &[String]) -> Result<(), Outcome> {
    let args = Args::parse(
        args,
        &[
            "cert",
            "key",
            "name",
            "days",
            "config",
            "spiffe-id",
            "ttl-secs",
        ],
    )?;
    match args.positional.as_slice() {
        [command] if command == "ca" => enrol_ca(&args),
        [command] if command == "token" => enrol_token(&args),
        [command] if command == "revoke" => enrol_revoke(&args),
        _ => Err(enrol_usage().into()),
    }
}

fn enrol_usage() -> UsageError {
    UsageError("usage: tunnelward enrol ca|token|revoke (see --help)".into())
}

fn enrol_ca(args: &Args) -> Result<(), Outcome> {
    let cert = args.get("cert").ok_or_else(enrol_usage)?;
    let key = args.get("key").ok_or_else(enrol_usage)?;
    let name = args.get("name").unwrap_or("Tunnelward enrolment CA");
    let days = args.parsed("days")?.unwrap_or(3650);
    enrol::make_ca(Path::new(cert), Path::new(key), name, days).map_err(Outcome::Failed)?;
    println!("enrolment CA written; name both files in [enrolment] ca_cert and ca_key");
    Ok(())
}

/// The gateway file and SPIFFE ID every enrol command but `ca` needs.
fn enrol_target(args: &Args) -> Result<(&Path, &str), UsageError> {
    let config = args.get("config").ok_or_else(enrol_usage)?;
    let id = args.get("spiffe-id").ok_or_else(enrol_usage)?;
    Ok((Path::new(config), id))
}

fn enrol_token(args: &Args) -> Result<(), Outcome> {
    let (config, id) = enrol_target(args)?;
    let ttl = std::time::Duration::from_secs(args.parsed("ttl-secs")?.unwrap_or(3600));
    println!(
        "{}",
        enrol::token(config, id, ttl).map_err(Outcome::Failed)?
    );
    Ok(())
}

fn enrol_revoke(args: &Args) -> Result<(), Outcome> {
    let (config, id) = enrol_target(args)?;
    if enrol::revoke(config, id).map_err(Outcome::Failed)? {
        println!("{id}: revoked; its SVID lapses when it expires");
        Ok(())
    } else {
        Err(Outcome::Failed(format!("{id} is not enrolled")))
    }
}

fn policy(args: &[String]) -> Result<(), Outcome> {
    let args = Args::parse(args, &["policy"])?;
    let usage = || UsageError("usage: tunnelward policy test --policy <file> <cases>".into());
    let ([command, cases], Some(file)) = (args.positional.as_slice(), args.get("policy")) else {
        return Err(usage().into());
    };
    if command != "test" {
        return Err(usage().into());
    }
    let (report, passed) =
        policy::test(Path::new(file), Path::new(cases)).map_err(Outcome::Failed)?;
    println!("{report}");
    passed
        .then_some(())
        .ok_or_else(|| Outcome::Failed("a policy case failed".into()))
}

fn audit_usage() -> UsageError {
    UsageError("usage: tunnelward audit keygen|verify|export (see --help)".into())
}

fn audit_keygen(args: &Args) -> Result<(), Outcome> {
    let out = args.get("out").ok_or_else(audit_usage)?;
    let (public, pseudonym) = audit::keygen(Path::new(out)).map_err(Outcome::Failed)?;
    println!("{out}\n{}\n{}", public.display(), pseudonym.display());
    Ok(())
}

fn audit_verify(args: &Args, log: &str) -> Result<(), Outcome> {
    let keys = args.get("key").ok_or_else(audit_usage)?;
    let keys: Vec<_> = keys.split(',').map(std::path::PathBuf::from).collect();
    let report = audit::verify_log(Path::new(log), &keys).map_err(Outcome::Failed)?;
    println!("{report}");
    Ok(())
}

fn audit(args: &[String]) -> Result<(), Outcome> {
    let args = Args::parse(args, &["out", "key"])?;
    match args.positional.as_slice() {
        [command] if command == "keygen" => audit_keygen(&args),
        [command, log] if command == "verify" => audit_verify(&args, log),
        [command, log] if command == "export" => {
            audit::export(Path::new(log)).map_err(Outcome::Failed)
        }
        _ => Err(audit_usage().into()),
    }
}

fn receipt(args: &[String]) -> Result<(), Outcome> {
    let args = Args::parse(args, &["key"])?;
    let usage = || UsageError("usage: tunnelward receipt verify --key <file.pub> <receipt>".into());
    let ([command, receipt], Some(key)) = (args.positional.as_slice(), args.get("key")) else {
        return Err(usage().into());
    };
    if command != "verify" {
        return Err(usage().into());
    }
    let fields = audit::verify_receipt(Path::new(key), receipt).map_err(Outcome::Failed)?;
    println!("{fields}");
    Ok(())
}

type Command = fn(&[String]) -> Result<(), Outcome>;

/// Every command, by the names that call it.
const COMMANDS: [(&[&str], Command); 12] = [
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
    (&["providers"], providers),
    (&["enrol"], enrol),
    (&["policy"], policy),
    (&["audit"], audit),
    (&["receipt"], receipt),
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
