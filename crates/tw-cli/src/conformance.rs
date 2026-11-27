// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward conformance`: the conformance kit against a gateway.

use std::path::Path;
use std::time::Duration;

use tunnelward_conformance::{Report, Target, run};

use crate::args::{Args, UsageError};
use crate::{Outcome, config};

/// Where the gateway is and who the kit connects as.
pub(crate) struct Options<'a> {
    pub(crate) gateway: &'a str,
    pub(crate) server_name: &'a str,
    pub(crate) ca: &'a Path,
    pub(crate) cert: &'a Path,
    pub(crate) key: &'a Path,
    pub(crate) route: Option<&'a str>,
    pub(crate) timeout: Duration,
}

/// The target `options` describe; its SPIFFE ID is the certificate's.
fn target(options: &Options<'_>) -> Result<Target, String> {
    let identity = config::identity(options.cert, options.key)?;
    let leaf = identity
        .chain
        .first()
        .ok_or_else(|| format!("{}: no certificate", options.cert.display()))?;
    let spiffe_id = tunnelward_identity::spiffe_id(leaf)
        .map_err(|e| format!("{}: {e}", options.cert.display()))?;
    let roots = config::roots(options.ca)?;
    let target = Target::new(
        options.gateway,
        options.server_name,
        &roots,
        &identity,
        spiffe_id,
    )?
    .with_timeout(options.timeout);
    Ok(match options.route {
        Some(route) => target.with_route(route),
        None => target,
    })
}

/// Runs every check; the report, whether or not they all passed.
pub(crate) fn check(options: &Options<'_>) -> Result<Report, String> {
    let target = target(options)?;
    let runtime = tokio::runtime::Runtime::new().map_err(|e| format!("cannot start: {e}"))?;
    Ok(runtime.block_on(run(&target)))
}

/// A required `--flag`.
fn required<'a>(args: &'a Args, flag: &str) -> Result<&'a str, UsageError> {
    args.get(flag)
        .ok_or_else(|| UsageError(format!("conformance needs --{flag}")))
}

/// Whether `--format` asks for JSON.
fn json(args: &Args) -> Result<bool, UsageError> {
    match args.get("format") {
        None | Some("text") => Ok(false),
        Some("json") => Ok(true),
        Some(other) => Err(UsageError(format!("'--format': cannot use {other:?}"))),
    }
}

/// The options `args` give, every required flag present.
fn options(args: &Args) -> Result<Options<'_>, UsageError> {
    Ok(Options {
        gateway: required(args, "gateway")?,
        server_name: required(args, "server-name")?,
        ca: Path::new(required(args, "ca")?),
        cert: Path::new(required(args, "cert")?),
        key: Path::new(required(args, "key")?),
        route: args.get("route"),
        timeout: Duration::from_secs(args.parsed("timeout-secs")?.unwrap_or(5)),
    })
}

/// Prints `report` as text or JSON.
fn print(report: &Report, json: bool) -> Result<(), Outcome> {
    if json {
        let text =
            serde_json::to_string_pretty(report).map_err(|e| Outcome::Failed(e.to_string()))?;
        println!("{text}");
    } else {
        println!("{report}");
    }
    Ok(())
}

/// `tunnelward conformance`: fails unless every check passed.
pub(crate) fn command(args: &[String]) -> Result<(), Outcome> {
    let known = [
        "gateway",
        "server-name",
        "ca",
        "cert",
        "key",
        "route",
        "timeout-secs",
        "format",
    ];
    let args = Args::parse(args, &known)?;
    let json = json(&args)?;
    let report = check(&options(&args)?).map_err(Outcome::Failed)?;
    print(&report, json)?;
    if report.passed() {
        Ok(())
    } else {
        Err(Outcome::Failed("conformance: a check failed".into()))
    }
}
