// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward control`: the control plane alpha (ADR 0012). Operators
//! publish tool policies through an API that takes their OIDC tokens;
//! gateways pull the newest signed bundle over mutual TLS.

mod api;
pub(crate) mod bundle;
mod file;
pub(crate) mod pull;
mod roles;
mod server;
mod store;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tokio_rustls::TlsAcceptor;

use crate::args::{Args, UsageError};
use crate::{Outcome, runtime};

/// `control --config <file>` or `control keygen --out <file>`.
pub(crate) fn command(args: &[String]) -> Result<(), Outcome> {
    if args.first().map(String::as_str) == Some("keygen") {
        let args = Args::parse(&args[1..], &["out"])?;
        let out = args
            .get("out")
            .ok_or_else(|| UsageError("control keygen needs '--out <file>'".into()))?;
        let public = crate::providers::keygen(Path::new(out)).map_err(Outcome::Failed)?;
        println!("{out}: signing key; gateways trust {}", public.display());
        return Ok(());
    }
    let args = Args::parse(args, &["config"])?;
    let path = args
        .get("config")
        .ok_or_else(|| UsageError("control needs '--config <file>'".into()))?;
    runtime()?
        .block_on(run(Path::new(path)))
        .map_err(Outcome::Failed)
}

/// Runs the control in `path` until a listener fails.
async fn run(path: &Path) -> Result<(), String> {
    let checked = file::check(path).map_err(|p| p.join("\n"))?;
    let store = store::Store::open(&checked.store_dir, checked.key)?;
    let audit = (checked.audit)
        .map(crate::audit::Checked::open)
        .transpose()
        .map_err(|e| format!("audit log: {e}"))?;
    for keys in &checked.operators.fetched {
        let (keys, every) = (keys.clone(), checked.operators.refresh);
        tokio::spawn(async move { keys.keep_fresh(every).await });
    }
    let control = Arc::new(server::Control {
        store,
        auth: checked.operators.auth,
        roles: checked.roles,
        gateways: checked.gateways,
        audit,
        fleet: Mutex::new(BTreeMap::new()),
    });
    let api = server::bind(checked.api).await?;
    let fleet = server::bind(checked.fleet).await?;
    println!(
        "tunnelward control: operators on {}, gateways on {}",
        addr(&api),
        addr(&fleet)
    );
    let api_task = server::serve_api(control.clone(), api, TlsAcceptor::from(checked.api_tls));
    let fleet_task = server::serve_fleet(control, fleet, TlsAcceptor::from(checked.fleet_tls));
    tokio::select! {
        r = api_task => r.map_err(|e| format!("operator listener: {e}")),
        r = fleet_task => r.map_err(|e| format!("fleet listener: {e}")),
    }
}

/// The address `listener` is bound to, for the startup line.
fn addr(listener: &tokio::net::TcpListener) -> String {
    listener
        .local_addr()
        .map_or_else(|e| e.to_string(), |a| a.to_string())
}
