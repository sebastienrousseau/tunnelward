// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward gateway --config <file>`: runs a gateway from its file.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tunnelward_gateway::Gateway;

use crate::config;
use crate::serve::{Listeners, bind, until_one_stops};

/// Binds every listener, then serves until one fails.
pub(crate) async fn run(path: &Path) -> Result<(), String> {
    let file = config::load(path)?;
    let checked = config::check(path, file).map_err(|problems| problems.join("\n"))?;
    // At once: a file renewed from here on is seen as a change.
    let watch = Watch {
        seen: stamps(&checked.watched),
        files: checked.watched,
        every: checked.reload_every,
    };
    let gateway = Gateway::new(checked.gateway);
    let listen = &checked.listen;
    let admin = match listen.admin {
        Some(addr) => Some((bind(addr).await?, checked.admin)),
        None => None,
    };
    let listeners = Listeners {
        connectors: bind(listen.connectors).await?,
        ingress: bind(listen.ingress).await?,
        admin,
    };
    println!("tunnelward gateway: {}", listeners.describe());
    let reload = tokio::spawn(reload(path.to_owned(), gateway.clone(), watch));
    let stopped = until_one_stops(&gateway, listeners).await;
    reload.abort();
    stopped
}

/// The files to watch for renewal, when they were last seen, and how
/// often to look.
struct Watch {
    files: Vec<PathBuf>,
    seen: Vec<Option<SystemTime>>,
    every: Duration,
}

/// Each file's modification time, `None` where it cannot be read.
fn stamps(files: &[PathBuf]) -> Vec<Option<SystemTime>> {
    files
        .iter()
        .map(|f| std::fs::metadata(f).and_then(|m| m.modified()).ok())
        .collect()
}

/// Every `every`, looks for changed files; when one changed, checks the
/// whole file again and swaps in its TLS configurations (G16). A file
/// that fails its checks leaves the running configuration in place.
async fn reload(path: PathBuf, gateway: Gateway, watch: Watch) {
    let Watch {
        mut files,
        mut seen,
        every,
    } = watch;
    loop {
        tokio::time::sleep(every).await;
        let now = stamps(&files);
        if now == seen {
            continue;
        }
        seen = now;
        match config::load(&path)
            .and_then(|file| config::check(&path, file).map_err(|p| p.join("; ")))
        {
            Ok(checked) => {
                gateway.set_tls(checked.gateway.tls.clone());
                gateway.set_ingress_tls(checked.gateway.ingress.tls.clone());
                seen = stamps(&checked.watched);
                files = checked.watched;
                println!("tunnelward gateway: certificates reloaded");
            }
            Err(e) => {
                eprintln!(
                    "tunnelward gateway: not reloaded, keeping the running certificates: {e}"
                );
            }
        }
    }
}
