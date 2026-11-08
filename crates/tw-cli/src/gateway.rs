// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward gateway --config <file>`: runs a gateway from its file.

use std::path::Path;

use tunnelward_gateway::Gateway;

use crate::config;
use crate::serve::{Listeners, bind, until_one_stops};

/// Binds every listener, then serves until one fails.
pub(crate) async fn run(path: &Path) -> Result<(), String> {
    let file = config::load(path)?;
    let checked = config::check(path, file).map_err(|problems| problems.join("\n"))?;
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
    let admin_note = listen.admin.map(|a| format!(", admin on {a}"));
    println!(
        "tunnelward gateway: connectors on {}, agents on {}{}",
        listen.connectors,
        listen.ingress,
        admin_note.unwrap_or_default()
    );
    until_one_stops(&gateway, listeners).await
}
