// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward doctor [--config <file>]`: checks the machine and, given a
//! file, the configuration and its listeners. One line per check.

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tunnelward_crypto::KeyExchange;

use crate::config;

/// 2026-01-01T00:00:00Z: a clock before this is wrong, and certificates
/// would look not yet valid.
const EARLIEST_SANE_CLOCK: Duration = Duration::from_secs(1_767_225_600);

/// One check's outcome.
pub(crate) struct Finding {
    pub(crate) ok: bool,
    pub(crate) what: String,
}

fn finding(ok: bool, what: impl Into<String>) -> Finding {
    Finding {
        ok,
        what: what.into(),
    }
}

fn clock() -> Finding {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    finding(
        now >= EARLIEST_SANE_CLOCK,
        "the system clock is after 2026-01-01",
    )
}

fn post_quantum() -> Finding {
    let groups = KeyExchange::default().groups();
    let first = groups.first().map(|g| format!("{:?}", g.name()));
    finding(
        first.as_deref() == Some("X25519MLKEM768"),
        format!(
            "TLS offers X25519MLKEM768 first (offers {})",
            first.unwrap_or_default()
        ),
    )
}

/// Whether `addr` can be bound now; the socket is released at once.
fn bindable(name: &str, addr: SocketAddr) -> Finding {
    match TcpListener::bind(addr) {
        Ok(_) => finding(true, format!("{name} address {addr} is free")),
        Err(e) => finding(false, format!("{name} address {addr}: {e}")),
    }
}

fn configuration(path: &Path) -> Vec<Finding> {
    let file = match config::load(path) {
        Ok(file) => file,
        Err(e) => return vec![finding(false, e)],
    };
    let listen = &file.listen;
    let mut found = vec![
        bindable("connector", listen.connectors),
        bindable("ingress", listen.ingress),
    ];
    if let Some(admin) = listen.admin {
        found.push(bindable("admin", admin));
    }
    match config::check(path, file) {
        Ok(_) => found.push(finding(
            true,
            format!("{} passes every check", path.display()),
        )),
        Err(problems) => found.extend(problems.into_iter().map(|p| finding(false, p))),
    }
    found
}

/// Every check, the machine's first.
pub(crate) fn run(path: Option<&Path>) -> Vec<Finding> {
    let mut found = vec![clock(), post_quantum()];
    if let Some(path) = path {
        found.extend(configuration(path));
    }
    found
}
