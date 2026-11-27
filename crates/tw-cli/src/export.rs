// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `[audit.export]`: each audit entry, as an OCSF event, to a SIEM over
//! syslog, OTLP logs, or both (ADR 0013). The log file stays the record.
//!
//! ```toml
//! [audit.export]                  # limits optional; defaults shown
//! queue = 4096                    # lines waiting; more are dropped
//! batch = 256                     # events per send
//! every_ms = 1000                 # longest an event waits
//!
//! [audit.export.syslog]           # RFC 5424, octet-counted, over TLS
//! address = "siem.example.org:6514"
//! ca = "siem-ca.crt"              # optional: else the system roots
//! plain = false                   # true: plain TCP, loopback only
//! app_name = "tunnelward"
//! hostname = "gw-eu-1"            # optional: else "-"
//! facility = 13                   # 0 to 23; 13 is log audit
//! timeout_ms = 10000
//!
//! [audit.export.otlp]             # OTLP/HTTP JSON to <endpoint>/v1/logs
//! endpoint = "https://otel.example.org:4318"   # or http:// to loopback
//! ca = "collector-ca.crt"         # optional: else the system roots
//! service_name = "tunnelward"
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_crypto::{KeyExchange, client_config};
use tunnelward_gateway::{OtlpLogSettings, SiemSettings, SyslogSettings};

use crate::config::{Problems, resolve};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Section {
    queue: Option<usize>,
    batch: Option<usize>,
    every_ms: Option<u64>,
    syslog: Option<Syslog>,
    otlp: Option<Otlp>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Syslog {
    address: String,
    ca: Option<PathBuf>,
    #[serde(default)]
    plain: bool,
    app_name: Option<String>,
    hostname: Option<String>,
    facility: Option<u8>,
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Otlp {
    endpoint: String,
    ca: Option<PathBuf>,
    service_name: Option<String>,
}

/// The export `section` describes, every problem noted.
pub(crate) fn check(
    base: &Path,
    section: &Section,
    problems: &mut Problems,
) -> Option<SiemSettings> {
    let d = SiemSettings::new();
    let mut settings = SiemSettings::new();
    settings.queue = section.queue.unwrap_or(d.queue);
    settings.batch = section.batch.unwrap_or(d.batch);
    settings.every = section.every_ms.map_or(d.every, Duration::from_millis);
    let before = problems.len();
    settings.syslog = (section.syslog.as_ref()).and_then(|s| syslog(base, s, problems));
    settings.otlp = (section.otlp.as_ref()).and_then(|o| otlp(base, o, problems));
    if problems.len() == before
        && let Err(found) = settings.check()
    {
        problems.extend(found.into_iter().map(|p| format!("[audit.export] {p}")));
    }
    (problems.len() == before).then_some(settings)
}

fn syslog(base: &Path, section: &Syslog, problems: &mut Problems) -> Option<SyslogSettings> {
    let tls = if section.plain {
        None
    } else {
        let config = roots(base, section.ca.as_ref()).and_then(|roots| {
            client_config(roots, None, KeyExchange::default(), &[]).map_err(|e| e.to_string())
        });
        match config {
            Ok(config) => Some(Arc::new(config)),
            Err(e) => {
                problems.push(format!("[audit.export.syslog] ca: {e}"));
                return None;
            }
        }
    };
    let mut settings = SyslogSettings::new(section.address.clone(), tls);
    if let Some(app_name) = &section.app_name {
        settings.app_name.clone_from(app_name);
    }
    settings.hostname.clone_from(&section.hostname);
    settings.facility = section.facility.unwrap_or(settings.facility);
    settings.timeout = section
        .timeout_ms
        .map_or(settings.timeout, Duration::from_millis);
    Some(settings)
}

fn otlp(base: &Path, section: &Otlp, problems: &mut Problems) -> Option<OtlpLogSettings> {
    // Roots only for https://, as for spans: a loopback collector needs none.
    let roots = if section.endpoint.starts_with("https://") {
        roots(base, section.ca.as_ref())
            .map_err(|e| problems.push(format!("[audit.export.otlp] ca: {e}")))
            .ok()?
    } else {
        Arc::new(RootCertStore::empty())
    };
    let mut settings = OtlpLogSettings::new(section.endpoint.clone(), roots);
    if let Some(service) = &section.service_name {
        settings.service.clone_from(service);
    }
    Some(settings)
}

/// `ca` read, else the system roots.
fn roots(base: &Path, ca: Option<&PathBuf>) -> Result<Arc<RootCertStore>, String> {
    crate::agents::system_roots(ca.map(|c| resolve(base, c)))
}
