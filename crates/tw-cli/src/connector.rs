// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward connector --config <file>`: a connector in front of a local
//! service, from its TOML file.
//!
//! ```toml
//! [gateway]
//! address = "gateway.example.org:7443"  # host:port; a name is looked up again every minute
//! server_name = "gateway.example.org"   # the name in the gateway's certificate
//! ca = "gateway-ca.crt"                 # PEM roots the gateway's certificate chains to
//!
//! [identity]                            # an X.509-SVID for spiffe_id, from
//! spiffe_id = "spiffe://example.org/ns/prod/sa/payments"
//! cert = "connector.crt"                # PEM files, read again when they
//! key = "connector.key"                 # change (every reload_secs, 10)
//! # workload_api = "unix:///run/spire/sockets/agent.sock"   # or the SPIFFE
//! #                                     # Workload API, rotating as it sends
//! # [identity.enrol]                    # or enrol with the gateway (a
//! # url = "https://gateway.example.org:8443"  # one-time token, then
//! # token_file = "enrol.token"          # renewal; TUNNELWARD_ENROL_TOKEN
//! # state_dir = "state"                 # if no file); SVID and key kept here
//! # ca = "ingress-ca.crt"               # optional: roots for the ingress
//!
//! [register]
//! routes = ["mcp/payments"]
//! domains = []                          # optional
//! capacity = 64                         # optional
//! attestation = "passmcp.bundle.json"   # optional: a signed passmcp
//!                                       # statement, read at every
//!                                       # registration (ADR 0009)
//!
//! [register.describe]                   # optional (ADR 0017): report the
//! path = "/mcp"                         # MCP server and guard its tools;
//! on_change = "block"                   # the HTTP endpoint (stdio: unused);
//!                                       # or "reregister"
//!
//! [target]                              # see backend.rs: or a stdio command
//! url = "http://127.0.0.1:8080"         # or unix:/path/to/socket
//!
//! [blind]                               # optional, experimental: open
//!                                       # gateway-blind calls (see blind.rs)
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use tunnelward_connector::{
    Config as Session, Connector, ConnectorConfig, Forward, Gateways, OnChange, Pinned, StdioBridge,
};
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{KeyExchange, RotatingIdentity, client_config_rotating};
use tunnelward_proto::{
    ALPN, ConnectorId, Limits, PROTOCOL_VERSION, Register, is_domain, is_route, is_spiffe_id,
};

use crate::config::{Problems, identity, resolve, roots};
use crate::svid::{self, Source, claims_its_certificate};

/// How often a gateway name is looked up again.
const DNS_REFRESH: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct File {
    gateway: GatewayPart,
    identity: IdentityPart,
    register: RegisterPart,
    target: crate::backend::TargetPart,
    blind: Option<crate::blind::Section>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayPart {
    address: String,
    server_name: String,
    ca: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityPart {
    spiffe_id: String,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    workload_api: Option<String>,
    reload_secs: Option<u64>,
    enrol: Option<EnrolPart>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrolPart {
    url: String,
    token_file: Option<PathBuf>,
    state_dir: PathBuf,
    ca: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterPart {
    routes: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    capacity: Option<u32>,
    attestation: Option<PathBuf>,
    describe: Option<DescribePart>,
}

/// `[register.describe]` (ADR 0017).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DescribePart {
    #[serde(default = "mcp_path")]
    path: String,
    #[serde(default)]
    on_change: OnChangePart,
}

fn mcp_path() -> String {
    "/mcp".into()
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum OnChangePart {
    #[default]
    Block,
    Reregister,
}

/// What to describe the server with: the HTTP path and what a change does.
type Describe = (String, OnChange);

fn describe(file: &File, problems: &mut Problems) -> Option<Describe> {
    let part = file.register.describe.as_ref()?;
    if !part.path.starts_with('/') {
        problems.push(format!(
            "[register.describe] path {:?}: give a path starting with /",
            part.path
        ));
    }
    let on_change = match part.on_change {
        OnChangePart::Block => OnChange::Block,
        OnChangePart::Reregister => OnChange::Reregister,
    };
    Some((part.path.clone(), on_change))
}

/// Whether a TOML text is a connector's file: it has a `[target]`.
pub(crate) fn is_connector_file(text: &str) -> bool {
    text.parse::<toml::Table>()
        .is_ok_and(|t| t.contains_key("target"))
}

pub(crate) fn load(path: &Path) -> Result<File, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// `host:port` as fixed addresses, or as a name to look up.
fn gateways(address: &str) -> Result<Gateways, String> {
    if let Ok(addr) = address.parse::<SocketAddr>() {
        return Ok(Gateways::Static(vec![addr]));
    }
    let (name, port) = address
        .rsplit_once(':')
        .ok_or_else(|| format!("[gateway] address {address:?}: give host:port"))?;
    let port = port
        .parse()
        .map_err(|_| format!("[gateway] address {address:?}: bad port"))?;
    Ok(Gateways::Dns {
        name: name.to_owned(),
        port,
        refresh: DNS_REFRESH,
    })
}

/// The routes, domains, identity and capacity, each checked.
fn register(file: &File, problems: &mut Problems) -> Register {
    let r = &file.register;
    let bad_routes = r.routes.iter().filter(|x| !is_route(x));
    problems.extend(bad_routes.map(|x| format!("[register] routes: {x:?} is not a route")));
    let bad_domains = r.domains.iter().filter(|x| !is_domain(x));
    problems.extend(bad_domains.map(|x| format!("[register] domains: {x:?} is not a domain")));
    if r.routes.is_empty() {
        problems.push("[register] routes: claim at least one route".into());
    }
    if !is_spiffe_id(&file.identity.spiffe_id) {
        problems.push(format!(
            "[identity] spiffe_id {:?} is not a SPIFFE ID",
            file.identity.spiffe_id
        ));
    }
    Register {
        version: PROTOCOL_VERSION,
        connector_id: ConnectorId([0; 16]),
        spiffe_id: file.identity.spiffe_id.clone(),
        routes: r.routes.clone(),
        domains: r.domains.clone(),
        mcp: None,
        attestation: None,
        capacity: r.capacity.unwrap_or(64),
    }
}

/// Where the SVID comes from: the files (loaded once now, so a file
/// for another identity fails the check), the Workload API endpoint, or
/// enrolment with the gateway.
fn source(base: &Path, id: &IdentityPart) -> Result<Source, String> {
    match (&id.cert, &id.key, &id.workload_api, &id.enrol) {
        (Some(cert), Some(key), None, None) => {
            let (cert, key) = (resolve(base, cert), resolve(base, key));
            claims_its_certificate(&identity(&cert, &key)?, &id.spiffe_id)?;
            let every = Duration::from_secs(id.reload_secs.unwrap_or(10).max(1));
            Ok(Source::Files { cert, key, every })
        }
        #[cfg(unix)]
        (None, None, Some(endpoint), None) => tunnelward_identity::workload::socket_path(endpoint)
            .map(Source::Workload)
            .map_err(|e| format!("[identity] workload_api: {e}")),
        (None, None, None, Some(enrol)) => enrolment(base, enrol).map(Source::Enrol),
        _ => Err(
            "[identity]: give cert and key, workload_api (Unix only), or [identity.enrol]".into(),
        ),
    }
}

fn enrolment(base: &Path, part: &EnrolPart) -> Result<crate::enrolled::Enrol, String> {
    if !part.url.starts_with("https://") {
        return Err(format!(
            "[identity.enrol] url {:?}: give an https:// URL",
            part.url
        ));
    }
    let roots = crate::agents::system_roots(part.ca.as_ref().map(|ca| resolve(base, ca)))
        .map_err(|e| format!("[identity.enrol] ca: {e}"))?;
    Ok(crate::enrolled::Enrol {
        url: part.url.clone(),
        token_file: part.token_file.as_ref().map(|t| resolve(base, t)),
        state_dir: resolve(base, &part.state_dir),
        roots,
    })
}

/// `[blind]`, checked: gateway-blind mode needs an HTTP target.
fn blind(base: &Path, file: &File, problems: &mut Problems) -> Option<tunnelward_connector::Blind> {
    let blind = (file.blind.as_ref()).and_then(|b| crate::blind::check(base, b, problems))?;
    if file.target.is_stdio() {
        problems.push("[blind]: gateway-blind mode needs an HTTP [target]".into());
        return None;
    }
    Some(blind)
}

/// A file that passed every check: everything but the SVID itself.
pub(crate) struct Checked {
    gateways: Gateways,
    target: crate::backend::Backend,
    register: Register,
    roots: Arc<RootCertStore>,
    server_name: ServerName<'static>,
    address: String,
    source: Source,
    attestation: Option<PathBuf>,
    blind: Option<tunnelward_connector::Blind>,
    describe: Option<Describe>,
}

/// `result`'s value, or its error added to `problems`.
fn note<T>(problems: &mut Problems, result: Result<T, String>) -> Option<T> {
    result.map_err(|e| problems.push(e)).ok()
}

/// Every check on `file`, read from `path`.
pub(crate) fn check(path: &Path, file: &File) -> Result<Checked, Problems> {
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let mut problems = Problems::new();
    let gateways = note(&mut problems, gateways(&file.gateway.address));
    let target = note(&mut problems, crate::backend::backend(&file.target));
    let source = note(&mut problems, source(base, &file.identity));
    let roots = note(&mut problems, roots(&resolve(base, &file.gateway.ca)));
    let name = &file.gateway.server_name;
    let server_name = note(
        &mut problems,
        ServerName::try_from(name.clone())
            .map_err(|e| format!("[gateway] server_name {name:?}: {e}")),
    );
    let register = register(file, &mut problems);
    let blind = blind(base, file, &mut problems);
    let describe = describe(file, &mut problems);
    let attestation = file.register.attestation.as_ref().map(|p| resolve(base, p));
    if let Some(path) = attestation.as_ref().filter(|p| !p.is_file()) {
        problems.push(format!(
            "[register] attestation: {} is not a file",
            path.display()
        ));
    }
    match (gateways, target, source, roots, server_name) {
        (Some(gateways), Some(target), Some(source), Some(roots), Some(server_name))
            if problems.is_empty() =>
        {
            Ok(Checked {
                gateways,
                target,
                register,
                roots,
                server_name,
                address: file.gateway.address.clone(),
                source,
                attestation,
                blind,
                describe,
            })
        }
        _ => Err(problems),
    }
}

/// The connector's configuration, presenting `identity` at each
/// handshake.
fn config(checked: Checked, identity: Arc<RotatingIdentity>) -> Result<ConnectorConfig, String> {
    let tls = client_config_rotating(checked.roots, identity, KeyExchange::default(), &[ALPN])
        .map_err(|e| format!("[identity]: {e}"))?;
    let session = Session {
        gateway: checked.address,
        server_name: checked.server_name,
        tls: Arc::new(tls),
        register: checked.register,
        limits: Limits::default(),
        handshake_timeout: Duration::from_secs(10),
        attestation_file: checked.attestation,
        pinned: None,
    };
    Ok(ConnectorConfig::new(checked.gateways, session))
}

/// Runs the connector until the process stops.
pub(crate) async fn run(path: &Path) -> Result<(), String> {
    let file = load(path)?;
    let mut checked = check(path, &file).map_err(|p| p.join("\n"))?;
    checked.register.connector_id = fresh_id()?;
    let (identity, keeper) =
        svid::start(checked.source.clone(), checked.register.spiffe_id.clone()).await?;
    let backend = checked.target.clone();
    let blind = checked.blind.take();
    let describe = checked.describe.take();
    let mut config = config(checked, identity)?;
    println!("tunnelward connector: {}", backend.describe());
    let pinned = match describe {
        Some((path, on_change)) => Some(Pinned::new(described(&backend, &path).await?, on_change)),
        None => None,
    };
    config.session.pinned.clone_from(&pinned);
    let connector = start(config, backend, blind, pinned);
    let events = connector.events();
    tokio::select! {
        () = report(events) => {}
        () = crate::signal::stop_asked() => stop(connector).await,
    }
    keeper.abort();
    Ok(())
}

/// What the server says it is, asked before the first registration.
async fn described(
    backend: &crate::backend::Backend,
    path: &str,
) -> Result<tunnelward_connector::Described, String> {
    let described = match backend {
        crate::backend::Backend::Http(target) => forward(target.clone(), None).describe(path).await,
        crate::backend::Backend::Stdio(stdio) => StdioBridge::new(stdio.clone()).describe().await,
    }
    .map_err(|e| format!("[register.describe]: {e}"))?;
    let d = described.descriptor();
    println!("tunnelward connector: serving {} {}", d.name, d.version);
    Ok(described)
}

/// Starts serving `backend`, held to `pinned` when there is one.
fn start(
    config: ConnectorConfig,
    backend: crate::backend::Backend,
    blind: Option<tunnelward_connector::Blind>,
    pinned: Option<Pinned>,
) -> Connector {
    match (backend, pinned) {
        (crate::backend::Backend::Http(target), Some(p)) => {
            Connector::start(config, forward(target, blind).with_pinned(p))
        }
        (crate::backend::Backend::Http(target), None) => {
            Connector::start(config, forward(target, blind))
        }
        (crate::backend::Backend::Stdio(stdio), Some(p)) => {
            Connector::start(config, StdioBridge::new(stdio).with_pinned(p))
        }
        (crate::backend::Backend::Stdio(stdio), None) => {
            Connector::start(config, StdioBridge::new(stdio))
        }
    }
}

/// The forwarder to an HTTP target, opening sealed calls with `blind`.
fn forward(
    target: tunnelward_connector::Target,
    blind: Option<tunnelward_connector::Blind>,
) -> Forward {
    let forward = Forward::new(target, Duration::from_secs(30));
    match blind {
        Some(blind) => forward.with_blind(blind),
        None => forward,
    }
}

/// A random connector id.
fn fresh_id() -> Result<ConnectorId, String> {
    let mut id = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| "no randomness for the connector id".to_owned())?;
    Ok(ConnectorId(id))
}

/// How long a stopping connector gives requests in flight.
const DRAIN: Duration = Duration::from_secs(30);

/// Stops on a signal: GOAWAY on every connection, so the gateways route
/// nothing new here, and up to [`DRAIN`] for requests in flight (G7).
async fn stop(connector: Connector) {
    println!(
        "tunnelward connector: stopping, letting requests finish for up to {}s",
        DRAIN.as_secs()
    );
    let completed = connector.shutdown(DRAIN).await;
    println!("tunnelward connector: stopped; every request finished: {completed}");
}

/// Prints the connector's events until it stops.
async fn report(
    mut events: tokio::sync::broadcast::Receiver<tunnelward_connector::ConnectorEvent>,
) {
    loop {
        match events.recv().await {
            Ok(event) => println!("tunnelward connector: {event:?}"),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        }
    }
}
