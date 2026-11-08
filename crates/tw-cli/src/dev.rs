// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward dev`: a gateway and a connector in one process, in front
//! of a local service, for trying Tunnelward out.
//!
//! The connector dials the gateway over the same mutual TLS a real
//! deployment uses, with throwaway certificates made at startup
//! ([`crate::devcert`]). Every listener is on loopback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use tunnelward_connector::{
    Config as Session, Connector, ConnectorConfig, Forward, Gateways, Target,
};
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_crypto::rustls::pki_types::{CertificateDer, ServerName};
use tunnelward_crypto::{ClientAuth, Identity, KeyExchange, client_config, server_config};
use tunnelward_gateway::{AdminConfig, Config, Gateway};
use tunnelward_proto::{ALPN, ConnectorId, Limits, PROTOCOL_VERSION, Register};

use crate::devcert::self_signed;
use crate::serve::{Listeners, bind, until_one_stops};

/// The name in the development gateway's certificate.
const GATEWAY_NAME: &str = "gateway.dev.tunnelward.invalid";
/// The name in the development connector's certificate.
const CONNECTOR_NAME: &str = "connector.dev.tunnelward.invalid";
/// How long the connector may take to register before `dev` gives up.
const READY_WITHIN: Duration = Duration::from_secs(10);

/// What `tunnelward dev` was asked for.
pub(crate) struct Dev {
    /// The local service, `host:port`.
    pub(crate) to: String,
    /// Where agents connect.
    pub(crate) listen: SocketAddr,
    /// The route the connector claims; `*` takes every request.
    pub(crate) route: String,
    /// Where the admin API listens, if anywhere.
    pub(crate) admin: Option<SocketAddr>,
}

type Error = Box<dyn std::error::Error + Send + Sync>;

/// `http://host:port` or `host:port` to `host:port`.
pub(crate) fn target_addr(to: &str) -> Result<String, String> {
    let addr = to
        .strip_prefix("http://")
        .unwrap_or(to)
        .trim_end_matches('/');
    if addr.contains("://") || addr.contains('/') || !addr.contains(':') {
        return Err(format!(
            "'--to {to}': give the local service as http://host:port"
        ));
    }
    Ok(addr.to_owned())
}

fn trusting(cert: CertificateDer<'static>) -> Result<Arc<RootCertStore>, Error> {
    let mut roots = RootCertStore::empty();
    roots.add(cert)?;
    Ok(Arc::new(roots))
}

fn connector_id() -> Result<ConnectorId, Error> {
    let mut id = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| "no randomness for the connector id")?;
    Ok(ConnectorId(id))
}

/// The supervised connector's configuration: `identity`, trusting only
/// `gateway_cert`, for the gateway at `gateway`.
fn connector(
    dev: &Dev,
    identity: Identity,
    gateway: SocketAddr,
    gateway_cert: CertificateDer<'static>,
) -> Result<ConnectorConfig, Error> {
    let tls = client_config(
        trusting(gateway_cert)?,
        Some(identity),
        KeyExchange::default(),
        &[ALPN],
    )?;
    let session = Session {
        gateway: gateway.to_string(),
        server_name: ServerName::try_from(GATEWAY_NAME)?.to_owned(),
        tls: Arc::new(tls),
        register: Register {
            version: PROTOCOL_VERSION,
            connector_id: connector_id()?,
            spiffe_id: "spiffe://dev.tunnelward.invalid/connector".into(),
            routes: vec![dev.route.clone()],
            domains: Vec::new(),
            mcp: None,
            attestation: None,
            capacity: 64,
        },
        limits: Limits::default(),
        handshake_timeout: Duration::from_secs(5),
    };
    Ok(ConnectorConfig::new(
        Gateways::Static(vec![gateway]),
        session,
    ))
}

/// A gateway trusting only `connector_cert`, with its own fresh identity.
fn gateway(
    connector_cert: CertificateDer<'static>,
) -> Result<(Gateway, CertificateDer<'static>), Error> {
    let (identity, cert) = self_signed(GATEWAY_NAME)?;
    let auth = ClientAuth::Required(trusting(connector_cert)?);
    let tls = server_config(identity, auth, KeyExchange::default(), &[ALPN])?;
    Ok((Gateway::new(Config::new(Arc::new(tls))), cert))
}

/// Waits until the connector's route is registered.
async fn registered(gateway: &Gateway) -> Result<(), Error> {
    let deadline = tokio::time::Instant::now() + READY_WITHIN;
    while gateway.routes().is_empty() {
        if tokio::time::Instant::now() >= deadline {
            return Err("the connector did not register in time".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

fn loopback_only(dev: &Dev) -> Result<(), Error> {
    for addr in [Some(dev.listen), dev.admin].into_iter().flatten() {
        if !addr.ip().is_loopback() {
            return Err(format!("{addr}: tunnelward dev listens on loopback only").into());
        }
    }
    Ok(())
}

/// The ingress and admin listeners, and the connector listener on a
/// free loopback port, with where the connector and agents connect.
async fn listeners(dev: &Dev) -> Result<(Listeners, SocketAddr, SocketAddr), String> {
    let admin = match dev.admin {
        Some(addr) => Some((bind(addr).await?, AdminConfig::default())),
        None => None,
    };
    let listeners = Listeners {
        connectors: bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?,
        ingress: bind(dev.listen).await?,
        admin,
    };
    let at = |l: &tokio::net::TcpListener| l.local_addr().map_err(|e| e.to_string());
    let (connectors, agents) = (at(&listeners.connectors)?, at(&listeners.ingress)?);
    Ok((listeners, connectors, agents))
}

/// The connector in front of `to`, once its route is registered.
async fn start_connector(
    dev: &Dev,
    gateway: &Gateway,
    at: SocketAddr,
    (identity, gateway_cert): (Identity, CertificateDer<'static>),
    to: &str,
) -> Result<Connector, Error> {
    let config = connector(dev, identity, at, gateway_cert)?;
    let forward = Forward::new(
        Target::Http {
            addr: to.to_owned(),
        },
        Duration::from_secs(30),
    );
    let started = Connector::start(config, forward);
    registered(gateway).await?;
    Ok(started)
}

/// Runs until a listener fails.
pub(crate) async fn run(dev: Dev) -> Result<(), Error> {
    let to = target_addr(&dev.to)?;
    loopback_only(&dev)?;
    let (connector_identity, connector_cert) = self_signed(CONNECTOR_NAME)?;
    let (gateway, gateway_cert) = gateway(connector_cert)?;
    let (listeners, at, agents) = listeners(&dev).await?;
    let serving = gateway.clone();
    let servers = tokio::spawn(async move { until_one_stops(&serving, listeners).await });
    let _connector =
        start_connector(&dev, &gateway, at, (connector_identity, gateway_cert), &to).await?;
    println!(
        "tunnelward dev: ready. http://{agents} -> http://{to} (route {})",
        dev.route
    );
    Ok(servers.await??)
}
