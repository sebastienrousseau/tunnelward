// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A client certificate replaced between handshakes: each new handshake
//! presents the identity current at that moment.

use std::sync::Arc;

use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::rustls::{ClientConnection, Connection, ServerConfig, ServerConnection};
use tunnelward_crypto::{
    ClientAuth, KeyExchange, RotatingIdentity, client_config_rotating, server_config,
};
use tunnelward_testpki::{self as pki, identity, roots};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

const ALPN: &[&[u8]] = &[b"tw/1"];

fn server() -> Res<ServerConfig> {
    Ok(server_config(
        identity(pki::GATEWAY),
        ClientAuth::Required(roots(pki::CA)?),
        KeyExchange::default(),
        ALPN,
    )?)
}

fn transfer(from: &mut Connection, to: &mut Connection) -> Res<()> {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf)?;
    }
    let mut rd = &buf[..];
    while !rd.is_empty() {
        to.read_tls(&mut rd)?;
    }
    to.process_new_packets()?;
    Ok(())
}

/// Completes one handshake and returns the client certificate the
/// server received.
fn presented(rotating: &Arc<RotatingIdentity>) -> Res<Vec<u8>> {
    let (mut c, mut s) = connections(rotating)?;
    for _ in 0..8 {
        transfer(&mut c, &mut s)?;
        transfer(&mut s, &mut c)?;
        if let Some(leaf) = client_leaf(&s) {
            return leaf;
        }
    }
    Err("handshake did not finish".into())
}

/// A fresh client presenting `rotating`, and a server.
fn connections(rotating: &Arc<RotatingIdentity>) -> Res<(Connection, Connection)> {
    let client = client_config_rotating(
        roots(pki::CA)?,
        rotating.clone(),
        KeyExchange::default(),
        ALPN,
    )?;
    let name = ServerName::try_from(pki::GATEWAY_NAME)?;
    let c = Connection::Client(ClientConnection::new(Arc::new(client), name)?);
    let s = Connection::Server(ServerConnection::new(Arc::new(server()?))?);
    Ok((c, s))
}

/// The client certificate a server got, once its handshake is done.
fn client_leaf(s: &Connection) -> Option<Res<Vec<u8>>> {
    let Connection::Server(server) = s else {
        return Some(Err("not a server".into()));
    };
    if server.is_handshaking() {
        return None;
    }
    let leaf = server.peer_certificates().and_then(|c| c.first());
    Some(
        leaf.map(|c| c.to_vec())
            .ok_or_else(|| "no client certificate".into()),
    )
}

#[test]
fn each_handshake_presents_the_current_identity() -> Res<()> {
    let rotating = RotatingIdentity::new(identity(pki::CONNECTOR))?;
    assert_eq!(presented(&rotating)?, pki::CONNECTOR.0);
    rotating.set(identity(pki::RIVAL))?;
    assert_eq!(presented(&rotating)?, pki::RIVAL.0);
    assert_eq!(rotating.leaf().as_ref(), pki::RIVAL.0);
    Ok(())
}

#[test]
fn a_key_that_is_not_the_certificates_is_refused_and_changes_nothing() -> Res<()> {
    let rotating = RotatingIdentity::new(identity(pki::CONNECTOR))?;
    let mismatched = identity((pki::RIVAL.0, pki::CONNECTOR.1));
    assert!(rotating.set(mismatched).is_err());
    assert_eq!(presented(&rotating)?, pki::CONNECTOR.0);
    Ok(())
}
