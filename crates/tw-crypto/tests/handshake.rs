// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-memory handshakes between configurations built by tw-crypto, with
//! certificates from a throwaway CA.

use std::sync::Arc;

use tw_crypto::rustls::pki_types::ServerName;
use tw_crypto::rustls::{
    ClientConfig, ClientConnection, Connection, NamedGroup, ProtocolVersion, ServerConfig,
    ServerConnection,
};
use tw_crypto::{ClientAuth, KeyExchange, client_config, negotiated_group, server_config};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

const ALPN: &[&[u8]] = &[b"tw/1"];
const SERVER_NAME: &str = "gateway.test";

use tw_testpki::{self as pki, identity, roots};

fn mtls() -> Res<ClientAuth> {
    Ok(ClientAuth::Required(roots(pki::CA)?))
}

fn server(auth: ClientAuth, kx: KeyExchange) -> Res<ServerConfig> {
    Ok(server_config(identity(pki::GATEWAY), auth, kx, ALPN)?)
}

fn client(cert: Option<pki::Pair>, kx: KeyExchange) -> Res<ClientConfig> {
    Ok(client_config(
        roots(pki::CA)?,
        cert.map(identity),
        kx,
        ALPN,
    )?)
}

/// Moves every pending TLS record from one side to the other.
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

fn handshake(
    client: ClientConfig,
    server: ServerConfig,
) -> Res<(ClientConnection, ServerConnection)> {
    let name = ServerName::try_from(SERVER_NAME)?;
    let mut c = Connection::Client(ClientConnection::new(Arc::new(client), name)?);
    let mut s = Connection::Server(ServerConnection::new(Arc::new(server))?);
    for _ in 0..8 {
        transfer(&mut c, &mut s)?;
        transfer(&mut s, &mut c)?;
        if !c.is_handshaking() && !s.is_handshaking() {
            if let (Connection::Client(c), Connection::Server(s)) = (c, s) {
                return Ok((c, s));
            }
            return Err("connection kinds swapped".into());
        }
    }
    Err("handshake did not finish".into())
}

#[test]
fn defaults_negotiate_the_hybrid_group_over_tls13() -> Res<()> {
    let kx = KeyExchange::default();
    let (c, s) = handshake(client(Some(pki::CONNECTOR), kx)?, server(mtls()?, kx)?)?;
    assert_eq!(negotiated_group(&c), Some(NamedGroup::X25519MLKEM768));
    assert_eq!(negotiated_group(&s), Some(NamedGroup::X25519MLKEM768));
    assert_eq!(c.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(s.alpn_protocol(), Some(&b"tw/1"[..]));
    assert!(s.peer_certificates().is_some_and(|chain| chain.len() == 1));
    Ok(())
}

#[test]
fn hybrid_only_on_both_sides_still_negotiates() -> Res<()> {
    let kx = KeyExchange::HybridOnly;
    let (c, _) = handshake(client(Some(pki::CONNECTOR), kx)?, server(mtls()?, kx)?)?;
    assert_eq!(negotiated_group(&c), Some(NamedGroup::X25519MLKEM768));
    Ok(())
}

/// A peer without post-quantum support: a server offering only X25519.
fn classical_server() -> Res<ServerConfig> {
    use tw_crypto::rustls::crypto::{CryptoProvider, aws_lc_rs};
    let provider = CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519],
        ..aws_lc_rs::default_provider()
    };
    let id = identity(pki::GATEWAY);
    Ok(ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&tw_crypto::rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(id.chain, id.key)?)
}

#[test]
fn hybrid_preferred_falls_back_to_x25519_for_a_classical_peer() -> Res<()> {
    let (c, _) = handshake(
        client(None, KeyExchange::HybridPreferred)?,
        classical_server()?,
    )?;
    assert_eq!(negotiated_group(&c), Some(NamedGroup::X25519));
    Ok(())
}

#[test]
fn hybrid_only_refuses_a_classical_peer() -> Res<()> {
    let result = handshake(client(None, KeyExchange::HybridOnly)?, classical_server()?);
    assert!(
        result.is_err(),
        "a classical-only peer must fail the handshake"
    );
    Ok(())
}

#[test]
fn mutual_tls_rejects_a_client_without_a_certificate() -> Res<()> {
    let kx = KeyExchange::default();
    assert!(handshake(client(None, kx)?, server(mtls()?, kx)?).is_err());
    Ok(())
}

#[test]
fn mutual_tls_rejects_a_certificate_from_another_ca() -> Res<()> {
    let kx = KeyExchange::default();
    assert!(handshake(client(Some(pki::INTRUDER), kx)?, server(mtls()?, kx)?).is_err());
    // The same certificate is accepted by a server that trusts its CA.
    let theirs = ClientAuth::Required(roots(pki::OTHER_CA)?);
    assert!(handshake(client(Some(pki::INTRUDER), kx)?, server(theirs, kx)?).is_ok());
    Ok(())
}

#[test]
fn no_client_auth_accepts_a_client_without_a_certificate() -> Res<()> {
    let kx = KeyExchange::default();
    let (_, s) = handshake(client(None, kx)?, server(ClientAuth::None, kx)?)?;
    assert!(s.peer_certificates().is_none());
    Ok(())
}

#[test]
fn identity_debug_never_prints_the_key() {
    let text = format!("{:?}", identity(pki::GATEWAY));
    assert!(
        text.contains("<redacted>") && !text.contains("Pkcs8"),
        "{text}"
    );
}
