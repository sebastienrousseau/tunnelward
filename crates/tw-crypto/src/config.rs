// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! rustls server and client configurations.

use core::fmt;
use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::{Identity, KeyExchange, provider};

/// Only TLS 1.3. TLS 1.2 support is not compiled in.
pub(crate) static VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// Whether a server asks clients for a certificate.
#[derive(Debug, Clone)]
pub enum ClientAuth {
    /// A client must present a certificate chaining to one of these roots.
    /// Used on the connector listener (mutual TLS).
    Required(Arc<RootCertStore>),
    /// No client certificate. Used on agent ingress, where clients
    /// authenticate with OAuth bearer tokens instead.
    None,
    /// Ask for a certificate, accept any or none, and check only that the
    /// client holds its key: for tokens bound to a client certificate
    /// (RFC 8705) on agent ingress. The certificate proves nothing else.
    AnyHolder,
}

/// A TLS configuration could not be built.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// rustls refused the configuration, for example a key that does not
    /// match its certificate.
    Tls(rustls::Error),
    /// The client-certificate verifier could not be built, for example from
    /// an empty root store.
    Verifier(rustls::server::VerifierBuilderError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls(e) => write!(f, "TLS configuration: {e}"),
            Self::Verifier(e) => write!(f, "client certificate verifier: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tls(e) => Some(e),
            Self::Verifier(e) => Some(e),
        }
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Self::Tls(e)
    }
}

fn verifier(auth: ClientAuth, kx: KeyExchange) -> Result<Arc<dyn ClientCertVerifier>, Error> {
    match auth {
        ClientAuth::Required(roots) => {
            WebPkiClientVerifier::builder_with_provider(roots, provider(kx))
                .build()
                .map_err(Error::Verifier)
        }
        ClientAuth::None => Ok(WebPkiClientVerifier::no_client_auth()),
        ClientAuth::AnyHolder => Ok(Arc::new(crate::holder::AnyHolder::new(
            provider(kx).signature_verification_algorithms,
        ))),
    }
}

/// A TLS 1.3 server presenting `identity`, offering `alpn` protocols in
/// order.
///
/// # Errors
///
/// [`Error::Verifier`] for an unusable root store, [`Error::Tls`] for a
/// key that does not match its certificate.
pub fn server_config(
    identity: Identity,
    auth: ClientAuth,
    kx: KeyExchange,
    alpn: &[&[u8]],
) -> Result<ServerConfig, Error> {
    let mut config = ServerConfig::builder_with_provider(provider(kx))
        .with_protocol_versions(VERSIONS)?
        .with_client_cert_verifier(verifier(auth, kx)?)
        .with_single_cert(identity.chain, identity.key)?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// A TLS 1.3 client trusting `roots`, presenting `identity` when the
/// server asks for a certificate, and offering `alpn` protocols in order.
///
/// # Errors
///
/// [`Error::Tls`] for a key that does not match its certificate.
pub fn client_config(
    roots: Arc<RootCertStore>,
    identity: Option<Identity>,
    kx: KeyExchange,
    alpn: &[&[u8]],
) -> Result<ClientConfig, Error> {
    let builder = ClientConfig::builder_with_provider(provider(kx))
        .with_protocol_versions(VERSIONS)?
        .with_root_certificates(roots);
    let mut config = match identity {
        Some(id) => builder.with_client_auth_cert(id.chain, id.key)?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}
