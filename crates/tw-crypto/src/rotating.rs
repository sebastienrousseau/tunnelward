// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A client certificate that can be replaced while the client runs, for
//! short-lived X.509-SVIDs: each new handshake presents the identity
//! current at that moment; established connections keep theirs.

use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use rustls::client::ResolvesClientCert;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, SignatureScheme};

use crate::config::VERSIONS;
use crate::{Error, Identity, KeyExchange, provider};

/// The client certificate a [`client_config_rotating`] configuration
/// presents, replaceable with [`RotatingIdentity::set`].
pub struct RotatingIdentity {
    current: RwLock<Arc<CertifiedKey>>,
}

impl fmt::Debug for RotatingIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotatingIdentity").finish_non_exhaustive()
    }
}

/// `identity` loaded for signing, its key checked against its certificate.
fn certified(identity: Identity) -> Result<Arc<CertifiedKey>, Error> {
    let provider = provider(KeyExchange::default());
    Ok(Arc::new(CertifiedKey::from_der(
        identity.chain,
        identity.key,
        &provider,
    )?))
}

impl RotatingIdentity {
    /// Starts with `identity`.
    ///
    /// # Errors
    ///
    /// [`Error::Tls`] for a key rustls cannot load or that is not the
    /// certificate's.
    pub fn new(identity: Identity) -> Result<Arc<Self>, Error> {
        Ok(Arc::new(Self {
            current: RwLock::new(certified(identity)?),
        }))
    }

    /// The leaf certificate presented now.
    #[must_use]
    pub fn leaf(&self) -> rustls::pki_types::CertificateDer<'static> {
        let current = self.current.read().unwrap_or_else(PoisonError::into_inner);
        current
            .cert
            .first()
            .cloned()
            .unwrap_or_else(|| Vec::new().into())
    }

    /// Presents `identity` from the next handshake on.
    ///
    /// # Errors
    ///
    /// As [`RotatingIdentity::new`]; the current identity is kept.
    pub fn set(&self, identity: Identity) -> Result<(), Error> {
        let next = certified(identity)?;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = next;
        Ok(())
    }
}

impl ResolvesClientCert for RotatingIdentity {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(
            self.current
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        )
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// [`crate::client_config`], presenting whatever `identity` holds at each
/// handshake.
///
/// # Errors
///
/// [`Error::Tls`] if rustls refuses the protocol versions.
pub fn client_config_rotating(
    roots: Arc<RootCertStore>,
    identity: Arc<RotatingIdentity>,
    kx: KeyExchange,
    alpn: &[&[u8]],
) -> Result<ClientConfig, Error> {
    let mut config = ClientConfig::builder_with_provider(provider(kx))
        .with_protocol_versions(VERSIONS)?
        .with_root_certificates(roots)
        .with_client_cert_resolver(identity);
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}
