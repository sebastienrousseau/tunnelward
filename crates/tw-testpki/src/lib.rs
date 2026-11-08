// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TEST-ONLY certificates and keys, written by `scripts/gen-test-pki.sh`.
//!
//! Two CAs: [`CA`], which the tests trust, and [`OTHER_CA`], which they do
//! not. The keys protect nothing; never use them outside tests.

use std::sync::Arc;

use tunnelward_crypto::Identity;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_crypto::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A certificate and its PKCS#8 key, both DER.
pub type Pair = (&'static [u8], &'static [u8]);

/// The CA the tests trust.
pub const CA: &[u8] = include_bytes!("../pki/ca.der");
/// A CA nothing trusts.
pub const OTHER_CA: &[u8] = include_bytes!("../pki/other-ca.der");
/// Server leaf for `gateway.test`, issued by [`CA`].
pub const GATEWAY: Pair = (
    include_bytes!("../pki/gateway.der"),
    include_bytes!("../pki/gateway.key"),
);
/// Client leaf issued by [`CA`]: an X.509-SVID for [`CONNECTOR_ID`], also
/// naming `connector.test`.
pub const CONNECTOR: Pair = (
    include_bytes!("../pki/connector.der"),
    include_bytes!("../pki/connector.key"),
);
/// The SPIFFE ID in [`CONNECTOR`]'s certificate.
pub const CONNECTOR_ID: &str = "spiffe://example.org/connector";
/// Client leaf issued by [`CA`]: an X.509-SVID for [`RIVAL_ID`].
pub const RIVAL: Pair = (
    include_bytes!("../pki/rival.der"),
    include_bytes!("../pki/rival.key"),
);
/// The SPIFFE ID in [`RIVAL`]'s certificate.
pub const RIVAL_ID: &str = "spiffe://example.org/rival";
/// Client leaf issued by [`CA`] with a DNS name and no SPIFFE ID.
pub const PLAIN: Pair = (
    include_bytes!("../pki/plain.der"),
    include_bytes!("../pki/plain.key"),
);
/// Client leaf issued by [`CA`] naming two SPIFFE IDs, which an
/// X.509-SVID may not.
pub const TWO_IDS: Pair = (
    include_bytes!("../pki/two-ids.der"),
    include_bytes!("../pki/two-ids.key"),
);
/// Client leaf for `intruder.test`, issued by [`OTHER_CA`].
pub const INTRUDER: Pair = (
    include_bytes!("../pki/intruder.der"),
    include_bytes!("../pki/intruder.key"),
);
/// The name in [`GATEWAY`]'s certificate.
pub const GATEWAY_NAME: &str = "gateway.test";

/// An [`Identity`] from a certificate and key pair.
#[must_use]
pub fn identity((cert, key): Pair) -> Identity {
    Identity {
        chain: vec![CertificateDer::from(cert.to_vec())],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
    }
}

/// A root store holding one CA certificate.
///
/// # Errors
///
/// The certificate does not parse.
pub fn roots(ca: &[u8]) -> Result<Arc<RootCertStore>, tunnelward_crypto::rustls::Error> {
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(ca.to_vec()))?;
    Ok(Arc::new(store))
}
