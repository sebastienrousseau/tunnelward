// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A client certificate as proof of holding a key, not of identity: the
//! server asks for one, accepts any (or none), and checks only that the
//! client signed the TLS 1.3 handshake with the certificate's key. That
//! is what a certificate-bound OAuth token (RFC 8705) needs: the token
//! names the certificate, and the handshake proves the caller holds it.
//! Nothing here trusts what the certificate says.

use rustls::DistinguishedName;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// Asks for a client certificate, accepts any or none, and verifies
/// the handshake signature with its key.
#[derive(Debug)]
pub(crate) struct AnyHolder {
    algorithms: WebPkiSupportedAlgorithms,
}

impl AnyHolder {
    pub(crate) fn new(algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self { algorithms }
    }
}

impl ClientCertVerifier for AnyHolder {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// Any certificate: who it names is not trusted, only its key used.
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    /// TLS 1.2 is not compiled in; refuse rather than pretend.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
