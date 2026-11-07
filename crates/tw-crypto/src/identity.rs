// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! A certificate chain and its private key.

use core::fmt;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// What an endpoint presents: its certificate chain, leaf first, and the
/// leaf's private key. `Debug` never prints the key.
pub struct Identity {
    /// The certificate chain, leaf first.
    pub chain: Vec<CertificateDer<'static>>,
    /// The leaf certificate's private key.
    pub key: PrivateKeyDer<'static>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("chain", &self.chain.len())
            .field("key", &"<redacted>")
            .finish()
    }
}
