// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tunnelward TLS configuration with hybrid post-quantum key exchange.
//!
//! Every Tunnelward TLS endpoint is built here, so every hop gets the same
//! policy (ADR 0002): TLS 1.3 only, the AWS-LC provider, and the hybrid
//! group `X25519MLKEM768` offered first. [`KeyExchange::HybridOnly`]
//! removes the classical fallback for deployments that must never
//! negotiate a group a quantum computer could break.
//!
//! ```
//! use tunnelward_crypto::{KeyExchange, negotiated_group, provider};
//!
//! let p = provider(KeyExchange::HybridOnly);
//! assert_eq!(p.kx_groups.len(), 1);
//! assert_eq!(format!("{:?}", p.kx_groups[0].name()), "X25519MLKEM768");
//! # let _ = negotiated_group;
//! ```

pub mod composite;
mod config;
mod holder;
mod identity;
mod rotating;

pub use config::{ClientAuth, Error, client_config, server_config};
pub use identity::Identity;
pub use rotating::{RotatingIdentity, client_config_rotating};
pub use rustls;

use std::sync::Arc;

use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::{CommonState, NamedGroup};

/// Which key-exchange groups an endpoint offers or accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyExchange {
    /// `X25519MLKEM768` first, then `X25519` and `secp256r1` for peers
    /// without post-quantum support. The default.
    #[default]
    HybridPreferred,
    /// `X25519MLKEM768` only. A peer without it fails the handshake.
    HybridOnly,
}

impl KeyExchange {
    /// The groups, most preferred first.
    #[must_use]
    pub fn groups(self) -> Vec<&'static dyn SupportedKxGroup> {
        match self {
            Self::HybridPreferred => vec![
                kx_group::X25519MLKEM768,
                kx_group::X25519,
                kx_group::SECP256R1,
            ],
            Self::HybridOnly => vec![kx_group::X25519MLKEM768],
        }
    }
}

/// The AWS-LC crypto provider restricted to `kx`'s groups.
#[must_use]
pub fn provider(kx: KeyExchange) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        kx_groups: kx.groups(),
        ..aws_lc_rs::default_provider()
    })
}

/// The key-exchange group a finished handshake used, for logs and for
/// `tunnelward crypto report`. `None` while still handshaking.
#[must_use]
pub fn negotiated_group(conn: &CommonState) -> Option<NamedGroup> {
    conn.negotiated_key_exchange_group()
        .map(SupportedKxGroup::name)
}
