// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! How the checked sections of a gateway file become its
//! [`Config`]: the optional sections that switch features on, and the
//! files to watch for changes.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tunnelward_gateway::{Cidr, Config, CorsRule, IngressConfig};

use super::{File, Problems, resolve};

/// The ingress's TLS, trusted proxies, PROXY protocol and CORS rules.
pub(super) fn with_ingress(
    ingress: &mut IngressConfig,
    tls: Option<tunnelward_crypto::rustls::ServerConfig>,
    trusted: Vec<Cidr>,
    cors: Vec<CorsRule>,
    file: &File,
) {
    ingress.tls = tls.map(Arc::new);
    ingress.trusted_proxies = trusted;
    ingress.proxy_protocol = file.ingress.proxy_protocol;
    ingress.cors = cors;
}

/// Turns agent authorisation on when `[agents]` was given, saying
/// whether the ingress asks for client certificates; returns the key
/// sets to fetch and how often.
pub(super) fn with_agents(
    gateway: &mut Config,
    agents: Option<crate::agents::Checked>,
    certificates: bool,
) -> (Vec<Arc<tunnelward_gateway::KeySet>>, std::time::Duration) {
    match agents {
        Some(mut a) => {
            a.auth.certificate_bound = certificates;
            gateway.ingress.agent_auth = Some(a.auth);
            (a.fetched, a.refresh)
        }
        None => (Vec::new(), std::time::Duration::from_secs(600)),
    }
}

/// Turns provider tagging on when `[providers]` was given; returns the
/// snapshot to keep fresh and the signers' key sets to fetch.
pub(super) fn with_providers(
    gateway: &mut Config,
    providers: Option<crate::providers::Checked>,
) -> (
    Option<crate::providers::Loaded>,
    Vec<Arc<tunnelward_gateway::KeySet>>,
) {
    let Some(p) = providers else {
        return (None, Vec::new());
    };
    gateway.ingress.providers = p.snapshot.as_ref().map(|s| s.providers.clone());
    gateway.ingress.bot_auth = p.bot_auth;
    (p.snapshot, p.signer_keys)
}

/// The optional sections that switch features on, each checked.
pub(super) struct Sections {
    shared: Option<crate::state::Checked>,
    policy: Option<tunnelward_policy::Policy>,
    attestation: Option<Arc<tunnelward_attest::Admission>>,
    risk: Option<Arc<tunnelward_risk::Risk>>,
    otlp: Option<crate::observe::Otlp>,
    control: Option<crate::control::pull::Puller>,
}

/// The `[state]` store, the `[policy]`, the `[attestation]`, the
/// `[risk]`, the `[telemetry]` and the `[control]`, each checked.
pub(super) fn state_and_policy(base: &Path, file: &File, problems: &mut Problems) -> Sections {
    Sections {
        shared: (file.state.as_ref()).and_then(|s| crate::state::check(base, s, problems)),
        policy: (file.policy.as_ref()).and_then(|p| crate::policy::check(base, p, problems)),
        attestation: (file.attestation.as_ref())
            .and_then(|a| crate::attest::check(base, a, problems)),
        risk: (file.risk.as_ref()).and_then(|r| crate::observe::risk(r, problems)),
        otlp: (file.telemetry.as_ref()).and_then(|t| crate::observe::telemetry(base, t, problems)),
        control: (file.control.as_ref())
            .and_then(|c| crate::control::pull::check(base, c, file.policy.is_some(), problems)),
    }
}

/// Shares state through the `[state]` store when one was given, turns
/// the tool policy, admission by attestation (FR-5) and the risk score
/// (FR-16) on; returns the span exporter and the `[control]` puller to
/// start with the gateway. With `[control]` the gateway denies every
/// call until its first bundle (ADR 0012).
pub(super) fn with_state(
    gateway: &mut Config,
    sections: Sections,
) -> (
    Option<crate::observe::Otlp>,
    Option<crate::control::pull::Puller>,
) {
    let Sections {
        shared,
        policy,
        attestation,
        risk,
        otlp,
        control,
    } = sections;
    gateway.attestation = attestation;
    gateway.ingress.risk = risk;
    if let Some(s) = shared {
        gateway.state = s.state;
        gateway.ingress.rate_limit.gateways = s.gateways;
    }
    gateway.ingress.policy =
        policy.map(|p| Arc::new(p) as Arc<dyn tunnelward_gateway::PolicyEngine>);
    if control.is_some() {
        gateway.ingress.policy = Some(crate::control::pull::until_first_bundle());
    }
    (otlp, control)
}

/// The file and every certificate and key it names, to watch for
/// renewal (G16).
pub(super) fn watched(path: &Path, base: &Path, file: &File) -> Vec<PathBuf> {
    let tls = &file.tls;
    let mut watched = vec![path.to_owned()];
    watched.extend([&tls.cert, &tls.key, &tls.client_ca].map(|p| resolve(base, p)));
    watched.extend(
        [&file.ingress.cert, &file.ingress.key]
            .into_iter()
            .flatten()
            .map(|p| resolve(base, p)),
    );
    watched.extend(file.policy.as_ref().map(|p| p.path(base)));
    watched.extend(file.attestation.iter().flat_map(|a| a.paths(base)));
    watched
}
