// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! A gateway's `[control]`: pull the newest policy bundle and apply it
//! if it verifies, is newer than the one running, and passes the checks
//! a policy file gets (ADR 0012). Until the first bundle the gateway
//! denies every call: it fails closed.
//!
//! ```toml
//! [control]
//! url = "https://control.example.org:9444/v1/bundle"
//! ca = "control-ca.crt"             # roots the control's certificate chains to
//! cert = "gateway-svid.crt"         # this gateway's SPIFFE certificate
//! key = "gateway-svid.key"
//! public_key = "bundle.key.pub"     # bundles must verify under this key
//! every_secs = 30                   # how often to ask (1 to 3600)
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tunnelward_crypto::composite::PUBLIC_LEN;
use tunnelward_crypto::rustls::ClientConfig;
use tunnelward_crypto::{KeyExchange, client_config};
use tunnelward_gateway::{Gateway, PolicyEngine};
use tunnelward_policy::Policy;

use super::bundle::{self, Bundle, MAX_ENVELOPE};
use crate::config::{Problems, identity, resolve, roots};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Section {
    url: String,
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    public_key: PathBuf,
    every_secs: Option<u64>,
}

/// A checked `[control]`.
#[derive(Clone)]
pub(crate) struct Puller {
    url: String,
    tls: Arc<ClientConfig>,
    public: Vec<u8>,
    every: Duration,
}

impl std::fmt::Debug for Puller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Puller")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// Checks `section`, read from a file in `base`; `with_policy` when the
/// file also has `[policy]`, which `[control]` replaces.
pub(crate) fn check(
    base: &Path,
    section: &Section,
    with_policy: bool,
    problems: &mut Problems,
) -> Option<Puller> {
    if with_policy {
        problems.push(
            "[control] and [policy]: the policy comes from one of them; drop [policy]".into(),
        );
    }
    if !section.url.starts_with("https://") {
        problems.push(format!(
            "[control] url {:?}: give the https:// URL",
            section.url
        ));
    }
    let tls = client_tls(base, section)
        .map_err(|e| problems.push(format!("[control]: {e}")))
        .ok();
    let public = public_key(&resolve(base, &section.public_key))
        .map_err(|e| problems.push(format!("[control] public_key: {e}")))
        .ok();
    Some(Puller {
        url: section.url.clone(),
        tls: tls?,
        public: public?,
        every: Duration::from_secs(section.every_secs.unwrap_or(30).clamp(1, 3600)),
    })
}

/// The client configuration: this gateway's SPIFFE certificate, and
/// the roots the control's chains to.
fn client_tls(base: &Path, section: &Section) -> Result<Arc<ClientConfig>, String> {
    let id = identity(&resolve(base, &section.cert), &resolve(base, &section.key))?;
    let ca = roots(&resolve(base, &section.ca))?;
    client_config(ca, Some(id), KeyExchange::default(), &[b"http/1.1"])
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

fn public_key(path: &Path) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    tunnelward_audit::unhex(text.trim())
        .filter(|k| k.len() == PUBLIC_LEN)
        .ok_or_else(|| format!("{}: not a composite public key", path.display()))
}

/// The policy a gateway with `[control]` runs before its first bundle:
/// every call denied.
pub(crate) fn until_first_bundle() -> Arc<dyn PolicyEngine> {
    Arc::new(Policy::deny_by_default())
}

/// Asks every `every` and applies each newer bundle; runs until dropped.
/// A failure keeps the running policy and is reported when it changes.
pub(crate) async fn keep_pulling(puller: Puller, gateway: Gateway) {
    let mut have = 0;
    let mut last_error = None;
    loop {
        match newer(&puller, have).await {
            Ok(Some((bundle, policy))) => {
                gateway.set_policy(Some(Arc::new(policy)));
                have = bundle.version;
                last_error = None;
                println!(
                    "tunnelward gateway: policy bundle {} from {} applied",
                    bundle.version, bundle.publisher
                );
            }
            Ok(None) => last_error = None,
            Err(e) if last_error.as_ref() != Some(&e) => {
                eprintln!("tunnelward gateway: control: {e}; keeping the running policy");
                last_error = Some(e);
            }
            Err(_) => {}
        }
        tokio::time::sleep(puller.every).await;
    }
}

/// The newest bundle and its policy, if the control has one newer than
/// `have` that verifies and checks.
pub(crate) async fn newer(puller: &Puller, have: u64) -> Result<Option<(Bundle, Policy)>, String> {
    let url = format!("{}?have={have}", puller.url);
    let body = tunnelward_gateway::https_get_as(&url, puller.tls.clone(), MAX_ENVELOPE).await?;
    accept(&body, &puller.public, have)
}

/// The bundle in `envelope` and its policy, if it verifies under
/// `public`, is newer than `have`, and its policy checks.
fn accept(envelope: &[u8], public: &[u8], have: u64) -> Result<Option<(Bundle, Policy)>, String> {
    let bundle = bundle::open(envelope, public)?;
    if bundle.version <= have {
        return Ok(None);
    }
    let at = format!("bundle {}", bundle.version);
    let policy = crate::policy::parse(&bundle.policy, &at).map_err(|p| p.join("; "))?;
    Ok(Some((bundle, policy)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelward_crypto::composite::SigningKey;

    fn sealed(key: &SigningKey, version: u64, policy: &str) -> Vec<u8> {
        let bundle = Bundle {
            version,
            issued_ms: 0,
            publisher: "ops".into(),
            policy: policy.into(),
        };
        bundle::seal(&bundle, key).unwrap().into_bytes()
    }

    #[test]
    fn only_a_newer_verified_bundle_with_a_valid_policy_is_taken() {
        let key = SigningKey::generate().unwrap().0;
        let public = key.public_key();
        let good = sealed(&key, 4, "default = \"deny\"\n");
        assert_eq!(accept(&good, &public, 3).unwrap().unwrap().0.version, 4);
        assert!(
            accept(&good, &public, 4).unwrap().is_none(),
            "the same version"
        );
        assert!(
            accept(&good, &public, 9).unwrap().is_none(),
            "an older one: no rollback by replay"
        );
        let other = SigningKey::generate().unwrap().0.public_key();
        assert!(accept(&good, &other, 0).is_err(), "another key");
        let bad = sealed(&key, 5, "default = \"maybe\"\n");
        assert!(
            accept(&bad, &public, 4).is_err(),
            "a policy a file would fail"
        );
    }
}
