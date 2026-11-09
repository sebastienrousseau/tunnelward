// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway's `[enrolment]` section and the `tunnelward enrol`
//! commands: make the enrolment CA, issue a one-time token for a SPIFFE
//! ID, revoke an identity.
//!
//! ```toml
//! [enrolment]                   # optional: connectors with no SVID enrol
//! ca_cert = "enrol-ca.crt"      # PEM, from `tunnelward enrol ca`
//! ca_key = "enrol-ca.key"       # PEM PKCS#8 (ECDSA P-256)
//! tokens = "enrolment"          # the token store, a directory
//! svid_ttl_secs = 3600          # how long an issued SVID lasts
//! ```
//!
//! The connector listener trusts `ca_cert` as well as `[tls] client_ca`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use tunnelward_crypto::rustls::pki_types::pem::PemObject;
use tunnelward_crypto::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tunnelward_gateway::{Enrolment, Tokens};
use tunnelward_identity::enrol::{self, Ca};

use crate::config::{Problems, chain, resolve};

/// Shortest and longest SVID lifetime the section accepts.
const TTL_RANGE: std::ops::RangeInclusive<u64> = 300..=7 * 86_400;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Section {
    ca_cert: PathBuf,
    ca_key: PathBuf,
    tokens: PathBuf,
    svid_ttl_secs: Option<u64>,
}

impl Section {
    /// The token store, relative to the file's directory `base`.
    pub(crate) fn tokens(&self, base: &Path) -> Tokens {
        Tokens::new(resolve(base, &self.tokens))
    }
}

/// A checked section: the enrolment, and its CA for the connector
/// listener to trust.
pub(crate) struct Checked {
    pub(crate) enrolment: Arc<Enrolment>,
    pub(crate) ca: CertificateDer<'static>,
}

fn load_ca(base: &Path, section: &Section) -> Result<Ca, String> {
    let cert_path = resolve(base, &section.ca_cert);
    let [cert] = chain(&cert_path)?.try_into().map_err(|_| {
        format!(
            "[enrolment] ca_cert {}: give exactly one certificate",
            cert_path.display()
        )
    })?;
    let key_path = resolve(base, &section.ca_key);
    let key = PrivateKeyDer::from_pem_file(&key_path)
        .map_err(|e| format!("[enrolment] ca_key {}: {e}", key_path.display()))?;
    Ca::load(cert.as_ref(), key.secret_der()).map_err(|e| format!("[enrolment]: {e}"))
}

/// Checks `section`; every problem goes to `problems`.
pub(crate) fn check(base: &Path, section: &Section, problems: &mut Problems) -> Option<Checked> {
    let ttl = section.svid_ttl_secs.unwrap_or(3600);
    if !TTL_RANGE.contains(&ttl) {
        problems.push(format!(
            "[enrolment] svid_ttl_secs {ttl}: give {} to {}",
            TTL_RANGE.start(),
            TTL_RANGE.end()
        ));
    }
    let ca = load_ca(base, section).map_err(|e| problems.push(e)).ok()?;
    let cert = CertificateDer::from(ca.certificate().to_vec());
    let enrolment = Enrolment::new(ca, section.tokens(base), Duration::from_secs(ttl))
        .map_err(|e| problems.push(format!("[enrolment]: {e}")))
        .ok()?;
    Some(Checked {
        enrolment: Arc::new(enrolment),
        ca: cert,
    })
}

/// Writes `text` to a new file `path`, readable by its owner only.
fn write_private(path: &Path, text: &str) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    std::io::Write::write_all(&mut file, text.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// `tunnelward enrol ca`: a new enrolment CA named `name`, valid for
/// `days`, written to `cert` and `key` (neither may exist).
pub(crate) fn make_ca(cert: &Path, key: &Path, name: &str, days: u64) -> Result<(), String> {
    let lifetime = Duration::from_secs(days * 86_400);
    let (der, pkcs8) =
        Ca::generate(name, lifetime, SystemTime::now()).map_err(|e| e.to_string())?;
    write_private(key, &enrol::pem("PRIVATE KEY", &pkcs8))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(cert)
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    std::io::Write::write_all(&mut file, enrol::pem("CERTIFICATE", &der).as_bytes())
        .map_err(|e| format!("{}: {e}", cert.display()))
}

/// The token store named by the gateway file at `config`.
pub(crate) fn store(config: &Path) -> Result<Tokens, String> {
    let file = crate::config::load(config)?;
    let base = config.parent().unwrap_or_else(|| Path::new("."));
    file.enrolment(base)
        .ok_or_else(|| format!("{}: no [enrolment] section", config.display()))
}

/// `tunnelward enrol token`: a one-time token for `spiffe_id`.
pub(crate) fn token(config: &Path, spiffe_id: &str, ttl: Duration) -> Result<String, String> {
    store(config)?
        .issue(spiffe_id, ttl, SystemTime::now())
        .map_err(|e| e.to_string())
}

/// `tunnelward enrol revoke`: stops `spiffe_id`'s renewals.
pub(crate) fn revoke(config: &Path, spiffe_id: &str) -> Result<bool, String> {
    store(config)?.revoke(spiffe_id).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Res = Result<(), Box<dyn std::error::Error>>;

    fn scratch(name: &str) -> std::io::Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!("tw-cli-enrol-{name}-{}", std::process::id()));
        let _fresh = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn section(ttl: Option<u64>) -> Section {
        Section {
            ca_cert: "ca.crt".into(),
            ca_key: "ca.key".into(),
            tokens: "tokens".into(),
            svid_ttl_secs: ttl,
        }
    }

    #[test]
    fn a_made_ca_loads_and_is_not_overwritten() -> Res {
        let dir = scratch("ca")?;
        make_ca(&dir.join("ca.crt"), &dir.join("ca.key"), "Test", 30)?;
        let mut problems = Problems::new();
        assert!(
            check(&dir, &section(None), &mut problems).is_some(),
            "{problems:?}"
        );
        assert!(make_ca(&dir.join("ca.crt"), &dir.join("other.key"), "Test", 30).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("ca.key"))?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        Ok(())
    }

    type Fallible<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    /// A gateway file in `dir` whose `[tls] client_ca` is a CA no test
    /// certificate chains to, with `[enrolment]`.
    fn gateway_file(dir: &Path) -> Fallible<PathBuf> {
        use tunnelward_testpki as pki;
        make_ca(&dir.join("ca.crt"), &dir.join("ca.key"), "Test", 30)?;
        for (name, label, der) in [
            ("gateway.crt", "CERTIFICATE", pki::GATEWAY.0),
            ("gateway.key", "PRIVATE KEY", pki::GATEWAY.1),
            ("other.crt", "CERTIFICATE", pki::OTHER_CA),
        ] {
            std::fs::write(dir.join(name), pki::pem(label, der))?;
        }
        let path = dir.join("gateway.toml");
        std::fs::write(
            &path,
            "[listen]\nconnectors = \"127.0.0.1:0\"\ningress = \"127.0.0.1:0\"\n\
             [tls]\ncert = \"gateway.crt\"\nkey = \"gateway.key\"\nclient_ca = \"other.crt\"\n\
             [enrolment]\nca_cert = \"ca.crt\"\nca_key = \"ca.key\"\ntokens = \"tokens\"\n",
        )?;
        Ok(path)
    }

    /// A registration with `addr` presenting an SVID `ca` issues.
    fn session(addr: String, ca: &Ca) -> Fallible<tunnelward_connector::Config> {
        use tunnelward_crypto::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
        use tunnelward_crypto::{Identity, KeyExchange, client_config};
        use tunnelward_testpki as pki;
        let key = enrol::new_key()?;
        let wanted = enrol::requested_key(&enrol::request(&key)?)?;
        let svid = ca.issue(ID, &wanted, Duration::from_secs(600), SystemTime::now())?;
        let identity = Identity {
            chain: vec![CertificateDer::from(svid)],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        };
        let alpn = [tunnelward_proto::ALPN];
        let tls = client_config(
            pki::roots(pki::CA)?,
            Some(identity),
            KeyExchange::default(),
            &alpn,
        )?;
        Ok(tunnelward_connector::Config {
            gateway: addr,
            server_name: ServerName::try_from(pki::GATEWAY_NAME)?.to_owned(),
            tls: Arc::new(tls),
            register: tunnelward_proto::Register {
                version: tunnelward_proto::PROTOCOL_VERSION,
                connector_id: tunnelward_proto::ConnectorId([1; 16]),
                spiffe_id: ID.into(),
                routes: vec!["mcp".into()],
                domains: Vec::new(),
                mcp: None,
                attestation: None,
                capacity: 1,
            },
            limits: tunnelward_proto::Limits::default(),
            handshake_timeout: Duration::from_secs(5),
        })
    }

    const ID: &str = "spiffe://example.org/connector";

    /// The gateway file's connector listener accepts an SVID the
    /// enrolment CA issued, though `[tls] client_ca` names another CA.
    #[tokio::test]
    async fn the_connector_listener_trusts_the_enrolment_ca() -> Fallible<()> {
        let dir = scratch("trust")?;
        let path = gateway_file(&dir)?;
        let checked =
            crate::config::check(&path, crate::config::load(&path)?).map_err(|p| p.join("; "))?;
        assert!(
            checked.gateway.ingress.enrolment.is_some(),
            "the ingress enrols"
        );
        let gateway = tunnelward_gateway::Gateway::new(checked.gateway);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();
        tokio::spawn(async move { gateway.serve_connectors(listener).await });
        let ca = load_ca(&dir, &section(None))?;
        assert!(
            tunnelward_connector::register(&session(addr, &ca)?)
                .await
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn a_lifetime_out_of_range_and_a_mismatched_key_are_problems() -> Res {
        let dir = scratch("problems")?;
        make_ca(&dir.join("ca.crt"), &dir.join("ca.key"), "Test", 30)?;
        let mut problems = Problems::new();
        let _checked = check(&dir, &section(Some(10)), &mut problems);
        assert!(problems.iter().any(|p| p.contains("svid_ttl_secs 10")));
        make_ca(&dir.join("b.crt"), &dir.join("b.key"), "Other", 30)?;
        let mut mixed = section(None);
        mixed.ca_key = "b.key".into();
        let mut problems = Problems::new();
        assert!(check(&dir, &mixed, &mut problems).is_none());
        assert!(
            problems
                .iter()
                .any(|p| p.contains("not the CA certificate's key"))
        );
        Ok(())
    }
}
