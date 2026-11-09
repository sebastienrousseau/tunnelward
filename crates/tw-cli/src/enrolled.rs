// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! A connector whose SVID comes from the gateway's enrolment: the first
//! start redeems a one-time token, and the SVID and its key are kept in
//! `state_dir` (`svid.crt`, `svid.key`) so a restart needs no token.
//! Two thirds into each SVID's life the connector renews it with a new
//! key; a failed renewal is tried again every 30 s until it works.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_crypto::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tunnelward_crypto::{Identity, RotatingIdentity};
use tunnelward_gateway::{request_enrolment, request_renewal};
use tunnelward_identity::enrol;

use crate::svid::claims_its_certificate;

/// Where the token comes from when no `token_file` is set.
pub(crate) const TOKEN_ENV: &str = "TUNNELWARD_ENROL_TOKEN";
/// How long to wait before trying a failed renewal again.
const RETRY: Duration = Duration::from_secs(30);
/// The least time between renewals, whatever the SVID's lifetime.
const LEAST: u64 = 1;

/// Enrolment as the connector's file configures it.
#[derive(Debug, Clone)]
pub(crate) struct Enrol {
    /// The gateway's ingress, `https://host[:port]`.
    pub(crate) url: String,
    /// The one-time token's file; [`TOKEN_ENV`] when `None`.
    pub(crate) token_file: Option<PathBuf>,
    /// Where the SVID and its key are kept.
    pub(crate) state_dir: PathBuf,
    /// Roots the ingress certificate chains to.
    pub(crate) roots: Arc<RootCertStore>,
}

/// An SVID and its PKCS#8 key, both DER.
#[derive(Clone)]
struct Held {
    cert: Vec<u8>,
    key: Vec<u8>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Held {
    fn identity(&self) -> Identity {
        Identity {
            chain: vec![CertificateDer::from(self.cert.clone())],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone())),
        }
    }

    /// When to renew: two thirds into the certificate's life.
    fn renew_at(&self) -> u64 {
        enrol::validity(&self.cert).map_or(0, |(from, until)| from + (until - from) * 2 / 3)
    }

    fn expired(&self, at: u64) -> bool {
        enrol::validity(&self.cert).is_none_or(|(_, until)| at >= until)
    }
}

/// The kept SVID and key, when both read and belong together.
fn load(dir: &Path) -> Option<Held> {
    use tunnelward_crypto::rustls::pki_types::pem::PemObject;
    let cert = crate::config::chain(&dir.join("svid.crt")).ok()?;
    let PrivateKeyDer::Pkcs8(key) = PrivateKeyDer::from_pem_file(dir.join("svid.key")).ok()? else {
        return None;
    };
    let held = Held {
        cert: cert.first()?.to_vec(),
        key: key.secret_pkcs8_der().to_vec(),
    };
    enrol::key_matches(&held.cert, &held.key).then_some(held)
}

/// Writes `text` to `path` through a temporary file, owner-only.
fn replace(path: &Path, text: &str) -> Result<(), String> {
    let temporary = path.with_extension("new");
    let _stale = std::fs::remove_file(&temporary);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let fail = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut file = options.open(&temporary).map_err(fail)?;
    std::io::Write::write_all(&mut file, text.as_bytes()).map_err(fail)?;
    std::fs::rename(&temporary, path).map_err(fail)
}

/// Keeps `held` in `dir`. A crash between the two writes leaves a pair
/// that does not match, which [`load`] treats as nothing kept.
fn save(dir: &Path, held: &Held) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    replace(&dir.join("svid.key"), &enrol::pem("PRIVATE KEY", &held.key))?;
    replace(
        &dir.join("svid.crt"),
        &enrol::pem("CERTIFICATE", &held.cert),
    )
}

fn token(enrol: &Enrol) -> Result<String, String> {
    let text = match &enrol.token_file {
        Some(path) => {
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?
        }
        None => std::env::var(TOKEN_ENV)
            .map_err(|_| format!("no enrolment token: set token_file or {TOKEN_ENV}"))?,
    };
    Ok(text.trim().to_owned())
}

async fn enrol_with_token(enrol: &Enrol) -> Result<Held, String> {
    let key = enrol::new_key().map_err(|e| e.to_string())?;
    let cert = request_enrolment(&enrol.url, &token(enrol)?, &key, enrol.roots.clone())
        .await
        .map_err(|e| format!("enrolment: {e}"))?;
    Ok(Held { cert, key })
}

async fn renew(enrol: &Enrol, held: &Held) -> Result<Held, String> {
    let key = enrol::new_key().map_err(|e| e.to_string())?;
    let cert = request_renewal(
        &enrol.url,
        (&held.cert, &held.key),
        &key,
        enrol.roots.clone(),
    )
    .await
    .map_err(|e| format!("renewal: {e}"))?;
    Ok(Held { cert, key })
}

/// The kept SVID, when it is for `spiffe_id` and not expired.
fn kept(enrol: &Enrol, spiffe_id: &str) -> Option<Held> {
    load(&enrol.state_dir)
        .filter(|h| !h.expired(now()) && claims_its_certificate(&h.identity(), spiffe_id).is_ok())
}

/// The SVID to start with: the kept one, renewed if due; else a new one
/// from the token.
async fn first(enrol: &Enrol, spiffe_id: &str) -> Result<Held, String> {
    let held = match kept(enrol, spiffe_id) {
        Some(held) if now() < held.renew_at() => return Ok(held),
        Some(held) => match renew(enrol, &held).await {
            Ok(next) => next,
            Err(e) => {
                println!("tunnelward connector: {e}; using the kept SVID meanwhile");
                return Ok(held);
            }
        },
        None => enrol_with_token(enrol).await?,
    };
    claims_its_certificate(&held.identity(), spiffe_id)?;
    save(&enrol.state_dir, &held)?;
    Ok(held)
}

/// The first SVID, and a task that renews it until aborted.
pub(crate) async fn start(
    enrol: Enrol,
    spiffe_id: String,
) -> Result<(Arc<RotatingIdentity>, JoinHandle<()>), String> {
    let held = first(&enrol, &spiffe_id).await?;
    let rotating =
        RotatingIdentity::new(held.identity()).map_err(|e| format!("[identity]: {e}"))?;
    let keeper = tokio::spawn(keep(enrol, spiffe_id, held, rotating.clone()));
    Ok((rotating, keeper))
}

/// Renews `held` when due, for ever.
async fn keep(enrol: Enrol, spiffe_id: String, mut held: Held, rotating: Arc<RotatingIdentity>) {
    loop {
        let wait = held.renew_at().saturating_sub(now()).max(LEAST);
        tokio::time::sleep(Duration::from_secs(wait)).await;
        match renew_and_apply(&enrol, &spiffe_id, &held, &rotating).await {
            Ok(next) => held = next,
            Err(e) => {
                println!("tunnelward connector: {e}; trying again in {RETRY:?}");
                tokio::time::sleep(RETRY).await;
            }
        }
    }
}

async fn renew_and_apply(
    enrol: &Enrol,
    spiffe_id: &str,
    held: &Held,
    rotating: &RotatingIdentity,
) -> Result<Held, String> {
    let next = renew(enrol, held).await?;
    let id = next.identity();
    claims_its_certificate(&id, spiffe_id)?;
    save(&enrol.state_dir, &next)?;
    rotating.set(id).map_err(|e| e.to_string())?;
    println!("tunnelward connector: SVID for {spiffe_id} renewed");
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tunnelward_crypto::{ClientAuth, KeyExchange, server_config};
    use tunnelward_gateway::{Config, Enrolment, Gateway, Tokens};
    use tunnelward_identity::enrol::Ca;
    use tunnelward_proto::ALPN;
    use tunnelward_testpki as pki;

    type Res = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    const ID: &str = "spiffe://example.org/connector";

    /// A gateway enrolling on a TLS ingress, each SVID valid for
    /// `lifetime`: its tokens and its ingress URL.
    async fn gateway(
        name: &str,
        lifetime: Duration,
    ) -> Result<(Tokens, String, PathBuf), Box<dyn std::error::Error + Send + Sync>> {
        let dir = std::env::temp_dir().join(format!("tw-enrolled-{name}-{}", std::process::id()));
        let _fresh = std::fs::remove_dir_all(&dir);
        let (cert, key) = Ca::generate("CA", Duration::from_secs(86_400), SystemTime::now())?;
        let tokens = Tokens::new(dir.join("tokens"));
        let enrolment = Enrolment::new(Ca::load(&cert, &key)?, tokens.clone(), lifetime)?;
        let id = || pki::identity(pki::GATEWAY);
        let connectors = server_config(
            id(),
            ClientAuth::Required(pki::roots(pki::CA)?),
            KeyExchange::default(),
            &[ALPN],
        )?;
        let mut config = Config::new(Arc::new(connectors));
        let ingress = server_config(
            id(),
            ClientAuth::None,
            KeyExchange::default(),
            &[b"http/1.1"],
        )?;
        config.ingress.tls = Some(Arc::new(ingress));
        config.ingress.enrolment = Some(Arc::new(enrolment));
        let gateway = Gateway::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("https://{}", listener.local_addr()?);
        tokio::spawn(async move { gateway.serve_ingress(listener).await });
        Ok((tokens, url, dir))
    }

    fn enrol_config(
        url: String,
        dir: &Path,
    ) -> Result<Enrol, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Enrol {
            url,
            token_file: Some(dir.join("token")),
            state_dir: dir.join("state"),
            roots: pki::roots(pki::CA)?,
        })
    }

    #[tokio::test]
    async fn a_token_enrols_and_a_restart_needs_none() -> Res {
        let (tokens, url, dir) = gateway("restart", Duration::from_secs(3600)).await?;
        let token = tokens.issue(ID, Duration::from_secs(60), SystemTime::now())?;
        std::fs::write(dir.join("token"), format!("{token}\n"))?;
        let config = enrol_config(url, &dir)?;
        let (rotating, keeper) = start(config.clone(), ID.into()).await?;
        keeper.abort();
        let first = rotating.leaf().to_vec();
        assert_eq!(tunnelward_identity::spiffe_id(&first)?, ID);
        std::fs::remove_file(dir.join("token"))?;
        let (again, keeper) = start(config, ID.into()).await?;
        keeper.abort();
        assert_eq!(again.leaf().as_ref(), first.as_slice(), "the kept SVID");
        Ok(())
    }

    #[tokio::test]
    async fn a_due_svid_is_renewed_with_a_new_key() -> Res {
        // Ten seconds of life, backdated a minute: due at once.
        let (tokens, url, dir) = gateway("renew", Duration::from_secs(10)).await?;
        let token = tokens.issue(ID, Duration::from_secs(60), SystemTime::now())?;
        std::fs::write(dir.join("token"), token)?;
        let config = enrol_config(url, &dir)?;
        let held = first(&config, ID).await?;
        let renewed = first(&config, ID).await?;
        assert_ne!(renewed.cert, held.cert);
        assert_ne!(
            enrol::public_key(&renewed.cert),
            enrol::public_key(&held.cert)
        );
        let kept = load(&config.state_dir).ok_or("nothing kept")?;
        assert_eq!(kept.cert, renewed.cert, "the renewal is kept");
        Ok(())
    }

    #[tokio::test]
    async fn an_svid_for_another_identity_is_refused() -> Res {
        let (tokens, url, dir) = gateway("other", Duration::from_secs(3600)).await?;
        let token = tokens.issue(
            "spiffe://example.org/rival",
            Duration::from_secs(60),
            SystemTime::now(),
        )?;
        std::fs::write(dir.join("token"), token)?;
        let err = first(&enrol_config(url, &dir)?, ID)
            .await
            .err()
            .unwrap_or_default();
        assert!(err.contains("is not the certificate's"), "{err}");
        assert!(load(&dir.join("state")).is_none(), "nothing kept");
        Ok(())
    }

    #[test]
    fn a_mismatched_pair_is_not_kept() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("tw-enrolled-pair-{}", std::process::id()));
        let _fresh = std::fs::remove_dir_all(&dir);
        let (cert, _) = pki::CONNECTOR;
        save(
            &dir,
            &Held {
                cert: cert.to_vec(),
                key: enrol::new_key()?,
            },
        )?;
        assert!(load(&dir).is_none());
        Ok(())
    }
}
