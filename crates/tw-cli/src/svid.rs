// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Where a connector's X.509-SVID comes from, and how it stays current:
//! files read again when they change, the SPIFFE Workload API's stream,
//! or enrolment with the gateway and renewal. Every SVID must be for the configured SPIFFE ID, proven by
//! its certificate; one that is not is refused and the current one kept.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::task::JoinHandle;
use tunnelward_crypto::{Identity, RotatingIdentity};

/// Where the SVID comes from.
#[derive(Debug, Clone)]
pub(crate) enum Source {
    /// A certificate chain and key in PEM files, looked at every `every`.
    Files {
        cert: PathBuf,
        key: PathBuf,
        every: Duration,
    },
    /// The Workload API on this Unix socket.
    #[cfg(unix)]
    Workload(PathBuf),
    /// Enrolment with the gateway, then renewal.
    Enrol(crate::enrolled::Enrol),
}

/// Fails unless `claimed` is the SPIFFE ID in `id`'s leaf certificate,
/// which the gateway checks too (TW-R003).
pub(crate) fn claims_its_certificate(id: &Identity, claimed: &str) -> Result<(), String> {
    let leaf = id.chain.first().ok_or("[identity] cert: no certificate")?;
    match tunnelward_identity::spiffe_id(leaf.as_ref()) {
        Ok(proven) if proven == claimed => Ok(()),
        Ok(proven) => Err(format!(
            "[identity] spiffe_id {claimed:?} is not the certificate's, {proven:?}"
        )),
        Err(e) => Err(format!("[identity] cert: {e}")),
    }
}

/// The first SVID from `source` for `spiffe_id`, and a task that keeps
/// it current until aborted.
pub(crate) async fn start(
    source: Source,
    spiffe_id: String,
) -> Result<(Arc<RotatingIdentity>, JoinHandle<()>), String> {
    match source {
        Source::Files { cert, key, every } => start_files(cert, key, every, spiffe_id),
        #[cfg(unix)]
        Source::Workload(socket) => workload::start(socket, spiffe_id).await,
        Source::Enrol(enrol) => crate::enrolled::start(enrol, spiffe_id).await,
    }
}

fn start_files(
    cert: PathBuf,
    key: PathBuf,
    every: Duration,
    spiffe_id: String,
) -> Result<(Arc<RotatingIdentity>, JoinHandle<()>), String> {
    let id = from_files(&cert, &key, &spiffe_id)?;
    let rotating = RotatingIdentity::new(id).map_err(|e| format!("[identity]: {e}"))?;
    let keeper = tokio::spawn(watch_files(cert, key, every, spiffe_id, rotating.clone()));
    Ok((rotating, keeper))
}

fn from_files(
    cert: &std::path::Path,
    key: &std::path::Path,
    spiffe_id: &str,
) -> Result<Identity, String> {
    let id = crate::config::identity(cert, key)?;
    claims_its_certificate(&id, spiffe_id)?;
    Ok(id)
}

fn stamps(files: [&PathBuf; 2]) -> [Option<SystemTime>; 2] {
    files.map(|f| std::fs::metadata(f).and_then(|m| m.modified()).ok())
}

/// Reloads the files when either changes; a bad pair keeps the current.
async fn watch_files(
    cert: PathBuf,
    key: PathBuf,
    every: Duration,
    spiffe_id: String,
    rotating: Arc<RotatingIdentity>,
) {
    let mut seen = stamps([&cert, &key]);
    loop {
        tokio::time::sleep(every).await;
        let now = stamps([&cert, &key]);
        if now == seen {
            continue;
        }
        seen = now;
        let loaded = from_files(&cert, &key, &spiffe_id)
            .and_then(|id| rotating.set(id).map_err(|e| format!("[identity]: {e}")));
        match loaded {
            Ok(()) => println!(
                "tunnelward connector: certificate reloaded from {}",
                cert.display()
            ),
            Err(e) => println!("tunnelward connector: kept the current certificate: {e}"),
        }
    }
}

#[cfg(unix)]
mod workload {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::task::JoinHandle;
    use tunnelward_crypto::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tunnelward_crypto::{Identity, RotatingIdentity};
    use tunnelward_identity::workload::{Svid, X509Stream, fetch_x509};

    use super::claims_its_certificate;

    /// Longest the first SVID may take.
    const FIRST: Duration = Duration::from_secs(10);

    pub(super) async fn start(
        socket: PathBuf,
        spiffe_id: String,
    ) -> Result<(Arc<RotatingIdentity>, JoinHandle<()>), String> {
        let (stream, svids) = tokio::time::timeout(FIRST, first(&socket))
            .await
            .map_err(|_| fail(&"no SVID within 10 s"))??;
        let id = choose(&svids, &spiffe_id)?;
        let rotating = RotatingIdentity::new(id).map_err(|e| fail(&e))?;
        let keeper = tokio::spawn(follow(stream, socket, spiffe_id, rotating.clone()));
        Ok((rotating, keeper))
    }

    fn fail(e: &dyn std::fmt::Display) -> String {
        format!("[identity] workload_api: {e}")
    }

    /// The stream and its first message.
    async fn first(socket: &std::path::Path) -> Result<(X509Stream, Vec<Svid>), String> {
        let mut stream = fetch_x509(socket).await.map_err(|e| fail(&e))?;
        let svids = stream.next().await.map_err(|e| fail(&e))?;
        Ok((stream, svids))
    }

    /// The SVID for `spiffe_id` among `svids`, its certificate checked.
    fn choose(svids: &[Svid], spiffe_id: &str) -> Result<Identity, String> {
        let svid = svids.iter().find(|s| s.spiffe_id == spiffe_id).ok_or_else(|| {
            let offered: Vec<&str> = svids.iter().map(|s| s.spiffe_id.as_str()).collect();
            format!("[identity] workload_api: no SVID for {spiffe_id:?}; the agent offers {offered:?}")
        })?;
        let id = Identity {
            chain: svid
                .chain
                .iter()
                .map(|c| CertificateDer::from(c.clone()))
                .collect(),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(svid.key.clone())),
        };
        claims_its_certificate(&id, spiffe_id)?;
        Ok(id)
    }

    /// Applies each new SVID; reconnects, backing off to 30 s, when the
    /// stream fails or the agent restarts.
    async fn follow(
        mut stream: X509Stream,
        socket: PathBuf,
        spiffe_id: String,
        rotating: Arc<RotatingIdentity>,
    ) {
        let mut wait = Duration::from_millis(250);
        loop {
            match stream.next().await {
                Ok(svids) => {
                    wait = Duration::from_millis(250);
                    apply(&svids, &spiffe_id, &rotating);
                }
                Err(e) => {
                    println!("tunnelward connector: Workload API: {e}; reconnecting in {wait:?}");
                    stream = reconnect(&socket, &mut wait).await;
                }
            }
        }
    }

    fn apply(svids: &[Svid], spiffe_id: &str, rotating: &RotatingIdentity) {
        let set =
            choose(svids, spiffe_id).and_then(|id| rotating.set(id).map_err(|e| e.to_string()));
        match set {
            Ok(()) => println!("tunnelward connector: SVID for {spiffe_id} rotated"),
            Err(e) => println!("tunnelward connector: kept the current SVID: {e}"),
        }
    }

    async fn reconnect(socket: &std::path::Path, wait: &mut Duration) -> X509Stream {
        loop {
            tokio::time::sleep(*wait).await;
            *wait = (*wait * 2).min(Duration::from_secs(30));
            if let Ok(stream) = fetch_x509(socket).await {
                return stream;
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tunnelward_testpki as pki;
    use tunnelward_testpki::agent::{self, message};

    type Res = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Waits up to 5 s for `rotating` to present `leaf`.
    async fn presents(rotating: &RotatingIdentity, leaf: &[u8]) -> bool {
        for _ in 0..100 {
            if rotating.leaf().as_ref() == leaf {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test]
    async fn the_workload_api_rotates_and_another_identity_is_refused() -> Res {
        let (socket, feed) = agent::start()?;
        feed.send(message(pki::CONNECTOR_ID, pki::CONNECTOR))
            .await?;
        let (rotating, keeper) = start(Source::Workload(socket), pki::CONNECTOR_ID.into()).await?;
        assert_eq!(rotating.leaf().as_ref(), pki::CONNECTOR.0);
        feed.send(message(pki::RIVAL_ID, pki::RIVAL)).await?;
        feed.send(message(pki::CONNECTOR_ID, pki::CONNECTOR_NEXT))
            .await?;
        assert!(presents(&rotating, pki::CONNECTOR_NEXT.0).await, "rotated");
        keeper.abort();
        Ok(())
    }

    fn write_pair(dir: &std::path::Path, pair: pki::Pair) -> std::io::Result<()> {
        std::fs::write(dir.join("svid.crt"), pki::pem("CERTIFICATE", pair.0))?;
        std::fs::write(dir.join("svid.key"), pki::pem("PRIVATE KEY", pair.1))
    }

    #[tokio::test]
    async fn changed_files_rotate_and_a_file_for_another_identity_is_refused() -> Res {
        let dir = std::env::temp_dir().join(format!("tw-svid-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        write_pair(&dir, pki::CONNECTOR)?;
        let source = Source::Files {
            cert: dir.join("svid.crt"),
            key: dir.join("svid.key"),
            every: Duration::from_millis(20),
        };
        let (rotating, keeper) = start(source, pki::CONNECTOR_ID.into()).await?;
        assert_eq!(rotating.leaf().as_ref(), pki::CONNECTOR.0);
        tokio::time::sleep(Duration::from_millis(50)).await;
        write_pair(&dir, pki::RIVAL)?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            rotating.leaf().as_ref(),
            pki::CONNECTOR.0,
            "another identity is refused"
        );
        write_pair(&dir, pki::CONNECTOR_NEXT)?;
        assert!(presents(&rotating, pki::CONNECTOR_NEXT.0).await, "rotated");
        keeper.abort();
        Ok(std::fs::remove_dir_all(dir)?)
    }

    #[tokio::test]
    async fn an_agent_without_our_identity_is_an_error() -> Res {
        let (socket, feed) = agent::start()?;
        feed.send(message(pki::RIVAL_ID, pki::RIVAL)).await?;
        let err = start(Source::Workload(socket), pki::CONNECTOR_ID.into())
            .await
            .err();
        assert!(err.is_some_and(|e| e.contains("no SVID for") && e.contains(pki::RIVAL_ID)));
        Ok(())
    }

    #[tokio::test]
    async fn an_svid_labelled_ours_but_certified_for_another_is_refused() -> Res {
        let (socket, feed) = agent::start()?;
        feed.send(message(pki::CONNECTOR_ID, pki::RIVAL)).await?;
        let err = start(Source::Workload(socket), pki::CONNECTOR_ID.into())
            .await
            .err();
        assert!(
            err.is_some_and(|e| e.contains("is not the certificate's")),
            "label alone is not trusted"
        );
        Ok(())
    }
}
