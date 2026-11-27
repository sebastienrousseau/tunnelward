// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Audit export over syslog with TLS (RFC 5425, ADR 0013): an entry an
//! audit log writes reaches a TLS receiver the forwarder trusts, and a
//! receiver it does not trust gets nothing.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tunnelward_audit::{Entry, RequestEntry, Settings, Sink};
use tunnelward_crypto::composite::SigningKey;
use tunnelward_crypto::{ClientAuth, KeyExchange, client_config, server_config};
use tunnelward_gateway::{Forwarder, SiemSettings, SyslogSettings};
use tunnelward_testpki as pki;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// A TLS syslog receiver with the test gateway's certificate; each
/// message it reads is sent on.
async fn receiver() -> Res<(String, mpsc::UnboundedReceiver<String>)> {
    let tls = server_config(
        pki::identity(pki::GATEWAY),
        ClientAuth::None,
        KeyExchange::default(),
        &[],
    )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?.to_string();
    let (sent, received) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let Ok(stream) = acceptor.accept(tcp).await else {
                continue;
            };
            let mut reader = BufReader::new(stream);
            let mut length = Vec::new();
            while reader
                .read_until(b' ', &mut length)
                .await
                .is_ok_and(|n| n > 0)
            {
                let n: usize = String::from_utf8_lossy(&length).trim().parse().unwrap_or(0);
                let mut message = vec![0; n];
                if reader.read_exact(&mut message).await.is_err() {
                    break;
                }
                let _sent = sent.send(String::from_utf8_lossy(&message).into_owned());
                length.clear();
            }
        }
    });
    Ok((address, received))
}

/// An audit log forwarding to syslog at `address`, trusting `ca`, with
/// one request entry written.
fn log_one(address: &str, ca: &[u8], name: &str) -> Res<Arc<Forwarder>> {
    let tls = client_config(pki::roots(ca)?, None, KeyExchange::default(), &[])?;
    let mut siem = SiemSettings::new();
    siem.syslog = Some(SyslogSettings::new(address, Some(Arc::new(tls))));
    siem.every = Duration::from_millis(20);
    let forwarder = Forwarder::start(siem)?;
    let path = std::env::temp_dir().join(format!("tw-siem-{name}-{}.jsonl", std::process::id()));
    let mut settings = Settings::new(path.clone(), SigningKey::generate()?.0, [3; 32]);
    settings.forward = Some(forwarder.clone());
    let sink = Sink::open(settings)?;
    let mut entry = RequestEntry::default();
    entry.method = "POST".into();
    entry.path = "/mcp/tls".into();
    entry.decision = "forwarded".into();
    entry.status = 200;
    sink.record(Entry::Request(Box::new(entry)), None);
    sink.close();
    std::fs::remove_file(path)?;
    Ok(forwarder)
}

#[tokio::test]
async fn an_entry_reaches_a_trusted_tls_receiver_and_no_other() -> Res<()> {
    let (address, mut messages) = receiver().await?;
    let _forwarder = log_one(&address, pki::CA, "trusted")?;
    let message = tokio::time::timeout(Duration::from_secs(10), messages.recv())
        .await?
        .ok_or("receiver gone")?;
    assert!(
        message.contains(" ocsf-4002 - ") && message.contains("/mcp/tls"),
        "{message}"
    );

    let (address, mut messages) = receiver().await?;
    let forwarder = log_one(&address, pki::OTHER_CA, "untrusted")?;
    let nothing = tokio::time::timeout(Duration::from_millis(500), messages.recv()).await;
    assert!(
        nothing.is_err(),
        "a receiver the forwarder does not trust gets nothing"
    );
    assert!(forwarder.failed() >= 1, "and the failure is counted");
    Ok(())
}
