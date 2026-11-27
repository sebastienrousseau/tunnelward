// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The conformance kit against Tunnelward's own gateway, which must pass
//! every check, and against a gateway that never answers, which must
//! fail the ones that need an answer.

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tunnelward_conformance::{Report, Target, run};
use tunnelward_testpki as pki;

use common::{Res, gateway_config, start};

fn target(addr: &str) -> Res<Target> {
    Ok(Target::new(
        addr,
        pki::GATEWAY_NAME,
        &pki::roots(pki::CA)?,
        &pki::identity(pki::CONNECTOR),
        "spiffe://example.org/connector",
    )?
    .with_timeout(Duration::from_secs(2)))
}

fn failed(report: &Report) -> Vec<&str> {
    report
        .outcomes
        .iter()
        .filter(|o| !o.passed)
        .map(|o| o.check)
        .collect()
}

#[tokio::test]
async fn the_gateway_passes_every_check() -> Res<()> {
    let (gateway, addr) = start(gateway_config()?).await?;
    let report = run(&target(&addr)?).await;
    assert!(report.passed(), "{report}");
    assert_eq!(report.outcomes.len(), 6);
    assert_eq!(
        gateway.routes(),
        ["conformance"],
        "the register check's route"
    );
    Ok(())
}

/// Speaks TLS with `tw/1`, then reads whatever comes and never answers.
async fn silent_gateway() -> Res<String> {
    let config = gateway_config()?;
    let acceptor = TlsAcceptor::from(Arc::clone(&config.tls));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let mut sink = [0; 1024];
                    while matches!(tls.read(&mut sink).await, Ok(n) if n > 0) {}
                }
            });
        }
    });
    Ok(addr)
}

#[tokio::test]
async fn a_gateway_that_never_answers_fails_the_checks_that_need_an_answer() -> Res<()> {
    let addr = silent_gateway().await?;
    let report = run(&target(&addr)?).await;
    assert!(!report.passed());
    assert_eq!(
        failed(&report),
        ["malformed", "oversized", "version", "identity", "register"],
        "{report}"
    );
    Ok(())
}
