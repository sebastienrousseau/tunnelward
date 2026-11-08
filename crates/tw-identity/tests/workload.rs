// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Workload API client against a fake agent: gRPC over HTTP/2 on a
//! Unix socket, streaming `X509SVIDResponse` messages built from the test
//! PKI.

#![cfg(unix)]

use tunnelward_identity::workload::{Svid, WorkloadError, fetch_x509};
use tunnelward_testpki as pki;
use tunnelward_testpki::agent::{self, grpc, message, trailers};

type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// An agent that has already been fed `frames`.
async fn agent(frames: Vec<hyper::body::Frame<bytes::Bytes>>) -> Res<std::path::PathBuf> {
    let (path, feed) = agent::start()?;
    for f in frames {
        feed.send(f).await?;
    }
    // Keep the feed open until the agent ends the stream with trailers.
    std::mem::forget(feed);
    Ok(path)
}

fn expect(svids: &[Svid], id: &str, pair: pki::Pair) {
    assert_eq!(svids.len(), 1);
    let s = &svids[0];
    assert_eq!(s.spiffe_id, id);
    assert_eq!(s.chain, [pair.0.to_vec()]);
    assert_eq!(s.key, pair.1);
    assert_eq!(s.bundle, [pki::CA.to_vec()]);
}

#[tokio::test]
async fn each_message_is_the_current_svid_until_the_stream_ends() -> Res<()> {
    let frames = vec![
        message(pki::CONNECTOR_ID, pki::CONNECTOR),
        message(pki::RIVAL_ID, pki::RIVAL),
        trailers(0),
    ];
    let mut stream = fetch_x509(&agent(frames).await?).await?;
    expect(&stream.next().await?, pki::CONNECTOR_ID, pki::CONNECTOR);
    expect(&stream.next().await?, pki::RIVAL_ID, pki::RIVAL);
    assert_eq!(stream.next().await, Err(WorkloadError::Ended));
    Ok(())
}

#[tokio::test]
async fn an_error_in_the_trailers_is_reported() -> Res<()> {
    let frames = vec![message(pki::CONNECTOR_ID, pki::CONNECTOR), trailers(14)];
    let mut stream = fetch_x509(&agent(frames).await?).await?;
    expect(&stream.next().await?, pki::CONNECTOR_ID, pki::CONNECTOR);
    assert!(matches!(
        stream.next().await,
        Err(WorkloadError::Status { code: 14, .. })
    ));
    Ok(())
}

#[tokio::test]
async fn a_malformed_message_is_refused() -> Res<()> {
    let junk = grpc(&[0x0a, 9]);
    let mut stream = fetch_x509(&agent(vec![junk]).await?).await?;
    assert!(matches!(
        stream.next().await,
        Err(WorkloadError::Malformed(_))
    ));
    Ok(())
}

#[tokio::test]
async fn a_missing_socket_is_a_connect_error() {
    let missing = std::env::temp_dir().join("tw-wl-missing.sock");
    assert!(matches!(
        fetch_x509(&missing).await.err(),
        Some(WorkloadError::Connect(_))
    ));
}
