// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Async frame reading and writing over an in-memory stream.

#![cfg(feature = "io")]

use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tunnelward_proto::io::{ReadError, read_frame, write_frame};
use tunnelward_proto::{
    Accept, ConnectorId, DecodeError, Frame, Limits, PROTOCOL_VERSION, Register, StreamLimits,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn register() -> Frame {
    Frame::Register(Register {
        version: PROTOCOL_VERSION,
        connector_id: ConnectorId([3; 16]),
        spiffe_id: "spiffe://example.org/connector".into(),
        routes: vec!["mcp/echo".into()],
        domains: Vec::new(),
        mcp: None,
        attestation: None,
        capacity: 8,
    })
}

#[tokio::test]
async fn a_frame_round_trips_and_leaves_following_bytes_unread() -> TestResult {
    let limits = Limits::default();
    let (mut a, mut b) = duplex(64);
    let accept = Frame::Accept(Accept {
        lease_secs: 30,
        limits: StreamLimits::default(),
    });
    let sent = accept.clone();
    let writer = tokio::spawn(async move {
        write_frame(&mut a, &register(), &limits).await?;
        write_frame(&mut a, &sent, &limits).await?;
        a.write_all(b"PRI * HTTP/2.0").await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    assert_eq!(read_frame(&mut b, &limits).await?, register());
    assert_eq!(read_frame(&mut b, &limits).await?, accept);
    let mut rest = [0; 14];
    b.read_exact(&mut rest).await?;
    assert_eq!(&rest, b"PRI * HTTP/2.0");
    writer.await?.map_err(|e| e.to_string())?;
    Ok(())
}

#[tokio::test]
async fn an_oversized_prefix_fails_before_the_body_is_read() -> TestResult {
    let limits = Limits::default();
    let (mut a, mut b) = duplex(64);
    a.write_all(&(limits.max_frame_len + 1).to_be_bytes())
        .await?;
    // Nothing follows the prefix: a reader that waited for the body would hang.
    let err = read_frame(&mut b, &limits).await;
    assert!(
        matches!(err, Err(ReadError::Decode(DecodeError::TooLarge { .. }))),
        "{err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn end_of_stream_mid_frame_is_an_io_error() -> TestResult {
    let limits = Limits::default();
    let (mut a, mut b) = duplex(64);
    a.write_all(&[0, 0, 0, 9, 1, 2]).await?;
    drop(a);
    let err = read_frame(&mut b, &limits).await;
    assert!(matches!(err, Err(ReadError::Io(_))), "{err:?}");
    Ok(())
}
