// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The checks, each its own connection.

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tunnelward_crypto::rustls::ClientConfig;
use tunnelward_proto::io::read_frame;
use tunnelward_proto::{
    ALPN, ConnectorId, Frame, LENGTH_PREFIX_LEN, PROTOCOL_VERSION, Register, RejectCode, encode,
};

use crate::{Outcome, Target};

/// What the gateway answered a frame with.
enum Reply {
    Frame(Frame),
    /// It closed the connection or the read failed.
    Closed(String),
    /// Nothing within the timeout.
    Silent,
}

fn outcome(check: &'static str, passed: bool, detail: impl Into<String>) -> Outcome {
    Outcome {
        check,
        passed,
        detail: detail.into(),
    }
}

async fn connect(target: &Target, tls: &Arc<ClientConfig>) -> Result<TlsStream<TcpStream>, String> {
    let tcp = timeout(target.timeout, TcpStream::connect(&target.addr))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|e| format!("connect: {e}"))?;
    let tls = TlsConnector::from(tls.clone()).connect(target.server_name.clone(), tcp);
    timeout(target.timeout, tls)
        .await
        .map_err(|_| "TLS timed out".to_owned())?
        .map_err(|e| format!("TLS: {e}"))
}

/// Sends `bytes` on `stream` and reads the answer.
async fn exchange(target: &Target, stream: &mut TlsStream<TcpStream>, bytes: &[u8]) -> Reply {
    if let Err(e) = stream.write_all(bytes).await.and(stream.flush().await) {
        return Reply::Closed(format!("write: {e}"));
    }
    match timeout(target.timeout, read_frame(stream, &target.limits)).await {
        Ok(Ok(frame)) => Reply::Frame(frame),
        Ok(Err(e)) => Reply::Closed(e.to_string()),
        Err(_) => Reply::Silent,
    }
}

/// A registration as `spiffe_id` for the target's route.
fn register_as(target: &Target, spiffe_id: &str, version: u16) -> Register {
    Register {
        version,
        connector_id: ConnectorId(*b"tw-conformance!!"),
        spiffe_id: spiffe_id.to_owned(),
        routes: vec![target.route.clone()],
        domains: Vec::new(),
        mcp: None,
        attestation: None,
        capacity: 1,
    }
}

/// `frame` with its length prefix, without the encoder's checks, so a
/// frame the protocol forbids can be sent.
fn raw(frame: &Frame) -> Result<Vec<u8>, String> {
    let mut out = cbor4ii::serde::to_vec(vec![0; LENGTH_PREFIX_LEN], frame)
        .map_err(|e| format!("CBOR: {e}"))?;
    let len = u32::try_from(out.len() - LENGTH_PREFIX_LEN).map_err(|e| e.to_string())?;
    out[..LENGTH_PREFIX_LEN].copy_from_slice(&len.to_be_bytes());
    Ok(out)
}

/// The gateway must answer `bytes` with a `Reject` carrying `want`.
async fn expect_reject(
    check: &'static str,
    target: &Target,
    bytes: &[u8],
    want: RejectCode,
) -> Outcome {
    let mut stream = match connect(target, &target.tw).await {
        Ok(s) => s,
        Err(e) => return outcome(check, false, e),
    };
    match exchange(target, &mut stream, bytes).await {
        Reply::Frame(Frame::Reject(r)) if r.code == want => outcome(
            check,
            true,
            format!("Reject {:?} ({})", r.code, r.code.id()),
        ),
        Reply::Frame(Frame::Reject(r)) => {
            outcome(check, false, format!("Reject {:?}, not {want:?}", r.code))
        }
        Reply::Frame(other) => outcome(check, false, format!("answered {other:?}")),
        Reply::Closed(e) => outcome(check, false, format!("closed without a Reject: {e}")),
        Reply::Silent => outcome(check, false, "no answer within the timeout"),
    }
}

/// A connection that does not offer `tw/1` must not be served.
pub(crate) async fn alpn(target: &Target) -> Outcome {
    const CHECK: &str = "alpn";
    let mut stream = match connect(target, &target.other).await {
        Err(e) => return outcome(CHECK, true, format!("refused at the handshake: {e}")),
        Ok(s) => s,
    };
    if stream.get_ref().1.alpn_protocol() == Some(ALPN) {
        return outcome(CHECK, false, "agreed to tw/1, which was not offered");
    }
    let Ok(bytes) = encode(
        &Frame::Register(register_as(target, &target.spiffe_id, PROTOCOL_VERSION)),
        &target.limits,
    ) else {
        return outcome(CHECK, false, "could not encode a registration");
    };
    match exchange(target, &mut stream, &bytes).await {
        Reply::Frame(Frame::Accept(_)) => {
            outcome(CHECK, false, "accepted a registration without tw/1")
        }
        _ => outcome(CHECK, true, "did not serve a connection without tw/1"),
    }
}

/// Bytes that are not CBOR must be refused as `Malformed`.
pub(crate) async fn malformed(target: &Target) -> Outcome {
    expect_reject(
        "malformed",
        target,
        &[0, 0, 0, 3, 0xff, 0xff, 0xff],
        RejectCode::Malformed,
    )
    .await
}

/// A length prefix over the limit must be refused before the body is
/// sent: the check sends no body, so a gateway that waits for one fails.
pub(crate) async fn oversized(target: &Target) -> Outcome {
    const CHECK: &str = "oversized";
    let mut stream = match connect(target, &target.tw).await {
        Ok(s) => s,
        Err(e) => return outcome(CHECK, false, e),
    };
    let prefix = target.limits.max_frame_len.saturating_add(1).to_be_bytes();
    match exchange(target, &mut stream, &prefix).await {
        Reply::Frame(Frame::Reject(r)) => {
            outcome(CHECK, true, format!("Reject {:?} before the body", r.code))
        }
        Reply::Closed(e) => outcome(CHECK, true, format!("closed before the body: {e}")),
        Reply::Frame(other) => outcome(CHECK, false, format!("answered {other:?}")),
        Reply::Silent => outcome(CHECK, false, "waited for a body over the limit"),
    }
}

/// An unknown protocol version must be refused.
pub(crate) async fn version(target: &Target) -> Outcome {
    let frame = Frame::Register(register_as(
        target,
        &target.spiffe_id,
        PROTOCOL_VERSION + 98,
    ));
    match raw(&frame) {
        Ok(bytes) => expect_reject("version", target, &bytes, RejectCode::UnsupportedVersion).await,
        Err(e) => outcome("version", false, e),
    }
}

/// A SPIFFE ID that is not the certificate's must be refused.
pub(crate) async fn identity(target: &Target) -> Outcome {
    let frame = Frame::Register(register_as(
        target,
        "spiffe://conformance.invalid/not-this-certificate",
        PROTOCOL_VERSION,
    ));
    match encode(&frame, &target.limits) {
        Ok(bytes) => expect_reject("identity", target, &bytes, RejectCode::IdentityMismatch).await,
        Err(e) => outcome("identity", false, format!("could not encode: {e}")),
    }
}

/// A valid registration must be accepted, and the gateway must then open
/// HTTP/2 as the client on the same connection.
pub(crate) async fn register(target: &Target) -> Outcome {
    const CHECK: &str = "register";
    let mut stream = match connect(target, &target.tw).await {
        Ok(s) => s,
        Err(e) => return outcome(CHECK, false, e),
    };
    let frame = Frame::Register(register_as(target, &target.spiffe_id, PROTOCOL_VERSION));
    let Ok(bytes) = encode(&frame, &target.limits) else {
        return outcome(CHECK, false, "could not encode a registration");
    };
    let accept = match exchange(target, &mut stream, &bytes).await {
        Reply::Frame(Frame::Accept(a)) if a.lease_secs >= 1 => a,
        Reply::Frame(other) => return outcome(CHECK, false, format!("answered {other:?}")),
        Reply::Closed(e) => return outcome(CHECK, false, format!("closed: {e}")),
        Reply::Silent => return outcome(CHECK, false, "no answer within the timeout"),
    };
    opens_http2(target, stream, accept.lease_secs).await
}

/// After `Accept`, the gateway must send the HTTP/2 client preface.
async fn opens_http2(target: &Target, stream: TlsStream<TcpStream>, lease_secs: u32) -> Outcome {
    const CHECK: &str = "register";
    match timeout(target.timeout, h2::server::handshake(stream)).await {
        Ok(Ok(_conn)) => outcome(
            CHECK,
            true,
            format!("Accept (lease {lease_secs} s), then HTTP/2 from the gateway"),
        ),
        Ok(Err(e)) => outcome(CHECK, false, format!("Accept, then no HTTP/2: {e}")),
        Err(_) => outcome(
            CHECK,
            false,
            "Accept, then no HTTP/2 preface within the timeout",
        ),
    }
}
