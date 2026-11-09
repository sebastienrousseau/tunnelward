// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TEST-ONLY: a fake SPIFFE Workload API agent. gRPC over HTTP/2 on a
//! Unix socket; the first `FetchX509SVID` stream gets the frames a test
//! sends through [`Feed`], later ones are told the agent is unavailable.

use std::convert::Infallible;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Request, Response};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::UnixListener;
use tokio::sync::mpsc;

use crate::{CA, Pair};

/// A response body fed from a channel.
struct Channel(mpsc::Receiver<Frame<Bytes>>);

impl Body for Channel {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|f| f.map(Ok))
    }
}

/// Sends frames down the agent's stream.
pub type Feed = mpsc::Sender<Frame<Bytes>>;

fn varint(mut n: usize, out: &mut Vec<u8>) {
    while n >= 0x80 {
        out.push(u8::try_from(n & 0x7f).unwrap_or(0) | 0x80);
        n >>= 7;
    }
    out.push(u8::try_from(n).unwrap_or(0));
}

/// A length-delimited protobuf field.
fn field(number: usize, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint(number << 3 | 2, &mut out);
    varint(bytes.len(), &mut out);
    out.extend_from_slice(bytes);
    out
}

/// One gRPC frame around `body`.
#[must_use]
pub fn grpc(body: &[u8]) -> Frame<Bytes> {
    let mut frame = vec![0];
    frame.extend_from_slice(&u32::try_from(body.len()).unwrap_or(0).to_be_bytes());
    frame.extend_from_slice(body);
    Frame::data(Bytes::from(frame))
}

/// An `X509SVIDResponse` carrying `pair` as the SVID for `id`, with
/// [`CA`] as its bundle.
#[must_use]
pub fn message(id: &str, pair: Pair) -> Frame<Bytes> {
    let svid = [
        field(1, id.as_bytes()),
        field(2, pair.0),
        field(3, pair.1),
        field(4, CA),
    ]
    .concat();
    grpc(&field(1, &svid))
}

/// Trailers ending the stream with gRPC status `code`.
#[must_use]
pub fn trailers(code: u32) -> Frame<Bytes> {
    let mut t = HeaderMap::new();
    t.insert("grpc-status", code.into());
    Frame::trailers(t)
}

/// Starts an agent on a fresh socket: its path, and the feed for the
/// first stream.
///
/// # Errors
///
/// The socket cannot be bound.
pub fn start() -> std::io::Result<(PathBuf, Feed)> {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("tw-agent-{}-{n}.sock", std::process::id()));
    let _stale = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    let (feed, rx) = mpsc::channel(16);
    let first = Arc::new(Mutex::new(Some(rx)));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let first = first.clone();
            let service = service_fn(move |req: Request<Incoming>| {
                let rx = first.lock().unwrap_or_else(PoisonError::into_inner).take();
                std::future::ready(Ok::<_, Infallible>(answer(&req, rx)))
            });
            let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
            tokio::spawn(async move {
                let _done = builder
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok((path, feed))
}

/// The stream for a well-formed request, status 3 for one without the
/// `workload.spiffe.io` header, status 14 once the stream was taken.
fn answer(req: &Request<Incoming>, rx: Option<mpsc::Receiver<Frame<Bytes>>>) -> Response<Channel> {
    let right = req.uri().path() == "/SpiffeWorkloadAPI/FetchX509SVID"
        && req
            .headers()
            .get("workload.spiffe.io")
            .is_some_and(|v| v == "true");
    let status = match (&rx, right) {
        (_, false) => Some(3_u16),
        (None, true) => Some(14),
        (Some(_), true) => None,
    };
    let body = rx.unwrap_or_else(|| mpsc::channel(1).1);
    let mut response = Response::new(Channel(body));
    let headers = response.headers_mut();
    headers.insert("content-type", HeaderValue::from_static("application/grpc"));
    if let Some(code) = status {
        headers.insert("grpc-status", code.into());
    }
    response
}
