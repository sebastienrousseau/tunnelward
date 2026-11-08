// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A client for the SPIFFE Workload API's X.509 stream: gRPC
//! `FetchX509SVID` over the agent's Unix socket. Each message carries the
//! workload's current SVIDs; the agent sends a new one before the old
//! certificates expire, so reading the stream is how a workload rotates.

use std::fmt;
use std::path::{Path, PathBuf};

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, Request};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::UnixStream;

use crate::der;
use crate::proto::{Value, fields};

/// The variable naming the Workload API endpoint.
pub const ENDPOINT_VARIABLE: &str = "SPIFFE_ENDPOINT_SOCKET";
/// Largest message read, in bytes.
const MAX_MESSAGE: usize = 4 * 1024 * 1024;

/// One X.509-SVID as the Workload API sends it.
#[derive(Clone, PartialEq, Eq)]
pub struct Svid {
    /// The SPIFFE ID the agent says it is for.
    pub spiffe_id: String,
    /// The certificate chain, DER, leaf first.
    pub chain: Vec<Vec<u8>>,
    /// The leaf's private key, PKCS#8 DER.
    pub key: Vec<u8>,
    /// The trust domain's CA certificates, DER.
    pub bundle: Vec<Vec<u8>>,
}

impl fmt::Debug for Svid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Svid")
            .field("spiffe_id", &self.spiffe_id)
            .field("chain", &self.chain.len())
            .field("bundle", &self.bundle.len())
            .finish_non_exhaustive()
    }
}

/// Why the Workload API could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadError {
    /// The endpoint is not `unix:` with a path.
    Endpoint(String),
    /// Connecting to the socket or speaking HTTP/2 failed.
    Connect(String),
    /// The agent answered with a gRPC error (for example 7, permission
    /// denied, when it has no identity for this workload).
    Status {
        /// The gRPC status code.
        code: u32,
        /// The agent's message, if any.
        message: String,
    },
    /// A message that is not an `X509SVIDResponse` this client reads.
    Malformed(&'static str),
    /// The stream ended.
    Ended,
}

impl fmt::Display for WorkloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint(e) => write!(f, "Workload API endpoint {e:?}: give unix:/path"),
            Self::Connect(e) => write!(f, "Workload API: {e}"),
            Self::Status { code, message } => write!(f, "Workload API status {code}: {message}"),
            Self::Malformed(why) => write!(f, "Workload API message: {why}"),
            Self::Ended => f.write_str("the Workload API stream ended"),
        }
    }
}

impl std::error::Error for WorkloadError {}

/// The socket path in a `unix:///path` or `unix:/path` endpoint.
///
/// # Errors
///
/// [`WorkloadError::Endpoint`] for any other form.
pub fn socket_path(endpoint: &str) -> Result<PathBuf, WorkloadError> {
    let path = endpoint
        .strip_prefix("unix://")
        .or_else(|| endpoint.strip_prefix("unix:"))
        .filter(|p| p.starts_with('/'))
        .ok_or_else(|| WorkloadError::Endpoint(endpoint.to_owned()))?;
    Ok(PathBuf::from(path))
}

/// The X.509 stream from the Workload API at `socket`.
pub struct X509Stream {
    body: Incoming,
    buf: BytesMut,
}

/// Opens the X.509 stream on `socket`.
///
/// # Errors
///
/// [`WorkloadError::Connect`], or [`WorkloadError::Status`] when the agent
/// refuses at once.
pub async fn fetch_x509(socket: &Path) -> Result<X509Stream, WorkloadError> {
    let mut sender = connect(socket).await?;
    // An empty X509SVIDRequest in one uncompressed gRPC frame.
    let request = Request::post("http://localhost/SpiffeWorkloadAPI/FetchX509SVID")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("workload.spiffe.io", "true")
        .body(Full::new(Bytes::from_static(&[0, 0, 0, 0, 0])))
        .map_err(|e| WorkloadError::Connect(e.to_string()))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| WorkloadError::Connect(e.to_string()))?;
    status(response.headers())?;
    Ok(X509Stream {
        body: response.into_body(),
        buf: BytesMut::new(),
    })
}

/// An HTTP/2 connection over the Unix socket at `socket`.
async fn connect(
    socket: &Path,
) -> Result<hyper::client::conn::http2::SendRequest<Full<Bytes>>, WorkloadError> {
    let failed = |e: &dyn fmt::Display| WorkloadError::Connect(e.to_string());
    let stream = UnixStream::connect(socket).await.map_err(|e| failed(&e))?;
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .map_err(|e| failed(&e))?;
    tokio::spawn(conn);
    Ok(sender)
}

/// The gRPC status in `headers` or trailers, if it is an error.
fn status(headers: &HeaderMap) -> Result<(), WorkloadError> {
    let code = headers
        .get("grpc-status")
        .and_then(|v| v.to_str().ok()?.parse::<u32>().ok());
    match code {
        None | Some(0) => Ok(()),
        Some(code) => Err(WorkloadError::Status {
            code,
            message: headers
                .get("grpc-message")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
        }),
    }
}

impl X509Stream {
    /// The next message's SVIDs, the default one first.
    ///
    /// # Errors
    ///
    /// [`WorkloadError::Status`] from the trailers, [`WorkloadError::Ended`]
    /// when the stream ends cleanly, [`WorkloadError::Malformed`].
    pub async fn next(&mut self) -> Result<Vec<Svid>, WorkloadError> {
        loop {
            if let Some(message) = self.frame()? {
                return svids(&message);
            }
            match self.body.frame().await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => self.buf.extend_from_slice(&data),
                    Err(frame) => status(frame.trailers_ref().unwrap_or(&HeaderMap::new()))?,
                },
                Some(Err(e)) => return Err(WorkloadError::Connect(e.to_string())),
                None => return Err(WorkloadError::Ended),
            }
        }
    }

    /// One complete gRPC message off the buffer, if there is one.
    fn frame(&mut self) -> Result<Option<Bytes>, WorkloadError> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        if self.buf[0] != 0 {
            return Err(WorkloadError::Malformed("a compressed message"));
        }
        let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]);
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len > MAX_MESSAGE {
            return Err(WorkloadError::Malformed("a message over 4 MiB"));
        }
        if self.buf.len() < 5 + len {
            return Ok(None);
        }
        self.buf.advance(5);
        Ok(Some(self.buf.split_to(len).freeze()))
    }
}

/// The SVIDs in an `X509SVIDResponse`.
fn svids(message: &[u8]) -> Result<Vec<Svid>, WorkloadError> {
    let parsed = fields(message).ok_or(WorkloadError::Malformed("not protobuf"))?;
    let out: Vec<Svid> = parsed
        .into_iter()
        .filter_map(|(n, v)| match (n, v) {
            (1, Value::Bytes(b)) => Some(svid(b)),
            _ => None,
        })
        .collect::<Result<_, _>>()?;
    if out.is_empty() {
        return Err(WorkloadError::Malformed("no SVID in the message"));
    }
    Ok(out)
}

/// One `X509SVID`: 1 `spiffe_id`, 2 `x509_svid`, 3 `x509_svid_key`, 4 `bundle`.
fn svid(message: &[u8]) -> Result<Svid, WorkloadError> {
    let bad = WorkloadError::Malformed;
    let mut svid = Svid {
        spiffe_id: String::new(),
        chain: Vec::new(),
        key: Vec::new(),
        bundle: Vec::new(),
    };
    for (n, v) in fields(message).ok_or(bad("an X509SVID is not protobuf"))? {
        if let Value::Bytes(b) = v {
            read_field(&mut svid, n, b)?;
        }
    }
    if svid.chain.is_empty() || svid.key.is_empty() {
        return Err(bad("an SVID without a certificate or key"));
    }
    Ok(svid)
}

/// Field `n` of an `X509SVID` into `svid`; unknown fields are skipped.
fn read_field(svid: &mut Svid, n: u64, b: &[u8]) -> Result<(), WorkloadError> {
    let bad = WorkloadError::Malformed;
    match n {
        1 => {
            svid.spiffe_id =
                String::from_utf8(b.to_vec()).map_err(|_| bad("a spiffe_id is not UTF-8"))?;
        }
        2 => svid.chain = certificates(b).ok_or(bad("x509_svid is not DER"))?,
        3 => svid.key = b.to_vec(),
        4 => svid.bundle = certificates(b).ok_or(bad("bundle is not DER"))?,
        _ => {}
    }
    Ok(())
}

/// Concatenated DER certificates, split.
fn certificates(mut bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (_, _, rest) = der::next(bytes)?;
        let used = bytes.len() - rest.len();
        out.push(bytes[..used].to_vec());
        bytes = rest;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_unix_paths() {
        assert_eq!(
            socket_path("unix:///run/spire/agent.sock"),
            Ok(PathBuf::from("/run/spire/agent.sock"))
        );
        assert_eq!(
            socket_path("unix:/tmp/a.sock"),
            Ok(PathBuf::from("/tmp/a.sock"))
        );
        for bad in [
            "tcp://127.0.0.1:8081",
            "unix:relative.sock",
            "/run/a.sock",
            "",
        ] {
            assert!(
                matches!(socket_path(bad), Err(WorkloadError::Endpoint(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn concatenated_certificates_are_split_whole() {
        let two = [&[0x30, 2, 1, 2][..], &[0x30, 1, 9]].concat();
        assert_eq!(
            certificates(&two),
            Some(vec![vec![0x30, 2, 1, 2], vec![0x30, 1, 9]])
        );
        assert_eq!(certificates(&[0x30, 5, 1]), None);
    }
}
