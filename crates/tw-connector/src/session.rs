// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One registration and the HTTP/2 server that follows it.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::{Body, Incoming};
use hyper::server::conn::http2;
use hyper::service::HttpService;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tunnelward_crypto::rustls::ClientConfig;
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_proto::io::{read_frame, write_frame};
use tunnelward_proto::{ALPN, Accept, Frame, Limits, Register};

use crate::Error;

/// How to reach and register with one gateway.
#[derive(Debug, Clone)]
pub struct Config {
    /// The gateway's address, `host:port`.
    pub gateway: String,
    /// The name the gateway's certificate must carry.
    pub server_name: ServerName<'static>,
    /// TLS configuration from `tunnelward_crypto::client_config`, offering ALPN
    /// `tw/1` and presenting the connector's certificate.
    pub tls: Arc<ClientConfig>,
    /// What to register.
    pub register: Register,
    /// A file holding the passmcp attestation to present (a Sigstore
    /// bundle or a DSSE envelope), read at every registration so a
    /// renewed statement is sent without a restart. It replaces
    /// `register.attestation`.
    pub attestation_file: Option<PathBuf>,
    /// The server the connector holds its target to (ADR 0017): its
    /// descriptor replaces `register.mcp` at every registration, and a
    /// change of server asks every connection to register again.
    pub pinned: Option<crate::Pinned>,
    /// Frame limits; the gateway's answer must fit them.
    pub limits: Limits,
    /// Longest the TCP, TLS and registration exchange may take together.
    pub handshake_timeout: Duration,
}

/// The HTTP/2 server on a registered connection.
pub(crate) type ServerConnection<S> =
    http2::Connection<TokioIo<TlsStream<TcpStream>>, S, TokioExecutor>;

/// A connector the gateway has accepted, ready to serve.
#[derive(Debug)]
pub struct Registered {
    stream: TlsStream<TcpStream>,
    accept: Accept,
    capacity: u32,
}

/// Dials the gateway, registers, and returns the accepted session.
///
/// # Errors
///
/// [`Error::Rejected`] when the gateway refuses; [`Error::Timeout`] when
/// the exchange takes longer than `config.handshake_timeout`; otherwise
/// the step that failed.
pub async fn register(config: &Config) -> Result<Registered, Error> {
    timeout(config.handshake_timeout, register_inner(config))
        .await
        .map_err(|_| Error::Timeout)?
}

async fn register_inner(config: &Config) -> Result<Registered, Error> {
    let tcp = TcpStream::connect(&config.gateway)
        .await
        .map_err(Error::Connect)?;
    let mut stream = TlsConnector::from(config.tls.clone())
        .connect(config.server_name.clone(), tcp)
        .await
        .map_err(Error::Connect)?;
    if stream.get_ref().1.alpn_protocol() != Some(ALPN) {
        return Err(Error::Alpn);
    }
    let frame = Frame::Register(claim(config).await?);
    write_frame(&mut stream, &frame, &config.limits)
        .await
        .map_err(Error::Write)?;
    match read_frame(&mut stream, &config.limits)
        .await
        .map_err(Error::Read)?
    {
        Frame::Accept(accept) => Ok(Registered {
            stream,
            accept,
            capacity: config.register.capacity,
        }),
        Frame::Reject(reject) => Err(Error::Rejected(reject)),
        Frame::Register(_) => Err(Error::UnexpectedFrame),
    }
}

/// The register frame to send: `config.register`, with the pinned
/// server's descriptor and the attestation file's contents when there
/// are.
async fn claim(config: &Config) -> Result<Register, Error> {
    let mut claim = config.register.clone();
    if let Some(pinned) = &config.pinned {
        claim.mcp = Some(pinned.descriptor());
    }
    if let Some(path) = &config.attestation_file {
        let max = config.limits.max_frame_len;
        claim.attestation = Some(read_attestation(path.clone(), max).await?);
    }
    Ok(claim)
}

/// The file at `path`, refused unread when it is larger than `max`: a
/// statement must fit in the register frame anyway.
async fn read_attestation(path: PathBuf, max: u32) -> Result<Vec<u8>, Error> {
    let read = move || {
        use std::io::Read;
        let file = std::fs::File::open(&path)?;
        let len = file.metadata()?.len();
        if len > u64::from(max) {
            let why = format!(
                "{} is {len} bytes, over the {max}-byte frame",
                path.display()
            );
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, why));
        }
        let mut bytes = Vec::new();
        file.take(u64::from(max)).read_to_end(&mut bytes)?;
        Ok(bytes)
    };
    tokio::task::spawn_blocking(read)
        .await
        .map_err(|e| Error::Attestation(std::io::Error::other(e)))?
        .map_err(Error::Attestation)
}

impl Registered {
    /// What the gateway granted.
    #[must_use]
    pub fn accept(&self) -> &Accept {
        &self.accept
    }

    /// Serves the gateway's requests with `service` until the gateway
    /// closes the connection. Concurrent streams are capped at the smaller
    /// of the connector's capacity and the gateway's grant.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] if the HTTP/2 connection fails.
    pub async fn serve<S>(self, service: S) -> Result<(), Error>
    where
        S: HttpService<Incoming>,
        S::Future: Send + 'static,
        S::ResBody: Send + 'static,
        <S::ResBody as Body>::Data: Send,
        <S::ResBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.into_connection(service).await.map_err(Error::Http)
    }

    /// The HTTP/2 server connection, for callers that shut it down
    /// gracefully themselves.
    pub(crate) fn into_connection<S>(self, service: S) -> ServerConnection<S>
    where
        S: HttpService<Incoming>,
        S::Future: Send + 'static,
        S::ResBody: Send + 'static,
        <S::ResBody as Body>::Data: Send,
        <S::ResBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let grant = self.accept.limits;
        http2::Builder::new(TokioExecutor::new())
            .max_concurrent_streams(self.capacity.min(grant.max_concurrent_streams))
            .max_header_list_size(grant.max_header_list_size)
            .initial_stream_window_size(grant.initial_stream_window)
            .initial_connection_window_size(grant.initial_connection_window)
            .serve_connection(TokioIo::new(self.stream), service)
    }
}
