// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The ready-made ingress listener: an optional PROXY header from trusted
//! proxies, optional TLS, then HTTP/2 or HTTP/1.1 by ALPN.

use std::net::SocketAddr;
use std::time::Duration;

use hyper::server::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::proxy_protocol::{self, Header};
use crate::{Gateway, Ingress};

/// Longest a trusted proxy may take to send its PROXY header.
const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(5);

impl Gateway {
    /// Serves agents on `listener` until it fails, each connection on its
    /// own task.
    ///
    /// # Errors
    ///
    /// The listener's accept error.
    pub async fn serve_ingress(&self, listener: TcpListener) -> std::io::Result<()> {
        let acceptor = self.inner.config.ingress.tls.clone().map(TlsAcceptor::from);
        loop {
            let (tcp, peer) = listener.accept().await?;
            let gateway = self.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move { gateway.ingress_connection(tcp, peer, acceptor).await });
        }
    }

    async fn ingress_connection(
        self,
        mut tcp: TcpStream,
        peer: SocketAddr,
        acceptor: Option<TlsAcceptor>,
    ) {
        let Some(peer) = self.proxied_peer(&mut tcp, peer).await else {
            return;
        };
        match acceptor {
            None => self.serve_http1(tcp, self.ingress(peer, false)).await,
            Some(acceptor) => {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let service = self.ingress(peer, true);
                if h2 {
                    self.serve_http2(tls, service).await;
                } else {
                    self.serve_http1(tls, service).await;
                }
            }
        }
    }

    /// The client address after a PROXY header, read only from trusted
    /// proxies and only when turned on. `None` drops the connection.
    async fn proxied_peer(&self, tcp: &mut TcpStream, peer: SocketAddr) -> Option<SocketAddr> {
        let ingress = &self.inner.config.ingress;
        let trusted = ingress
            .trusted_proxies
            .iter()
            .any(|range| range.contains(peer.ip()));
        if !(ingress.proxy_protocol && trusted) {
            return Some(peer);
        }
        match tokio::time::timeout(PROXY_HEADER_TIMEOUT, proxy_protocol::read(tcp)).await {
            Ok(Ok(Header::Proxied(client))) => Some(client),
            Ok(Ok(Header::Local)) => Some(peer),
            _ => None,
        }
    }

    async fn serve_http1<IO>(&self, io: IO, service: Ingress)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let ingress = &self.inner.config.ingress;
        let header_limit = usize::try_from(self.inner.config.limits.stream.max_header_list_size)
            .unwrap_or(usize::MAX);
        let _ended = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(ingress.idle_timeout)
            .max_buf_size(header_limit.max(8 * 1024))
            .serve_connection(TokioIo::new(io), service)
            .await;
    }

    async fn serve_http2<IO>(&self, io: IO, service: Ingress)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let config = &self.inner.config;
        let _ended = http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(config.ingress.idle_timeout)
            .keep_alive_timeout(config.ingress.idle_timeout)
            .max_header_list_size(config.limits.stream.max_header_list_size)
            .serve_connection(TokioIo::new(io), service)
            .await;
    }
}
