// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Forwarding the gateway's requests to a local HTTP server (G5).
//!
//! [`Forward`] is a ready-made service for [`Registered::serve`]: it sends
//! each request on to a target over HTTP/1.1, by TCP, TLS with a pinned CA,
//! or a Unix domain socket, and streams the answer back. Hop-by-hop headers
//! are removed both ways. A target that cannot be reached gives 502, one
//! that does not answer in time gives 504; the HTTP/2 connection to the
//! gateway is never failed because of a target.
//!
//! Each request opens its own connection to the target. Targets are local,
//! so this costs little; pooling is measured with the benchmarks (v0.0.13).
//!
//! [`Registered::serve`]: crate::Registered::serve

use core::future::Future;
use core::pin::Pin;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::uri::PathAndQuery;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tunnelward_crypto::rustls::ClientConfig;
use tunnelward_crypto::rustls::pki_types::ServerName;

/// The body [`Forward`] answers with.
pub type ForwardBody = BoxBody<Bytes, hyper::Error>;

/// A request on its way to the target: streamed from the gateway, or
/// buffered (gateway-blind mode rewrites its body).
pub(crate) type Outgoing = Request<ForwardBody>;

/// Where [`Forward`] sends requests.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Target {
    /// Plain HTTP to `host:port`.
    Http {
        /// The target's address, `host:port`.
        addr: String,
    },
    /// HTTPS to `host:port`, verifying the certificate with `tls` (pin the
    /// local server's CA there) against `server_name`.
    Https {
        /// The target's address, `host:port`.
        addr: String,
        /// The name the target's certificate must carry.
        server_name: ServerName<'static>,
        /// TLS configuration, typically from `tunnelward_crypto::client_config`
        /// with ALPN `http/1.1`.
        tls: Arc<ClientConfig>,
    },
    /// Plain HTTP over a Unix domain socket.
    #[cfg(unix)]
    Unix {
        /// The socket's path.
        path: std::path::PathBuf,
    },
}

/// Changes a request before it is sent to the target (G8), for example
/// to add a header the target expects.
pub type RequestHook = Arc<dyn Fn(&mut Request<Incoming>) + Send + Sync>;

/// Forwards each request to a [`Target`]. Cloning is cheap.
#[derive(Clone)]
pub struct Forward {
    target: Arc<Target>,
    timeout: Duration,
    hook: Option<RequestHook>,
    blind: Option<Arc<crate::blind::Blind>>,
    pinned: Option<crate::Pinned>,
}

impl core::fmt::Debug for Forward {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Forward")
            .field("target", &self.target)
            .field("timeout", &self.timeout)
            .field("hook", &self.hook.is_some())
            .field("blind", &self.blind.is_some())
            .field("pinned", &self.pinned.is_some())
            .finish()
    }
}

impl Forward {
    /// Forwards to `target`, giving each request `timeout` to connect and
    /// answer with its headers.
    #[must_use]
    pub fn new(target: Target, timeout: Duration) -> Self {
        Self {
            target: Arc::new(target),
            timeout,
            hook: None,
            blind: None,
            pinned: None,
        }
    }

    /// Runs `hook` on every request before it is forwarded, after the
    /// gateway's routing and before hop-by-hop headers are removed.
    #[must_use]
    pub fn with_request_hook(mut self, hook: RequestHook) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Opens gateway-blind calls sealed to the connector and seals their
    /// answers (ADR 0016, experimental).
    #[must_use]
    pub fn with_blind(mut self, blind: crate::blind::Blind) -> Self {
        self.blind = Some(Arc::new(blind));
        self
    }

    /// Holds the target to the server it registered as: answers to
    /// `initialize` and `tools/list` that show another server, version
    /// or tool set are refused (ADR 0017).
    #[must_use]
    pub fn with_pinned(mut self, pinned: crate::Pinned) -> Self {
        self.pinned = Some(pinned);
        self
    }

    /// Asks the target who it is and what tools it has, at `path`
    /// (ADR 0017). The guard does not see these requests.
    ///
    /// # Errors
    ///
    /// The step that failed.
    pub async fn describe(&self, path: &str) -> Result<crate::Described, String> {
        crate::describe::http(self, path).await
    }

    async fn forward(self, mut request: Request<Incoming>) -> Response<ForwardBody> {
        if let Some(hook) = &self.hook {
            hook(&mut request);
        }
        let request = request.map(BodyExt::boxed);
        if let Some(blind) = self.blind.clone() {
            return blind.forward(&self, request).await;
        }
        self.send(request).await
    }

    /// Sends `request` to the target within the timeout, through the
    /// guard when a server is pinned.
    pub(crate) async fn send(&self, request: Outgoing) -> Response<ForwardBody> {
        match &self.pinned {
            Some(pinned) if request.method() == hyper::Method::POST => {
                crate::guard::send(self, pinned, request).await
            }
            _ => self.send_unguarded(request).await,
        }
    }

    /// [`Forward::send`] without the guard.
    pub(crate) async fn send_unguarded(&self, request: Outgoing) -> Response<ForwardBody> {
        match timeout(self.timeout, self.exchange(request)).await {
            Ok(Ok(response)) => response.map(BodyExt::boxed),
            Ok(Err(why)) => error_response(StatusCode::BAD_GATEWAY, &why),
            Err(_) => error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "the target did not answer in time",
            ),
        }
    }

    async fn exchange(&self, request: Outgoing) -> Result<Response<Incoming>, String> {
        let request = origin_form(request, &self.target)?;
        match self.target.as_ref() {
            Target::Http { addr } => send(tcp(addr).await?, request).await,
            Target::Https {
                addr,
                server_name,
                tls,
            } => send(tls_to(addr, server_name, tls).await?, request).await,
            #[cfg(unix)]
            Target::Unix { path } => send(unix(path).await?, request).await,
        }
    }
}

async fn tcp(addr: &str) -> Result<TcpStream, String> {
    TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect {addr}: {e}"))
}

async fn tls_to(
    addr: &str,
    server_name: &ServerName<'static>,
    tls: &Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    TlsConnector::from(tls.clone())
        .connect(server_name.clone(), tcp(addr).await?)
        .await
        .map_err(|e| format!("TLS to {addr}: {e}"))
}

#[cfg(unix)]
async fn unix(path: &std::path::Path) -> Result<tokio::net::UnixStream, String> {
    tokio::net::UnixStream::connect(path)
        .await
        .map_err(|e| format!("connect {}: {e}", path.display()))
}

impl hyper::service::Service<Request<Incoming>> for Forward {
    type Response = Response<ForwardBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { Ok(this.forward(request).await) })
    }
}

/// One HTTP/1.1 exchange on a fresh connection.
async fn send<IO>(io: IO, request: Outgoing) -> Result<Response<Incoming>, String>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| format!("HTTP/1.1 handshake: {e}"))?;
    tokio::spawn(async move {
        // Ends when the response body is read or dropped.
        let _done = conn.await;
    });
    let mut response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("request: {e}"))?;
    strip_hop_by_hop(response.headers_mut());
    Ok(response)
}

/// Rewrites a gateway request for an HTTP/1.1 target: origin-form URI, a
/// `Host` header (the gateway's authority, else the target's), no
/// hop-by-hop headers.
fn origin_form(mut request: Outgoing, target: &Target) -> Result<Outgoing, String> {
    let host = request
        .uri()
        .authority()
        .map_or_else(|| target_host(target), |a| a.as_str().to_owned());
    let path = request
        .uri()
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    *request.uri_mut() = Uri::from(path);
    strip_hop_by_hop(request.headers_mut());
    if !request.headers().contains_key(header::HOST) {
        let value = HeaderValue::from_str(&host).map_err(|_| format!("bad host {host:?}"))?;
        request.headers_mut().insert(header::HOST, value);
    }
    Ok(request)
}

fn target_host(target: &Target) -> String {
    match target {
        Target::Http { addr } | Target::Https { addr, .. } => addr.clone(),
        #[cfg(unix)]
        Target::Unix { .. } => "localhost".to_owned(),
    }
}

/// Headers that describe one connection, not the message (RFC 9110
/// section 7.6.1), plus any the `Connection` header names.
///
/// hyper's HTTP/2 layer (1.12) also strips these on the tunnel side, so on
/// today's path this is a second layer of defence. It is kept because the
/// target side is HTTP/1.1, where hyper does not, and because the QUIC
/// transport (M3) will not go through hyper's HTTP/2 code.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub(crate) fn error_response(status: StatusCode, why: &str) -> Response<ForwardBody> {
    let mut response = Response::new(
        Full::new(Bytes::from(format!("{why}\n")))
            .map_err(|e| match e {})
            .boxed(),
    );
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_headers_and_those_connection_names_are_removed() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("connection", "close, x-private"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("x-private", "1"),
            ("x-kept", "1"),
            ("content-type", "text/plain"),
        ] {
            h.append(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        strip_hop_by_hop(&mut h);
        let mut left: Vec<&str> = h.keys().map(HeaderName::as_str).collect();
        left.sort_unstable();
        assert_eq!(left, ["content-type", "x-kept"]);
    }
}
