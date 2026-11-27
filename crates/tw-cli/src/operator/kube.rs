// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: GPL-3.0-only

//! The Kubernetes API, as far as the operator needs it (ADR 0015): GET,
//! server-side apply and status patches, HTTPS and JSON over hyper and
//! rustls. The bearer token is read again for every request, since a
//! service account's token is rotated under the operator's feet.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header;
use hyper::{Method, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::TcpStream;
use tunnelward_crypto::rustls::ClientConfig;
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{KeyExchange, client_config};

/// Where a pod finds its service account.
const SERVICE_ACCOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
/// Largest answer read, such as a long list.
const MAX_ANSWER: usize = 16 * 1024 * 1024;
/// Longest a request may take.
const TIMEOUT: Duration = Duration::from_secs(30);
/// Who the operator's applies belong to.
const FIELD_MANAGER: &str = "tunnelward-operator";

/// A client for one API server.
pub(crate) struct Kube {
    server: Uri,
    token_file: PathBuf,
    tls: Arc<ClientConfig>,
}

impl Kube {
    /// The API server at `server` (`https://host:port`), trusting the CA
    /// in `ca`, with the token in `token_file`.
    pub(crate) fn new(server: &str, token_file: PathBuf, ca: &Path) -> Result<Self, String> {
        let server: Uri = server
            .parse()
            .map_err(|e| format!("server {server:?}: {e}"))?;
        if server.scheme_str() != Some("https") || server.host().is_none() {
            return Err(format!("server {server}: give https://host:port"));
        }
        let roots = crate::config::roots(ca)?;
        let tls = client_config(roots, None, KeyExchange::default(), &[b"http/1.1"])
            .map_err(|e| format!("TLS: {e}"))?;
        Ok(Self {
            server,
            token_file,
            tls: Arc::new(tls),
        })
    }

    /// The API server of the cluster this pod runs in, with its service
    /// account.
    pub(crate) fn in_cluster() -> Result<Self, String> {
        let var = |name: &str| {
            std::env::var(name)
                .map_err(|_| format!("{name} is not set: not in a pod? give --server"))
        };
        let (host, port) = (
            var("KUBERNETES_SERVICE_HOST")?,
            var("KUBERNETES_SERVICE_PORT")?,
        );
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        let account = Path::new(SERVICE_ACCOUNT);
        Self::new(
            &format!("https://{host}:{port}"),
            account.join("token"),
            &account.join("ca.crt"),
        )
    }

    /// The object at `path`; `None` when there is none.
    pub(crate) async fn get(&self, path: &str) -> Result<Option<Value>, String> {
        let (status, body) = self.send(Method::GET, path, None, Vec::new()).await?;
        match status {
            StatusCode::NOT_FOUND => Ok(None),
            s if s.is_success() => serde_json::from_slice(&body)
                .map(Some)
                .map_err(|e| format!("GET {path}: {e}")),
            s => Err(failure("GET", path, s, &body)),
        }
    }

    /// Applies `object` at `path` (server-side apply, taking over fields
    /// another manager set).
    pub(crate) async fn apply(&self, path: &str, object: &Value) -> Result<(), String> {
        let query = format!("{path}?fieldManager={FIELD_MANAGER}&force=true");
        let body = object.to_string().into_bytes();
        let (status, answer) = self
            .send(
                Method::PATCH,
                &query,
                Some("application/apply-patch+yaml"),
                body,
            )
            .await?;
        status
            .is_success()
            .then_some(())
            .ok_or_else(|| failure("apply", path, status, &answer))
    }

    /// Merges `status` into the status of the object at `path`.
    pub(crate) async fn status(&self, path: &str, status: &Value) -> Result<(), String> {
        let path = format!("{path}/status");
        let body = serde_json::json!({ "status": status })
            .to_string()
            .into_bytes();
        let (code, answer) = self
            .send(
                Method::PATCH,
                &path,
                Some("application/merge-patch+json"),
                body,
            )
            .await?;
        code.is_success()
            .then_some(())
            .ok_or_else(|| failure("status", &path, code, &answer))
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Vec<u8>), String> {
        let token = std::fs::read_to_string(&self.token_file)
            .map_err(|e| format!("{}: {e}", self.token_file.display()))?;
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(
                header::HOST,
                self.server.authority().map_or("", |a| a.as_str()),
            )
            .header(header::AUTHORIZATION, format!("Bearer {}", token.trim()))
            .header(header::ACCEPT, "application/json");
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let request = request
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| e.to_string())?;
        tokio::time::timeout(TIMEOUT, self.exchange(request))
            .await
            .map_err(|_| format!("{path}: timed out"))?
    }

    async fn exchange(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<(StatusCode, Vec<u8>), String> {
        let mut sender = self.connect().await?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| format!("HTTP: {e}"))?;
        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_ANSWER)
            .collect()
            .await
            .map_err(|e| format!("body: {e}"))?
            .to_bytes();
        Ok((status, body.to_vec()))
    }

    /// An HTTP/1.1 connection to the API server over TLS.
    async fn connect(
        &self,
    ) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>, String> {
        let host = self
            .server
            .host()
            .unwrap_or_default()
            .trim_matches(['[', ']']);
        let port = self.server.port_u16().unwrap_or(443);
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let name = ServerName::try_from(host.to_owned()).map_err(|e| format!("host: {e}"))?;
        let tls = tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, tcp)
            .await
            .map_err(|e| format!("TLS: {e}"))?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| format!("HTTP: {e}"))?;
        tokio::spawn(conn);
        Ok(sender)
    }
}

/// What a refused request says: the status and the API's message.
fn failure(verb: &str, path: &str, status: StatusCode, body: &[u8]) -> String {
    let message = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("message")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| String::from_utf8_lossy(&body[..body.len().min(200)]).into_owned());
    format!("{verb} {path}: {status}: {message}")
}
