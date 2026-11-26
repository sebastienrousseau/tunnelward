// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The span exporter: OTLP/HTTP JSON to a collector (ADR 0010). Spans go
//! through a bounded queue to a task that posts them in batches; a full
//! queue drops the span and counts it, so export never holds up a
//! request.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http::{StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_mcp::{Envelope, Kind};

use super::span::{Pending, request};
use crate::{ProxyObserver, RequestInfo};

/// Most requests in flight a span is kept for; more are not traced.
const MAX_PENDING: usize = 10_000;

/// Largest collector answer read.
const ANSWER_LIMIT: usize = 64 * 1024;

/// Where and how spans are exported. [`OtlpSettings::new`] gives the
/// defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpSettings {
    /// The collector's OTLP/HTTP base URL, such as
    /// `https://otel.example.org:4318`: `https://`, or `http://` to a
    /// loopback address only. Spans go to `<endpoint>/v1/traces`.
    pub endpoint: String,
    /// The `service.name` the spans carry.
    pub service: String,
    /// Most spans waiting to be sent; more are dropped and counted.
    pub queue: usize,
    /// Most spans in one request to the collector.
    pub batch: usize,
    /// Longest a span waits for its batch to fill.
    pub every: Duration,
}

impl OtlpSettings {
    /// Spans to `endpoint` as `tunnelward-gateway`: a queue of 2,048,
    /// batches of 512, sent at least every 5 s.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            service: "tunnelward-gateway".into(),
            queue: 2048,
            batch: 512,
            every: Duration::from_secs(5),
        }
    }
}

/// Exports a span per ingress request. Install it as
/// [`crate::IngressConfig::otlp`]; the gateway then also names its span
/// as the parent in the `traceparent` the connector sees.
#[derive(Debug)]
pub struct OtlpExporter {
    pending: Mutex<HashMap<u64, Pending>>,
    queue: mpsc::Sender<Value>,
    dropped: AtomicU64,
    failed: Arc<AtomicU64>,
}

impl OtlpExporter {
    /// An exporter sending to `settings.endpoint`, trusting `roots` for
    /// `https://`. Must be called inside a Tokio runtime: it spawns the
    /// sending task.
    ///
    /// # Errors
    ///
    /// The endpoint is not `https://`, or is `http://` to an address
    /// other than loopback.
    pub fn start(settings: OtlpSettings, roots: Arc<RootCertStore>) -> Result<Arc<Self>, String> {
        let url = traces_url(&settings.endpoint)?;
        let (queue, spans) = mpsc::channel(settings.queue.max(1));
        let failed = Arc::new(AtomicU64::new(0));
        let sender = Sender {
            url,
            roots,
            settings,
            failed: failed.clone(),
        };
        tokio::spawn(sender.run(spans));
        Ok(Arc::new(Self {
            pending: Mutex::new(HashMap::new()),
            queue,
            dropped: AtomicU64::new(0),
            failed,
        }))
    }

    /// Spans dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Batches the collector did not accept.
    #[must_use]
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    fn with(&self, info: &RequestInfo, edit: impl FnOnce(&mut Pending)) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(p) = pending.get_mut(&info.id) {
            edit(p);
        }
    }

    /// Ends `info`'s span and queues it.
    fn finish(&self, info: &RequestInfo) {
        let done = (self.pending.lock().unwrap_or_else(PoisonError::into_inner)).remove(&info.id);
        if let Some(p) = done
            && self.queue.try_send(p.span(info)).is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl ProxyObserver for OtlpExporter {
    fn on_request(&self, info: &RequestInfo) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if pending.len() < MAX_PENDING {
            pending.insert(info.id, Pending::new());
        }
    }

    fn on_envelope(&self, info: &RequestInfo, envelope: &Envelope) {
        let calls = envelope
            .messages
            .iter()
            .filter(|m| m.kind != Kind::Response);
        let (methods, tools): (Vec<_>, Vec<_>) =
            calls.map(|m| (m.method.clone(), m.tool.clone())).unzip();
        self.with(info, |p| {
            p.methods = methods.into_iter().flatten().collect();
            p.tools = tools.into_iter().flatten().collect();
        });
    }

    fn on_alert(&self, info: &RequestInfo) {
        self.with(info, |p| p.alerted = true);
    }

    fn on_failure(&self, info: &RequestInfo, _status: StatusCode, reason: &str) {
        self.with(info, |p| p.failure = Some(reason.to_owned()));
    }

    fn on_response(&self, info: &RequestInfo, status: StatusCode, _elapsed: Duration) {
        let mut refused = false;
        self.with(info, |p| {
            p.status = Some(status.as_u16());
            refused = p.failure.is_some();
        });
        // A refusal has no body to complete: its span ends here.
        if refused {
            self.finish(info);
        }
    }

    fn on_complete(&self, info: &RequestInfo, _bytes: u64, _elapsed: Duration) {
        self.finish(info);
    }
}

/// `<endpoint>/v1/traces`, if the endpoint is one spans may go to.
fn traces_url(endpoint: &str) -> Result<Uri, String> {
    let url = format!("{}/v1/traces", endpoint.trim_end_matches('/'));
    let uri: Uri = url
        .parse()
        .map_err(|e| format!("endpoint {endpoint:?}: {e}"))?;
    let host = uri.host().unwrap_or_default().trim_matches(['[', ']']);
    let loopback = host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    match uri.scheme_str() {
        Some("https") if !host.is_empty() => Ok(uri),
        Some("http") if loopback => Ok(uri),
        _ => Err(format!(
            "endpoint {endpoint:?}: give https://, or http:// to a loopback address"
        )),
    }
}

/// The task that posts batches.
struct Sender {
    url: Uri,
    roots: Arc<RootCertStore>,
    settings: OtlpSettings,
    failed: Arc<AtomicU64>,
}

impl Sender {
    async fn run(self, mut spans: mpsc::Receiver<Value>) {
        let mut batch = Vec::with_capacity(self.settings.batch);
        loop {
            let next = tokio::time::timeout(self.settings.every, spans.recv()).await;
            let (closed, timed_out) = (matches!(next, Ok(None)), next.is_err());
            if let Ok(Some(span)) = next {
                batch.push(span);
            }
            let full = batch.len() >= self.settings.batch.max(1);
            if !batch.is_empty() && (full || closed || timed_out) {
                let body = request(&self.settings.service, &std::mem::take(&mut batch));
                if self.post(body.to_string().into_bytes()).await.is_err() {
                    self.failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            if closed {
                return;
            }
        }
    }

    async fn post(&self, body: Vec<u8>) -> Result<(), String> {
        if self.url.scheme_str() == Some("https") {
            let url = self.url.to_string();
            return crate::https_post(&url, body, self.roots.clone(), ANSWER_LIMIT)
                .await
                .map(drop);
        }
        plain_post(&self.url, body).await
    }
}

/// POSTs JSON over plain HTTP/1.1, for a collector on loopback.
async fn plain_post(url: &Uri, body: Vec<u8>) -> Result<(), String> {
    let host = url.host().unwrap_or_default().trim_matches(['[', ']']);
    let tcp = TcpStream::connect((host, url.port_u16().unwrap_or(80)))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .map_err(|e| format!("HTTP: {e}"))?;
    tokio::spawn(conn);
    let authority = url.authority().map_or(host, http::uri::Authority::as_str);
    let request = http::Request::post(url.path())
        .header(http::header::HOST, authority)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| format!("request: {e}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("HTTP: {e}"))?;
    let status = response.status();
    let _answer = Limited::new(response.into_body(), ANSWER_LIMIT)
        .collect()
        .await;
    status
        .is_success()
        .then_some(())
        .ok_or_else(|| format!("status {status}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_go_over_tls_or_stay_on_the_machine() {
        let ok = [
            "https://otel.example.org:4318",
            "http://127.0.0.1:4318/",
            "http://[::1]:4318",
            "http://localhost:4318",
        ];
        for endpoint in ok {
            assert!(traces_url(endpoint).is_ok(), "{endpoint}");
        }
        assert_eq!(
            traces_url("https://otel.example.org:4318/").map(|u| u.to_string()),
            Ok("https://otel.example.org:4318/v1/traces".into())
        );
        for endpoint in [
            "http://otel.example.org:4318",
            "http://10.0.0.5:4318",
            "ftp://x",
            "otel:4318",
        ] {
            assert!(traces_url(endpoint).is_err(), "{endpoint}");
        }
    }
}
