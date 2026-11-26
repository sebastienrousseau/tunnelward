// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Telemetry (ADR 0010): RED metrics per route on `/metrics`, with
//! exemplars in `OpenMetrics`, and a span per request exported as
//! OTLP/HTTP JSON to a collector, here a fake one on loopback.

mod common;

use std::convert::Infallible;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::TcpListener;
use tunnelward_connector::register;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_gateway::{AdminConfig, Gateway, OtlpExporter, OtlpSettings};
use tunnelward_policy::{Effect, Policy, Rule};

use common::ingress::{h1, ingress_config, start_ingress};
use common::{Res, connector_config, eventually, registration};

const CLIENT_TRACE: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

/// A collector that keeps every span it is sent.
#[derive(Debug, Default)]
struct Collector(Mutex<Vec<Value>>);

impl Collector {
    async fn start() -> Res<(Arc<Self>, String)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let collector = Arc::new(Self::default());
        let keeper = collector.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let keeper = keeper.clone();
                let service = service_fn(move |req: Request<Incoming>| {
                    let keeper = keeper.clone();
                    async move {
                        let path_ok = req.uri().path() == "/v1/traces";
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(http_body_util::Collected::to_bytes);
                        let spans = body
                            .ok()
                            .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
                        if let (true, Some(request)) = (path_ok, spans) {
                            keeper.keep(&request);
                        }
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("{}"))))
                    }
                });
                let conn = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service);
                tokio::spawn(conn);
            }
        });
        Ok((collector, endpoint))
    }

    fn keep(&self, request: &Value) {
        let spans = request["resourceSpans"][0]["scopeSpans"][0]["spans"].as_array();
        let mut kept = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        kept.extend(spans.into_iter().flatten().cloned());
    }

    fn spans(&self) -> Vec<Value> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The value of attribute `key` in `span`, as JSON.
fn attribute<'a>(span: &'a Value, key: &str) -> Option<&'a Value> {
    let attributes = span["attributes"].as_array()?;
    let found = attributes.iter().find(|a| a["key"] == key)?;
    Some(&found["value"])
}

/// A gateway exporting spans to a fresh collector, with a policy that
/// forbids `delete_*`, and a connector on `mcp` that answers with the
/// `traceparent` it was sent.
async fn traced() -> Res<(Gateway, String, Arc<Collector>)> {
    let (collector, endpoint) = Collector::start().await?;
    let settings = OtlpSettings {
        every: Duration::from_millis(50),
        ..OtlpSettings::new(endpoint)
    };
    let otlp = OtlpExporter::start(settings, Arc::new(RootCertStore::empty()))?;
    let policy = Policy {
        rules: vec![
            Rule::any(Effect::Permit),
            Rule {
                tools: vec!["delete_*".into()],
                ..Rule::any(Effect::Forbid)
            },
        ],
        baseline: false,
        ..Policy::deny_by_default()
    };
    let config = ingress_config(|i| {
        i.otlp = Some(otlp);
        i.policy = Some(Arc::new(policy));
    })?;
    let (gateway, connectors, ingress) = start_ingress(config).await?;
    let session = register(&connector_config(
        &connectors,
        registration(1, &["mcp"], &[]),
    )?)
    .await?;
    tokio::spawn(async move {
        let service = service_fn(|req: Request<Incoming>| {
            let seen = req.headers().get("traceparent").cloned();
            let mut answer = Response::new(Full::new(Bytes::from(
                r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            )));
            if let Some(seen) = seen {
                answer.headers_mut().insert("x-seen-traceparent", seen);
            }
            std::future::ready(Ok::<_, Infallible>(answer))
        });
        let _ended = session.serve(service).await;
    });
    Ok((gateway, ingress, collector))
}

async fn call(
    ingress: &str,
    tool: &str,
    traceparent: Option<&str>,
) -> Res<(StatusCode, hyper::HeaderMap)> {
    let body =
        format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}"}}}}"#);
    let mut request = Request::post("/mcp/x")
        .header("host", "mcp.example.org")
        .header("content-type", "application/json");
    if let Some(t) = traceparent {
        request = request.header("traceparent", t);
    }
    let (status, headers, _) = h1(ingress, request.body(Full::new(Bytes::from(body)))?).await?;
    Ok((status, headers))
}

#[tokio::test]
async fn each_request_is_a_span_that_continues_the_clients_trace() -> Res<()> {
    let (_gateway, ingress, collector) = traced().await?;
    let (status, headers) = call(&ingress, "read_balance", Some(CLIENT_TRACE)).await?;
    assert_eq!(status, StatusCode::OK);
    eventually("the span", || !collector.spans().is_empty()).await?;
    let span = collector.spans().remove(0);
    assert_eq!(span["traceId"], "0af7651916cd43dd8448eb211c80319c");
    assert_eq!(span["parentSpanId"], "b7ad6b7169203331");
    assert_eq!(
        (span["kind"].as_u64(), span["status"]["code"].as_u64()),
        (Some(2), Some(0))
    );
    assert_eq!(
        attribute(&span, "tunnelward.route"),
        Some(&serde_json::json!({ "stringValue": "mcp" }))
    );
    assert_eq!(
        attribute(&span, "http.response.status_code"),
        Some(&serde_json::json!({ "intValue": "200" }))
    );
    let tools =
        attribute(&span, "mcp.tools").map(|v| v["arrayValue"]["values"][0]["stringValue"].clone());
    assert_eq!(tools, Some(Value::from("read_balance")));
    let seen = headers
        .get("x-seen-traceparent")
        .and_then(|v| v.to_str().ok())
        .ok_or("no traceparent")?;
    let span_id = span["spanId"].as_str().ok_or("no span id")?;
    assert_eq!(
        seen,
        format!("00-0af7651916cd43dd8448eb211c80319c-{span_id}-01"),
        "the connector's parent is the gateway's span"
    );
    Ok(())
}

#[tokio::test]
async fn a_refused_request_is_an_error_span() -> Res<()> {
    let (_gateway, ingress, collector) = traced().await?;
    let (status, _) = call(&ingress, "delete_account", None).await?;
    assert_eq!(status, StatusCode::OK, "a JSON-RPC error");
    eventually("the span", || !collector.spans().is_empty()).await?;
    let span = collector.spans().remove(0);
    assert_eq!(span["status"]["code"], 2);
    assert!(span["parentSpanId"].is_null(), "no client trace: a new one");
    assert_eq!(span["traceId"].as_str().map(str::len), Some(32));
    Ok(())
}

async fn scrape(gateway: &Gateway, accept: &str) -> Res<(String, String)> {
    let request = Request::get("/metrics").header("accept", accept).body(())?;
    let answer = gateway
        .admin(&AdminConfig::default(), "127.0.0.1:9".parse()?, &request)
        .await;
    let kind = answer
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = answer.into_body().collect().await?.to_bytes();
    Ok((kind, String::from_utf8(body.to_vec())?))
}

#[tokio::test]
async fn metrics_count_requests_per_route_with_exemplars_on_request() -> Res<()> {
    let (gateway, ingress, _collector) = traced().await?;
    call(&ingress, "read_balance", Some(CLIENT_TRACE)).await?;
    call(&ingress, "delete_account", None).await?;
    let (kind, text) = scrape(&gateway, "text/plain").await?;
    assert!(kind.starts_with("text/plain"), "{kind}");
    assert!(
        text.contains("tunnelward_requests_total{route=\"mcp\",code=\"2xx\"} 2"),
        "{text}"
    );
    assert!(
        text.contains("tunnelward_request_duration_seconds_count{route=\"mcp\"} 2"),
        "{text}"
    );
    assert!(text.contains("tunnelward_spans_dropped_total 0"), "{text}");
    assert!(
        !text.contains("# {trace_id="),
        "no exemplars in the Prometheus format"
    );
    let (kind, open) = scrape(&gateway, "application/openmetrics-text; version=1.0.0").await?;
    assert!(kind.starts_with("application/openmetrics-text"), "{kind}");
    assert!(open.contains("# {trace_id=\""), "{open}");
    assert!(
        open.contains("# TYPE tunnelward_requests counter") && open.ends_with("# EOF\n"),
        "{open}"
    );
    Ok(())
}
