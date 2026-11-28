// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: GPL-3.0-only

//! Gateway-blind mode end to end (ADR 0016): an agent seals a call's
//! arguments to the connector's X-Wing key; the gateway routes it on the
//! tool name and records it with only a digest of the sealed arguments;
//! the connector opens it for the local server and seals the answer,
//! which only the agent opens.

mod common;

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tunnelward_connector::{Blind, Forward, Target, register};
use tunnelward_crypto::xwing::PrivateKeyXWing;
use tunnelward_mcp::blind::{open_answer, seal_call};

use common::ingress::{h1, ingress_config, start_ingress};
use common::{Res, audit_sink, connector_config, logged, registration};

const WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The local MCP server: records each body it gets and answers with the
/// arguments it saw.
async fn server(seen: Arc<Mutex<Vec<String>>>) -> Res<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let seen = seen.clone();
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let seen = seen.clone();
                async move {
                    let body = request
                        .into_body()
                        .collect()
                        .await
                        .map(http_body_util::Collected::to_bytes)
                        .unwrap_or_default();
                    let call: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                    seen.lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(String::from_utf8_lossy(&body).into_owned());
                    let answer = serde_json::json!({"jsonrpc":"2.0","id":call["id"],"result":{"echo":call["params"]["arguments"]}});
                    let mut response = Response::new(Full::new(Bytes::from(answer.to_string())));
                    response.headers_mut().insert(
                        "content-type",
                        "application/json"
                            .parse()
                            .unwrap_or_else(|_| unreachable!()),
                    );
                    Ok::<_, Infallible>(response)
                }
            });
            tokio::spawn(http1::Builder::new().serve_connection(TokioIo::new(tcp), service));
        }
    });
    Ok(addr)
}

/// A gateway with an audit log and a blind connector before `server`:
/// its ingress, the connector's public key, and the log.
struct Setup {
    ingress: String,
    public: Vec<u8>,
    sink: Arc<tunnelward_audit::Sink>,
    log: std::path::PathBuf,
}

async fn start(seen: Arc<Mutex<Vec<String>>>) -> Res<Setup> {
    let key = PrivateKeyXWing::generate()?;
    let public = key.public_key().to_vec();
    let target = Target::Http {
        addr: server(seen).await?,
    };
    let (sink, log) = audit_sink("blind")?;
    let mut config = ingress_config(|_| {})?;
    config.audit = Some(sink.clone());
    let (_gateway, connectors, ingress) = start_ingress(config).await?;
    let session = register(&connector_config(
        &connectors,
        registration(1, &["mcp"], &[]),
    )?)
    .await?;
    let forward = Forward::new(target, WAIT).with_blind(Blind::new(key));
    tokio::spawn(async move { session.serve(forward).await });
    Ok(Setup {
        ingress,
        public,
        sink,
        log,
    })
}

/// The audit log records the tool and no argument.
fn audited_without_arguments(s: &Setup) -> Res<()> {
    let entries = logged(&s.sink, &s.log, "request")?;
    let line = entries.first().ok_or("no audit entry")?.to_string();
    assert!(
        line.contains("\"tool\":\"transfer\""),
        "the gateway saw the tool: {line}"
    );
    assert!(!line.contains("alice"), "but not the arguments: {line}");
    Ok(())
}

#[tokio::test]
async fn a_sealed_call_crosses_the_gateway_unread() -> Res<()> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = start(seen.clone()).await?;
    let call = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"transfer","arguments":{"to":"alice","amount":5}}}"#;
    let (sealed, response_key) = seal_call(call, &s.public)?;
    let request = Request::post("/mcp")
        .header("host", "mcp.example.org")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(sealed)))?;
    let (status, _, body) = h1(&s.ingress, request).await?;
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains("alice"), "the answer crossed sealed: {body}");
    let answer: serde_json::Value =
        serde_json::from_slice(&open_answer(body.as_bytes(), &response_key)?)?;
    assert_eq!(
        answer["result"]["echo"],
        serde_json::json!({"to":"alice","amount":5})
    );
    let server_saw = seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        server_saw.len() == 1 && server_saw[0].contains("\"alice\""),
        "the server got the plain call"
    );
    audited_without_arguments(&s)
}

#[tokio::test]
async fn a_connector_that_requires_sealing_refuses_a_plain_call() -> Res<()> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let target = Target::Http {
        addr: server(seen.clone()).await?,
    };
    let (_gateway, connectors, ingress) = start_ingress(ingress_config(|_| {})?).await?;
    let session = register(&connector_config(
        &connectors,
        registration(1, &["mcp"], &[]),
    )?)
    .await?;
    let mut blind = Blind::new(PrivateKeyXWing::generate()?);
    blind.require = true;
    tokio::spawn(async move {
        session
            .serve(Forward::new(target, WAIT).with_blind(blind))
            .await
    });

    let plain = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer","arguments":{"to":"alice"}}}"#;
    let request = Request::post("/mcp")
        .header("host", "mcp.example.org")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(plain)))?;
    let (_, _, body) = h1(&ingress, request).await?;
    assert!(
        body.contains("sealed tools/call only") && body.contains("-32602"),
        "{body}"
    );
    assert!(
        seen.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty(),
        "nothing reached the server"
    );
    Ok(())
}
