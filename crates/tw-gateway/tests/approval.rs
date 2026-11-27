// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Out-of-band approval for high-impact tools (FR-17, ADR 0014): a call
//! gets MCP's URL elicitation; a person signs in at their provider and
//! approves exactly that call; it then runs once, and a changed call
//! needs its own approval. Only the agent's user or an approver group
//! may decide, and each sign-in and form works once.

mod common;

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aws_lc_rs::digest::{SHA256, digest};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tunnelward_connector::register;
use tunnelward_crypto::{ClientAuth, KeyExchange, server_config};
use tunnelward_gateway::{AgentAuth, Approvals, InMemory, Issuer, KeySet};
use tunnelward_policy::{Effect, Policy, Rule};
use tunnelward_testpki as pki;

use common::agent::{Agent, ISSUER, RESOURCE, agent, transfer};
use common::ingress::{h1, ingress_config, start_ingress};
use common::jwt::{Signer, b64, now};
use common::{Res, audit_sink, connector_config, registration};

const IDP: &str = "https://idp.example.org";
const CLIENT: &str = "tunnelward-approvals";

/// Who the provider signs in next, and the sign-in it must match.
#[derive(Default)]
struct Next {
    sub: String,
    groups: Vec<String>,
    nonce: String,
    challenge: String,
    /// Sign another sign-in's nonce instead, as a replayed token would.
    stale_nonce: bool,
}

/// The provider's token endpoint over TLS: an ID token for `next`, once
/// the PKCE verifier matches the challenge.
async fn token_endpoint(idp: Arc<Signer>, next: Arc<Mutex<Next>>) -> Res<String> {
    let tls = server_config(
        pki::identity(pki::GATEWAY),
        ClientAuth::None,
        KeyExchange::default(),
        &[b"http/1.1"],
    )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("https://{}/token", listener.local_addr()?);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (idp, next) = (idp.clone(), next.clone());
            let Ok(stream) = acceptor.accept(tcp).await else {
                continue;
            };
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let (idp, next) = (idp.clone(), next.clone());
                async move { Ok::<_, Infallible>(issue(&idp, &next, request).await) }
            });
            let _ended = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        }
    });
    Ok(url)
}

async fn issue(
    idp: &Signer,
    next: &Mutex<Next>,
    request: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    let form = request
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let form = String::from_utf8_lossy(&form).into_owned();
    let verifier = value(&form, "code_verifier").unwrap_or_default();
    let next = next
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if b64(digest(&SHA256, verifier.as_bytes()).as_ref()) != next.challenge {
        let mut refused = Response::new(Full::new(Bytes::from_static(b"{}")));
        *refused.status_mut() = StatusCode::BAD_REQUEST;
        return refused;
    }
    let nonce = if next.stale_nonce {
        "stale"
    } else {
        &next.nonce
    };
    let claims = format!(
        r#"{{"iss":"{IDP}","aud":"{CLIENT}","sub":"{}","nonce":"{}","groups":{:?},"exp":{}}}"#,
        next.sub,
        nonce,
        next.groups,
        now() + 300
    );
    let token = idp.token(&claims).unwrap_or_default();
    Response::new(Full::new(Bytes::from(format!(
        r#"{{"id_token":"{token}"}}"#
    ))))
}

/// `name`'s value in a query or form, as the gateway encodes it.
fn value(text: &str, name: &str) -> Option<String> {
    let raw = text
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix(&format!("{name}=")))?;
    Some(raw.replace("%2F", "/").replace("%3A", ":"))
}

/// A running gateway with approvals, its ingress, the provider's next
/// sign-in, the tool's run count and the audit log.
struct Setup {
    ingress: String,
    agent: Agent,
    next: Arc<Mutex<Next>>,
    runs: Arc<AtomicUsize>,
    log: std::path::PathBuf,
}

fn approvals(idp: &Signer, token_url: String) -> Res<Approvals> {
    let keys = KeySet::from_jwks(Signer::jwks(&[idp]).as_bytes())?;
    let issuer = Issuer {
        issuer: IDP.into(),
        keys: Arc::new(keys),
    };
    let endpoints = (format!("{IDP}/authorize"), token_url);
    let verifier = AgentAuth::new(CLIENT, vec![issuer]);
    let mut approvals = Approvals::new(
        RESOURCE,
        endpoints,
        CLIENT.into(),
        verifier,
        pki::roots(pki::CA)?,
    );
    approvals.approver_groups = vec!["tw-approvers".into()];
    Ok(approvals)
}

/// The gateway: agent auth, `transfer` high impact, approvals on, the
/// state in memory and the audit log in `sink`.
fn config(
    agent: &Agent,
    approvals: Approvals,
    sink: Arc<tunnelward_audit::Sink>,
) -> Res<tunnelward_gateway::Config> {
    let keys = KeySet::from_jwks(Signer::jwks(&[&agent.issuer]).as_bytes())?;
    let issuer = Issuer {
        issuer: ISSUER.into(),
        keys: Arc::new(keys),
    };
    let policy = Policy {
        rules: vec![Rule::any(Effect::Permit)],
        high_impact: vec!["transfer".into()],
        ..Policy::deny_by_default()
    };
    let mut config = ingress_config(|i| {
        i.agent_auth = Some(AgentAuth::new(RESOURCE, vec![issuer]));
        i.policy = Some(Arc::new(policy));
        i.approvals = Some(Arc::new(approvals));
    })?;
    config.state = Arc::new(InMemory::default());
    config.audit = Some(sink);
    Ok(config)
}

async fn start(name: &str) -> Res<Setup> {
    let (agent, idp) = (agent()?, Arc::new(Signer::es256("idp")?));
    let next = Arc::new(Mutex::new(Next::default()));
    let approvals = approvals(&idp, token_endpoint(idp.clone(), next.clone()).await?)?;
    let (sink, log) = audit_sink(name)?;
    let (_gateway, connectors, ingress) = start_ingress(config(&agent, approvals, sink)?).await?;
    let runs = Arc::new(AtomicUsize::new(0));
    serve_tool(&connectors, runs.clone()).await?;
    Ok(Setup {
        ingress,
        agent,
        next,
        runs,
        log,
    })
}

/// The connector: each run of the tool counted.
async fn serve_tool(connectors: &str, runs: Arc<AtomicUsize>) -> Res<()> {
    let session = register(&connector_config(
        connectors,
        registration(1, &["mcp"], &[]),
    )?)
    .await?;
    tokio::spawn(async move {
        let service = service_fn(move |_request: Request<hyper::body::Incoming>| {
            let run = runs.fetch_add(1, Ordering::SeqCst) + 1;
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"run":{run}}}}}"#);
            std::future::ready(Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                body,
            )))))
        });
        let _ended = session.serve(service).await;
    });
    Ok(())
}

/// A `transfer` of `amount` under a fresh idempotency key: its answer.
async fn call(s: &Setup, amount: u32) -> Res<String> {
    let key = format!("k-{amount}-{}", common::agent::now_nanos());
    let (status, _, body) = transfer(&s.ingress, &s.agent, (amount, Some(&key)), true).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(body)
}

/// The approval page's path in an elicitation answer.
fn elicited(body: &str) -> Res<String> {
    let answer: serde_json::Value = serde_json::from_str(body)?;
    assert_eq!(answer["error"]["code"], -32042, "{body}");
    let url = answer["error"]["data"]["elicitations"][0]["url"]
        .as_str()
        .ok_or("no url")?;
    Ok(url
        .strip_prefix(RESOURCE)
        .ok_or("not this gateway's")?
        .to_owned())
}

/// A request to the approval page: status, `Location`, body.
async fn page(
    s: &Setup,
    method: &str,
    path: &str,
    form: &str,
) -> Res<(StatusCode, String, String)> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mcp.example.org")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from(form.to_owned())))?;
    let (status, headers, body) = h1(&s.ingress, request).await?;
    let location = headers
        .get("location")
        .and_then(|l| l.to_str().ok())
        .unwrap_or_default();
    Ok((status, location.to_owned(), body))
}

/// Opens `path`, and signs in at the provider as `sub` in `groups`: the
/// callback's answer, and the state it used.
async fn sign_in(
    s: &Setup,
    path: &str,
    (sub, groups): (&str, &[&str]),
) -> Res<(StatusCode, String, String)> {
    let (status, authorize, _) = page(s, "GET", path, "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        authorize.contains("code_challenge_method=S256")
            && authorize.contains("redirect_uri=https%3A%2F%2Fmcp.example.org"),
        "{authorize}"
    );
    let state = value(&authorize, "state").ok_or("no state")?;
    {
        let mut next = s
            .next
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        next.sub = sub.into();
        next.groups = groups.iter().map(|g| (*g).to_owned()).collect();
        next.nonce = value(&authorize, "nonce").ok_or("no nonce")?;
        next.challenge = value(&authorize, "code_challenge").ok_or("no challenge")?;
    }
    let callback = format!("/.well-known/tunnelward/approvals/callback?code=c1&state={state}");
    let (status, _, body) = page(s, "GET", &callback, "").await?;
    Ok((status, body, callback))
}

/// Posts `decision` with the form in `shown`, for the page at `path`.
async fn decide(s: &Setup, path: &str, shown: &str, decision: &str) -> Res<String> {
    let token = shown
        .split("name=\"token\" value=\"")
        .nth(1)
        .and_then(|t| t.split('"').next())
        .ok_or("no form")?;
    let (status, _, body) = page(
        s,
        "POST",
        path,
        &format!("token={token}&decision={decision}"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(body)
}

#[tokio::test]
async fn an_approved_call_runs_once_and_a_changed_one_needs_its_own_approval() -> Res<()> {
    let s = start("approval-once").await?;
    let path = elicited(&call(&s, 5).await?)?;
    assert_eq!(s.runs.load(Ordering::SeqCst), 0, "not without approval");
    let (status, shown, _) = sign_in(&s, &path, ("alice", &[])).await?;
    assert_eq!(status, StatusCode::OK, "{shown}");
    assert!(
        shown.contains("transfer") && shown.contains("&quot;amount&quot;: 5"),
        "{shown}"
    );
    assert!(
        decide(&s, &path, &shown, "approve")
            .await?
            .contains("Approved")
    );
    // A changed argument is another call, even with this one approved.
    elicited(&call(&s, 6).await?)?;
    assert!(
        call(&s, 5).await?.contains(r#""run":1"#),
        "the approved call runs"
    );
    elicited(&call(&s, 5).await?)?;
    assert_eq!(s.runs.load(Ordering::SeqCst), 1, "once, and only that call");
    let log = std::fs::read_to_string(&s.log)?;
    assert!(
        log.contains(r#""action":"approve""#) && log.contains(r#""actor":"alice""#),
        "{log}"
    );
    Ok(())
}

#[tokio::test]
async fn only_the_agents_user_or_an_approver_may_decide_and_each_sign_in_works_once() -> Res<()> {
    let s = start("approval-who").await?;
    let path = elicited(&call(&s, 9).await?)?;
    let (status, body, _) = sign_in(&s, &path, ("mallory", &[])).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("may not approve"), "{body}");
    let (status, shown, used) = sign_in(&s, &path, ("bob", &["tw-approvers"])).await?;
    assert_eq!(status, StatusCode::OK, "{shown}");
    let (again, _, body) = page(&s, "GET", &used, "").await?;
    assert_eq!(again, StatusCode::FORBIDDEN, "{body}");
    assert!(decide(&s, &path, &shown, "deny").await?.contains("Denied"));
    let (status, _, body) = page(&s, "POST", &path, "token=x&decision=approve").await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    elicited(&call(&s, 9).await?)?;
    assert_eq!(s.runs.load(Ordering::SeqCst), 0);
    let _ = std::fs::remove_file(&s.log);
    Ok(())
}

#[tokio::test]
async fn an_id_token_for_another_sign_in_is_refused() -> Res<()> {
    let s = start("approval-nonce").await?;
    let path = elicited(&call(&s, 3).await?)?;
    s.next
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .stale_nonce = true;
    let (status, body, _) = sign_in(&s, &path, ("alice", &[])).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("nonce"), "{body}");
    let _ = std::fs::remove_file(&s.log);
    Ok(())
}
