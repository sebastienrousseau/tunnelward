// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The approval page (ADR 0014), served by the gateway on its ingress:
//!
//! | Request | Does |
//! | :-- | :-- |
//! | `GET <prefix><id>` | starts the approver's sign-in |
//! | `GET <prefix>callback?code&state` | checks the sign-in, shows the call and the form |
//! | `POST <prefix><id>` (`token`, `decision`) | records the approval or denial |
//!
//! It runs no script, and its Content-Security-Policy allows nothing but
//! posting its own form.

use std::time::SystemTime;

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, LOCATION};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use serde_json::Value;
use tunnelward_audit::{AdminEntry, Entry, Sink};

use super::form::{escape, field};
use super::store::{self, Form, Login};
use super::{Approvals, CALLBACK, PREFIX, oidc};
use crate::{Caller, RequestInfo, SharedState};

/// Largest form body read.
const MAX_FORM: usize = 4096;

/// What the page needs from the gateway.
pub(crate) struct Context<'a> {
    pub(crate) approvals: &'a Approvals,
    pub(crate) state: &'a dyn SharedState,
    pub(crate) audit: Option<&'a Sink>,
    pub(crate) info: &'a RequestInfo,
}

/// An answer: a status and an HTML message, or a redirect.
enum Page {
    Html(StatusCode, String),
    Redirect(String),
}

/// Whether `path` is the approval page's.
pub(crate) fn is_path(path: &str) -> bool {
    path.starts_with(PREFIX)
}

/// The page's answer to `request`.
pub(crate) async fn respond(cx: &Context<'_>, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let path = request.uri().path().to_owned();
    let tail = path.strip_prefix(PREFIX).unwrap_or_default();
    let method = request.method().clone();
    let page = if method == Method::GET && path == CALLBACK {
        callback(cx, request.uri().query().unwrap_or_default()).await
    } else if method == Method::GET {
        start(cx, tail).await
    } else if method == Method::POST {
        match body(request).await {
            Some(form) => decide(cx, tail, &form).await,
            None => Ok(message(
                StatusCode::BAD_REQUEST,
                "The form did not arrive whole.",
            )),
        }
    } else {
        Ok(message(StatusCode::METHOD_NOT_ALLOWED, "Not here."))
    };
    let page = page.unwrap_or_else(|e| message(StatusCode::SERVICE_UNAVAILABLE, &e));
    answer(page)
}

fn message(status: StatusCode, text: &str) -> Page {
    Page::Html(status, format!("<p>{}</p>", escape(text)))
}

/// Starts the approver's sign-in for request `id`.
async fn start(cx: &Context<'_>, id: &str) -> Result<Page, String> {
    let ttl = cx.approvals.ttl;
    let request: Option<store::Request> =
        store::get(cx.state, &format!("approval:{id}"), ttl).await?;
    if request.is_none() {
        return Ok(message(
            StatusCode::NOT_FOUND,
            "No such approval, or it has expired.",
        ));
    }
    let (state, nonce, verifier) = (oidc::random(32)?, oidc::random(16)?, oidc::random(32)?);
    let url = oidc::authorize_url(cx.approvals, &state, &nonce, &verifier);
    let login = Login {
        id: id.to_owned(),
        verifier,
        nonce,
    };
    store::put(cx.state, &format!("approval-login:{state}"), &login, ttl).await?;
    Ok(Page::Redirect(url))
}

/// Checks the sign-in the provider sent back, then shows the call.
async fn callback(cx: &Context<'_>, query: &str) -> Result<Page, String> {
    let ttl = cx.approvals.ttl;
    let refused = |text: &str| Ok(message(StatusCode::FORBIDDEN, text));
    let Some((code, state)) = oidc::callback(query) else {
        return refused("The sign-in did not come back whole.");
    };
    let key = format!("approval-login:{state}");
    let login: Option<Login> = store::get(cx.state, &key, ttl).await?;
    let fresh = store::first(cx.state, &format!("approval-login-used:{state}"), ttl).await?;
    let (Some(login), true) = (login, fresh) else {
        return refused("This sign-in is unknown or was used already.");
    };
    let Some(request) = store::get(cx.state, &format!("approval:{}", login.id), ttl).await? else {
        return Ok(message(
            StatusCode::NOT_FOUND,
            "No such approval, or it has expired.",
        ));
    };
    let secrets = (code.as_str(), login.verifier.as_str(), login.nonce.as_str());
    let approver = match oidc::approver(cx.approvals, secrets, SystemTime::now()).await {
        Ok(approver) => approver,
        Err(why) => return refused(&format!("The sign-in failed: {why}")),
    };
    if !may_approve(cx.approvals, &approver, &request) {
        return refused("You may not approve this call.");
    }
    let token = oidc::random(32)?;
    let form = Form {
        id: request.id.clone(),
        approver: name(&approver),
    };
    store::put(cx.state, &format!("approval-form:{token}"), &form, ttl).await?;
    Ok(Page::Html(
        StatusCode::OK,
        details(&request, &form.approver, &token),
    ))
}

/// Records the decision on request `id` the signed-in approver posted.
async fn decide(cx: &Context<'_>, id: &str, body: &str) -> Result<Page, String> {
    let ttl = cx.approvals.ttl;
    let token = field(body, "token").unwrap_or_default();
    let form: Option<Form> = store::get(cx.state, &format!("approval-form:{token}"), ttl).await?;
    let fresh = store::first(cx.state, &format!("approval-form-used:{token}"), ttl).await?;
    let (Some(form), true) = (form, fresh) else {
        return Ok(message(
            StatusCode::FORBIDDEN,
            "This form is unknown or was used already.",
        ));
    };
    if form.id != id {
        return Ok(message(
            StatusCode::FORBIDDEN,
            "This form is for another call.",
        ));
    }
    let Some(request) =
        store::get::<store::Request>(cx.state, &format!("approval:{id}"), ttl).await?
    else {
        return Ok(message(
            StatusCode::NOT_FOUND,
            "No such approval, or it has expired.",
        ));
    };
    let approve = field(body, "decision").as_deref() == Some("approve");
    if approve {
        store::put(
            cx.state,
            &format!("approved:{}", request.digest),
            &request.id,
            ttl,
        )
        .await?;
    }
    record(cx, approve, &request, form.approver);
    Ok(message(
        StatusCode::OK,
        if approve {
            "Approved. Your agent can send the call again; it will run once."
        } else {
            "Denied. The call will not run."
        },
    ))
}

/// Whether `approver` may decide `request`: the agent's own user, or a
/// member of an approver group.
fn may_approve(approvals: &Approvals, approver: &Caller, request: &store::Request) -> bool {
    let own = approver.subject.is_some() && approver.subject == request.sub;
    let groups: Vec<&str> = match approver.claims.get(&approvals.approver_claim) {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    own || approvals
        .approver_groups
        .iter()
        .any(|g| groups.contains(&g.as_str()))
}

fn name(caller: &Caller) -> String {
    (caller.subject.clone())
        .or_else(|| caller.client_id.clone())
        .unwrap_or_else(|| "unnamed".to_owned())
}

/// The call, and the form to approve or deny it.
fn details(request: &store::Request, approver: &str, token: &str) -> String {
    let arguments = serde_json::to_string_pretty(&request.arguments).unwrap_or_default();
    format!(
        "<h1>Approve {tool}?</h1>\
         <p>An agent asks to run <strong>{tool}</strong> on {path}.</p>\
         <dl><dt>Agent</dt><dd>{client} for {sub}</dd><dt>You</dt><dd>{approver}</dd></dl>\
         <pre>{arguments}</pre>\
         <form method=\"post\" action=\"{PREFIX}{id}\">\
         <input type=\"hidden\" name=\"token\" value=\"{token}\">\
         <button name=\"decision\" value=\"approve\">Approve once</button> \
         <button name=\"decision\" value=\"deny\">Deny</button></form>",
        tool = escape(&request.tool),
        path = escape(&request.path),
        client = escape(request.client_id.as_deref().unwrap_or("an unnamed client")),
        sub = escape(request.sub.as_deref().unwrap_or("an unnamed user")),
        approver = escape(approver),
        arguments = escape(&arguments),
        id = escape(&request.id),
        token = escape(token),
    )
}

/// An admin entry for the decision, when the gateway keeps a log.
fn record(cx: &Context<'_>, approve: bool, request: &store::Request, approver: String) {
    let Some(sink) = cx.audit else { return };
    let peer = sink
        .pseudonyms()
        .of("ip", cx.info.client.client.to_string().as_bytes());
    let target = format!(
        "approval={} tool={} digest={}",
        request.id, request.tool, request.digest
    );
    let action = if approve { "approve" } else { "deny" };
    let entry = AdminEntry::new(action, target, approve, peer).by(approver);
    sink.record(Entry::Admin(entry), None);
}

/// A form body of at most [`MAX_FORM`] bytes, as text.
async fn body(request: Request<Incoming>) -> Option<String> {
    let bytes = Limited::new(request.into_body(), MAX_FORM)
        .collect()
        .await
        .ok()?;
    String::from_utf8(bytes.to_bytes().to_vec()).ok()
}

fn answer(page: Page) -> Response<Full<Bytes>> {
    let (status, body, location) = match page {
        Page::Html(status, body) => (status, body, None),
        Page::Redirect(url) => (StatusCode::SEE_OTHER, String::new(), Some(url)),
    };
    let html = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">\
         <title>Tunnelward approval</title><body>{body}</body></html>"
    );
    let mut response = Response::new(Full::new(Bytes::from(html)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; form-action 'self'; frame-ancestors 'none'"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    if let Some(value) = location.and_then(|l| HeaderValue::from_str(&l).ok()) {
        headers.insert(LOCATION, value);
    }
    response
}
