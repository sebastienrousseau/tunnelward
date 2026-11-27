// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Out-of-band approval for high-impact tools (FR-17, ADR 0014). A
//! `tools/call` to a tool the policy marks `high_impact` runs only with
//! an unspent approval of exactly that call: its agent, path, tool and
//! arguments, digested. Without one, the gateway answers MCP's
//! URL-elicitation error (-32042) with a page where a person signs in at
//! their identity provider (OIDC) and approves or denies it.

mod form;
mod oidc;
mod page;
mod store;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::StatusCode;
use serde_json::{Value, json};
use tunnelward_crypto::rustls::RootCertStore;

use crate::refusal::Refusal;
use crate::{AgentAuth, RequestInfo, SharedState};

pub(crate) use page::{Context, is_path, respond};

/// Where approval pages live on the ingress.
const PREFIX: &str = "/.well-known/tunnelward/approvals/";
/// Where the approvers' provider sends them back.
const CALLBACK: &str = "/.well-known/tunnelward/approvals/callback";
/// The error id of a call that needs approval.
const REQUIRED: &str = "TW-P006";
/// MCP's `URLElicitationRequiredError`.
const URL_ELICITATION_REQUIRED: i32 = -32042;

/// How approvals work on this gateway. Turn them on with
/// [`crate::IngressConfig::approvals`]; they need agent auth on, since an
/// approval is bound to the agent's token.
#[derive(Clone)]
#[non_exhaustive]
pub struct Approvals {
    /// Where approvers reach this gateway, such as
    /// `https://mcp.example.org`: the base of the elicitation URL and of
    /// the sign-in's redirect URI.
    pub public_url: String,
    /// The approvers' provider's authorization endpoint.
    pub authorization_endpoint: String,
    /// Its token endpoint (`https://`).
    pub token_endpoint: String,
    /// This gateway's client id there; ID tokens must name it in `aud`.
    pub client_id: String,
    /// The client secret, for a confidential client; PKCE alone for a
    /// public one.
    pub client_secret: Option<String>,
    /// Checks the approvers' ID tokens: their issuer and keys, with
    /// `client_id` as the resource.
    pub verifier: AgentAuth,
    /// Roots trusted for the token endpoint.
    pub roots: Arc<RootCertStore>,
    /// Groups whose members may approve any call; anyone may approve the
    /// calls of their own agents (the same `sub`).
    pub approver_groups: Vec<String>,
    /// The ID token claim that lists groups (`groups`).
    pub approver_claim: String,
    /// How long a call waits for approval, and an approval for its call.
    pub ttl: Duration,
}

impl std::fmt::Debug for Approvals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Approvals")
            .field("public_url", &self.public_url)
            .field("client_id", &self.client_id)
            .field("approver_groups", &self.approver_groups)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl Approvals {
    /// Approvals signed in at a provider with these endpoints, as
    /// `client_id`, approved by the agents' own users only, waiting 600 s.
    #[must_use]
    pub fn new(
        public_url: &str,
        (authorization_endpoint, token_endpoint): (String, String),
        client_id: String,
        verifier: AgentAuth,
        roots: Arc<RootCertStore>,
    ) -> Self {
        Self {
            public_url: public_url.trim_end_matches('/').to_owned(),
            authorization_endpoint,
            token_endpoint,
            client_id,
            client_secret: None,
            verifier,
            roots,
            approver_groups: Vec::new(),
            approver_claim: "groups".into(),
            ttl: Duration::from_secs(600),
        }
    }
}

/// The one `tools/call` in a request that needs approval.
struct Call {
    id: Value,
    tool: String,
    arguments: Value,
    digest: String,
}

impl Call {
    /// The call in `body`, which must hold it alone, bound to `info`'s
    /// agent and path.
    fn of(body: &[u8], info: &RequestInfo) -> Result<Self, &'static str> {
        let message = match serde_json::from_slice(body) {
            Ok(Value::Array(_)) => return Err("approve one call at a time: send it alone"),
            Ok(message) => message,
            Err(_) => return Err("the call does not parse"),
        };
        let params = message
            .get("params")
            .filter(|_| message.get("method").and_then(Value::as_str) == Some("tools/call"));
        let tool = (params.and_then(|p| p.get("name")?.as_str())).ok_or("not a tools/call")?;
        let arguments = params
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null);
        Ok(Self {
            id: message.get("id").cloned().unwrap_or(Value::Null),
            digest: digest(info, tool, &arguments),
            tool: tool.to_owned(),
            arguments,
        })
    }
}

/// What an approval binds: the agent token's `sub` and client, the path,
/// the tool, and the arguments as JSON with sorted keys.
fn digest(info: &RequestInfo, tool: &str, arguments: &Value) -> String {
    let arguments = tunnelward_audit::digest(arguments.to_string().as_bytes());
    let bound = [
        info.subject.as_deref().unwrap_or("-"),
        info.client_id.as_deref().unwrap_or("-"),
        info.uri.path(),
        tool,
        &arguments,
    ];
    tunnelward_audit::digest(bound.join("\n").as_bytes())
}

/// Lets a high-impact call through once with an unspent approval of
/// exactly it; otherwise stores a request for one and answers MCP's
/// URL elicitation (`TW-P006`).
pub(crate) async fn gate(
    approvals: &Approvals,
    state: &dyn SharedState,
    body: &[u8],
    info: &RequestInfo,
) -> Result<(), Refusal> {
    let call =
        Call::of(body, info).map_err(|why| Refusal::new("TW-P007", StatusCode::FORBIDDEN, why))?;
    let unavailable = |e: String| Refusal::new("TW-P008", StatusCode::SERVICE_UNAVAILABLE, e);
    let ttl = approvals.ttl;
    let granted: Option<String> = store::get(state, &format!("approved:{}", call.digest), ttl)
        .await
        .map_err(unavailable)?;
    if let Some(id) = granted
        && store::first(state, &format!("approval-spent:{id}"), ttl)
            .await
            .map_err(unavailable)?
    {
        return Ok(());
    }
    let id = oidc::random(16).map_err(unavailable)?;
    let request = store::Request {
        id: id.clone(),
        digest: call.digest,
        tool: call.tool,
        arguments: call.arguments,
        sub: info.subject.clone(),
        client_id: info.client_id.clone(),
        path: info.uri.path().to_owned(),
        at_ms: tunnelward_audit::now_ms(),
    };
    store::put(state, &format!("approval:{id}"), &request, ttl)
        .await
        .map_err(unavailable)?;
    Err(elicitation(approvals, &call.id, &request))
}

/// The JSON-RPC error that sends the user to `request`'s page.
fn elicitation(approvals: &Approvals, rpc_id: &Value, request: &store::Request) -> Refusal {
    let message = format!("{} needs your approval before it runs", request.tool);
    let body = json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {
            "code": URL_ELICITATION_REQUIRED,
            "message": message,
            "data": {
                "elicitations": [{
                    "mode": "url",
                    "elicitationId": request.id,
                    "url": format!("{}{PREFIX}{}", approvals.public_url, request.id),
                    "message": message,
                }],
                "tw_error": REQUIRED,
            },
        },
    });
    Refusal {
        json: Some(Bytes::from(body.to_string())),
        ..Refusal::new(REQUIRED, StatusCode::OK, "the call needs approval")
    }
}
