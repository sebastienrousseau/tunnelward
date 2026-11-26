// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The risk score on the request path (FR-16, ADR 0011): every request
//! is scored after its body is read and before the policy decides, so a
//! rule can forbid risky calls. A canary refuses the request and ends
//! the subject's session (`TW-I013`).

use std::time::Instant;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::Full;
use tunnelward_risk::{Counts, Risk, key, prefix};

use crate::ingress::Ingress;
use crate::refusal::Refusal;
use crate::{Gateway, RequestInfo};

/// The error id of a request a canary ended.
const ENDED: &str = "TW-I013";

impl Gateway {
    /// The route claim that would serve a request for `host` and `path`
    /// now, if any.
    pub(crate) fn route_of(&self, host: Option<&str>, path: &str) -> Option<String> {
        let resolver = self.inner.config.resolver.as_ref();
        let target = crate::Target {
            host: host.map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase()),
            path: path.to_owned(),
        };
        self.inner.registry.route_for(resolver, &target)
    }
}

impl Ingress {
    /// Scores `request` into `info.risk`, alerting observers at the
    /// threshold; refuses one whose subject or session a canary ended,
    /// or that fires a canary itself.
    pub(crate) async fn assess(
        &self,
        request: &Request<Full<Bytes>>,
        body: &Bytes,
        info: &mut RequestInfo,
    ) -> Result<(), Refusal> {
        let gateway = self.gateway();
        let config = &gateway.inner.config;
        let Some(risk) = config.ingress.risk.as_ref() else {
            return Ok(());
        };
        let subject = subject(info);
        let session = info.mcp_session.as_deref();
        if risk.blocked(&subject, session, Instant::now()) {
            return Err(ended("this session was ended by a canary"));
        }
        let tools = tools(request, body);
        let counts = counts(gateway, risk, &subject, &tools, info).await;
        let searched = body.len().min(config.limits.max_policy_body as usize);
        let scored = tunnelward_risk::Request {
            subject: &subject,
            session,
            tools: &tools,
            body: body.get(..searched).unwrap_or_default(),
        };
        let assessment = risk.assess(&scored, &counts);
        let (alert, canary) = (
            assessment.score >= risk.settings().alert_at || assessment.canary(),
            assessment.canary(),
        );
        info.risk = Some(assessment);
        if alert {
            for o in &config.ingress.observers {
                o.on_alert(info);
            }
        }
        if canary {
            return Err(ended("a canary fired; the session is ended"));
        }
        Ok(())
    }
}

/// Who a request comes from: its OAuth client, else its address.
fn subject(info: &RequestInfo) -> String {
    info.client_id.as_ref().map_or_else(
        || format!("addr:{}", info.client.client),
        |id| format!("client:{id}"),
    )
}

/// The tools a JSON-RPC POST calls, in order.
fn tools(request: &Request<Full<Bytes>>, body: &Bytes) -> Vec<String> {
    if request.method() != Method::POST {
        return Vec::new();
    }
    tunnelward_mcp::parse(body).map_or_else(
        |_| Vec::new(),
        |envelope| {
            envelope
                .messages
                .into_iter()
                .filter_map(|m| m.tool)
                .collect()
        },
    )
}

/// The request's velocity counts from the shared store; a count the
/// store fails to give is left out (risk fails open, ADR 0011).
async fn counts(
    gateway: &Gateway,
    risk: &Risk,
    subject: &str,
    tools: &[String],
    info: &RequestInfo,
) -> Counts {
    let state = gateway.inner.config.state.as_ref();
    let window = risk.settings().window;
    let count = |k: String| async move { state.count(&k, window).await.ok() };
    let mut per_tool = Vec::with_capacity(tools.len());
    for tool in tools {
        per_tool.push(count(key("tool", &format!("{subject}\n{tool}"))).await);
    }
    Counts {
        subject: count(key("subject", subject)).await,
        tools: per_tool,
        prefix: count(key("prefix", &prefix(info.client.client))).await,
    }
}

fn ended(reason: &str) -> Refusal {
    Refusal::new(ENDED, StatusCode::FORBIDDEN, reason)
}
