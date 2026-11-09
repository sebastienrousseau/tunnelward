// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The agent-facing request path (FR-2, G12, G13).
//!
//! [`Ingress`] is a hyper service for one client connection: it resolves
//! the client (FR-11), applies the limits, buffers the request body up to
//! `max_body`, restates the forwarding headers, and sends the request
//! through a connector. The response streams back. Embedders mount it in
//! their own server with [`Gateway::ingress`]; [`Gateway::serve_ingress`]
//! is the ready-made listener.

use core::future::Future;
use core::pin::Pin;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

use bytes::Bytes;
use http::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST, RETRY_AFTER, WWW_AUTHENTICATE,
};
use http::{HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;

use crate::answers::{json, metadata, preflight, ready, stamp_request_id};
use crate::auth;
use crate::cors::{self, Cors};
use crate::enrol;
use crate::forwarding::{Stamp, rewrite};
use crate::idempotent;
use crate::observed::Observed;
use crate::provenance;
use crate::refusal::{Refusal, refusal_for};
use crate::{ClientAddr, Gateway, RequestInfo, ResponseBody};

/// The ingress response body: a connector's stream, or the gateway's own
/// short answer.
pub type IngressBody = BoxBody<Bytes, hyper::Error>;

/// The ingress service for one client connection. Cloning is cheap.
#[derive(Clone, Debug)]
pub struct Ingress {
    gateway: Gateway,
    peer: SocketAddr,
    secure: bool,
    /// SHA-256 of the client's TLS certificate, when it sent one.
    client_cert: Option<[u8; 32]>,
}

impl core::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Gateway").finish_non_exhaustive()
    }
}

impl Gateway {
    /// The ingress service for a client connection from `peer` (after any
    /// PROXY header). `secure` says whether the client used TLS, for the
    /// `proto` the connector is told.
    #[must_use]
    pub fn ingress(&self, peer: SocketAddr, secure: bool) -> Ingress {
        Ingress {
            gateway: self.clone(),
            peer,
            secure,
            client_cert: None,
        }
    }
}

impl Ingress {
    /// The same service for a client that presented the TLS certificate
    /// `der`, which a token bound to it (RFC 8705) must name.
    #[must_use]
    pub fn with_client_certificate(mut self, der: &[u8]) -> Self {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der);
        self.client_cert = digest.as_ref().try_into().ok();
        self
    }
}

impl hyper::service::Service<Request<Incoming>> for Ingress {
    type Response = Response<IngressBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { Ok(this.handle(request).await) })
    }
}

/// A forwarded request's answer: streamed from the connector, or held
/// whole by the gateway.
enum Forwarded {
    Stream(Response<ResponseBody>),
    Ready(Response<Full<Bytes>>),
}

/// The response header naming a refusal's error id.
const TW_ERROR: http::HeaderName = http::HeaderName::from_static("tw-error");

impl Ingress {
    async fn handle(self, request: Request<Incoming>) -> Response<IngressBody> {
        let started = Instant::now();
        let inner = &self.gateway.inner;
        let ingress = &inner.config.ingress;
        let client = ClientAddr::resolve(self.peer, request.headers(), &ingress.trusted_proxies);
        let provider = ingress
            .providers
            .as_ref()
            .and_then(|p| p.lookup(client.client));
        let headers = request.headers();
        let info = RequestInfo {
            id: inner.next_request.fetch_add(1, Ordering::Relaxed),
            method: request.method().clone(),
            uri: request.uri().clone(),
            client,
            request_id: provenance::request_id(),
            user_agent: provenance::declared(headers, "user-agent"),
            traceparent: provenance::traceparent(headers),
            mcp_session: provenance::declared(headers, tunnelward_mcp::SESSION_HEADER),
            client_id: None,
            provider,
            evidence: tunnelward_policy::Evidence::Declared,
        };
        for o in &ingress.observers {
            o.on_request(&info);
        }
        if let Some(enrolment) = &ingress.enrolment
            && enrol::is_enrolment_path(request.uri().path())
        {
            return self.enrol(enrolment, request, info, started).await;
        }
        if let Some(response) = self.metadata(&request, &info) {
            return response;
        }
        let cors = cors::decide(&ingress.cors, &request);
        let mut response = match cors {
            Cors::Preflight(ref headers) => preflight(headers, &info),
            Cors::Refused => {
                let refusal = Refusal::new("TW-I007", StatusCode::FORBIDDEN, "origin not allowed");
                self.refuse(&info, &refusal, started)
            }
            Cors::None | Cors::Allowed(_) => self.serve(request, info, started).await,
        };
        if let Cors::Allowed(headers) = cors {
            response.headers_mut().extend(headers);
        }
        response
    }

    /// The protected-resource metadata, when agent auth is on and
    /// `request` asks for it.
    fn metadata(
        &self,
        request: &Request<Incoming>,
        info: &RequestInfo,
    ) -> Option<Response<IngressBody>> {
        let auth = self.gateway.inner.config.ingress.agent_auth.as_ref()?;
        auth::is_metadata_request(auth, request.method(), request.uri().path())
            .then(|| metadata(auth, info))
    }

    /// Authorises, then forwards: the path of every request that is not
    /// a CORS preflight or the metadata document.
    async fn serve(
        &self,
        request: Request<Incoming>,
        mut info: RequestInfo,
        started: Instant,
    ) -> Response<IngressBody> {
        let outcome = match self.check(&request, &mut info).await {
            Ok(()) => self.forward(request, &info).await,
            Err(refusal) => Err(refusal),
        };
        match outcome {
            Ok(Forwarded::Stream(response)) => self.observed(response, info, started),
            Ok(Forwarded::Ready(response)) => {
                let observers = &self.gateway.inner.config.ingress.observers;
                ready(observers, response, &info, started)
            }
            Err(refusal) => self.refuse(&info, &refusal, started),
        }
    }

    /// Answers an enrolment or renewal (connector bootstrap): rate
    /// limited like any request, never forwarded.
    async fn enrol(
        &self,
        enrolment: &crate::Enrolment,
        request: Request<Incoming>,
        info: RequestInfo,
        started: Instant,
    ) -> Response<IngressBody> {
        let answered = match self.admit(&request, &info).await {
            Ok(()) => enrol::respond(enrolment, request).await,
            Err(refusal) => Err(refusal),
        };
        match answered {
            Ok(body) => {
                for o in &self.gateway.inner.config.ingress.observers {
                    o.on_response(&info, StatusCode::OK, started.elapsed());
                }
                json(body, &info)
            }
            Err(refusal) => self.refuse(&info, &refusal, started),
        }
    }

    /// Admits, buffers and decides `request`, then sends it on: once
    /// only, for a high-impact tool (FR-13).
    async fn forward(
        &self,
        request: Request<Incoming>,
        info: &RequestInfo,
    ) -> Result<Forwarded, Refusal> {
        let ingress = &self.gateway.inner.config.ingress;
        self.admit(&request, info).await?;
        let (request, body) = self.buffer(request).await?;
        self.envelope(&request, &body, info);
        let high_impact = self.decide(&request, &body, info)?;
        let request = self.restate(request, info);
        if high_impact {
            let key = idempotent::key(&request, info)?;
            let once = idempotent::send(
                &self.gateway,
                &key,
                (request, &body),
                ingress.request_timeout,
            );
            return once.await.map(Forwarded::Ready);
        }
        match tokio::time::timeout(ingress.request_timeout, self.gateway.send(request)).await {
            Ok(Ok(response)) => Ok(Forwarded::Stream(response)),
            Ok(Err(error)) => Err(refusal_for(&error)),
            Err(_) => Err(Refusal::new(
                "TW-I006",
                StatusCode::GATEWAY_TIMEOUT,
                "no response within the request timeout",
            )),
        }
    }

    /// The policy's decision on every call in the request, if there is a
    /// policy: whether one is to a high-impact tool.
    fn decide(
        &self,
        request: &Request<Full<Bytes>>,
        body: &Bytes,
        info: &RequestInfo,
    ) -> Result<bool, Refusal> {
        let Some(engine) = self.gateway.policy() else {
            return Ok(false);
        };
        let verdict = crate::policy::decide(engine.as_ref(), request.method(), body, info)?;
        Ok(verdict == crate::policy::Verdict::Forward { high_impact: true })
    }

    /// With [`crate::AgentAuth`] on, admits only a request whose token
    /// passes, and whose token and `DPoP` proof are not replays; records
    /// its client id.
    async fn authorise(
        &self,
        request: &Request<Incoming>,
        info: &mut RequestInfo,
    ) -> Result<bool, Refusal> {
        let config = &self.gateway.inner.config;
        let Some(auth) = &config.ingress.agent_auth else {
            return Ok(false);
        };
        let parts = auth::Request {
            method: request.method(),
            path: request.uri().path(),
            headers: request.headers(),
            client_cert: self.client_cert.as_ref(),
        };
        let principal = auth::authorise_once(auth, config.state.as_ref(), &parts)
            .await
            .map_err(|r| Refusal {
                challenge: r.challenge,
                ..Refusal::new(r.id, r.status, r.reason)
            })?;
        info.client_id = principal.client_id;
        Ok(principal.bound)
    }

    /// Every check on who sent `request`: the agent's token, then its
    /// Web Bot Auth signature.
    async fn check(
        &self,
        request: &Request<Incoming>,
        info: &mut RequestInfo,
    ) -> Result<(), Refusal> {
        let bound = self.authorise(request, info).await?;
        let config = &self.gateway.inner.config;
        if let Some(bot_auth) = &config.ingress.bot_auth {
            crate::botauth::identify(bot_auth, config.state.as_ref(), request, info).await?;
        }
        info.evidence = crate::policy::evidence(info, bound);
        Ok(())
    }

    /// Checks that cost nothing: URL length, declared body size, rate.
    async fn admit(&self, request: &Request<Incoming>, info: &RequestInfo) -> Result<(), Refusal> {
        let ingress = &self.gateway.inner.config.ingress;
        if request.uri().to_string().len() > ingress.max_url_len {
            return Err(Refusal::new(
                "TW-I001",
                StatusCode::URI_TOO_LONG,
                "URL over the limit",
            ));
        }
        let declared = request
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
        if declared.is_some_and(|n| n > ingress.max_body as u64) {
            return Err(Refusal::new(
                "TW-I002",
                StatusCode::PAYLOAD_TOO_LARGE,
                "declared body over the limit",
            ));
        }
        let inner = &self.gateway.inner;
        inner
            .limiter
            .check(
                inner.config.state.as_ref(),
                info.client.client,
                Instant::now(),
            )
            .await
            .map_err(|wait| Refusal {
                retry_after: Some(wait),
                ..Refusal::new("TW-I004", StatusCode::TOO_MANY_REQUESTS, "rate limit")
            })
    }

    /// Reads the body, stopping at `max_body`; returns it beside the request.
    async fn buffer(
        &self,
        request: Request<Incoming>,
    ) -> Result<(Request<Full<Bytes>>, Bytes), Refusal> {
        let max = self.gateway.inner.config.ingress.max_body;
        let (parts, body) = request.into_parts();
        let collected = Limited::new(body, max).collect().await.map_err(|e| {
            if e.is::<LengthLimitError>() {
                Refusal::new(
                    "TW-I003",
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body over the limit",
                )
            } else {
                Refusal::new("TW-I005", StatusCode::BAD_REQUEST, "request body failed")
            }
        })?;
        let body = collected.to_bytes();
        Ok((Request::from_parts(parts, Full::new(body.clone())), body))
    }

    /// States the resolved client in the forwarding headers.
    fn restate(
        &self,
        mut request: Request<Full<Bytes>>,
        info: &RequestInfo,
    ) -> Request<Full<Bytes>> {
        let ingress = &self.gateway.inner.config.ingress;
        let host = request
            .uri()
            .authority()
            .map(|a| a.as_str().to_owned())
            .or_else(|| {
                request
                    .headers()
                    .get(HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(str::to_owned)
            });
        let stamp = Stamp {
            client: info.client.client,
            proto: if self.secure { "https" } else { "http" },
            host: host.as_deref(),
            via: &ingress.via_name,
            http_version: if request.version() == Version::HTTP_2 {
                "2"
            } else {
                "1.1"
            },
            legacy: ingress.legacy_forwarded,
        };
        rewrite(request.headers_mut(), &stamp);
        stamp_request_id(request.headers_mut(), info);
        if ingress.agent_auth.is_some() {
            // The token and its DPoP proof are for the gateway; passing
            // them on is forbidden.
            request.headers_mut().remove(AUTHORIZATION);
            request.headers_mut().remove("dpop");
        }
        request
    }

    /// Tells observers the MCP envelope of a JSON POST, if it is one.
    fn envelope(&self, request: &Request<Full<Bytes>>, body: &Bytes, info: &RequestInfo) {
        let observers = &self.gateway.inner.config.ingress.observers;
        let json = request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(tunnelward_mcp::is_json);
        if observers.is_empty() || request.method() != Method::POST || !json {
            return;
        }
        if let Ok(envelope) = tunnelward_mcp::parse(body) {
            for o in observers {
                o.on_envelope(info, &envelope);
            }
        }
    }

    fn observed(
        &self,
        response: Response<ResponseBody>,
        info: RequestInfo,
        started: Instant,
    ) -> Response<IngressBody> {
        let observers = self.gateway.inner.config.ingress.observers.clone();
        for o in &observers {
            o.on_response(&info, response.status(), started.elapsed());
        }
        let mut response = response;
        stamp_request_id(response.headers_mut(), &info);
        response.map(|body| {
            Observed {
                inner: body,
                observers,
                info,
                started,
                bytes: 0,
                done: false,
            }
            .boxed()
        })
    }

    fn refuse(
        &self,
        info: &RequestInfo,
        refusal: &Refusal,
        started: Instant,
    ) -> Response<IngressBody> {
        let observers = &self.gateway.inner.config.ingress.observers;
        for o in observers {
            o.on_failure(info, refusal.status, &refusal.reason);
        }
        for o in observers {
            o.on_response(info, refusal.status, started.elapsed());
        }
        let url = tunnelward_proto::error_url(refusal.id);
        let body = refusal.json.clone().unwrap_or_else(|| {
            let text = format!(
                "{}: {} [{}] {url}\n",
                refusal.status, refusal.reason, refusal.id
            );
            Bytes::from(text)
        });
        let mut response = Response::new(Full::new(body).map_err(|e| match e {}).boxed());
        if refusal.json.is_some() {
            let json = HeaderValue::from_static("application/json");
            response.headers_mut().insert(CONTENT_TYPE, json);
        }
        *response.status_mut() = refusal.status;
        response
            .headers_mut()
            .insert(TW_ERROR, HeaderValue::from_static(refusal.id));
        stamp_request_id(response.headers_mut(), info);
        if let Some(value) = refusal
            .challenge
            .as_deref()
            .and_then(|c| HeaderValue::from_str(c).ok())
        {
            response.headers_mut().insert(WWW_AUTHENTICATE, value);
        }
        if let Some(wait) = refusal.retry_after {
            let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(secs.max(1)));
        }
        response
    }
}
