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
use core::task::{Context, Poll};
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
use hyper::body::{Body, Frame, Incoming, SizeHint};

use crate::answers::{json, metadata, preflight, stamp_request_id};
use crate::auth;
use crate::cors::{self, Cors};
use crate::enrol;
use crate::forwarding::{Stamp, rewrite};
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
        }
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
            Ok(response) => self.observed(response, info, started),
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

    async fn forward(
        &self,
        request: Request<Incoming>,
        info: &RequestInfo,
    ) -> Result<Response<ResponseBody>, Refusal> {
        let ingress = &self.gateway.inner.config.ingress;
        self.admit(&request, info).await?;
        let (request, body) = self.buffer(request).await?;
        self.envelope(&request, &body, info);
        let request = self.restate(request, info);
        match tokio::time::timeout(ingress.request_timeout, self.gateway.send(request)).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(refusal_for(&error)),
            Err(_) => Err(Refusal::new(
                "TW-I006",
                StatusCode::GATEWAY_TIMEOUT,
                "no response within the request timeout",
            )),
        }
    }

    /// With [`crate::AgentAuth`] on, admits only a request whose bearer
    /// token passes, recording its client id.
    fn authorise(
        &self,
        request: &Request<Incoming>,
        info: &mut RequestInfo,
    ) -> Result<(), Refusal> {
        let Some(auth) = &self.gateway.inner.config.ingress.agent_auth else {
            return Ok(());
        };
        let principal = auth::authorise(auth, request.headers()).map_err(|r| Refusal {
            challenge: Some(r.challenge),
            ..Refusal::new(r.id, r.status, r.reason)
        })?;
        info.client_id = principal.client_id;
        Ok(())
    }

    /// Every check on who sent `request`: the agent's token, then its
    /// Web Bot Auth signature.
    async fn check(
        &self,
        request: &Request<Incoming>,
        info: &mut RequestInfo,
    ) -> Result<(), Refusal> {
        self.authorise(request, info)?;
        let config = &self.gateway.inner.config;
        match &config.ingress.bot_auth {
            Some(bot_auth) => {
                crate::botauth::identify(bot_auth, config.state.as_ref(), request, info).await
            }
            None => Ok(()),
        }
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
            // The token is for the gateway; passing it on is forbidden.
            request.headers_mut().remove(AUTHORIZATION);
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
        let text = format!(
            "{}: {} [{}] {url}\n",
            refusal.status, refusal.reason, refusal.id
        );
        let mut response =
            Response::new(Full::new(Bytes::from(text)).map_err(|e| match e {}).boxed());
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

/// A response body that tells observers when it ends, and how big it was.
struct Observed {
    inner: ResponseBody,
    observers: Vec<std::sync::Arc<dyn crate::ProxyObserver>>,
    info: RequestInfo,
    started: Instant,
    bytes: u64,
    done: bool,
}

impl Observed {
    fn finish(&mut self) {
        if !self.done {
            self.done = true;
            let elapsed = self.started.elapsed();
            for o in &self.observers {
                o.on_complete(&self.info, self.bytes, elapsed);
            }
        }
    }
}

impl Drop for Observed {
    fn drop(&mut self) {
        self.finish();
    }
}

impl Body for Observed {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                let len = frame.data_ref().map_or(0, Bytes::len);
                self.bytes += len as u64;
            }
            Poll::Ready(None | Some(Err(_))) => self.finish(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
