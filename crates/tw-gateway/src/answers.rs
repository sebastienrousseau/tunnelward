// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway's own answers on the ingress, which no connector sees: a
//! CORS preflight, the protected-resource metadata, enrolment.

use bytes::Bytes;
use http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use http::{HeaderValue, Response, StatusCode};
use http_body_util::{BodyExt, Full};

use crate::RequestInfo;
use crate::auth;
use crate::ingress::IngressBody;
use crate::provenance;

/// The gateway's own answer to an allowed CORS preflight: 204, the CORS
/// headers, and the request id. The connector never sees it.
pub(crate) fn preflight(headers: &http::HeaderMap, info: &RequestInfo) -> Response<IngressBody> {
    let mut response = Response::new(Full::new(Bytes::new()).map_err(|e| match e {}).boxed());
    *response.status_mut() = StatusCode::NO_CONTENT;
    response.headers_mut().extend(headers.clone());
    stamp_request_id(response.headers_mut(), info);
    response
}

/// The protected-resource metadata, answered by the gateway itself and
/// readable from any origin.
pub(crate) fn metadata(auth: &crate::AgentAuth, info: &RequestInfo) -> Response<IngressBody> {
    let body = Full::new(Bytes::from(auth::metadata(auth)));
    let mut response = Response::new(body.map_err(|e| match e {}).boxed());
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    stamp_request_id(headers, info);
    response
}

/// Names the request's id in its response (`tw-request-id`), replacing
/// any the connector set.
pub(crate) fn stamp_request_id(headers: &mut http::HeaderMap, info: &RequestInfo) {
    if let Ok(id) = HeaderValue::from_str(&info.request_id) {
        headers.insert(provenance::REQUEST_ID, id);
    }
}

/// A JSON answer from the gateway itself.
pub(crate) fn json(body: Bytes, info: &RequestInfo) -> Response<IngressBody> {
    let mut response = Response::new(Full::new(body).map_err(|e| match e {}).boxed());
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    stamp_request_id(headers, info);
    response
}

/// An answer the gateway holds whole (a replayed idempotent call), as
/// the observers see it.
pub(crate) fn ready(
    observers: &[std::sync::Arc<dyn crate::ProxyObserver>],
    response: Response<Full<Bytes>>,
    info: &RequestInfo,
    started: std::time::Instant,
) -> Response<IngressBody> {
    use hyper::body::Body as _;
    let size = response.body().size_hint().exact().unwrap_or(0);
    for o in observers {
        o.on_response(info, response.status(), started.elapsed());
        o.on_complete(info, size, started.elapsed());
    }
    let mut response = response.map(|b| b.map_err(|e| match e {}).boxed());
    stamp_request_id(response.headers_mut(), info);
    response
}
