// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Idempotency keys on high-impact tools (FR-13): a call to one needs an
//! `Idempotency-Key` header, and a repeated key gets the first call's
//! answer without the tool running again.
//!
//! The key is claimed in the shared state before the call is forwarded,
//! so two gateways cannot both run it. A repeat while the first is still
//! running gets 409; a repeat of a finished call gets its stored answer;
//! the same key on a different request gets 422. If the first call's
//! outcome is unknown (the connection failed after the request left, or
//! the answer was too big to keep), repeats get 502 rather than a second
//! run: a tool that moves money must not run twice to find out.

use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::header::CONTENT_TYPE;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};

use crate::refusal::{Refusal, refusal_for};
use crate::state::Claim;
use crate::{Gateway, RequestInfo, SendError};

/// The request header carrying the key.
const HEADER: &str = "idempotency-key";
/// How long a key and its answer are kept.
const KEEP: Duration = Duration::from_secs(24 * 3600);
/// Largest answer kept for replay.
const MAX_ANSWER: usize = 1024 * 1024;
/// The response header that marks a replayed answer.
const REPLAYED: &str = "tw-idempotent-replay";

/// What a call left behind: its fingerprint and, when known, its answer.
struct Stored {
    fingerprint: [u8; 32],
    answer: Option<(u16, Option<Bytes>, Bytes)>,
}

impl Stored {
    fn encode(&self) -> Bytes {
        let mut out = BytesMut::new();
        out.put_slice(&self.fingerprint);
        if let Some((status, content_type, body)) = &self.answer {
            let content_type = content_type.as_deref().unwrap_or_default();
            out.put_u16(*status);
            out.put_u16(u16::try_from(content_type.len()).unwrap_or(0));
            out.put_slice(content_type);
            out.put_slice(body);
        }
        out.freeze()
    }

    fn decode(mut bytes: Bytes) -> Option<Self> {
        let fingerprint: [u8; 32] = bytes.get(..32)?.try_into().ok()?;
        bytes.advance(32);
        if bytes.is_empty() {
            return Some(Self {
                fingerprint,
                answer: None,
            });
        }
        let status = bytes.try_get_u16().ok()?;
        let len = usize::from(bytes.try_get_u16().ok()?);
        let content_type = (len > 0).then(|| bytes.split_to(len.min(bytes.len())));
        Some(Self {
            fingerprint,
            answer: Some((status, content_type, bytes)),
        })
    }
}

fn refusal(id: &'static str, status: StatusCode, reason: &str) -> Refusal {
    Refusal::new(id, status, reason)
}

/// The store key for `request`'s idempotency key, scoped to the agent
/// (or the client address without one) and the path.
pub(crate) fn key<B>(request: &Request<B>, info: &RequestInfo) -> Result<String, Refusal> {
    let key = request
        .headers()
        .get(HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|k| !k.is_empty() && k.len() <= 255)
        .ok_or_else(|| {
            refusal(
                "TW-P002",
                StatusCode::BAD_REQUEST,
                "a high-impact tool needs an Idempotency-Key header (1 to 255 characters)",
            )
        })?;
    let who = info
        .client_id
        .clone()
        .unwrap_or_else(|| info.client.client.to_string());
    Ok(format!("idem:{who}:{}:{key}", info.uri.path()))
}

/// What identifies a request, so a key reused on another one is caught.
fn fingerprint(request: &Request<Full<Bytes>>, body: &Bytes) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    ctx.update(request.method().as_str().as_bytes());
    ctx.update(b"\n");
    ctx.update(request.uri().path().as_bytes());
    ctx.update(b"\n");
    ctx.update(body);
    ctx.finish().as_ref().try_into().unwrap_or([0; 32])
}

/// Sends `request` (body `body`) once for `key`, or answers from what
/// the first call with `key` left.
pub(crate) async fn send(
    gateway: &Gateway,
    key: &str,
    (request, body): (Request<Full<Bytes>>, &Bytes),
    timeout: Duration,
) -> Result<Response<Full<Bytes>>, Refusal> {
    let state = gateway.inner.config.state.as_ref();
    let print = fingerprint(&request, body);
    match state.claim(key, KEEP).await {
        Ok(Claim::First) => first(gateway, key, request, print, timeout).await,
        Ok(Claim::Pending) => Err(Refusal {
            retry_after: Some(Duration::from_secs(1)),
            ..refusal(
                "TW-P003",
                StatusCode::CONFLICT,
                "a call with this Idempotency-Key is still running",
            )
        }),
        Ok(Claim::Done(bytes)) => replay(bytes, print),
        Err(e) => Err(refusal(
            crate::state::UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("cannot check the Idempotency-Key: {e}"),
        )),
    }
}

/// The answer the first call left, if `print` is the same request.
fn replay(bytes: Bytes, print: [u8; 32]) -> Result<Response<Full<Bytes>>, Refusal> {
    let stored = Stored::decode(bytes).ok_or_else(|| unknown("the stored answer is unreadable"))?;
    if stored.fingerprint != print {
        return Err(refusal(
            "TW-P004",
            StatusCode::UNPROCESSABLE_ENTITY,
            "this Idempotency-Key was used for a different request",
        ));
    }
    let answer = stored
        .answer
        .ok_or_else(|| unknown("the first call's outcome is unknown; it may have run"))?;
    let mut response = respond(answer);
    response
        .headers_mut()
        .insert(REPLAYED, HeaderValue::from_static("true"));
    Ok(response)
}

/// A response with `status`, `content_type` and `body`.
fn respond((status, content_type, body): (u16, Option<Bytes>, Bytes)) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    if let Some(value) = content_type.and_then(|c| HeaderValue::from_maybe_shared(c).ok()) {
        response.headers_mut().insert(CONTENT_TYPE, value);
    }
    response
}

fn unknown(reason: &str) -> Refusal {
    refusal("TW-P005", StatusCode::BAD_GATEWAY, reason)
}

/// Runs the call for the first time and keeps its answer.
async fn first(
    gateway: &Gateway,
    key: &str,
    request: Request<Full<Bytes>>,
    print: [u8; 32],
    timeout: Duration,
) -> Result<Response<Full<Bytes>>, Refusal> {
    let state = gateway.inner.config.state.as_ref();
    let sent = tokio::time::timeout(timeout, gateway.send(request)).await;
    let answer = match sent {
        Ok(Ok(response)) => collect(response).await,
        // Never left the gateway: let a retry run it.
        Ok(Err(
            e @ (SendError::NoRoute | SendError::Unavailable { .. } | SendError::BadRequest(_)),
        )) => {
            let _released = state.release(key).await;
            return Err(refusal_for(&e));
        }
        Ok(Err(_)) | Err(_) => None,
    };
    let stored = Stored {
        fingerprint: print,
        answer,
    };
    let _kept = state.complete(key, stored.encode(), KEEP).await;
    stored.answer.map(respond).ok_or_else(|| {
        unknown(
            "the call's outcome is unknown, or its answer is over 1 MiB to keep; it may have run",
        )
    })
}

/// The status, content type and body of `response`, when the body
/// arrives whole and within [`MAX_ANSWER`].
async fn collect(response: Response<crate::ResponseBody>) -> Option<(u16, Option<Bytes>, Bytes)> {
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .map(|v| Bytes::copy_from_slice(v.as_bytes()));
    let body = Limited::new(response.into_body(), MAX_ANSWER)
        .collect()
        .await
        .ok()?
        .to_bytes();
    Some((status, content_type, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_answers_round_trip() {
        let with = Stored {
            fingerprint: [7; 32],
            answer: Some((
                201,
                Some(Bytes::from_static(b"application/json")),
                Bytes::from_static(b"{}"),
            )),
        };
        let back = Stored::decode(with.encode());
        assert_eq!(back.as_ref().map(|s| s.fingerprint), Some([7; 32]));
        assert_eq!(back.and_then(|s| s.answer), with.answer);
        let without = Stored {
            fingerprint: [1; 32],
            answer: None,
        };
        assert!(Stored::decode(without.encode()).is_some_and(|s| s.answer.is_none()));
        assert!(Stored::decode(Bytes::from_static(b"short")).is_none());
    }
}
