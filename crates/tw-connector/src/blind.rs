// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gateway-blind mode at the connector (ADR 0016, experimental): a
//! `tools/call` sealed to this connector's X-Wing key is opened before
//! it reaches the local server, and its answer is sealed before it goes
//! back through the gateway. Every other request passes unchanged,
//! unless [`Blind::require`] is on, which refuses an unsealed
//! `tools/call`.
//!
//! Bodies are buffered here, within [`Blind::max_body`]. An answer that
//! is not JSON (an event stream) is refused: this alpha seals one JSON
//! answer per call.

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderValue, Method, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use serde_json::{Value, json};
use tunnelward_crypto::blind::ResponseKey;
use tunnelward_crypto::xwing::PrivateKeyXWing;
use tunnelward_mcp::blind::{BlindError, open_call, seal_answer};

use crate::forward::{Forward, ForwardBody, Outgoing, error_response};

/// The JSON-RPC error code of a call this connector refuses or cannot
/// open: invalid params.
const INVALID_PARAMS: i64 = -32602;

/// Gateway-blind mode's settings.
#[derive(Debug)]
#[non_exhaustive]
pub struct Blind {
    /// This connector's X-Wing key.
    pub key: PrivateKeyXWing,
    /// Refuse a `tools/call` that is not sealed.
    pub require: bool,
    /// Largest request or answer body buffered, in bytes.
    pub max_body: usize,
}

impl Blind {
    /// Blind mode with `key`, unsealed calls allowed, bodies up to 1 MiB.
    #[must_use]
    pub fn new(key: PrivateKeyXWing) -> Self {
        Self {
            key,
            require: false,
            max_body: tunnelward_mcp::MAX_BODY,
        }
    }

    /// Opens a sealed call in `request`, forwards it, and seals the
    /// answer; anything else goes on as it came.
    pub(crate) async fn forward(
        &self,
        forward: &Forward,
        request: Outgoing,
    ) -> Response<ForwardBody> {
        if request.method() != Method::POST {
            return forward.send(request).await;
        }
        let (mut parts, body) = request.into_parts();
        let Ok(body) = Limited::new(body, self.max_body)
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
        else {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request is over the blind-mode limit",
            );
        };
        let opened = match open_call(&body, &self.key) {
            Ok(opened) => opened,
            Err(e) => return refusal(&body, &e.to_string()),
        };
        let Some((plain, response_key)) = opened else {
            if self.require && is_call(&body) {
                return refusal(&body, "this connector takes sealed tools/call only");
            }
            return forward.send(rebuilt(parts, body)).await;
        };
        parts
            .headers
            .insert(CONTENT_LENGTH, HeaderValue::from(plain.len()));
        let answer = forward.send(rebuilt(parts, Bytes::from(plain))).await;
        self.seal(answer, &response_key).await
    }

    /// The target's answer, sealed; a non-JSON or oversized answer is
    /// refused rather than passed on in the clear.
    async fn seal(
        &self,
        answer: Response<ForwardBody>,
        key: &ResponseKey,
    ) -> Response<ForwardBody> {
        let json = (answer.headers().get(CONTENT_TYPE))
            .and_then(|v| v.to_str().ok())
            .is_some_and(tunnelward_mcp::is_json);
        if !json {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "blind mode needs a JSON answer from the server",
            );
        }
        let (mut parts, body) = answer.into_parts();
        let Ok(body) = Limited::new(body, self.max_body)
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
        else {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "the answer is over the blind-mode limit",
            );
        };
        match seal_answer(&body, key) {
            Ok(sealed) => {
                parts
                    .headers
                    .insert(CONTENT_LENGTH, HeaderValue::from(sealed.len()));
                Response::from_parts(parts, full(Bytes::from(sealed)))
            }
            Err(BlindError::NotAnAnswer) => error_response(
                StatusCode::BAD_GATEWAY,
                "the server's answer is not JSON-RPC",
            ),
            Err(e) => error_response(StatusCode::BAD_GATEWAY, &e.to_string()),
        }
    }
}

fn full(bytes: Bytes) -> ForwardBody {
    Full::new(bytes).map_err(|e| match e {}).boxed()
}

fn rebuilt(parts: http::request::Parts, body: Bytes) -> Outgoing {
    Outgoing::from_parts(parts, full(body))
}

fn is_call(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .is_ok_and(|v| v.get("method").and_then(Value::as_str) == Some("tools/call"))
}

/// The connector's own JSON-RPC error for the call in `body`.
fn refusal(body: &[u8], why: &str) -> Response<ForwardBody> {
    let id = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(Value::Null);
    let error =
        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": INVALID_PARAMS, "message": why } });
    let mut response = Response::new(full(Bytes::from(error.to_string())));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}
