// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The tool-list guard on the HTTP path (ADR 0017): with a pinned
//! server, POST bodies are buffered within [`tunnelward_mcp::MAX_BODY`]
//! so the guard can see which requests are `initialize` or `tools/list`,
//! and the answers to those are read in full and checked before they go
//! back. Every other answer streams as before.

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{HeaderValue, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use serde_json::Value;

use crate::blind::{full, rebuilt};
use crate::forward::{Forward, ForwardBody, Outgoing, error_response};
use crate::tools::{self, Asked, Pinned};

/// Sends `request` through `forward`, checking guarded answers.
pub(crate) async fn send(
    forward: &Forward,
    pinned: &Pinned,
    request: Outgoing,
) -> Response<ForwardBody> {
    let (parts, body) = request.into_parts();
    let Ok(body) = collect(body).await else {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the request is over the guard's limit",
        );
    };
    let messages = tools::answers(false, &body);
    let asked = tools::asked(&messages);
    let batch = body.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'[');
    let answer = forward.send_unguarded(rebuilt(parts, body)).await;
    if asked.is_empty() {
        return answer;
    }
    checked(pinned, &asked, batch, answer).await
}

async fn collect(body: ForwardBody) -> Result<Bytes, ()> {
    Limited::new(body, tunnelward_mcp::MAX_BODY)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .map_err(|_| ())
}

/// `answer`, read in full; replaced with the guard's errors when it
/// shows a changed server.
async fn checked(
    pinned: &Pinned,
    asked: &[(Value, Asked)],
    batch: bool,
    answer: Response<ForwardBody>,
) -> Response<ForwardBody> {
    let event_stream = (answer.headers().get(CONTENT_TYPE))
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| t.starts_with(tunnelward_mcp::EVENT_STREAM));
    let (parts, body) = answer.into_parts();
    let Ok(body) = collect(body).await else {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "the server's answer is over the guard's limit",
        );
    };
    match pinned.check(asked, &tools::answers(event_stream, &body)) {
        Ok(()) => Response::from_parts(parts, full(body)),
        Err(why) => json(&tools::refusal(asked, &why, batch)),
    }
}

fn json(value: &Value) -> Response<ForwardBody> {
    let mut response = Response::new(full(Bytes::from(value.to_string())));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}
