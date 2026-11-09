// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! How the ingress refuses a request: a stable error id, a status, a
//! reason, and the headers that go with it.

use std::time::Duration;

use http::StatusCode;

use crate::SendError;

/// A refusal: the status, the reason for observers, and any `Retry-After`.
pub(crate) struct Refusal {
    /// The stable error id (`docs/errors.md`).
    pub(crate) id: &'static str,
    pub(crate) status: StatusCode,
    pub(crate) reason: String,
    pub(crate) retry_after: Option<Duration>,
    /// `WWW-Authenticate`, for an authorisation refusal.
    pub(crate) challenge: Option<String>,
}

impl Refusal {
    pub(crate) fn new(id: &'static str, status: StatusCode, reason: impl Into<String>) -> Self {
        Self {
            id,
            status,
            reason: reason.into(),
            retry_after: None,
            challenge: None,
        }
    }
}

/// The refusal a failed send becomes.
pub(crate) fn refusal_for(error: &SendError) -> Refusal {
    let id = error.id();
    match error {
        SendError::NoRoute => {
            Refusal::new(id, StatusCode::NOT_FOUND, "no connector serves this route")
        }
        SendError::Unavailable { retry_after } => Refusal {
            retry_after: Some(*retry_after),
            ..Refusal::new(id, StatusCode::SERVICE_UNAVAILABLE, "no connector free")
        },
        SendError::BadRequest(_) => Refusal::new(id, StatusCode::BAD_REQUEST, error.to_string()),
        _ => Refusal::new(id, StatusCode::BAD_GATEWAY, error.to_string()),
    }
}
