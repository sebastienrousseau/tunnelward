// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! One retry for requests a connection refused unprocessed.
//!
//! A connector renewing its lease, or shutting down, sends HTTP/2 GOAWAY.
//! A request the gateway started on that connection in the same moment is
//! refused before the connector reads it: retrying it elsewhere cannot run
//! it twice. Nothing else is retried; a request that may have reached the
//! connector is never sent again.

use std::error::Error as _;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;

/// Whether `error` proves the connector never processed the request: the
/// stream was refused (`REFUSED_STREAM`) or beyond the `GOAWAY`'s last stream,
/// or the request was cancelled before it was sent.
pub(crate) fn unprocessed(error: &hyper::Error) -> bool {
    if error.is_canceled() {
        return true;
    }
    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(h2) = cause.downcast_ref::<h2::Error>() {
            return h2.is_go_away() || h2.reason() == Some(h2::Reason::REFUSED_STREAM);
        }
        source = cause.source();
    }
    false
}

/// A copy of `request` for a second attempt. Extensions are not copied:
/// they are in-process values, and routing does not read them.
pub(crate) fn copy(request: &Request<Full<Bytes>>) -> Request<Full<Bytes>> {
    let mut copy = Request::new(request.body().clone());
    *copy.method_mut() = request.method().clone();
    *copy.uri_mut() = request.uri().clone();
    *copy.version_mut() = request.version();
    *copy.headers_mut() = request.headers().clone();
    copy
}
