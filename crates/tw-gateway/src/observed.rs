// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! A connector's response body as the ingress streams it, telling
//! observers when it ends and how big it was.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};

use crate::{RequestInfo, ResponseBody};

/// A response body that tells observers when it ends, and how big it was.
pub(crate) struct Observed {
    pub(crate) inner: ResponseBody,
    pub(crate) observers: Vec<std::sync::Arc<dyn crate::ProxyObserver>>,
    pub(crate) info: RequestInfo,
    pub(crate) started: Instant,
    pub(crate) bytes: u64,
    pub(crate) done: bool,
    /// The audit log's part, when there is one.
    pub(crate) audit: Option<Audited>,
}

/// A streamed answer's audit state: its status, and the hash of the
/// body so far.
pub(crate) struct Audited {
    sink: std::sync::Arc<tunnelward_audit::Sink>,
    status: u16,
    hash: aws_lc_rs::digest::Context,
}

impl Audited {
    pub(crate) fn new(sink: std::sync::Arc<tunnelward_audit::Sink>, status: u16) -> Self {
        Self {
            sink,
            status,
            hash: aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256),
        }
    }
}

impl Observed {
    /// Tells observers and the audit log the answer ended; `clean` when
    /// the body reached its end, so its digest is of all of it.
    fn finish(&mut self, clean: bool) {
        if self.done {
            return;
        }
        self.done = true;
        let elapsed = self.started.elapsed();
        for o in &self.observers {
            o.on_complete(&self.info, self.bytes, elapsed);
        }
        if let Some(audit) = self.audit.take() {
            let digest = clean.then(|| tunnelward_audit::hex(audit.hash.finish().as_ref()));
            let ended = crate::audit::Ended {
                status: audit.status,
                decision: crate::audit::Decision::Forwarded,
                bytes: self.bytes,
                result_digest: digest,
                started: self.started,
            };
            crate::audit::record(&audit.sink, &self.info, ended);
        }
    }
}

impl Drop for Observed {
    fn drop(&mut self) {
        // hyper stops polling once the body says it has ended, so a body
        // dropped at its end ended cleanly.
        let clean = self.inner.is_end_stream();
        self.finish(clean);
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
                let data = frame.data_ref().map_or(&[][..], |d| &d[..]);
                self.bytes += data.len() as u64;
                if let Some(audit) = self.audit.as_mut() {
                    audit.hash.update(data);
                }
            }
            Poll::Ready(None) => self.finish(true),
            Poll::Ready(Some(Err(_))) => self.finish(false),
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
