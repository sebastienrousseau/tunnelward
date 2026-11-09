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
