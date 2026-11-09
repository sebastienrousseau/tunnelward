// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A server-sent event stream: first the events a reconnecting client
//! missed, then each new one as it comes, with a comment every 20 s so
//! the connection does not look idle to the proxies in between.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame};
use tokio::sync::mpsc;
use tokio::time::{Instant, Sleep, sleep_until};

use super::session::Event;

/// How often an otherwise quiet stream sends a comment.
const KEEP_ALIVE: Duration = Duration::from_secs(20);

/// The body of a `GET` event stream.
pub(crate) struct EventStream {
    missed: VecDeque<Event>,
    live: mpsc::Receiver<Event>,
    keep_alive: Pin<Box<Sleep>>,
}

impl EventStream {
    pub(crate) fn new(missed: Vec<Event>, live: mpsc::Receiver<Event>) -> Self {
        Self {
            missed: missed.into(),
            live,
            keep_alive: Box::pin(sleep_until(Instant::now() + KEEP_ALIVE)),
        }
    }
}

/// One event in the wire format: its id, then its data on one line.
pub(crate) fn format((id, data): &Event) -> Bytes {
    Bytes::from(format!("id: {id}\ndata: {data}\n\n"))
}

impl Body for EventStream {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(event) = self.missed.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(format(&event)))));
        }
        match self.live.poll_recv(cx) {
            Poll::Ready(Some(event)) => return Poll::Ready(Some(Ok(Frame::data(format(&event))))),
            // The session ended.
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => {}
        }
        if self.keep_alive.as_mut().poll(cx).is_ready() {
            let next = Instant::now() + KEEP_ALIVE;
            self.keep_alive.as_mut().reset(next);
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
                b": keep-alive\n\n",
            )))));
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_carry_their_id_and_data() {
        assert_eq!(
            format(&(7, r#"{"jsonrpc":"2.0"}"#.into())),
            Bytes::from_static(b"id: 7\ndata: {\"jsonrpc\":\"2.0\"}\n\n")
        );
    }
}
