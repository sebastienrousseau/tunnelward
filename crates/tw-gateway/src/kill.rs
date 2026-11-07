// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! A stream the gateway can cut, so a drain deadline resets in-flight
//! requests (FR-7).
//!
//! hyper keeps an HTTP/2 client connection open while any request on it is
//! in flight, even after the task that drives it is aborted. Cutting the
//! stream underneath is the one way to end those requests at once: every
//! read and write fails, the HTTP/2 connection errors, and so does every
//! stream on it.

use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Cuts a [`Killable`] stream.
#[derive(Debug, Default)]
pub(crate) struct KillSwitch {
    killed: AtomicBool,
    wakers: Mutex<Vec<Waker>>,
}

impl KillSwitch {
    /// Cuts the stream and wakes anything waiting on it.
    pub(crate) fn kill(&self) {
        self.killed.store(true, Ordering::Release);
        let wakers =
            std::mem::take(&mut *self.wakers.lock().unwrap_or_else(PoisonError::into_inner));
        wakers.into_iter().for_each(Waker::wake);
    }

    fn check(&self, cx: &Context<'_>) -> io::Result<()> {
        if self.killed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "connection cut by the gateway",
            ));
        }
        let mut wakers = self.wakers.lock().unwrap_or_else(PoisonError::into_inner);
        if !wakers.iter().any(|w| w.will_wake(cx.waker())) {
            wakers.push(cx.waker().clone());
        }
        Ok(())
    }
}

/// A stream whose reads and writes fail once its [`KillSwitch`] is used.
#[derive(Debug)]
pub(crate) struct Killable<IO> {
    inner: IO,
    switch: Arc<KillSwitch>,
}

impl<IO> Killable<IO> {
    pub(crate) fn new(inner: IO) -> (Self, Arc<KillSwitch>) {
        let switch = Arc::new(KillSwitch::default());
        (
            Self {
                inner,
                switch: switch.clone(),
            },
            switch,
        )
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Killable<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.switch.check(cx)?;
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Killable<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.switch.check(cx)?;
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.switch.check(cx)?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, duplex};

    #[tokio::test]
    async fn a_pending_read_fails_as_soon_as_the_switch_is_used() -> io::Result<()> {
        let (a, _b) = duplex(64);
        let (mut stream, switch) = Killable::new(a);
        let reader = tokio::spawn(async move {
            let mut buf = [0; 8];
            stream.read(&mut buf).await
        });
        tokio::task::yield_now().await;
        switch.kill();
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), reader).await;
        let err = read
            .map_err(|_| io::Error::other("read did not wake"))?
            .map_err(io::Error::other)?;
        assert_eq!(
            err.map_err(|e| e.kind()),
            Err(io::ErrorKind::ConnectionReset)
        );
        Ok(())
    }
}
