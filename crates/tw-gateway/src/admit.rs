// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Admitting one connector connection.

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tw_proto::io::{ReadError, read_frame, write_frame};
use tw_proto::{ALPN, Accept, ConnectorId, Frame, MAX_REASON_LEN, Register, Reject, RejectCode};

use crate::kill::Killable;
use crate::registry::Link;
use crate::{AdmitError, Gateway};

/// What a decoded first frame turned into.
enum Outcome {
    Admit(Register),
    Refuse(RejectCode, String),
}

impl Gateway {
    /// Admits one connector connection: TLS, ALPN, the register frame, the
    /// answer, then the HTTP/2 client. Returns once the connector is
    /// routable; its connection is driven on a spawned task and the
    /// connector leaves the registry when the connection ends.
    ///
    /// # Errors
    ///
    /// The step that failed. A refused registration is answered with a
    /// [`Reject`] before [`AdmitError::Rejected`] is returned.
    pub async fn admit<IO>(&self, io: IO) -> Result<ConnectorId, AdmitError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.admit_from(io, None).await
    }

    /// [`Gateway::admit`], recording the connector's address so a drain can
    /// select it ([`DrainTarget::Peer`](crate::DrainTarget::Peer)).
    ///
    /// # Errors
    ///
    /// As [`Gateway::admit`].
    pub async fn admit_from<IO>(
        &self,
        io: IO,
        peer: Option<IpAddr>,
    ) -> Result<ConnectorId, AdmitError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let config = &self.inner.config;
        let (mut tls, outcome) = timeout(config.registration_timeout, self.handshake(io))
            .await
            .map_err(|_| AdmitError::Timeout)??;
        let register = match outcome {
            Outcome::Admit(r) => r,
            Outcome::Refuse(code, reason) => return self.refuse(&mut tls, code, reason).await,
        };
        let accept = Frame::Accept(Accept {
            lease_secs: config.lease_secs,
            limits: config.limits.stream,
        });
        write_frame(&mut tls, &accept, &config.limits)
            .await
            .map_err(AdmitError::Write)?;
        self.connect(tls, register, peer).await
    }

    async fn handshake<IO>(&self, io: IO) -> Result<(TlsStream<IO>, Outcome), AdmitError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let mut tls = self
            .inner
            .acceptor
            .accept(io)
            .await
            .map_err(AdmitError::Tls)?;
        if tls.get_ref().1.alpn_protocol() != Some(ALPN) {
            return Err(AdmitError::Alpn);
        }
        let outcome = match read_frame(&mut tls, &self.inner.config.limits).await {
            Ok(Frame::Register(r)) => Outcome::Admit(r),
            Ok(_) => Outcome::Refuse(RejectCode::Malformed, "expected a Register frame".into()),
            Err(ReadError::Decode(e)) => Outcome::Refuse(e.reject_code(), e.to_string()),
            Err(e) => return Err(AdmitError::Read(e)),
        };
        Ok((tls, outcome))
    }

    async fn refuse<IO>(
        &self,
        tls: &mut TlsStream<IO>,
        code: RejectCode,
        reason: String,
    ) -> Result<ConnectorId, AdmitError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let reject = Frame::Reject(Reject {
            code,
            reason: printable(&reason),
        });
        write_frame(tls, &reject, &self.inner.config.limits)
            .await
            .map_err(AdmitError::Write)?;
        Err(AdmitError::Rejected(code))
    }

    async fn connect<IO>(
        &self,
        tls: TlsStream<IO>,
        register: Register,
        peer: Option<IpAddr>,
    ) -> Result<ConnectorId, AdmitError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (stream, kill) = Killable::new(tls);
        let grant = self.inner.config.limits.stream;
        let (sender, conn) = http2::Builder::new(TokioExecutor::new())
            .max_header_list_size(grant.max_header_list_size)
            .initial_stream_window_size(grant.initial_stream_window)
            .initial_connection_window_size(grant.initial_connection_window)
            .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
            .await
            .map_err(AdmitError::Http)?;
        let id = register.connector_id;
        let task = tokio::spawn(async move {
            let _ended = conn.await;
        });
        let link = Link {
            sender,
            grant: grant.max_concurrent_streams,
            peer,
            kill,
        };
        let session = self.inner.registry.insert(register, link);
        let gateway = self.clone();
        tokio::spawn(async move { gateway.supervise(session, task).await });
        Ok(id)
    }

    /// Waits for the connection to end or its lease to expire; an expired
    /// lease drains it with `drain_grace`. Either way the session then
    /// leaves the registry.
    async fn supervise(&self, session: u64, mut task: JoinHandle<()>) {
        let lease = Duration::from_secs(u64::from(self.inner.config.lease_secs));
        tokio::select! {
            _ = &mut task => {}
            () = tokio::time::sleep(lease) => {
                self.inner.registry.mark_draining(|e| e.session == session);
                let _report = self.finish(&[session], self.inner.config.drain_grace).await;
                let _ended = task.await;
            }
        }
        self.remove(session);
    }
}

/// `text` without control characters, cut to [`MAX_REASON_LEN`] bytes on
/// a character boundary, so it is always a valid `Reject` reason.
fn printable(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars().map(|c| if c.is_control() { '?' } else { c }) {
        if out.len() + c.len_utf8() > MAX_REASON_LEN {
            break;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_are_made_printable_and_short() {
        assert_eq!(printable("bad\u{1b}[2Jframe\n"), "bad?[2Jframe?");
        let long = "é".repeat(MAX_REASON_LEN);
        let cut = printable(&long);
        assert!(cut.len() <= MAX_REASON_LEN && cut.chars().all(|c| c == 'é'));
    }
}
