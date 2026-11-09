// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! A Redis-compatible store (Redis, Valkey, `KeyDB`, managed services that
//! speak RESP) shared by several gateways: `redis://host:port`, or
//! `rediss://host:port` over TLS 1.3.
//!
//! Each method is one command or one atomic script, so two gateways never
//! see half an update. One connection, opened when first needed and
//! again after a failure; every command has a 2 s deadline, and a store
//! that does not answer in time is a [`StateError`], which each check
//! turns into its failure mode.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{KeyExchange, client_config};

use super::resp::{self, Reply};
use super::{Claim, SharedState, StateError, StateFuture};

/// Longest a command may take, connecting included.
const DEADLINE: Duration = Duration::from_secs(2);

/// Adds one to a counter and sets its expiry on the first count, in one
/// step, so a counter can never be left without one.
const COUNT: &[u8] = b"local n = redis.call('INCR', KEYS[1]) \
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end return n";

/// A pending idempotency key's value; a finished one is `d` and the answer.
const PENDING: &[u8] = b"p";

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type Connection = BufReader<Box<dyn Io>>;

/// Where the store is and how to reach it.
struct Target {
    host: String,
    port: u16,
    tls: Option<Arc<tunnelward_crypto::rustls::ClientConfig>>,
    password: Option<String>,
}

/// A store over RESP.
pub struct RedisState {
    target: Target,
    connection: Mutex<Option<Connection>>,
}

impl std::fmt::Debug for RedisState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisState")
            .field("host", &self.target.host)
            .field("port", &self.target.port)
            .field("tls", &self.target.tls.is_some())
            .finish_non_exhaustive()
    }
}

fn fail(what: &str, e: &dyn std::fmt::Display) -> StateError {
    StateError(format!("{what}: {e}"))
}

fn millis(ttl: Duration) -> Vec<u8> {
    ttl.as_millis().max(1).to_string().into_bytes()
}

impl RedisState {
    /// The store at `url` (`redis://host:port` or `rediss://host:port`,
    /// port 6379 when absent), authenticating with `password` when given
    /// and trusting `roots` for TLS. Nothing connects until first used.
    ///
    /// # Errors
    ///
    /// A URL that is not one of those forms, one with a user or password
    /// in it (give `password` instead), or TLS that cannot be set up.
    pub fn new(
        url: &str,
        password: Option<String>,
        roots: Arc<RootCertStore>,
    ) -> Result<Self, StateError> {
        let (tls, rest) = match (url.strip_prefix("rediss://"), url.strip_prefix("redis://")) {
            (Some(rest), _) => (true, rest),
            (None, Some(rest)) => (false, rest),
            _ => return Err(StateError(format!("{url:?}: give redis:// or rediss://"))),
        };
        let authority = rest.trim_end_matches('/');
        if authority.contains(['@', '/']) || authority.is_empty() {
            return Err(StateError(format!(
                "{url:?}: give host:port only; the password goes in its own setting"
            )));
        }
        let (host, port) = split_host_port(authority)?;
        let tls = tls
            .then(|| client_config(roots, None, KeyExchange::default(), &[]))
            .transpose()
            .map_err(|e| fail("TLS", &e))?
            .map(Arc::new);
        Ok(Self {
            target: Target {
                host,
                port,
                tls,
                password,
            },
            connection: Mutex::new(None),
        })
    }

    async fn connect(&self) -> Result<Connection, StateError> {
        let t = &self.target;
        let tcp = TcpStream::connect((t.host.as_str(), t.port))
            .await
            .map_err(|e| fail("connect", &e))?;
        let mut connection = BufReader::new(self.wrap(tcp).await?);
        if let Some(password) = &t.password {
            match exchange(&mut connection, &[b"AUTH", password.as_bytes()]).await? {
                Reply::Simple(_) => {}
                other => return Err(StateError(format!("AUTH: {other:?}"))),
            }
        }
        Ok(connection)
    }

    /// `tcp` as it is, or inside TLS for `rediss://`.
    async fn wrap(&self, tcp: TcpStream) -> Result<Box<dyn Io>, StateError> {
        let Some(config) = &self.target.tls else {
            return Ok(Box::new(tcp));
        };
        let name = ServerName::try_from(self.target.host.clone()).map_err(|e| fail("host", &e))?;
        let stream = tokio_rustls::TlsConnector::from(config.clone())
            .connect(name, tcp)
            .await
            .map_err(|e| fail("TLS", &e))?;
        Ok(Box::new(stream))
    }

    /// Sends one command and reads its reply, connecting if needed. A
    /// failure drops the connection; a command on a connection reused
    /// from before is tried once more on a fresh one.
    async fn call(&self, parts: &[&[u8]]) -> Result<Reply, StateError> {
        tokio::time::timeout(DEADLINE, self.call_once_or_twice(parts))
            .await
            .map_err(|_| StateError("no answer within 2 s".into()))?
    }

    async fn call_once_or_twice(&self, parts: &[&[u8]]) -> Result<Reply, StateError> {
        let mut slot = self.connection.lock().await;
        let reused = slot.is_some();
        for attempt in 0..2 {
            let mut connection = match slot.take() {
                Some(c) => c,
                None => self.connect().await?,
            };
            match exchange(&mut connection, parts).await {
                Ok(reply) => {
                    *slot = Some(connection);
                    return reply_or_error(reply);
                }
                Err(e) if attempt == 0 && reused => drop(e),
                Err(e) => return Err(e),
            }
        }
        Err(StateError("the store closed the connection".into()))
    }

    async fn set(
        &self,
        key: &str,
        value: &[u8],
        ttl: Duration,
        nx: bool,
    ) -> Result<bool, StateError> {
        let ms = millis(ttl);
        let mut parts: Vec<&[u8]> = vec![b"SET", key.as_bytes(), value, b"PX", &ms];
        if nx {
            parts.push(b"NX");
        }
        match self.call(&parts).await? {
            Reply::Simple(_) => Ok(true),
            Reply::Bulk(None) => Ok(false),
            other => Err(StateError(format!("SET: {other:?}"))),
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StateError> {
        match self.call(&[b"GET", key.as_bytes()]).await? {
            Reply::Bulk(value) => Ok(value),
            other => Err(StateError(format!("GET: {other:?}"))),
        }
    }

    async fn claim_key(&self, key: &str, ttl: Duration) -> Result<Claim, StateError> {
        if self.set(key, PENDING, ttl, true).await? {
            return Ok(Claim::First);
        }
        Ok(match self.get(key).await? {
            Some(value) => match value.split_first() {
                Some((b'd', answer)) => Claim::Done(Bytes::copy_from_slice(answer)),
                _ => Claim::Pending,
            },
            // Expired between the two commands: treat as still running,
            // and let the caller's retry claim it.
            None => Claim::Pending,
        })
    }

    async fn count_key(&self, key: &str, ttl: Duration) -> Result<u64, StateError> {
        let ms = millis(ttl);
        match self
            .call(&[b"EVAL", COUNT, b"1", key.as_bytes(), &ms])
            .await?
        {
            Reply::Integer(n) => u64::try_from(n).map_err(|e| fail("EVAL", &e)),
            other => Err(StateError(format!("EVAL: {other:?}"))),
        }
    }
}

/// `host[:port]` or `[v6][:port]`; the port defaults to 6379.
fn split_host_port(authority: &str) -> Result<(String, u16), StateError> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => {
            let (host, rest) = v6
                .split_once(']')
                .ok_or_else(|| StateError(format!("{authority:?}: unclosed [")))?;
            (host, rest.strip_prefix(':'))
        }
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    let port = port.map_or(Ok(6379), |p| {
        p.parse()
            .map_err(|_| StateError(format!("{authority:?}: bad port")))
    })?;
    Ok((host.to_owned(), port))
}

async fn exchange(connection: &mut Connection, parts: &[&[u8]]) -> Result<Reply, StateError> {
    connection
        .get_mut()
        .write_all(&resp::command(parts))
        .await
        .map_err(|e| fail("write", &e))?;
    connection
        .get_mut()
        .flush()
        .await
        .map_err(|e| fail("write", &e))?;
    resp::read(connection).await.map_err(|e| fail("read", &e))
}

fn reply_or_error(reply: Reply) -> Result<Reply, StateError> {
    match reply {
        Reply::Error(e) => Err(StateError(format!("the store refused: {e}"))),
        other => Ok(other),
    }
}

impl SharedState for RedisState {
    fn first_use<'a>(&'a self, key: &'a str, ttl: Duration) -> StateFuture<'a, bool> {
        Box::pin(self.set(key, b"1", ttl, true))
    }

    fn claim<'a>(&'a self, key: &'a str, ttl: Duration) -> StateFuture<'a, Claim> {
        Box::pin(self.claim_key(key, ttl))
    }

    fn complete<'a>(&'a self, key: &'a str, answer: Bytes, ttl: Duration) -> StateFuture<'a, ()> {
        Box::pin(async move {
            let value = [&b"d"[..], &answer].concat();
            self.set(key, &value, ttl, false).await.map(|_| ())
        })
    }

    fn release<'a>(&'a self, key: &'a str) -> StateFuture<'a, ()> {
        Box::pin(async move {
            match self.call(&[b"DEL", key.as_bytes()]).await? {
                Reply::Integer(_) => Ok(()),
                other => Err(StateError(format!("DEL: {other:?}"))),
            }
        })
    }

    fn count<'a>(&'a self, key: &'a str, ttl: Duration) -> StateFuture<'a, u64> {
        Box::pin(self.count_key(key, ttl))
    }
}
