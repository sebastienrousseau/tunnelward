// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The Redis-compatible shared store: every `SharedState` operation, two
//! gateways sharing it, a password, and a dropped connection. Each test
//! runs against a small fake RESP server; the `real_store_` tests run the
//! same checks against a real one at `TUNNELWARD_TEST_REDIS_URL` (CI
//! starts Valkey for them).

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tunnelward_crypto::rustls::RootCertStore;
use tunnelward_gateway::{Claim, RedisState, SharedState};

use common::Res;

type Store = Arc<Mutex<Map>>;

/// A fake server: SET (PX, NX), GET, DEL, the counter EVAL and AUTH.
/// After `close_after` replies on a connection it closes it.
async fn fake(password: Option<&'static str>, close_after: usize) -> Res<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let store: Store = Arc::default();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(serve(tcp, store.clone(), password, close_after));
        }
    });
    Ok(format!("redis://{addr}"))
}

async fn serve(tcp: TcpStream, store: Store, password: Option<&str>, close_after: usize) {
    let mut reader = BufReader::new(tcp);
    let mut authed = password.is_none();
    for _ in 0..close_after {
        let Some(parts) = command(&mut reader).await else {
            return;
        };
        let reply = answer(&store, &parts, password, &mut authed);
        if reader.get_mut().write_all(&reply).await.is_err() {
            return;
        }
    }
}

async fn command(reader: &mut BufReader<TcpStream>) -> Option<Vec<Vec<u8>>> {
    let mut line = String::new();
    reader.read_line(&mut line).await.ok()?;
    let count: usize = line.trim().strip_prefix('*')?.parse().ok()?;
    let mut parts = Vec::with_capacity(count);
    for _ in 0..count {
        line.clear();
        reader.read_line(&mut line).await.ok()?;
        let len: usize = line.trim().strip_prefix('$')?.parse().ok()?;
        let mut data = vec![0; len + 2];
        reader.read_exact(&mut data).await.ok()?;
        data.truncate(len);
        parts.push(data);
    }
    Some(parts)
}

fn bulk(value: Option<&[u8]>) -> Vec<u8> {
    match value {
        None => b"$-1\r\n".to_vec(),
        Some(v) => [format!("${}\r\n", v.len()).as_bytes(), v, b"\r\n"].concat(),
    }
}

/// The reply to AUTH, or to anything before a successful one; `None`
/// once authenticated.
fn gatekeep(
    name: &[u8],
    parts: &[Vec<u8>],
    password: Option<&str>,
    authed: &mut bool,
) -> Option<Vec<u8>> {
    if name == b"AUTH" {
        *authed = password.is_some_and(|p| parts.get(1).is_some_and(|g| g == p.as_bytes()));
        let reply: &[u8] = if *authed {
            b"+OK\r\n"
        } else {
            b"-WRONGPASS\r\n"
        };
        return Some(reply.to_vec());
    }
    (!*authed).then(|| b"-NOAUTH Authentication required.\r\n".to_vec())
}

fn answer(store: &Store, parts: &[Vec<u8>], password: Option<&str>, authed: &mut bool) -> Vec<u8> {
    let name = parts
        .first()
        .map(|p| p.to_ascii_uppercase())
        .unwrap_or_default();
    if let Some(reply) = gatekeep(&name, parts, password, authed) {
        return reply;
    }
    let mut map = store.lock().unwrap_or_else(PoisonError::into_inner);
    let now = Instant::now();
    map.retain(|_, (_, until)| until.is_none_or(|u| u > now));
    dispatch(&mut map, &name, parts)
}

/// SET, GET, DEL and the counter EVAL on a store holding live keys only.
fn dispatch(map: &mut Map, name: &[u8], parts: &[Vec<u8>]) -> Vec<u8> {
    match (name, parts) {
        (b"SET", [_, key, value, rest @ ..]) => set(map, key, value, rest),
        (b"GET", [_, key]) => bulk(map.get(key).map(|(v, _)| v.as_slice())),
        (b"DEL", [_, key]) => format!(":{}\r\n", i32::from(map.remove(key).is_some())).into_bytes(),
        (b"EVAL", [_, _, _, key, ms]) => count(map, key, ms),
        _ => b"-ERR unknown command\r\n".to_vec(),
    }
}

type Map = HashMap<Vec<u8>, (Vec<u8>, Option<Instant>)>;

/// `ms` milliseconds from now.
fn deadline(ms: Option<&Vec<u8>>) -> Option<Instant> {
    let millis = String::from_utf8_lossy(ms?).parse().ok()?;
    Some(Instant::now() + Duration::from_millis(millis))
}

/// SET key value PX ms [NX].
fn set(map: &mut Map, key: &[u8], value: &[u8], rest: &[Vec<u8>]) -> Vec<u8> {
    let nx = rest.iter().any(|p| p.eq_ignore_ascii_case(b"NX"));
    if nx && map.contains_key(key) {
        return bulk(None);
    }
    map.insert(key.to_vec(), (value.to_vec(), deadline(rest.get(1))));
    b"+OK\r\n".to_vec()
}

/// The counter script: INCR, and PEXPIRE on the first count.
fn count(map: &mut Map, key: &[u8], ms: &Vec<u8>) -> Vec<u8> {
    let entry = map.entry(key.to_vec()).or_insert((b"0".to_vec(), None));
    let n: u64 = String::from_utf8_lossy(&entry.0).parse().unwrap_or(0) + 1;
    entry.0 = n.to_string().into_bytes();
    if n == 1 {
        entry.1 = deadline(Some(ms));
    }
    format!(":{n}\r\n").into_bytes()
}

fn store(url: &str, password: Option<&str>) -> Res<RedisState> {
    let roots = Arc::new(RootCertStore::empty());
    Ok(RedisState::new(url, password.map(str::to_owned), roots)?)
}

/// A key no other run uses, so a real store can be shared.
fn key(name: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("tw-test:{name}:{nanos}")
}

const MINUTE: Duration = Duration::from_secs(60);

/// Every operation, and two gateways sharing the store.
async fn every_operation(url: &str, password: Option<&str>) -> Res<()> {
    let (a, b) = (store(url, password)?, store(url, password)?);
    replay_is_shared(&a, &b).await?;
    idempotency_is_shared(&a, &b).await?;
    let rate = key("rate");
    assert_eq!(a.count(&rate, MINUTE).await?, 1);
    assert_eq!(b.count(&rate, MINUTE).await?, 2);
    Ok(())
}

async fn replay_is_shared(a: &RedisState, b: &RedisState) -> Res<()> {
    let nonce = key("nonce");
    assert!(a.first_use(&nonce, MINUTE).await?);
    assert!(
        !b.first_use(&nonce, MINUTE).await?,
        "replayed to the other gateway"
    );
    Ok(())
}

async fn idempotency_is_shared(a: &RedisState, b: &RedisState) -> Res<()> {
    let idem = key("idem");
    assert_eq!(a.claim(&idem, MINUTE).await?, Claim::First);
    assert_eq!(b.claim(&idem, MINUTE).await?, Claim::Pending);
    a.complete(&idem, Bytes::from_static(b"answer"), MINUTE)
        .await?;
    assert_eq!(
        b.claim(&idem, MINUTE).await?,
        Claim::Done(Bytes::from_static(b"answer"))
    );
    let retry = key("retry");
    assert_eq!(a.claim(&retry, MINUTE).await?, Claim::First);
    a.release(&retry).await?;
    assert_eq!(b.claim(&retry, MINUTE).await?, Claim::First, "released");
    Ok(())
}

/// Keys expire after their time-to-live.
async fn keys_expire(url: &str, password: Option<&str>) -> Res<()> {
    let s = store(url, password)?;
    let (nonce, rate) = (key("short"), key("short-rate"));
    assert!(s.first_use(&nonce, Duration::from_millis(200)).await?);
    assert_eq!(s.count(&rate, Duration::from_millis(200)).await?, 1);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(s.first_use(&nonce, MINUTE).await?, "expired");
    assert_eq!(s.count(&rate, MINUTE).await?, 1, "the counter expired too");
    Ok(())
}

#[tokio::test]
async fn every_operation_against_the_fake() -> Res<()> {
    every_operation(&fake(None, usize::MAX).await?, None).await
}

#[tokio::test]
async fn keys_expire_against_the_fake() -> Res<()> {
    keys_expire(&fake(None, usize::MAX).await?, None).await
}

#[tokio::test]
async fn a_password_is_sent_and_a_wrong_one_is_an_error() -> Res<()> {
    let url = fake(Some("s3cret"), usize::MAX).await?;
    every_operation(&url, Some("s3cret")).await?;
    let wrong = store(&url, Some("nope"))?;
    assert!(wrong.first_use(&key("x"), MINUTE).await.is_err());
    let none = store(&url, None)?;
    assert!(none.first_use(&key("x"), MINUTE).await.is_err(), "NOAUTH");
    Ok(())
}

#[tokio::test]
async fn a_dropped_connection_is_reopened() -> Res<()> {
    // The server closes each connection after one reply.
    let s = store(&fake(None, 1).await?, None)?;
    for _ in 0..3 {
        assert!(s.first_use(&key("again"), MINUTE).await?);
    }
    Ok(())
}

#[tokio::test]
async fn a_store_that_is_not_there_is_an_error_within_the_deadline() -> Res<()> {
    let unused = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
    let s = store(&format!("redis://{unused}"), None)?;
    let started = Instant::now();
    assert!(s.first_use(&key("gone"), MINUTE).await.is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
    Ok(())
}

#[test]
fn only_redis_urls_without_credentials_are_accepted() {
    for bad in [
        "http://h:1",
        "redis://user:pw@h:1",
        "redis://",
        "redis://h:port",
        "redis://h/1",
    ] {
        assert!(store(bad, None).is_err(), "{bad}");
    }
    for good in [
        "redis://h",
        "redis://h:6380",
        "rediss://h:6380",
        "redis://[::1]:6379",
    ] {
        assert!(store(good, None).is_ok(), "{good}");
    }
}

fn real_store() -> Res<String> {
    std::env::var("TUNNELWARD_TEST_REDIS_URL")
        .map_err(|_| "set TUNNELWARD_TEST_REDIS_URL to a Redis-compatible store".into())
}

#[tokio::test]
#[ignore = "needs a Redis-compatible store at TUNNELWARD_TEST_REDIS_URL; CI runs it"]
async fn real_store_every_operation() -> Res<()> {
    every_operation(&real_store()?, None).await
}

#[tokio::test]
#[ignore = "needs a Redis-compatible store at TUNNELWARD_TEST_REDIS_URL; CI runs it"]
async fn real_store_keys_expire() -> Res<()> {
    keys_expire(&real_store()?, None).await
}
