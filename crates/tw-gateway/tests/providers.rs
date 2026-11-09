// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Provider identification, network level (FR-12): a signed, versioned
//! snapshot of providers' published egress ranges, and each request
//! tagged with the provider whose range its client address is in.

mod common;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use hyper::StatusCode;
use tunnelward_gateway::{ProviderError, ProviderTag, Providers, ProxyObserver, RequestInfo};

use common::Res;
use common::ingress::{get, h1, ingress_config, start_ingress};

/// A snapshot at `version` with Anthropic's published outbound ranges and
/// one test range.
fn snapshot(version: u64, test_range: &str) -> Vec<u8> {
    format!(
        r#"{{"version":{version},"created":"2026-11-08T00:00:00Z","providers":[
            {{"provider":"anthropic","agent":"outbound","source":"https://platform.claude.com/docs/en/api/ip-addresses",
              "ranges":["160.79.104.0/21","153.61.208.0/20"]}},
            {{"provider":"test","agent":"loopback","source":"test","ranges":["{test_range}"]}}]}}"#
    )
    .into_bytes()
}

fn signer() -> Res<Ed25519KeyPair> {
    Ok(Ed25519KeyPair::generate().map_err(|_| "key generation")?)
}

fn trusting(key: &Ed25519KeyPair) -> Providers {
    Providers::new(vec![key.public_key().as_ref().to_vec()])
}

fn ip(text: &str) -> Res<IpAddr> {
    Ok(text.parse()?)
}

#[test]
fn a_signed_snapshot_tags_addresses_in_its_ranges() -> Res<()> {
    let key = signer()?;
    let providers = trusting(&key);
    let snap = snapshot(3, "2001:db8::/32");
    assert_eq!(providers.load(&snap, key.sign(&snap).as_ref()), Ok(3));
    let tag = providers.lookup(ip("160.79.111.255")?);
    assert_eq!(
        tag,
        Some(ProviderTag {
            provider: "anthropic".into(),
            agent: "outbound".into(),
            level: "network",
            snapshot: Some(3),
        })
    );
    assert!(providers.lookup(ip("153.61.208.1")?).is_some());
    assert_eq!(
        providers.lookup(ip("160.79.112.0")?),
        None,
        "just outside the /21"
    );
    assert_eq!(
        providers.lookup(ip("2001:db8::1")?).map(|t| t.provider),
        Some("test".into())
    );
    Ok(())
}

#[test]
fn tampered_or_foreign_snapshots_are_refused() -> Res<()> {
    let (key, stranger) = (signer()?, signer()?);
    let providers = trusting(&key);
    let snap = snapshot(1, "192.0.2.0/24");
    let mut tampered = snap.clone();
    tampered[20] ^= 1;
    assert_eq!(
        providers.load(&tampered, key.sign(&snap).as_ref()),
        Err(ProviderError::Signature)
    );
    assert_eq!(
        providers.load(&snap, stranger.sign(&snap).as_ref()),
        Err(ProviderError::Signature)
    );
    assert_eq!(
        providers.load(&snap, b"short"),
        Err(ProviderError::Signature)
    );
    assert_eq!(
        providers.lookup(ip("160.79.104.1")?),
        None,
        "nothing loaded"
    );
    Ok(())
}

#[test]
fn an_older_snapshot_cannot_replace_a_newer_one() -> Res<()> {
    let key = signer()?;
    let providers = trusting(&key);
    let load = |v: u64| {
        let s = snapshot(v, "192.0.2.0/24");
        providers.load(&s, key.sign(&s).as_ref())
    };
    assert_eq!(load(5), Ok(5));
    assert_eq!(
        load(4),
        Err(ProviderError::Rollback {
            loaded: 5,
            offered: 4
        })
    );
    assert_eq!(load(5), Ok(5), "the same version again is fine");
    assert_eq!(load(6), Ok(6));
    assert_eq!(providers.version(), Some(6));
    Ok(())
}

#[test]
fn a_signed_snapshot_with_a_bad_range_is_refused_whole() -> Res<()> {
    let key = signer()?;
    let providers = trusting(&key);
    let snap = snapshot(1, "not-a-range");
    assert!(matches!(
        providers.load(&snap, key.sign(&snap).as_ref()),
        Err(ProviderError::Format(_))
    ));
    Ok(())
}

#[derive(Debug, Default)]
struct Tags(Mutex<Vec<Option<ProviderTag>>>);

impl ProxyObserver for Tags {
    fn on_response(&self, info: &RequestInfo, _: StatusCode, _: std::time::Duration) {
        if let Ok(mut t) = self.0.lock() {
            t.push(info.provider.clone());
        }
    }
}

#[tokio::test]
async fn ingress_requests_carry_their_provider_tag() -> Res<()> {
    let key = signer()?;
    let providers = Arc::new(trusting(&key));
    let snap = snapshot(7, "127.0.0.0/8");
    providers.load(&snap, key.sign(&snap).as_ref())?;
    let tags = Arc::new(Tags::default());
    let observer = tags.clone();
    let config = ingress_config(|i| {
        i.providers = Some(providers);
        i.observers.push(observer);
    })?;
    let (_gateway, _connectors, ingress) = start_ingress(config).await?;
    let _answer = h1(&ingress, get("/anything")?).await?;
    let seen = tags.0.lock().map(|t| t.clone()).unwrap_or_default();
    let tag = seen.first().cloned().flatten();
    assert_eq!(
        tag.map(|t| (t.provider, t.snapshot)),
        Some(("test".to_owned(), Some(7)))
    );
    Ok(())
}
