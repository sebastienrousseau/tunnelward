// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Web Bot Auth: the test vectors of draft-ietf-webbotauth-httpsig-
//! protocol-00, Appendix E.2 (the Ed25519 test key of RFC 9421 B.1.4),
//! and what the verifier refuses.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, HeaderValue, Method};
use tunnelward_gateway::{BotAuth, BotAuthError, KeySet, OnInvalid, Signer};

use common::Res;

/// RFC 9421 B.1.4's Ed25519 test key, as a key directory.
const DIRECTORY: &str =
    r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}"#;
const AGENT: &str = "https://signature-agent.test";
const KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

/// E.2.1: the dictionary form of Signature-Agent.
fn dictionary_vector() -> Res<HeaderMap> {
    headers(
        r#"agent2="https://signature-agent.test""#,
        &format!(
            r#"sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="{KEYID}";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth""#
        ),
        "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:",
    )
}

/// E.2.2: the legacy string form.
fn legacy_vector() -> Res<HeaderMap> {
    headers(
        r#""https://signature-agent.test""#,
        &format!(
            r#"sig2=("@authority" "signature-agent");created=1735689600;keyid="{KEYID}";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth""#
        ),
        "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:",
    )
}

fn headers(agent: &str, input: &str, signature: &str) -> Res<HeaderMap> {
    let mut h = HeaderMap::new();
    h.insert("signature-agent", HeaderValue::from_str(agent)?);
    h.insert("signature-input", HeaderValue::from_str(input)?);
    h.insert("signature", HeaderValue::from_str(signature)?);
    Ok(h)
}

fn verifier(agent: &str) -> Res<BotAuth> {
    let keys = Arc::new(KeySet::from_jwks(DIRECTORY.as_bytes())?);
    let signer = Signer {
        signature_agent: agent.into(),
        provider: "test".into(),
        agent: "vector".into(),
        keys,
    };
    Ok(BotAuth::new(vec![signer], OnInvalid::Reject))
}

/// Ten seconds after the vectors' `created`.
fn soon() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_735_689_610)
}

fn check(
    v: &BotAuth,
    authority: &str,
    h: &HeaderMap,
    at: SystemTime,
) -> Result<Option<String>, BotAuthError> {
    v.verify(&Method::GET, authority, "/", h, at)
        .map(|s| s.map(|s| s.agent.clone()))
}

#[test]
fn both_draft_vectors_verify() -> Res<()> {
    let v = verifier(AGENT)?;
    assert_eq!(
        check(&v, "example.com", &dictionary_vector()?, soon()),
        Ok(Some("vector".into()))
    );
    assert_eq!(
        check(&v, "example.com", &legacy_vector()?, soon()),
        Ok(Some("vector".into()))
    );
    Ok(())
}

#[test]
fn another_authority_does_not_verify() -> Res<()> {
    let v = verifier(AGENT)?;
    assert_eq!(
        check(&v, "example.org", &dictionary_vector()?, soon()),
        Err(BotAuthError::BadSignature)
    );
    Ok(())
}

#[test]
fn a_nonce_is_accepted_once() -> Res<()> {
    let v = verifier(AGENT)?;
    let h = dictionary_vector()?;
    assert!(check(&v, "example.com", &h, soon())?.is_some());
    assert_eq!(
        check(&v, "example.com", &h, soon()),
        Err(BotAuthError::Replayed)
    );
    Ok(())
}

#[test]
fn an_old_or_future_signature_is_out_of_window() -> Res<()> {
    let v = verifier(AGENT)?;
    let h = dictionary_vector()?;
    let late = UNIX_EPOCH + Duration::from_secs(1_735_689_600 + 301);
    let early = UNIX_EPOCH + Duration::from_secs(1_735_689_600 - 61);
    assert_eq!(
        check(&v, "example.com", &h, late),
        Err(BotAuthError::Expired)
    );
    assert_eq!(
        check(&v, "example.com", &h, early),
        Err(BotAuthError::Expired)
    );
    Ok(())
}

#[test]
fn an_untrusted_agent_or_key_is_refused() -> Res<()> {
    let v = verifier("https://other-agent.test")?;
    assert_eq!(
        check(&v, "example.com", &dictionary_vector()?, soon()),
        Err(BotAuthError::UnknownAgent)
    );
    let mut h = dictionary_vector()?;
    let input = h
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .replace(KEYID, "nope");
    h.insert("signature-input", HeaderValue::from_str(&input)?);
    assert_eq!(
        check(&verifier(AGENT)?, "example.com", &h, soon()),
        Err(BotAuthError::UnknownKey)
    );
    Ok(())
}

#[test]
fn unsigned_and_other_tags_are_not_web_bot_auth() -> Res<()> {
    let v = verifier(AGENT)?;
    assert_eq!(
        check(&v, "example.com", &HeaderMap::new(), soon()),
        Ok(None)
    );
    let mut h = dictionary_vector()?;
    let input = h
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .replace("web-bot-auth", "other");
    h.insert("signature-input", HeaderValue::from_str(&input)?);
    assert_eq!(check(&v, "example.com", &h, soon()), Ok(None));
    Ok(())
}

#[test]
fn a_signature_that_skips_signature_agent_is_malformed() -> Res<()> {
    let v = verifier(AGENT)?;
    let mut h = legacy_vector()?;
    let input = h
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .replace(r#"("@authority" "signature-agent")"#, r#"("@authority")"#);
    h.insert("signature-input", HeaderValue::from_str(&input)?);
    assert!(matches!(
        check(&v, "example.com", &h, soon()),
        Err(BotAuthError::Malformed(_))
    ));
    Ok(())
}

mod through_the_ingress {
    use super::*;
    use std::sync::Mutex;

    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use hyper::StatusCode;
    use tunnelward_gateway::{ProviderTag, ProxyObserver, RequestInfo};

    use super::common::ingress::{get, h1, ingress_config, start_ingress};
    use super::common::jwt::b64;

    #[derive(Debug, Default)]
    struct Tags(Mutex<Vec<Option<ProviderTag>>>);

    impl ProxyObserver for Tags {
        fn on_response(&self, info: &RequestInfo, _: StatusCode, _: Duration) {
            if let Ok(mut t) = self.0.lock() {
                t.push(info.provider.clone());
            }
        }
    }

    /// A gateway trusting `key` as agent `a` of provider `test`.
    async fn gateway(key: &Ed25519KeyPair, on_invalid: OnInvalid) -> Res<(String, Arc<Tags>)> {
        let jwk = format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{}"}}]}}"#,
            b64(key.public_key().as_ref())
        );
        let signer = Signer {
            signature_agent: "https://agent.test".into(),
            provider: "test".into(),
            agent: "a".into(),
            keys: Arc::new(KeySet::from_jwks(jwk.as_bytes())?),
        };
        let tags = Arc::new(Tags::default());
        let observer = tags.clone();
        let config = ingress_config(|i| {
            i.bot_auth = Some(Arc::new(BotAuth::new(vec![signer], on_invalid)));
            i.observers.push(observer);
        })?;
        let (_gateway, _connectors, ingress) = start_ingress(config).await?;
        Ok((ingress, tags))
    }

    /// A GET to `ingress` signed by `key` for `authority`.
    fn signed(
        key: &Ed25519KeyPair,
        authority: &str,
        nonce: &str,
    ) -> Res<hyper::Request<http_body_util::Full<bytes::Bytes>>> {
        let thumb = format!(
            r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
            b64(key.public_key().as_ref())
        );
        let keyid =
            b64(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, thumb.as_bytes()).as_ref());
        let created = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let params = format!(
            r#"("@authority" "signature-agent";key="a");created={created};keyid="{keyid}";expires={};nonce="{nonce}";tag="web-bot-auth""#,
            created + 60
        );
        let base = format!(
            "\"@authority\": {authority}\n\"signature-agent\";key=\"a\": \"https://agent.test\"\n\"@signature-params\": {params}"
        );
        let signature = key.sign(base.as_bytes());
        let mut request = get("/x")?;
        let h = request.headers_mut();
        h.insert(
            "signature-agent",
            HeaderValue::from_static(r#"a="https://agent.test""#),
        );
        h.insert(
            "signature-input",
            HeaderValue::from_str(&format!("s={params}"))?,
        );
        h.insert(
            "signature",
            HeaderValue::from_str(&format!("s=:{}:", standard(signature.as_ref())))?,
        );
        Ok(request)
    }

    /// Standard base64 with padding.
    fn standard(bytes: &[u8]) -> String {
        let url = b64(bytes).replace('-', "+").replace('_', "/");
        let pad = (4 - url.len() % 4) % 4;
        format!("{url}{}", "=".repeat(pad))
    }

    fn last_tag(tags: &Tags) -> Option<ProviderTag> {
        tags.0.lock().ok().and_then(|t| t.last().cloned().flatten())
    }

    #[tokio::test]
    async fn a_verified_signature_tags_the_request_at_signature_level() -> Res<()> {
        let key = Ed25519KeyPair::generate().map_err(|_| "keygen")?;
        let (ingress, tags) = gateway(&key, OnInvalid::Reject).await?;
        let _answer = h1(&ingress, signed(&key, "mcp.example.org", "n1")?).await?;
        let tag = last_tag(&tags).ok_or("no tag")?;
        assert_eq!(
            (tag.provider.as_str(), tag.agent.as_str(), tag.level),
            ("test", "a", "signature")
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failing_signature_is_refused_or_downgraded_as_configured() -> Res<()> {
        let key = Ed25519KeyPair::generate().map_err(|_| "keygen")?;
        let (ingress, _) = gateway(&key, OnInvalid::Reject).await?;
        let (status, headers, _) = h1(&ingress, signed(&key, "elsewhere.test", "n2")?).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            headers.get("tw-error").map(HeaderValue::as_bytes),
            Some(&b"TW-I010"[..])
        );
        let (ingress, tags) = gateway(&key, OnInvalid::Downgrade).await?;
        let (status, _, _) = h1(&ingress, signed(&key, "elsewhere.test", "n3")?).await?;
        assert_ne!(status, StatusCode::UNAUTHORIZED, "downgraded, not refused");
        assert_eq!(last_tag(&tags), None, "and not tagged");
        Ok(())
    }
}
