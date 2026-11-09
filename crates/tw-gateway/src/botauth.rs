// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Web Bot Auth (FR-12, signature level): an agent's HTTP message
//! signature (RFC 9421) as draft-ietf-webbotauth-httpsig-protocol
//! profiles it. The signature must carry `tag="web-bot-auth"`, `created`,
//! `expires` and a `keyid` that is the RFC 7638 thumbprint of an Ed25519
//! key; cover `@authority` and `signature-agent`; and come from a
//! `Signature-Agent` the gateway was configured to trust, whose key
//! directory it fetches itself. An agent-supplied URL is never fetched.
//!
//! `created` must be within five minutes, and a nonce seen before is a
//! replay, so a captured signature cannot be reused for long.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, Method};

use crate::KeySet;
use crate::auth::Alg;
use crate::sfv::{self, Bare, Item, Member};
use crate::state::SharedState;

/// Clock skew allowed on `created`.
const SKEW: u64 = 60;

/// One agent the gateway accepts signatures from.
#[derive(Debug, Clone)]
pub struct Signer {
    /// The agent's identifier: the URL its requests name in
    /// `Signature-Agent`, exactly.
    pub signature_agent: String,
    /// The provider to tag its requests with, for example `openai`.
    pub provider: String,
    /// The agent within the provider, for example `chatgpt-agent`.
    pub agent: String,
    /// Its key directory (`/.well-known/http-message-signatures-directory`).
    pub keys: Arc<KeySet>,
}

/// What to do with a request whose signature fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnInvalid {
    /// Refuse it: 401, `TW-I010`.
    Reject,
    /// Serve it as if unsigned: network-level evidence at most.
    Downgrade,
}

/// Why a signature was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotAuthError {
    /// The signature fields do not follow the profile.
    Malformed(&'static str),
    /// `Signature-Agent` names no configured signer.
    UnknownAgent,
    /// The signer has no key with this `keyid`.
    UnknownKey,
    /// The signature does not verify.
    BadSignature,
    /// Outside its time window.
    Expired,
    /// The nonce was seen before.
    Replayed,
}

impl std::fmt::Display for BotAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed: {why}"),
            Self::UnknownAgent => f.write_str("the Signature-Agent is not trusted"),
            Self::UnknownKey => f.write_str("the keyid is not in the agent's directory"),
            Self::BadSignature => f.write_str("the signature does not verify"),
            Self::Expired => f.write_str("the signature is outside its time window"),
            Self::Replayed => f.write_str("the nonce was used before"),
        }
    }
}

impl std::error::Error for BotAuthError {}

/// The signers a gateway trusts. The nonces it has seen are in the
/// gateway's [`SharedState`], so a replay to another gateway is caught.
#[derive(Debug)]
pub struct BotAuth {
    /// The agents accepted.
    pub signers: Vec<Signer>,
    /// What a failing signature leads to.
    pub on_invalid: OnInvalid,
    /// How old `created` may be.
    pub max_age: Duration,
}

/// The request parts a signature can cover.
pub(crate) struct Signed<'a> {
    pub(crate) method: &'a Method,
    pub(crate) authority: &'a str,
    pub(crate) path: &'a str,
    pub(crate) headers: &'a HeaderMap,
}

/// One signature, parsed.
struct Signature {
    label: String,
    components: Vec<Item>,
    list_params: Vec<(String, Bare)>,
    created: u64,
    expires: u64,
    keyid: String,
    nonce: Option<String>,
}

impl BotAuth {
    /// Accepts `signers`; signatures may be at most five minutes old.
    #[must_use]
    pub fn new(signers: Vec<Signer>, on_invalid: OnInvalid) -> Self {
        Self {
            signers,
            on_invalid,
            max_age: Duration::from_secs(300),
        }
    }

    /// The signer of a request for `authority` with `method` and `path`,
    /// if it carries a Web Bot Auth signature; `Ok(None)` if it carries
    /// none.
    ///
    /// # Errors
    ///
    /// [`BotAuthError`] for a signature that is there but fails, or whose
    /// nonce `state` cannot check (the check fails closed).
    pub async fn verify(
        &self,
        request: (&Method, &str, &str, &HeaderMap),
        now: SystemTime,
        state: &dyn SharedState,
    ) -> Result<Option<&Signer>, BotAuthError> {
        let (method, authority, path, headers) = request;
        let request = Signed {
            method,
            authority,
            path,
            headers,
        };
        let Some(sig) = find(headers)? else {
            return Ok(None);
        };
        let signer = self.signer(headers, &sig)?;
        self.in_window(&sig, now)?;
        verify_with(signer, &request, &sig)?;
        self.fresh_nonce(&sig, now, state).await?;
        Ok(Some(signer))
    }

    /// The configured signer `Signature-Agent` names for `sig`.
    fn signer(&self, headers: &HeaderMap, sig: &Signature) -> Result<&Signer, BotAuthError> {
        let agent = signature_agent(headers, sig)?;
        self.signers
            .iter()
            .find(|s| s.signature_agent == agent)
            .ok_or(BotAuthError::UnknownAgent)
    }

    fn in_window(&self, sig: &Signature, now: SystemTime) -> Result<(), BotAuthError> {
        let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let young = sig.created <= now.saturating_add(SKEW)
            && now <= sig.created.saturating_add(self.max_age.as_secs());
        (young && now < sig.expires)
            .then_some(())
            .ok_or(BotAuthError::Expired)
    }

    /// Records the nonce until the signature could no longer be fresh;
    /// a seen one is a replay. Called only after the signature verified,
    /// so unsigned junk cannot fill the store.
    async fn fresh_nonce(
        &self,
        sig: &Signature,
        now: SystemTime,
        state: &dyn SharedState,
    ) -> Result<(), BotAuthError> {
        let Some(nonce) = &sig.nonce else {
            return Ok(());
        };
        // Long enough that the signature is stale before the nonce is
        // forgotten, counted from `now`.
        let forget_after = sig.created.saturating_add(self.max_age.as_secs() + SKEW);
        let ttl = Duration::from_secs(forget_after.saturating_sub(unix(now)).max(1));
        match state.first_use(&format!("nonce:{nonce}"), ttl).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(BotAuthError::Replayed),
            Err(_) => Err(BotAuthError::Malformed(
                "the nonce cannot be checked for replay",
            )),
        }
    }
}

fn unix(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Raises `info`'s provider tag to `signature` for a verified signature;
/// a failing one is refused (`TW-I010`) or ignored as configured.
pub(crate) async fn identify<B>(
    bot_auth: &BotAuth,
    state: &dyn SharedState,
    request: &http::Request<B>,
    info: &mut crate::RequestInfo,
) -> Result<(), crate::refusal::Refusal> {
    let authority = request
        .uri()
        .authority()
        .map(http::uri::Authority::as_str)
        .or_else(|| {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
        })
        .unwrap_or_default();
    let parts = (
        request.method(),
        authority,
        request.uri().path(),
        request.headers(),
    );
    match bot_auth.verify(parts, SystemTime::now(), state).await {
        Ok(Some(signer)) => info.provider = Some(crate::ProviderTag::signed(signer)),
        Err(e) if bot_auth.on_invalid == OnInvalid::Reject => {
            let reason = format!("the Web Bot Auth signature fails: {e}");
            return Err(crate::refusal::Refusal::new(
                "TW-I010",
                http::StatusCode::UNAUTHORIZED,
                reason,
            ));
        }
        // Unsigned, or a failing signature downgraded: no signature tag.
        Ok(None) | Err(_) => {}
    }
    Ok(())
}

/// Fails unless `sig` verifies with `signer`'s key named by its keyid.
fn verify_with(signer: &Signer, request: &Signed<'_>, sig: &Signature) -> Result<(), BotAuthError> {
    let key = signer
        .keys
        .ed25519(&sig.keyid)
        .ok_or(BotAuthError::UnknownKey)?;
    let signature = signature_bytes(request.headers, &sig.label)?;
    let base = base(request, sig)?;
    key.verifies(Alg::EdDsa, base.as_bytes(), &signature)
        .then_some(())
        .ok_or(BotAuthError::BadSignature)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn string(params: &[(String, Bare)], key: &str) -> Option<String> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            Bare::String(s) => Some(s.clone()),
            _ => None,
        })
}

fn integer(params: &[(String, Bare)], key: &str) -> Option<u64> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            Bare::Integer(n) => u64::try_from(*n).ok(),
            _ => None,
        })
}

/// The first `tag="web-bot-auth"` signature in `Signature-Input`.
fn find(headers: &HeaderMap) -> Result<Option<Signature>, BotAuthError> {
    let Some(input) = header(headers, "signature-input") else {
        return Ok(None);
    };
    let dict = sfv::dictionary(input).ok_or(BotAuthError::Malformed("Signature-Input"))?;
    let found = dict.into_iter().find_map(|(label, member)| match member {
        Member::InnerList(items, params)
            if string(&params, "tag").as_deref() == Some("web-bot-auth") =>
        {
            Some((label, items, params))
        }
        _ => None,
    });
    found
        .map(|(label, items, params)| signature(label, items, params))
        .transpose()
}

fn signature(
    label: String,
    components: Vec<Item>,
    params: Vec<(String, Bare)>,
) -> Result<Signature, BotAuthError> {
    let bad = BotAuthError::Malformed;
    if string(&params, "alg").is_some_and(|a| a != "ed25519") {
        return Err(bad("alg is not ed25519"));
    }
    covers_what_it_must(&components)?;
    Ok(Signature {
        created: integer(&params, "created").ok_or(bad("no created"))?,
        expires: integer(&params, "expires").ok_or(bad("no expires"))?,
        keyid: string(&params, "keyid").ok_or(bad("no keyid"))?,
        nonce: string(&params, "nonce"),
        label,
        components,
        list_params: params,
    })
}

/// Fails unless the components include `@authority` and
/// `signature-agent`.
fn covers_what_it_must(components: &[Item]) -> Result<(), BotAuthError> {
    let covers = |name: &str| {
        components
            .iter()
            .any(|c| c.bare == Bare::String(name.to_owned()))
    };
    (covers("@authority") && covers("signature-agent"))
        .then_some(())
        .ok_or(BotAuthError::Malformed(
            "it must cover @authority and signature-agent",
        ))
}

/// The agent URL `Signature-Agent` names for `sig`: the dictionary
/// member its `signature-agent` component selects, or (legacy) the
/// whole field as one string.
fn signature_agent(headers: &HeaderMap, sig: &Signature) -> Result<String, BotAuthError> {
    let value =
        header(headers, "signature-agent").ok_or(BotAuthError::Malformed("no Signature-Agent"))?;
    match agent_item(value, sig)?.bare {
        Bare::String(url) if url.starts_with("https://") => Ok(url),
        _ => Err(BotAuthError::Malformed(
            "Signature-Agent is not an https URL string",
        )),
    }
}

/// The item `sig`'s `signature-agent` component selects from `value`.
fn agent_item(value: &str, sig: &Signature) -> Result<Item, BotAuthError> {
    let component = sig
        .components
        .iter()
        .find(|c| c.bare == Bare::String("signature-agent".into()));
    match component.and_then(|c| string(&c.params, "key")) {
        Some(key) => member(value, &key),
        None => sfv::item(value).ok_or(BotAuthError::Malformed("Signature-Agent")),
    }
}

fn member(dictionary: &str, key: &str) -> Result<Item, BotAuthError> {
    let dict = sfv::dictionary(dictionary).ok_or(BotAuthError::Malformed("Signature-Agent"))?;
    dict.into_iter()
        .find_map(|(k, m)| match m {
            Member::Item(item) if k == key => Some(item),
            _ => None,
        })
        .ok_or(BotAuthError::Malformed(
            "Signature-Agent lacks the member signed",
        ))
}

fn signature_bytes(headers: &HeaderMap, label: &str) -> Result<Vec<u8>, BotAuthError> {
    let value = header(headers, "signature").ok_or(BotAuthError::Malformed("no Signature"))?;
    let dict = sfv::dictionary(value).ok_or(BotAuthError::Malformed("Signature"))?;
    dict.into_iter()
        .find_map(|(k, m)| match m {
            Member::Item(Item {
                bare: Bare::Bytes(b),
                ..
            }) if k == label => Some(b),
            _ => None,
        })
        .ok_or(BotAuthError::Malformed("no Signature for the label"))
}

/// The signature base (RFC 9421 section 2.5).
fn base(request: &Signed<'_>, sig: &Signature) -> Result<String, BotAuthError> {
    let mut out = String::new();
    for component in &sig.components {
        let Bare::String(name) = &component.bare else {
            return Err(BotAuthError::Malformed("a component is not a string"));
        };
        let value = component_value(request, name, &component.params)?;
        let _infallible = writeln!(
            out,
            "{}{}: {value}",
            sfv::bare(&component.bare),
            sfv::params(&component.params)
        );
    }
    let params = sfv::inner_list(&sig.components, &sig.list_params);
    let _infallible = write!(out, "\"@signature-params\": {params}");
    Ok(out)
}

fn component_value(
    request: &Signed<'_>,
    name: &str,
    params: &[(String, Bare)],
) -> Result<String, BotAuthError> {
    match name {
        "@authority" => Ok(request.authority.to_ascii_lowercase()),
        "@method" => Ok(request.method.as_str().to_owned()),
        "@path" => Ok(request.path.to_owned()),
        derived if derived.starts_with('@') => {
            Err(BotAuthError::Malformed("an unsupported derived component"))
        }
        field => field_value(request.headers, field, params),
    }
}

/// A covered header field's value: the whole field, or with `key` the
/// dictionary member it names, serialised.
fn field_value(
    headers: &HeaderMap,
    field: &str,
    params: &[(String, Bare)],
) -> Result<String, BotAuthError> {
    let value =
        header(headers, field).ok_or(BotAuthError::Malformed("a covered field is missing"))?;
    match string(params, "key") {
        Some(key) => serialised_member(value, &key),
        None => Ok(value.trim().to_owned()),
    }
}

fn serialised_member(dictionary: &str, key: &str) -> Result<String, BotAuthError> {
    let item = member(dictionary, key)?;
    Ok(format!(
        "{}{}",
        sfv::bare(&item.bare),
        sfv::params(&item.params)
    ))
}
