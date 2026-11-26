// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! DSSE envelopes, bare or inside a Sigstore bundle.

use core::fmt;

use serde::Deserialize;
use serde::de::{Deserializer, IgnoredAny, SeqAccess, Visitor};
use tunnelward_audit::b64;

use crate::Error;

/// The payload type of an in-toto statement.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// A DSSE envelope as JSON writes it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Wire {
    payload_type: String,
    payload: String,
    signatures: Vec<WireSignature>,
}

#[derive(Deserialize)]
struct WireSignature {
    sig: String,
}

/// A Sigstore bundle (only its `dsseEnvelope` is read) or a bare
/// envelope, in one pass and without buffering the document.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Shape {
    dsse_envelope: Option<Wire>,
    payload_type: Option<String>,
    payload: Option<String>,
    #[serde(default)]
    signatures: Vec<WireSignature>,
}

/// How many signatures either shape carries, read without keeping any.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Counted {
    dsse_envelope: Option<CountedEnvelope>,
    signatures: Option<Items>,
}

#[derive(Deserialize)]
struct CountedEnvelope {
    signatures: Option<Items>,
}

/// The length of a JSON array whose items are skipped, not stored.
struct Items(usize);

impl<'de> Deserialize<'de> for Items {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Count;
        impl<'de> Visitor<'de> for Count {
            type Value = Items;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Items, A::Error> {
                let mut n = 0_usize;
                while seq.next_element::<IgnoredAny>()?.is_some() {
                    n = n.saturating_add(1);
                }
                Ok(Items(n))
            }
        }
        d.deserialize_seq(Count)
    }
}

/// A decoded envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Envelope {
    /// The statement, as signed.
    pub(crate) payload: Vec<u8>,
    /// The signatures, decoded.
    pub(crate) signatures: Vec<Vec<u8>>,
}

const NOT_AN_ENVELOPE: Error = Error::Envelope("neither a DSSE envelope nor a Sigstore bundle");

impl Envelope {
    /// `bytes` read as a Sigstore bundle or a bare DSSE envelope with at
    /// most `max_signatures` signatures, counted before any is kept.
    pub(crate) fn parse(bytes: &[u8], max_signatures: usize) -> Result<Self, Error> {
        if count(bytes)? > max_signatures {
            return Err(Error::Envelope("more signatures than the gateway allows"));
        }
        let wire = wire(serde_json::from_slice(bytes).map_err(|_| NOT_AN_ENVELOPE)?)?;
        Self::decode(&wire)
    }

    /// `wire`'s payload type checked and its base64 decoded.
    fn decode(wire: &Wire) -> Result<Self, Error> {
        if wire.payload_type != PAYLOAD_TYPE {
            return Err(Error::Envelope(
                "the payload type is not an in-toto statement",
            ));
        }
        if wire.signatures.is_empty() {
            return Err(Error::Unsigned);
        }
        let payload = base64(&wire.payload).ok_or(Error::Envelope("the payload is not base64"))?;
        let signatures = wire
            .signatures
            .iter()
            .map(|s| base64(&s.sig))
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::Envelope("a signature is not base64"))?;
        Ok(Self {
            payload,
            signatures,
        })
    }

    /// The DSSE pre-authentication encoding the signatures cover.
    pub(crate) fn pae(&self) -> Vec<u8> {
        pae(PAYLOAD_TYPE, &self.payload)
    }
}

/// How many signatures `bytes` carries, either shape, none kept.
fn count(bytes: &[u8]) -> Result<usize, Error> {
    let counted: Counted = serde_json::from_slice(bytes).map_err(|_| NOT_AN_ENVELOPE)?;
    let inner = counted.dsse_envelope.and_then(|e| e.signatures);
    Ok(inner.or(counted.signatures).map_or(0, |Items(n)| n))
}

/// The envelope inside a bundle, or the bare one.
fn wire(shape: Shape) -> Result<Wire, Error> {
    if let Some(wire) = shape.dsse_envelope {
        return Ok(wire);
    }
    match (shape.payload_type, shape.payload) {
        (Some(payload_type), Some(payload)) => Ok(Wire {
            payload_type,
            payload,
            signatures: shape.signatures,
        }),
        _ => Err(NOT_AN_ENVELOPE),
    }
}

/// `DSSEv1 <len(type)> <type> <len(body)> <body>`, lengths in decimal.
pub(crate) fn pae(payload_type: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "DSSEv1 {} {payload_type} {} ",
        payload_type.len(),
        body.len()
    );
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    out
}

/// Standard base64 with padding, as Go and cosign write it, or the URL
/// alphabet without, which DSSE also allows.
fn base64(text: &str) -> Option<Vec<u8>> {
    b64::decode_standard(text).or_else(|| b64::decode(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_the_dsse_specification_example() {
        // DSSE protocol.md: PAE("http://example.com/HelloWorld", "hello world").
        let out = pae("http://example.com/HelloWorld", b"hello world");
        assert_eq!(
            out,
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[test]
    fn reads_both_shapes_and_both_alphabets() {
        let bare = br#"{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":"AQI"}]}"#;
        let e = Envelope::parse(bare, 8).unwrap();
        assert_eq!(
            (e.payload.as_slice(), e.signatures[0].as_slice()),
            (&b"{}"[..], &[1, 2][..])
        );
        let bundle = br#"{"mediaType":"x","dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":"AQI="}]}}"#;
        assert_eq!(Envelope::parse(bundle, 8).unwrap(), e);
    }

    #[test]
    fn refuses_what_is_not_a_signed_statement() {
        let cases: [&[u8]; 5] = [
            b"not json",
            br#"{"payloadType":"text/plain","payload":"e30=","signatures":[{"sig":"AQI="}]}"#,
            br#"{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}"#,
            br#"{"payloadType":"application/vnd.in-toto+json","payload":"*","signatures":[{"sig":"AQI="}]}"#,
            br#"{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":"*"}]}"#,
        ];
        for case in cases {
            assert!(Envelope::parse(case, 8).is_err());
        }
        let many = format!(
            r#"{{"payloadType":"{PAYLOAD_TYPE}","payload":"e30=","signatures":[{}]}}"#,
            [r#"{"sig":"AQI="}"#; 9].join(",")
        );
        let too_many = Err(Error::Envelope("more signatures than the gateway allows"));
        assert_eq!(Envelope::parse(many.as_bytes(), 8), too_many);
        assert!(Envelope::parse(many.as_bytes(), 9).is_ok());
        let bundle = format!(r#"{{"dsseEnvelope":{many}}}"#);
        assert_eq!(Envelope::parse(bundle.as_bytes(), 8), too_many);
        // Counted before any is decoded: nine undecodable signatures are
        // refused for their number, not their content.
        let junk = many.replace("AQI=", "*");
        assert_eq!(Envelope::parse(junk.as_bytes(), 8), too_many);
        let bare = br#"{"signatures":[{"sig":"AQI="}]}"#;
        assert!(Envelope::parse(bare, 8).is_err(), "no payload");
    }
}
