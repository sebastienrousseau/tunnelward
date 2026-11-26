// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! DSSE envelopes, bare or inside a Sigstore bundle.

use serde::Deserialize;
use tunnelward_audit::b64;

use crate::Error;

/// The payload type of an in-toto statement.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Most signatures an envelope may carry; each is tried against every key.
pub const MAX_SIGNATURES: usize = 8;

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

/// A Sigstore bundle: only its envelope is read.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bundle {
    dsse_envelope: Wire,
}

/// Either shape on the wire.
#[derive(Deserialize)]
#[serde(untagged)]
enum Shape {
    Bundle(Bundle),
    Envelope(Wire),
}

/// A decoded envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Envelope {
    /// The statement, as signed.
    pub(crate) payload: Vec<u8>,
    /// The signatures, decoded.
    pub(crate) signatures: Vec<Vec<u8>>,
}

impl Envelope {
    /// `bytes` read as a Sigstore bundle or a bare DSSE envelope.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let wire = match serde_json::from_slice(bytes) {
            Ok(Shape::Bundle(b)) => b.dsse_envelope,
            Ok(Shape::Envelope(e)) => e,
            Err(_) => {
                return Err(Error::Envelope(
                    "neither a DSSE envelope nor a Sigstore bundle",
                ));
            }
        };
        if wire.payload_type != PAYLOAD_TYPE {
            return Err(Error::Envelope(
                "the payload type is not an in-toto statement",
            ));
        }
        if wire.signatures.is_empty() {
            return Err(Error::Unsigned);
        }
        if wire.signatures.len() > MAX_SIGNATURES {
            return Err(Error::Envelope("more than 8 signatures"));
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
        let e = Envelope::parse(bare).unwrap();
        assert_eq!(
            (e.payload.as_slice(), e.signatures[0].as_slice()),
            (&b"{}"[..], &[1, 2][..])
        );
        let bundle = br#"{"mediaType":"x","dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":"AQI="}]}}"#;
        assert_eq!(Envelope::parse(bundle).unwrap(), e);
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
            assert!(Envelope::parse(case).is_err());
        }
        let many = format!(
            r#"{{"payloadType":"{PAYLOAD_TYPE}","payload":"e30=","signatures":[{}]}}"#,
            [r#"{"sig":"AQI="}"#; 9].join(",")
        );
        assert_eq!(
            Envelope::parse(many.as_bytes()),
            Err(Error::Envelope("more than 8 signatures"))
        );
    }
}
