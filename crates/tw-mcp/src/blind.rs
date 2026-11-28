// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gateway-blind mode on the wire (ADR 0016, experimental). A
//! `tools/call` keeps its method, tool name and id in the clear, so the
//! gateway can route it and its policy can decide it, while its
//! arguments travel sealed to the connector:
//!
//! ```json
//! {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer",
//!  "arguments":{"tw_blind":{"v":1,"enc":"<base64url>","ct":"<base64url>"}}}}
//! ```
//!
//! The answer comes back with its `result` (or `error`) sealed:
//! `{"jsonrpc":"2.0","id":1,"result":{"tw_blind":{"v":1,"ct":"<base64url>"}}}`.
//! The AAD is `tools/call`, a zero byte, and the tool name, so a changed
//! name does not open.

use serde_json::{Map, Value, json};
use tunnelward_crypto::blind::{self, ResponseKey};
use tunnelward_crypto::hpke::HpkeError;
use tunnelward_crypto::xwing::PrivateKeyXWing;

/// The field a sealed value sits in.
pub const FIELD: &str = "tw_blind";
/// The wire version this module writes and reads.
pub const VERSION: u64 = 1;

/// Why a body could not be sealed or opened.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlindError {
    /// Not one JSON-RPC `tools/call` (batches are not sealed).
    NotACall,
    /// Not one JSON-RPC answer with an id and a result or an error.
    NotAnAnswer,
    /// A sealed value with the wrong version or fields.
    Malformed(&'static str),
    /// It did not open: another key, a changed tool name or ciphertext.
    Crypto(HpkeError),
}

impl core::fmt::Display for BlindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotACall => f.write_str("gateway-blind mode seals one tools/call at a time"),
            Self::NotAnAnswer => f.write_str("not a JSON-RPC answer"),
            Self::Malformed(what) => write!(f, "sealed value: {what}"),
            Self::Crypto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BlindError {}

impl From<HpkeError> for BlindError {
    fn from(e: HpkeError) -> Self {
        Self::Crypto(e)
    }
}

fn aad(tool: &str) -> Vec<u8> {
    [b"tools/call\0".as_slice(), tool.as_bytes()].concat()
}

/// The tool name and the params of a single `tools/call`.
fn call(message: &mut Value) -> Option<(String, &mut Map<String, Value>)> {
    let object = message.as_object_mut()?;
    if object.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let params = object.get_mut("params")?.as_object_mut()?;
    let tool = params.get("name")?.as_str()?.to_owned();
    Some((tool, params))
}

/// Agent side: seals a `tools/call`'s arguments to the connector key
/// `public`. Returns the body to send and the key that opens its answer.
///
/// # Errors
///
/// [`BlindError::NotACall`] for anything but one `tools/call`;
/// [`BlindError::Crypto`] for a key X-Wing refuses.
pub fn seal_call(body: &[u8], public: &[u8]) -> Result<(Vec<u8>, ResponseKey), BlindError> {
    let mut message: Value = serde_json::from_slice(body).map_err(|_| BlindError::NotACall)?;
    let (tool, params) = call(&mut message).ok_or(BlindError::NotACall)?;
    let arguments = params.remove("arguments").unwrap_or_else(|| json!({}));
    let plaintext = serde_json::to_vec(&arguments).map_err(|_| BlindError::NotACall)?;
    let sealed = blind::seal(public, &aad(&tool), &plaintext)?;
    params.insert(
        "arguments".into(),
        json!({ FIELD: { "v": VERSION, "enc": b64::encode(&sealed.enc), "ct": b64::encode(&sealed.ciphertext) } }),
    );
    Ok((message.to_string().into_bytes(), sealed.response))
}

/// The `tw_blind` object inside `value`, checked for the version.
fn sealed(value: &Value) -> Option<Result<&Map<String, Value>, BlindError>> {
    let inner = value.get(FIELD)?;
    Some(match inner.as_object() {
        Some(o) if o.get("v").and_then(Value::as_u64) == Some(VERSION) => Ok(o),
        _ => Err(BlindError::Malformed("unknown version")),
    })
}

fn field(object: &Map<String, Value>, name: &'static str) -> Result<Vec<u8>, BlindError> {
    let text = object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(BlindError::Malformed(name))?;
    b64::decode(text).ok_or(BlindError::Malformed(name))
}

/// Connector side: opens a sealed call with the connector's `key`.
/// `Ok(None)` when the body is not a sealed call: it goes on unchanged.
///
/// # Errors
///
/// [`BlindError::Malformed`] or [`BlindError::Crypto`] for a sealed
/// call that does not open; the connector answers it itself.
pub fn open_call(
    body: &[u8],
    key: &PrivateKeyXWing,
) -> Result<Option<(Vec<u8>, ResponseKey)>, BlindError> {
    let Ok(mut message) = serde_json::from_slice::<Value>(body) else {
        return Ok(None);
    };
    let Some((tool, params)) = call(&mut message) else {
        return Ok(None);
    };
    let Some(sealed) = params.get("arguments").and_then(sealed) else {
        return Ok(None);
    };
    let sealed = sealed?;
    let (enc, ct) = (field(sealed, "enc")?, field(sealed, "ct")?);
    let (plaintext, response) = blind::open(key, &aad(&tool), &enc, &ct)?;
    let arguments: Value =
        serde_json::from_slice(&plaintext).map_err(|_| BlindError::Malformed("arguments"))?;
    params.insert("arguments".into(), arguments);
    Ok(Some((message.to_string().into_bytes(), response)))
}

/// Connector side: seals a JSON-RPC answer's `result` or `error`.
///
/// # Errors
///
/// [`BlindError::NotAnAnswer`] for anything else.
pub fn seal_answer(body: &[u8], key: &ResponseKey) -> Result<Vec<u8>, BlindError> {
    let answer: Value = serde_json::from_slice(body).map_err(|_| BlindError::NotAnAnswer)?;
    let object = answer.as_object().ok_or(BlindError::NotAnAnswer)?;
    let id = object.get("id").cloned().ok_or(BlindError::NotAnAnswer)?;
    let inner: Map<String, Value> = ["result", "error"]
        .iter()
        .filter_map(|k| object.get(*k).map(|v| ((*k).to_owned(), v.clone())))
        .collect();
    if inner.len() != 1 {
        return Err(BlindError::NotAnAnswer);
    }
    let plaintext = Value::Object(inner).to_string();
    let ct = key.seal(plaintext.as_bytes())?;
    let sealed = json!({ "jsonrpc": "2.0", "id": id, "result": { FIELD: { "v": VERSION, "ct": b64::encode(&ct) } } });
    Ok(sealed.to_string().into_bytes())
}

/// Agent side: opens a sealed answer with the call's `key`, giving the
/// answer as the server wrote it.
///
/// # Errors
///
/// [`BlindError::NotAnAnswer`], [`BlindError::Malformed`] or
/// [`BlindError::Crypto`].
pub fn open_answer(body: &[u8], key: &ResponseKey) -> Result<Vec<u8>, BlindError> {
    let answer: Value = serde_json::from_slice(body).map_err(|_| BlindError::NotAnAnswer)?;
    let id = answer.get("id").cloned().ok_or(BlindError::NotAnAnswer)?;
    let plaintext = key.open(&sealed_answer(&answer)?)?;
    let inner: Map<String, Value> =
        serde_json::from_slice(&plaintext).map_err(|_| BlindError::Malformed("answer"))?;
    let mut out = Map::new();
    out.insert("jsonrpc".into(), json!("2.0"));
    out.insert("id".into(), id);
    out.extend(inner);
    Ok(Value::Object(out).to_string().into_bytes())
}

/// The ciphertext in an answer's `result.tw_blind`.
fn sealed_answer(answer: &Value) -> Result<Vec<u8>, BlindError> {
    let result = answer.get("result").ok_or(BlindError::NotAnAnswer)?;
    let sealed = sealed(result).ok_or(BlindError::Malformed("not sealed"))??;
    field(sealed, "ct")
}

/// Unpadded base64url (RFC 4648 section 5).
mod b64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    pub(super) fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
            for i in 0..=chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
            }
        }
        out
    }

    pub(super) fn decode(text: &str) -> Option<Vec<u8>> {
        if text.len() % 4 == 1 {
            return None;
        }
        let mut out = Vec::with_capacity(text.len() * 3 / 4);
        for chunk in text.as_bytes().chunks(4) {
            let mut n = 0u32;
            for (i, c) in chunk.iter().enumerate() {
                let v = ALPHABET.iter().position(|a| a == c)?;
                n |= u32::try_from(v).ok()? << (18 - 6 * i);
            }
            let bytes = n.to_be_bytes();
            out.extend_from_slice(&bytes[1..chunk.len()]);
        }
        Some(out)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn rfc_4648_vectors_without_padding() {
            for (plain, encoded) in [
                ("", ""),
                ("f", "Zg"),
                ("fo", "Zm8"),
                ("foo", "Zm9v"),
                ("foob", "Zm9vYg"),
                ("fooba", "Zm9vYmE"),
                ("foobar", "Zm9vYmFy"),
            ] {
                assert_eq!(super::encode(plain.as_bytes()), encoded);
                assert_eq!(super::decode(encoded).unwrap(), plain.as_bytes());
            }
            assert_eq!(super::encode(&[0xfb, 0xff]), "-_8", "url alphabet");
            assert!(super::decode("Zm9v!").is_none());
            assert!(super::decode("Z").is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connector() -> PrivateKeyXWing {
        PrivateKeyXWing::generate().unwrap()
    }

    #[test]
    fn a_call_and_its_answer_cross_the_gateway_sealed() {
        let key = connector();
        let call = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"transfer","arguments":{"to":"alice","amount":5},"_meta":{"x":1}}}"#;
        let (sent, response_key) = seal_call(call, key.public_key()).unwrap();
        let on_the_wire: Value = serde_json::from_slice(&sent).unwrap();
        assert_eq!(
            on_the_wire["params"]["name"], "transfer",
            "the gateway sees the tool"
        );
        assert_eq!(on_the_wire["params"]["_meta"]["x"], 1);
        assert!(
            !String::from_utf8_lossy(&sent).contains("alice"),
            "but not the arguments"
        );

        let (opened, connector_key) = open_call(&sent, &key).unwrap().unwrap();
        let opened: Value = serde_json::from_slice(&opened).unwrap();
        assert_eq!(
            opened["params"]["arguments"],
            json!({"to":"alice","amount":5})
        );

        let answer = br#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"sent 5 to alice"}]}}"#;
        let sealed = seal_answer(answer, &connector_key).unwrap();
        assert!(!String::from_utf8_lossy(&sealed).contains("alice"));
        let back: Value =
            serde_json::from_slice(&open_answer(&sealed, &response_key).unwrap()).unwrap();
        assert_eq!(back, serde_json::from_slice::<Value>(answer).unwrap());
    }

    #[test]
    fn a_renamed_tool_or_a_plain_call_is_handled_safely() {
        let key = connector();
        let call = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer","arguments":{}}}"#;
        let (sent, _) = seal_call(call, key.public_key()).unwrap();
        let renamed = String::from_utf8(sent)
            .unwrap()
            .replace("\"transfer\"", "\"read_balance\"");
        assert_eq!(
            open_call(renamed.as_bytes(), &key).unwrap_err(),
            BlindError::Crypto(HpkeError::Open)
        );
        let plain = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"a":1}}}"#;
        assert!(
            open_call(plain, &key).unwrap().is_none(),
            "an unsealed call passes through"
        );
        assert!(open_call(b"not json", &key).unwrap().is_none());
        let batch = br#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}]"#;
        assert_eq!(
            seal_call(batch, key.public_key()).unwrap_err(),
            BlindError::NotACall
        );
        let v2 = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"tw_blind":{"v":2}}}}"#;
        assert_eq!(
            open_call(v2, &key).unwrap_err(),
            BlindError::Malformed("unknown version")
        );
    }

    #[test]
    fn an_error_answer_is_sealed_too() {
        let key = connector();
        let call = br#"{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"x"}}"#;
        let (sent, response_key) = seal_call(call, key.public_key()).unwrap();
        let (_, connector_key) = open_call(&sent, &key).unwrap().unwrap();
        let error = br#"{"jsonrpc":"2.0","id":"a","error":{"code":-32000,"message":"account 42 is closed"}}"#;
        let sealed = seal_answer(error, &connector_key).unwrap();
        assert!(!String::from_utf8_lossy(&sealed).contains("account 42"));
        let back: Value =
            serde_json::from_slice(&open_answer(&sealed, &response_key).unwrap()).unwrap();
        assert_eq!(back["error"]["message"], "account 42 is closed");
    }
}
