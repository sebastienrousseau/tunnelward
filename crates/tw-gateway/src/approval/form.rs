// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! What the approval page reads and writes as text: query strings and
//! form bodies (`application/x-www-form-urlencoded`), and HTML.

use std::fmt::Write as _;

/// `text` percent-encoded, every byte but the unreserved ones (RFC 3986).
pub(super) fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `text` decoded from a form: `+` is a space, `%XX` a byte. `None` for a
/// broken escape or bytes that are not UTF-8.
pub(super) fn decode(text: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some((&b, tail)) = rest.split_first() {
        rest = tail;
        match b {
            b'+' => bytes.push(b' '),
            b'%' => {
                let hex = std::str::from_utf8(rest.get(..2)?).ok()?;
                bytes.push(u8::from_str_radix(hex, 16).ok()?);
                rest = &rest[2..];
            }
            _ => bytes.push(b),
        }
    }
    String::from_utf8(bytes).ok()
}

/// The value of `name` in the form or query `text`, decoded.
pub(super) fn field(text: &str, name: &str) -> Option<String> {
    text.split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .and_then(|(_, value)| decode(value))
}

/// `text` safe inside HTML text and quoted attributes.
pub(super) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_survive_encoding_and_forms_decode() {
        let value = "https://gw.example/cb?a=1&b=é ü";
        let encoded = encode(value);
        let unreserved = |b: u8| b.is_ascii_alphanumeric() || b"-._~%".contains(&b);
        assert!(encoded.bytes().all(unreserved), "{encoded}");
        let query = format!("x=1&redirect_uri={encoded}&y");
        assert_eq!(field(&query, "redirect_uri").as_deref(), Some(value));
        assert_eq!(field("a=b+c%21", "a").as_deref(), Some("b c!"));
        assert_eq!(field("a=%zz", "a"), None);
        assert_eq!(field("a=%e", "a"), None);
        assert_eq!(field("a=1", "b"), None);
    }

    #[test]
    fn html_is_escaped() {
        assert_eq!(
            escape(r#"<script>"x" & 'y'</script>"#),
            "&lt;script&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/script&gt;"
        );
    }
}
