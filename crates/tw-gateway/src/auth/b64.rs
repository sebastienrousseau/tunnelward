// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Unpadded base64url (RFC 4648 section 5), as JOSE uses it.

/// `text` decoded; `None` for a character outside the alphabet, padding,
/// an impossible length, or stray bits in the last character.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0_u32, 0_u32);
    for c in text.bytes() {
        acc = (acc << 6) | u32::from(value(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
}

/// `text` in standard base64 (`+`, `/`) with `=` padding to a multiple
/// of four, decoded; as RFC 9651 byte sequences use it.
pub(crate) fn decode_standard(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let body = text.trim_end_matches('=');
    if text.len() - body.len() > 2 {
        return None;
    }
    decode(&body.replace('+', "-").replace('/', "_")).filter(|_| !body.contains(['-', '_']))
}

/// `bytes` as unpadded base64url.
pub(crate) fn encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0_u32, |acc, &b| acc << 8 | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            let index = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
            out.push(char::from(ALPHABET[index]));
        }
    }
    out
}

fn value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors_without_padding() {
        for (text, bytes) in [
            ("", &b""[..]),
            ("Zg", b"f"),
            ("Zm8", b"fo"),
            ("Zm9v", b"foo"),
            ("Zm9vYg", b"foob"),
            ("Zm9vYmE", b"fooba"),
            ("Zm9vYmFy", b"foobar"),
        ] {
            assert_eq!(decode(text).as_deref(), Some(bytes), "{text}");
        }
        assert_eq!(decode("-_8").as_deref(), Some(&[0xfb, 0xff][..]));
    }

    #[test]
    fn standard_base64_with_padding() {
        assert_eq!(decode_standard("Zm9vYg==").as_deref(), Some(&b"foob"[..]));
        assert_eq!(decode_standard("+/8=").as_deref(), Some(&[0xfb, 0xff][..]));
        assert_eq!(decode_standard("Zm9vYg"), None, "unpadded");
        assert_eq!(decode_standard("-_8="), None, "url alphabet");
        assert_eq!(decode_standard("Z==="), None);
    }

    #[test]
    fn encoding_round_trips() {
        for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", &[0xfb, 0xff]] {
            assert_eq!(decode(&encode(bytes)).as_deref(), Some(bytes));
        }
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn padding_bad_lengths_and_stray_bits_are_refused() {
        assert_eq!(decode("Zg=="), None);
        assert_eq!(decode("Z"), None);
        assert_eq!(decode("Zh"), None, "stray bits");
        assert_eq!(decode("Zm9+"), None, "standard alphabet");
    }
}
