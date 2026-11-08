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
    fn padding_bad_lengths_and_stray_bits_are_refused() {
        assert_eq!(decode("Zg=="), None);
        assert_eq!(decode("Z"), None);
        assert_eq!(decode("Zh"), None, "stray bits");
        assert_eq!(decode("Zm9+"), None, "standard alphabet");
    }
}
