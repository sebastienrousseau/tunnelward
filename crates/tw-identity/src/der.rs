// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The little DER an X.509 certificate's alternative names need: one
//! tag-length-value at a time, definite lengths only, low tag numbers
//! only. Anything else is `None`.

/// One TLV off the front of `input`: its tag, its content, and the rest.
pub(crate) fn next(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (len, rest) = length(rest)?;
    if rest.len() < len {
        return None;
    }
    let (content, rest) = rest.split_at(len);
    Some((tag, content, rest))
}

/// A length and what follows it. The indefinite form (BER) and lengths
/// over four bytes are refused.
fn length(input: &[u8]) -> Option<(usize, &[u8])> {
    let (&first, rest) = input.split_first()?;
    if first < 0x80 {
        return Some((usize::from(first), rest));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 || rest.len() < count {
        return None;
    }
    let (bytes, rest) = rest.split_at(count);
    let len = bytes
        .iter()
        .fold(0_usize, |acc, &b| acc << 8 | usize::from(b));
    Some((len, rest))
}

/// The content of `input` when it is exactly one TLV tagged `tag`.
pub(crate) fn whole(input: &[u8], tag: u8) -> Option<&[u8]> {
    let (found, content, rest) = next(input)?;
    (found == tag && rest.is_empty()).then_some(content)
}

/// The TLVs that make up `content`, in order, as tag and content.
pub(crate) fn items(mut content: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (tag, value, rest) = next(content)?;
        out.push((tag, value));
        content = rest;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_short_long_and_refused() {
        assert_eq!(
            next(&[0x04, 0x01, 0xaa]),
            Some((0x04, &[0xaa][..], &[][..]))
        );
        let long = [&[0x04, 0x81, 0x80][..], &[0; 0x80]].concat();
        assert_eq!(next(&long).map(|(_, c, _)| c.len()), Some(0x80));
        assert_eq!(next(&[0x30, 0x80, 0x00, 0x00]), None, "indefinite");
        assert_eq!(
            next(&[0x04, 0x85, 1, 0, 0, 0, 0]),
            None,
            "five length bytes"
        );
        assert_eq!(next(&[0x1f, 0x01, 0x00]), None, "high tag number");
        assert_eq!(next(&[0x04, 0x02, 0xaa]), None, "short content");
    }

    #[test]
    fn whole_wants_one_tlv_of_the_tag() {
        assert_eq!(whole(&[0x30, 0x00], 0x30), Some(&[][..]));
        assert_eq!(whole(&[0x30, 0x00], 0x31), None);
        assert_eq!(whole(&[0x30, 0x00, 0x00], 0x30), None);
    }
}
