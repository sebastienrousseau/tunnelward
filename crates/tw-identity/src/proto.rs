// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The little protobuf the Workload API's X.509 messages need: fields as
//! number and value, length-delimited values kept as bytes, the other
//! wire types read and skipped.

/// One field's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    /// A 32- or 64-bit fixed value, unused here.
    Fixed,
}

/// The fields of the message `buf`, in order; `None` if it does not parse.
pub(crate) fn fields(mut buf: &[u8]) -> Option<Vec<(u64, Value<'_>)>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let (key, rest) = varint(buf)?;
        let (value, rest) = value(key & 7, rest)?;
        let number = key >> 3;
        if number == 0 {
            return None;
        }
        out.push((number, value));
        buf = rest;
    }
    Some(out)
}

fn value(wire: u64, buf: &[u8]) -> Option<(Value<'_>, &[u8])> {
    match wire {
        0 => varint(buf).map(|(v, rest)| (Value::Varint(v), rest)),
        1 => Some((Value::Fixed, buf.get(8..)?)),
        2 => delimited(buf),
        5 => Some((Value::Fixed, buf.get(4..)?)),
        _ => None,
    }
}

/// A length-delimited value: its length, then that many bytes.
fn delimited(buf: &[u8]) -> Option<(Value<'_>, &[u8])> {
    let (len, rest) = varint(buf)?;
    let len = usize::try_from(len).ok()?;
    (rest.len() >= len).then(|| (Value::Bytes(&rest[..len]), &rest[len..]))
}

/// A base-128 varint and what follows it; at most ten bytes.
fn varint(buf: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0_u64;
    for (i, &b) in buf.iter().enumerate().take(10) {
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, &buf[i + 1..]));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_of_each_wire_type_are_read() {
        // 1: varint 150; 2: bytes "hi"; 3: fixed64; 4: fixed32.
        let msg = [
            0x08, 0x96, 0x01, 0x12, 2, b'h', b'i', 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0x25, 0, 0, 0, 0,
        ];
        let f = fields(&msg).unwrap_or_default();
        assert_eq!(
            f,
            [
                (1, Value::Varint(150)),
                (2, Value::Bytes(b"hi")),
                (3, Value::Fixed),
                (4, Value::Fixed)
            ]
        );
    }

    #[test]
    fn truncated_and_invalid_messages_do_not_parse() {
        assert_eq!(fields(&[0x12, 5, b'h']), None, "short bytes");
        assert_eq!(fields(&[0x08, 0x80]), None, "unfinished varint");
        assert_eq!(fields(&[0x0b]), None, "group wire type");
        assert_eq!(fields(&[0x02, 0]), None, "field 0");
        assert_eq!(
            fields(&[0x08; 11].map(|_| 0xff)),
            None,
            "varint over ten bytes"
        );
    }
}
