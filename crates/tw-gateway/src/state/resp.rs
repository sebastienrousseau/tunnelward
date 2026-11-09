// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The Redis serialization protocol (RESP2), as far as the shared store
//! needs it: commands out as arrays of bulk strings, and simple strings,
//! errors, integers and bulk strings back.

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

/// Largest bulk string read back: an idempotent answer plus a margin.
pub(crate) const MAX_BULK: usize = 4 * 1024 * 1024;

/// One reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reply {
    /// `+OK` and the like.
    Simple(String),
    /// `-ERR ...`: the server refused the command.
    Error(String),
    /// `:<n>`.
    Integer(i64),
    /// `$<len>`, or `None` for the null bulk string `$-1`.
    Bulk(Option<Vec<u8>>),
}

/// `parts` as a RESP command: an array of bulk strings.
pub(crate) fn command(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", parts.len()).into_bytes();
    for part in parts {
        out.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        out.extend_from_slice(part);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// One line without its CRLF, at most 512 bytes.
async fn line<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut limited = (&mut *reader).take(512);
    limited.read_until(b'\n', &mut buf).await?;
    let text = buf
        .strip_suffix(b"\r\n")
        .ok_or_else(|| invalid("a reply line without CRLF"))?;
    String::from_utf8(text.to_vec()).map_err(|_| invalid("a reply line that is not UTF-8"))
}

fn invalid(what: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_owned())
}

/// Reads one reply. Arrays and RESP3 types are refused: no command the
/// store sends returns one.
pub(crate) async fn read<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Reply> {
    let text = line(reader).await?;
    let (kind, rest) = text
        .split_at_checked(1)
        .ok_or_else(|| invalid("an empty reply"))?;
    match kind {
        "+" => Ok(Reply::Simple(rest.to_owned())),
        "-" => Ok(Reply::Error(rest.to_owned())),
        ":" => rest
            .parse()
            .map(Reply::Integer)
            .map_err(|_| invalid("an integer reply that does not parse")),
        "$" => bulk(reader, rest).await,
        _ => Err(invalid("a reply type the store does not use")),
    }
}

async fn bulk<R: AsyncBufRead + Unpin>(reader: &mut R, len: &str) -> std::io::Result<Reply> {
    if len == "-1" {
        return Ok(Reply::Bulk(None));
    }
    let len: usize = len
        .parse()
        .map_err(|_| invalid("a bulk length that does not parse"))?;
    if len > MAX_BULK {
        return Err(invalid("a bulk reply over the limit"));
    }
    let mut data = vec![0; len + 2];
    reader.read_exact(&mut data).await?;
    if data.split_off(len) != b"\r\n" {
        return Err(invalid("a bulk reply without CRLF"));
    }
    Ok(Reply::Bulk(Some(data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    type Res = Result<(), Box<dyn std::error::Error>>;

    async fn parse(bytes: &[u8]) -> std::io::Result<Reply> {
        read(&mut tokio::io::BufReader::new(bytes)).await
    }

    #[test]
    fn commands_are_arrays_of_bulk_strings() {
        assert_eq!(
            command(&[b"SET", b"k", b"v"]),
            b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n".to_vec()
        );
        assert_eq!(command(&[b""]), b"*1\r\n$0\r\n\r\n".to_vec());
    }

    #[tokio::test]
    async fn each_reply_type_reads_back() -> Res {
        assert_eq!(parse(b"+OK\r\n").await?, Reply::Simple("OK".into()));
        assert_eq!(parse(b"-ERR no\r\n").await?, Reply::Error("ERR no".into()));
        assert_eq!(parse(b":42\r\n").await?, Reply::Integer(42));
        assert_eq!(parse(b"$-1\r\n").await?, Reply::Bulk(None));
        assert_eq!(
            parse(b"$2\r\nhi\r\n").await?,
            Reply::Bulk(Some(b"hi".to_vec()))
        );
        assert_eq!(
            parse(b"$4\r\na\r\nb\r\n").await?,
            Reply::Bulk(Some(b"a\r\nb".to_vec()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn malformed_replies_are_errors() {
        for bad in [
            &b"OK\r\n"[..],
            b"+OK\n",
            b":x\r\n",
            b"$5\r\nhi\r\n",
            b"$2\r\nhiXX",
            b"*1\r\n:1\r\n",
            b"$99999999\r\n",
            b"",
        ] {
            assert!(parse(bad).await.is_err(), "{bad:?}");
        }
    }
}
