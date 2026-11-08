// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! PROXY protocol v1 and v2 (G12): the client address a load balancer in
//! front of the gateway puts at the start of each connection.
//!
//! [`parse`] works on a buffer and says when it needs more bytes, like the
//! frame codec; [`read`] reads exactly the header from a stream and nothing
//! after it. The ingress applies it only to connections from trusted
//! proxies: from anyone else a PROXY header would be a free spoof.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
/// v1 headers are at most 107 bytes, CRLF included.
const V1_MAX: usize = 107;
/// The largest v2 address-and-TLV block accepted.
const V2_MAX_LEN: usize = 512;

/// What a complete header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Header {
    /// The client's address.
    Proxied(SocketAddr),
    /// A health check or unknown family: use the socket's own peer address.
    Local,
}

/// The result of [`parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    /// A whole header, and its length in bytes.
    Complete(Header, usize),
    /// At least this many more bytes are needed.
    NeedMore(usize),
}

/// Bytes that are not a PROXY protocol header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyError(&'static str);

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PROXY protocol: {}", self.0)
    }
}

impl std::error::Error for ProxyError {}

/// Parses a PROXY v1 or v2 header at the start of `buf`.
///
/// # Errors
///
/// [`ProxyError`] when `buf` does not start with a valid header.
pub fn parse(buf: &[u8]) -> Result<Parsed, ProxyError> {
    match buf.first() {
        None => Ok(Parsed::NeedMore(1)),
        Some(b'\r') => parse_v2(buf),
        Some(b'P') => parse_v1(buf),
        Some(_) => Err(ProxyError("no header")),
    }
}

fn parse_v2(buf: &[u8]) -> Result<Parsed, ProxyError> {
    let Some(fixed) = buf.get(..16) else {
        let seen = &buf[..buf.len().min(12)];
        if !V2_SIGNATURE.starts_with(seen) {
            return Err(ProxyError("bad v2 signature"));
        }
        return Ok(Parsed::NeedMore(16 - buf.len()));
    };
    if &fixed[..12] != V2_SIGNATURE {
        return Err(ProxyError("bad v2 signature"));
    }
    let (ver_cmd, family) = (fixed[12], fixed[13]);
    let len = usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    if ver_cmd >> 4 != 2 || len > V2_MAX_LEN {
        return Err(ProxyError("bad v2 version or length"));
    }
    let Some(body) = buf.get(16..16 + len) else {
        return Ok(Parsed::NeedMore(16 + len - buf.len()));
    };
    let header = match ver_cmd & 0x0f {
        0 => Header::Local,
        1 => v2_address(family, body)?,
        _ => return Err(ProxyError("bad v2 command")),
    };
    Ok(Parsed::Complete(header, 16 + len))
}

fn v2_address(family: u8, body: &[u8]) -> Result<Header, ProxyError> {
    let short = ProxyError("v2 address block too short");
    match family {
        0x11 => {
            let b = body.get(..12).ok_or(short)?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Ok(Header::Proxied(SocketAddr::new(
                IpAddr::V4(ip),
                u16::from_be_bytes([b[8], b[9]]),
            )))
        }
        0x21 => {
            let b = body.get(..36).ok_or(short)?;
            let mut octets = [0; 16];
            octets.copy_from_slice(&b[..16]);
            let ip = Ipv6Addr::from(octets);
            Ok(Header::Proxied(SocketAddr::new(
                IpAddr::V6(ip),
                u16::from_be_bytes([b[32], b[33]]),
            )))
        }
        // UNSPEC, UDP and Unix sockets carry no usable client address.
        _ => Ok(Header::Local),
    }
}

fn parse_v1(buf: &[u8]) -> Result<Parsed, ProxyError> {
    let window = &buf[..buf.len().min(V1_MAX)];
    let Some(end) = window.windows(2).position(|w| w == b"\r\n") else {
        if buf.len() >= V1_MAX {
            return Err(ProxyError("v1 header too long"));
        }
        if !(b"PROXY ".starts_with(window) || window.starts_with(b"PROXY ")) {
            return Err(ProxyError("bad v1 header"));
        }
        return Ok(Parsed::NeedMore(1));
    };
    let line =
        std::str::from_utf8(&buf[..end]).map_err(|_| ProxyError("v1 header is not ASCII"))?;
    Ok(Parsed::Complete(v1_line(line)?, end + 2))
}

fn v1_line(line: &str) -> Result<Header, ProxyError> {
    let fields: Vec<&str> = line.split(' ').collect();
    match fields.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Ok(Header::Local),
        ["PROXY", proto @ ("TCP4" | "TCP6"), src, dst, port, dst_port] => {
            v1_tcp(proto, src, dst, port, dst_port)
        }
        _ => Err(ProxyError("bad v1 header")),
    }
}

fn v1_tcp(
    proto: &str,
    src: &str,
    dst: &str,
    port: &str,
    dst_port: &str,
) -> Result<Header, ProxyError> {
    let src: IpAddr = field(src)?;
    let _dst: IpAddr = field(dst)?;
    let port: u16 = field(port)?;
    let _dst_port: u16 = field(dst_port)?;
    if (proto == "TCP4") != src.is_ipv4() {
        return Err(ProxyError("v1 address family does not match"));
    }
    Ok(Header::Proxied(SocketAddr::new(src, port)))
}

fn field<T: core::str::FromStr>(text: &str) -> Result<T, ProxyError> {
    text.parse().map_err(|_| ProxyError("bad v1 field"))
}

/// Reads one header from `r`, and not one byte more.
///
/// # Errors
///
/// [`ProxyError`] when the bytes are not a header or the stream ends first.
pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<Header, ProxyError> {
    let mut buf = Vec::new();
    loop {
        match parse(&buf)? {
            Parsed::Complete(header, _) => return Ok(header),
            Parsed::NeedMore(n) => {
                let have = buf.len();
                buf.resize(have + n, 0);
                r.read_exact(&mut buf[have..])
                    .await
                    .map_err(|_| ProxyError("stream ended in the header"))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2(cmd: u8, family: u8, body: &[u8]) -> Vec<u8> {
        let mut out = V2_SIGNATURE.to_vec();
        out.extend_from_slice(&[0x20 | cmd, family]);
        out.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    #[test]
    fn v1_tcp4_tcp6_and_unknown() {
        let line = b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 443\r\nGET";
        assert_eq!(
            parse(line),
            Ok(Parsed::Complete(
                Header::Proxied(addr("203.0.113.7:51234")),
                43
            ))
        );
        let six = b"PROXY TCP6 2001:db8::7 2001:db8::1 1 2\r\n";
        assert_eq!(
            parse(six),
            Ok(Parsed::Complete(
                Header::Proxied(addr("[2001:db8::7]:1")),
                six.len()
            ))
        );
        assert_eq!(
            parse(b"PROXY UNKNOWN\r\n"),
            Ok(Parsed::Complete(Header::Local, 15))
        );
    }

    #[test]
    fn v1_rejects_malformed_lines() {
        for bad in [
            &b"PROXY TCP4 1.2.3.4 5.6.7.8 1\r\n"[..],
            b"PROXY TCP4 2001:db8::1 5.6.7.8 1 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2 3\r\n",
            b"PROXY UDP4 1.2.3.4 5.6.7.8 1 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 99999 2\r\n",
            b"PROXX TCP4\r\n",
            b"GET / HTTP/1.1\r\n",
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert!(parse(&[b'P'; 200]).is_err(), "too long without CRLF");
    }

    #[test]
    fn v2_ipv4_ipv6_local_and_tlvs() {
        let mut b4 = vec![203, 0, 113, 7, 10, 0, 0, 1];
        b4.extend_from_slice(&51234_u16.to_be_bytes());
        b4.extend_from_slice(&443_u16.to_be_bytes());
        b4.extend_from_slice(&[0x01, 0x00, 0x02, b'h', b'2']); // an ALPN TLV, ignored
        let h = v2(1, 0x11, &b4);
        assert_eq!(
            parse(&h),
            Ok(Parsed::Complete(
                Header::Proxied(addr("203.0.113.7:51234")),
                h.len()
            ))
        );

        let mut b6 = [0_u8; 36];
        b6[..16].copy_from_slice(
            &"2001:db8::7"
                .parse::<Ipv6Addr>()
                .map(|i| i.octets())
                .unwrap_or_default(),
        );
        b6[32..34].copy_from_slice(&8080_u16.to_be_bytes());
        let h = v2(1, 0x21, &b6);
        assert_eq!(
            parse(&h),
            Ok(Parsed::Complete(
                Header::Proxied(addr("[2001:db8::7]:8080")),
                h.len()
            ))
        );

        assert_eq!(
            parse(&v2(0, 0x11, &b4)),
            Ok(Parsed::Complete(Header::Local, 16 + b4.len()))
        );
    }

    #[test]
    fn v2_rejects_bad_signatures_versions_lengths_and_short_blocks() {
        let mut bad_sig = v2(1, 0x11, &[0; 12]);
        bad_sig[5] = b'x';
        assert!(parse(&bad_sig).is_err());
        let mut v1_marked = v2(1, 0x11, &[0; 12]);
        v1_marked[12] = 0x11;
        assert!(parse(&v1_marked).is_err());
        assert!(
            parse(&v2(1, 0x11, &[0; 4])).is_err(),
            "IPv4 block too short"
        );
        let mut huge = V2_SIGNATURE.to_vec();
        huge.extend_from_slice(&[0x21, 0x11, 0xff, 0xff]);
        assert!(
            parse(&huge).is_err(),
            "length over the limit fails before reading it"
        );
    }

    #[test]
    fn partial_input_asks_for_more() {
        let h = v2(1, 0x11, &[0; 12]);
        for cut in 1..h.len() {
            assert!(
                matches!(parse(&h[..cut]), Ok(Parsed::NeedMore(_))),
                "cut at {cut}"
            );
        }
        assert!(matches!(parse(b"PROXY TCP4 1.2"), Ok(Parsed::NeedMore(1))));
    }

    #[tokio::test]
    async fn read_stops_exactly_at_the_end_of_the_header() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut data: &[u8] = b"PROXY TCP4 203.0.113.7 10.0.0.1 1 2\r\nGET / HTTP/1.1\r\n";
        assert_eq!(
            read(&mut data).await?,
            Header::Proxied(addr("203.0.113.7:1"))
        );
        assert_eq!(data, b"GET / HTTP/1.1\r\n");
        Ok(())
    }
}
