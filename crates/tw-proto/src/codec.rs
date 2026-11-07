// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Length-prefixed CBOR framing.
//!
//! A frame on the wire is a 4-byte big-endian body length followed by the
//! body, one CBOR value. The length is checked against the limit before
//! any of the body is read, so a peer cannot make the reader buffer more
//! than [`Limits::max_frame_len`] bytes.

use core::fmt;

use crate::code::RejectCode;
use crate::frame::Frame;
use crate::limits::{LENGTH_PREFIX_LEN, Limits};
use crate::validate::{Invalid, validate};

/// The result of [`decode`] on a buffer that may hold a partial frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// A whole frame, and how many bytes of the buffer it used.
    Frame {
        /// The frame.
        frame: Frame,
        /// Bytes of the buffer the frame used, prefix included.
        consumed: usize,
    },
    /// The buffer ends mid-frame; at least this many more bytes are needed.
    NeedMore(usize),
}

/// Why bytes could not be decoded as a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The length prefix is zero.
    Empty,
    /// The length prefix is over the limit. Nothing past it was read.
    TooLarge {
        /// The declared body length.
        len: u32,
        /// The limit.
        max: u32,
    },
    /// The body is not a frame in CBOR.
    Cbor(String),
    /// The body holds bytes after the CBOR value.
    TrailingBytes(usize),
    /// The frame parsed but breaks a protocol rule.
    Invalid(Invalid),
}

impl DecodeError {
    /// The code a gateway sends back for this error.
    #[must_use]
    pub fn reject_code(&self) -> RejectCode {
        match self {
            Self::Invalid(i) => i.code,
            _ => RejectCode::Malformed,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty frame"),
            Self::TooLarge { len, max } => {
                write!(f, "frame of {len} bytes is over the {max}-byte limit")
            }
            Self::Cbor(e) => write!(f, "frame is not valid CBOR: {e}"),
            Self::TrailingBytes(n) => write!(f, "{n} bytes after the frame body"),
            Self::Invalid(i) => i.fmt(f),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Why a frame could not be encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// The encoded body is over the limit.
    TooLarge {
        /// The body length.
        len: usize,
        /// The limit.
        max: u32,
    },
    /// The frame breaks a protocol rule; it is never sent.
    Invalid(Invalid),
    /// The CBOR serializer failed.
    Cbor(String),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { len, max } => {
                write!(f, "frame of {len} bytes is over the {max}-byte limit")
            }
            Self::Invalid(i) => i.fmt(f),
            Self::Cbor(e) => write!(f, "cannot encode frame: {e}"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Encodes `frame`, length prefix included, after checking it is valid.
///
/// # Errors
///
/// [`EncodeError::Invalid`] for a frame that breaks a rule, and
/// [`EncodeError::TooLarge`] for one over `limits.max_frame_len`.
pub fn encode(frame: &Frame, limits: &Limits) -> Result<Vec<u8>, EncodeError> {
    validate(frame, limits).map_err(EncodeError::Invalid)?;
    let mut out = cbor4ii::serde::to_vec(vec![0; LENGTH_PREFIX_LEN], frame)
        .map_err(|e| EncodeError::Cbor(e.to_string()))?;
    let len = out.len() - LENGTH_PREFIX_LEN;
    let prefix = u32::try_from(len)
        .ok()
        .filter(|n| *n <= limits.max_frame_len)
        .ok_or(EncodeError::TooLarge {
            len,
            max: limits.max_frame_len,
        })?;
    out[..LENGTH_PREFIX_LEN].copy_from_slice(&prefix.to_be_bytes());
    Ok(out)
}

/// Decodes one frame from the start of `buf`.
///
/// Returns [`Decoded::NeedMore`] when `buf` ends before the frame does;
/// call again with more bytes. A declared length over
/// `limits.max_frame_len` fails as soon as the prefix is read.
///
/// # Errors
///
/// A [`DecodeError`]; [`DecodeError::reject_code`] gives the code to
/// answer with.
pub fn decode(buf: &[u8], limits: &Limits) -> Result<Decoded, DecodeError> {
    let Some(prefix) = buf.first_chunk::<LENGTH_PREFIX_LEN>() else {
        return Ok(Decoded::NeedMore(LENGTH_PREFIX_LEN - buf.len()));
    };
    let len = body_len(u32::from_be_bytes(*prefix), limits.max_frame_len)?;
    let Some(body) = buf.get(LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + len) else {
        return Ok(Decoded::NeedMore(LENGTH_PREFIX_LEN + len - buf.len()));
    };
    let frame = parse_body(body)?;
    validate(&frame, limits).map_err(DecodeError::Invalid)?;
    Ok(Decoded::Frame {
        frame,
        consumed: LENGTH_PREFIX_LEN + len,
    })
}

fn body_len(len: u32, max: u32) -> Result<usize, DecodeError> {
    match len {
        0 => Err(DecodeError::Empty),
        n if n > max => Err(DecodeError::TooLarge { len: n, max }),
        // A u32 always fits in usize on the 32- and 64-bit targets built.
        n => usize::try_from(n).map_err(|_| DecodeError::TooLarge { len: n, max }),
    }
}

/// Parses one CBOR value from `body` and requires that it fills `body`.
/// cbor4ii's reader stops nesting at 256 levels and caps any
/// preallocation, so a hostile length inside the body cannot allocate
/// more than the body's own size.
fn parse_body(body: &[u8]) -> Result<Frame, DecodeError> {
    let mut rest = body;
    let frame: Frame =
        cbor4ii::serde::from_reader(&mut rest).map_err(|e| DecodeError::Cbor(e.to_string()))?;
    if rest.is_empty() {
        Ok(frame)
    } else {
        Err(DecodeError::TrailingBytes(rest.len()))
    }
}
