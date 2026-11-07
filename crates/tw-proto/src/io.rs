// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading and writing frames on tokio streams (feature `io`).
//!
//! [`read_frame`] reads exactly one frame's bytes and no more, so the
//! stream is positioned at whatever follows: after `Accept`, the HTTP/2
//! connection preface. Callers wrap these in a timeout; neither function
//! has one of its own.

use core::fmt;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::{DecodeError, Decoded, EncodeError, decode, encode};
use crate::frame::Frame;
use crate::limits::{LENGTH_PREFIX_LEN, Limits};

/// A frame could not be read.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReadError {
    /// The stream failed or ended mid-frame.
    Io(io::Error),
    /// The bytes are not a valid frame.
    Decode(DecodeError),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "reading a frame: {e}"),
            Self::Decode(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Decode(e) => Some(e),
        }
    }
}

/// A frame could not be written.
#[derive(Debug)]
#[non_exhaustive]
pub enum WriteError {
    /// The stream failed.
    Io(io::Error),
    /// The frame is invalid or too large; nothing was written.
    Encode(EncodeError),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "writing a frame: {e}"),
            Self::Encode(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Encode(e) => Some(e),
        }
    }
}

/// Reads one frame. The length prefix is checked against
/// `limits.max_frame_len` before any of the body is read.
///
/// # Errors
///
/// [`ReadError::Io`] if the stream fails or ends mid-frame,
/// [`ReadError::Decode`] if the bytes are not a valid frame.
pub async fn read_frame<R>(r: &mut R, limits: &Limits) -> Result<Frame, ReadError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0; LENGTH_PREFIX_LEN];
    r.read_exact(&mut buf).await.map_err(ReadError::Io)?;
    loop {
        match decode(&buf, limits).map_err(ReadError::Decode)? {
            Decoded::Frame { frame, .. } => return Ok(frame),
            Decoded::NeedMore(n) => {
                let have = buf.len();
                buf.resize(have + n, 0);
                r.read_exact(&mut buf[have..])
                    .await
                    .map_err(ReadError::Io)?;
            }
        }
    }
}

/// Encodes and writes one frame, then flushes.
///
/// # Errors
///
/// [`WriteError::Encode`] for a frame that is invalid or too large (nothing
/// is written), [`WriteError::Io`] if the stream fails.
pub async fn write_frame<W>(w: &mut W, frame: &Frame, limits: &Limits) -> Result<(), WriteError>
where
    W: AsyncWrite + Unpin,
{
    let bytes = encode(frame, limits).map_err(WriteError::Encode)?;
    w.write_all(&bytes).await.map_err(WriteError::Io)?;
    w.flush().await.map_err(WriteError::Io)
}
