// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Feeds arbitrary bytes to the frame decoder. It must never panic, never
//! claim more bytes than it was given, and every frame it accepts must
//! encode and decode back to itself.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tw_proto::{Decoded, Limits, decode, encode};

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();
    let Ok(Decoded::Frame { frame, consumed }) = decode(data, &limits) else {
        return;
    };
    assert!(consumed <= data.len());
    let again = encode(&frame, &limits).expect("a decoded frame re-encodes");
    let back = decode(&again, &limits).expect("a re-encoded frame decodes");
    assert_eq!(back, Decoded::Frame { frame, consumed: again.len() });
});
