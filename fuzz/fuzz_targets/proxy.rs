// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Feeds arbitrary bytes to the PROXY protocol parser. It must never panic,
//! never claim more bytes than it was given, and a complete header must
//! parse the same from exactly its own bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tw_gateway::proxy_protocol::{Parsed, parse};

fuzz_target!(|data: &[u8]| {
    if let Ok(Parsed::Complete(header, used)) = parse(data) {
        assert!(used <= data.len());
        assert_eq!(parse(&data[..used]), Ok(Parsed::Complete(header, used)));
    }
});
