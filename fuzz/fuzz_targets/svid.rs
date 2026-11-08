// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Feeds arbitrary bytes to the X.509-SVID reader. It must never panic,
//! and anything it accepts is a SPIFFE ID.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tunnelward_identity::spiffe_id;
use tunnelward_proto::is_spiffe_id;

fuzz_target!(|data: &[u8]| {
    if let Ok(id) = spiffe_id(data) {
        assert!(is_spiffe_id(&id), "accepted {id:?}");
    }
});
