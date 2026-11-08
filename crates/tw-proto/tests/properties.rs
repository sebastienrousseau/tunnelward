// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Property tests: valid frames round-trip, and no input makes the decoder
//! panic or read past its limit.

use proptest::prelude::*;
use tw_proto::{
    Accept, ConnectorId, Decoded, Frame, LENGTH_PREFIX_LEN, Limits, McpDescriptor,
    PROTOCOL_VERSION, Register, Reject, RejectCode, StreamLimits, decode, encode,
};

/// Miri is slow and isolated from the file system, so it runs a few cases
/// and keeps no failure file.
fn config() -> ProptestConfig {
    if cfg!(miri) {
        ProptestConfig {
            cases: 4,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    } else {
        ProptestConfig::with_cases(512)
    }
}

fn route() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z0-9][a-z0-9-]{0,20}", 1..=4).prop_map(|s| s.join("/"))
}

fn register() -> impl Strategy<Value = Register> {
    (
        any::<[u8; 16]>(),
        "[a-z0-9]{1,12}(\\.[a-z0-9]{1,12}){0,2}",
        proptest::collection::vec("[A-Za-z0-9._-]{0,6}[A-Za-z0-9_-]", 1..=4),
        proptest::collection::btree_set(route(), 1..=8),
        proptest::collection::btree_set("(\\*\\.)?[a-z0-9]{1,10}\\.[a-z]{2,6}", 0..=4),
        proptest::option::of(("[ -~]{1,40}", "[ -~]{1,20}", any::<[u8; 32]>())),
        proptest::option::of(proptest::collection::vec(any::<u8>(), 0..512)),
        1..=u32::MAX,
    )
        .prop_map(
            |(id, domain, path, routes, domains, mcp, attestation, capacity)| Register {
                version: PROTOCOL_VERSION,
                connector_id: ConnectorId(id),
                spiffe_id: format!("spiffe://{domain}/{}", path.join("/")),
                routes: routes.into_iter().collect(),
                domains: domains.into_iter().collect(),
                mcp: mcp.map(|(name, version, tools_digest)| McpDescriptor {
                    name,
                    version,
                    tools_digest,
                }),
                attestation,
                capacity,
            },
        )
}

fn frame() -> impl Strategy<Value = Frame> {
    let nonzero = || 1..=u32::MAX;
    prop_oneof![
        register().prop_map(Frame::Register),
        (nonzero(), nonzero(), nonzero(), nonzero(), nonzero()).prop_map(
            |(lease_secs, a, b, c, d)| {
                Frame::Accept(Accept {
                    lease_secs,
                    limits: StreamLimits {
                        max_concurrent_streams: a,
                        max_header_list_size: b,
                        initial_stream_window: c,
                        initial_connection_window: d,
                    },
                })
            }
        ),
        (1..=11u16, "[^\\p{Cc}]{0,200}").prop_filter_map("short reason", |(n, reason)| {
            let code = RejectCode::try_from(n).ok()?;
            (reason.len() <= 1024).then_some(Frame::Reject(Reject { code, reason }))
        }),
    ]
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn valid_frames_round_trip(frame in frame()) {
        let limits = Limits::default();
        let bytes = encode(&frame, &limits).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let consumed = bytes.len();
        prop_assert_eq!(decode(&bytes, &limits), Ok(Decoded::Frame { frame, consumed }));
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_never_overrun(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let limits = Limits { max_frame_len: 1024, ..Limits::default() };
        match decode(&bytes, &limits) {
            Ok(Decoded::Frame { consumed, .. }) => {
                prop_assert!(consumed <= bytes.len());
                prop_assert!(consumed <= LENGTH_PREFIX_LEN + 1024);
            }
            Ok(Decoded::NeedMore(n)) => prop_assert!(bytes.len() + n <= LENGTH_PREFIX_LEN + 1024),
            Err(_) => {}
        }
    }
}
