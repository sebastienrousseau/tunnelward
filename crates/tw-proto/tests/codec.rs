// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Codec behaviour at the edges: partial input, limits, malformed bodies.

use tw_proto::{
    Accept, ConnectorId, DecodeError, Decoded, EncodeError, Frame, LENGTH_PREFIX_LEN, Limits,
    McpDescriptor, PROTOCOL_VERSION, Register, Reject, RejectCode, StreamLimits, decode, encode,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A `Reject` whose code is a bare number, so it can be one the protocol lacks.
#[derive(serde::Serialize)]
struct BadReject {
    code: u16,
    reason: &'static str,
}

/// An `Accept` with a field the protocol does not have.
#[derive(serde::Serialize)]
struct AcceptPlus {
    lease_secs: u32,
    limits: StreamLimits,
    extra: bool,
}

fn register() -> Register {
    Register {
        version: PROTOCOL_VERSION,
        connector_id: ConnectorId([1; 16]),
        spiffe_id: "spiffe://example.org/ns/prod/sa/payments".into(),
        routes: vec!["mcp/payments".into(), "mcp/ledger".into()],
        domains: vec!["mcp.example.org".into(), "*.tools.example.org".into()],
        mcp: Some(McpDescriptor {
            name: "payments".into(),
            version: "1.4.0".into(),
            tools_digest: [9; 32],
        }),
        attestation: Some(vec![0xde, 0xad]),
        capacity: 64,
    }
}

fn with_prefix(body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut out = len.to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

fn cbor(value: &impl serde::Serialize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(cbor4ii::serde::to_vec(Vec::new(), value)?)
}

/// A frame as a one-key map, the way serde writes an enum variant.
fn variant<T: serde::Serialize>(
    name: &'static str,
    body: T,
) -> std::collections::BTreeMap<&'static str, T> {
    std::iter::once((name, body)).collect()
}

#[test]
fn every_frame_kind_round_trips() -> TestResult {
    let limits = Limits::default();
    let frames = [
        Frame::Register(register()),
        Frame::Accept(Accept {
            lease_secs: 30,
            limits: StreamLimits::default(),
        }),
        Frame::Reject(Reject {
            code: RejectCode::RouteOwned,
            reason: "mcp/payments is owned".into(),
        }),
    ];
    for frame in frames {
        let bytes = encode(&frame, &limits)?;
        assert_eq!(
            decode(&bytes, &limits)?,
            Decoded::Frame {
                frame,
                consumed: bytes.len()
            }
        );
    }
    Ok(())
}

#[test]
fn catch_all_and_no_domains_are_valid() -> TestResult {
    let limits = Limits::default();
    let frame = Frame::Register(Register {
        routes: vec!["*".into()],
        domains: Vec::new(),
        ..register()
    });
    let bytes = encode(&frame, &limits)?;
    assert_eq!(
        decode(&bytes, &limits)?,
        Decoded::Frame {
            frame,
            consumed: bytes.len()
        }
    );
    Ok(())
}

#[test]
fn partial_input_asks_for_exactly_what_is_missing() -> TestResult {
    let limits = Limits::default();
    let bytes = encode(&Frame::Register(register()), &limits)?;
    for cut in 0..bytes.len() {
        let want = if cut < LENGTH_PREFIX_LEN {
            LENGTH_PREFIX_LEN - cut
        } else {
            bytes.len() - cut
        };
        assert_eq!(
            decode(&bytes[..cut], &limits)?,
            Decoded::NeedMore(want),
            "cut at {cut}"
        );
    }
    Ok(())
}

#[test]
fn a_second_frame_in_the_buffer_is_left_alone() -> TestResult {
    let limits = Limits::default();
    let one = encode(&Frame::Register(register()), &limits)?;
    let mut two = one.clone();
    two.extend_from_slice(&one);
    assert_eq!(
        decode(&two, &limits)?,
        Decoded::Frame {
            frame: Frame::Register(register()),
            consumed: one.len()
        }
    );
    Ok(())
}

#[test]
fn oversized_length_fails_from_the_prefix_alone() {
    let limits = Limits::default();
    let prefix = (limits.max_frame_len + 1).to_be_bytes();
    assert_eq!(
        decode(&prefix, &limits),
        Err(DecodeError::TooLarge {
            len: limits.max_frame_len + 1,
            max: limits.max_frame_len
        })
    );
    assert_eq!(
        decode(&u32::MAX.to_be_bytes(), &limits).map_err(|e| e.reject_code()),
        Err(RejectCode::Malformed)
    );
}

#[test]
fn zero_length_is_rejected() {
    assert_eq!(
        decode(&[0, 0, 0, 0], &Limits::default()),
        Err(DecodeError::Empty)
    );
}

#[test]
fn a_lower_limit_is_honoured_both_ways() -> TestResult {
    let big = Limits::default();
    let small = Limits {
        max_frame_len: 16,
        ..Limits::default()
    };
    let frame = Frame::Register(register());
    assert!(matches!(
        encode(&frame, &small),
        Err(EncodeError::TooLarge { max: 16, .. })
    ));
    let bytes = encode(&frame, &big)?;
    assert!(matches!(
        decode(&bytes, &small),
        Err(DecodeError::TooLarge { max: 16, .. })
    ));
    Ok(())
}

#[test]
fn garbage_and_trailing_bytes_are_malformed() -> TestResult {
    let limits = Limits::default();
    let garbage = decode(&with_prefix(&[0xff, 0x00, 0x13]), &limits);
    assert!(matches!(garbage, Err(DecodeError::Cbor(_))), "{garbage:?}");

    let mut body = cbor(&Frame::Register(register()))?;
    body.push(0);
    assert_eq!(
        decode(&with_prefix(&body), &limits),
        Err(DecodeError::TrailingBytes(1))
    );
    Ok(())
}

#[test]
fn unknown_fields_and_codes_are_malformed() -> TestResult {
    let limits = Limits::default();
    // A Reject with code 99, built by hand.
    let bad = variant(
        "Reject",
        BadReject {
            code: 99,
            reason: "x",
        },
    );
    let err = decode(&with_prefix(&cbor(&bad)?), &limits);
    assert!(matches!(err, Err(DecodeError::Cbor(_))), "{err:?}");

    // An Accept with a field the protocol does not have.
    let plus = variant(
        "Accept",
        AcceptPlus {
            lease_secs: 5,
            limits: StreamLimits::default(),
            extra: true,
        },
    );
    let err = decode(&with_prefix(&cbor(&plus)?), &limits);
    assert!(matches!(err, Err(DecodeError::Cbor(_))), "{err:?}");
    Ok(())
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

/// Valid registrations with one header rule broken, and the code each gets.
fn broken_headers() -> Vec<(Register, RejectCode)> {
    let ok = register();
    vec![
        (
            Register {
                version: 2,
                ..ok.clone()
            },
            RejectCode::UnsupportedVersion,
        ),
        (
            Register {
                spiffe_id: "spiffe://example.org".into(),
                ..ok.clone()
            },
            RejectCode::Invalid,
        ),
        (Register { capacity: 0, ..ok }, RejectCode::Invalid),
    ]
}

/// Valid registrations with one claim rule broken; all get `Invalid`.
fn broken_claims() -> Vec<Register> {
    let ok = register();
    let many = |p: &str, n: usize| (0..n).map(|i| format!("{p}{i}.org")).collect::<Vec<_>>();
    vec![
        Register {
            routes: Vec::new(),
            ..ok.clone()
        },
        Register {
            routes: names(&["mcp/ok", "Bad Route"]),
            ..ok.clone()
        },
        Register {
            routes: names(&["mcp/a", "mcp/a"]),
            ..ok.clone()
        },
        Register {
            routes: (0..65).map(|i| format!("r{i}")).collect(),
            ..ok.clone()
        },
        Register {
            domains: names(&["Bad.Domain"]),
            ..ok.clone()
        },
        Register {
            domains: names(&["a.org", "a.org"]),
            ..ok.clone()
        },
        Register {
            domains: many("d", 17),
            ..ok
        },
    ]
}

fn broken_registers() -> impl Iterator<Item = (Register, RejectCode)> {
    let claims = broken_claims()
        .into_iter()
        .map(|r| (r, RejectCode::Invalid));
    broken_headers().into_iter().chain(claims)
}

#[test]
fn invalid_frames_are_never_encoded_and_are_rejected_on_decode() -> TestResult {
    let limits = Limits::default();
    for (register, code) in broken_registers() {
        let frame = Frame::Register(register);
        assert!(matches!(encode(&frame, &limits), Err(EncodeError::Invalid(i)) if i.code == code));
        let bytes = with_prefix(&cbor(&frame)?);
        assert_eq!(
            decode(&bytes, &limits).map_err(|e| e.reject_code()),
            Err(code)
        );
    }
    Ok(())
}

#[test]
fn accept_and_reject_rules() {
    let limits = Limits::default();
    let zero_lease = Frame::Accept(Accept {
        lease_secs: 0,
        limits: StreamLimits::default(),
    });
    let zero_window = Frame::Accept(Accept {
        lease_secs: 5,
        limits: StreamLimits {
            initial_stream_window: 0,
            ..StreamLimits::default()
        },
    });
    let control = Frame::Reject(Reject {
        code: RejectCode::Internal,
        reason: "a\u{1b}[2J".into(),
    });
    let long = Frame::Reject(Reject {
        code: RejectCode::Internal,
        reason: "x".repeat(1025),
    });
    for frame in [zero_lease, zero_window, control, long] {
        assert!(
            matches!(encode(&frame, &limits), Err(EncodeError::Invalid(_))),
            "{frame:?}"
        );
    }
}
