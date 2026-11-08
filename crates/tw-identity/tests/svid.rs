// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading the SPIFFE ID out of real certificates from the test PKI.

use tunnelward_identity::{SvidError, spiffe_id};
use tunnelward_testpki as pki;

#[test]
fn an_svid_names_its_spiffe_id() {
    assert_eq!(
        spiffe_id(pki::CONNECTOR.0).as_deref(),
        Ok(pki::CONNECTOR_ID)
    );
    assert_eq!(spiffe_id(pki::RIVAL.0).as_deref(), Ok(pki::RIVAL_ID));
}

#[test]
fn a_certificate_without_a_spiffe_id_is_not_an_svid() {
    assert_eq!(spiffe_id(pki::PLAIN.0), Err(SvidError::NoSpiffeId));
    assert_eq!(spiffe_id(pki::GATEWAY.0), Err(SvidError::NoSpiffeId));
}

#[test]
fn two_spiffe_ids_are_refused() {
    assert_eq!(spiffe_id(pki::TWO_IDS.0), Err(SvidError::SeveralUris));
}

#[test]
fn anything_but_a_certificate_is_malformed() {
    assert_eq!(spiffe_id(b""), Err(SvidError::Malformed));
    assert_eq!(spiffe_id(b"\x30\x80\x00\x00"), Err(SvidError::Malformed));
    let cert = pki::CONNECTOR.0;
    for cut in [1, 4, cert.len() / 2, cert.len() - 1] {
        assert_eq!(
            spiffe_id(&cert[..cut]),
            Err(SvidError::Malformed),
            "cut at {cut}"
        );
    }
    let mut trailing = cert.to_vec();
    trailing.push(0);
    assert_eq!(spiffe_id(&trailing), Err(SvidError::Malformed));
}
