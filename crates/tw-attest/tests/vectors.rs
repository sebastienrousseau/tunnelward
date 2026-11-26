// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The interop vectors from scripts/gen-attest-vectors.sh: passmcp's own
//! statement, signed by cosign (and checked by cosign) and by openssl.

use std::time::{Duration, UNIX_EPOCH};

use aws_lc_rs::digest::{SHA256, digest};
use tunnelward_attest::{Error, Limits, TrustedKey, verify};

const STATEMENT: &[u8] = include_bytes!("vectors/statement.json");
const COSIGN_BUNDLE: &[u8] = include_bytes!("vectors/cosign-bundle.json");
const ED25519_DSSE: &[u8] = include_bytes!("vectors/ed25519-dsse.json");
const TAMPERED: &[u8] = include_bytes!("vectors/tampered-bundle.json");

fn p256() -> Result<TrustedKey, String> {
    TrustedKey::from_pem(include_bytes!("vectors/cosign-p256.pub"))
}

fn ed25519() -> Result<TrustedKey, String> {
    TrustedKey::from_pem(include_bytes!("vectors/ed25519.pub"))
}

#[test]
fn a_cosign_bundle_verifies_and_reads_back_passmcps_statement() {
    let key = p256().unwrap();
    let attested = verify(
        COSIGN_BUNDLE,
        &[ed25519().unwrap(), p256().unwrap()],
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(attested.key, key.id());
    assert_eq!(
        attested.digest.as_slice(),
        digest(&SHA256, STATEMENT).as_ref()
    );
    assert_eq!(
        attested.subject,
        "a386a033799c95c21f3d01b2f0efcf71b95b1ef2a420908ce34e3c1eb41a2325"
    );
    assert_eq!(
        (attested.transport.as_str(), attested.endpoint.as_str()),
        ("http", "https://mcp.example.com/mcp")
    );
    assert_eq!(
        attested.ran_at,
        UNIX_EPOCH + Duration::from_secs(1_790_078_400)
    );
    assert_eq!((attested.counts.pass, attested.counts.fail), (1, 1));
    assert_eq!(attested.score, Some(88.0));
    assert_eq!(attested.status("protocol.origin"), Some("fail"));
    assert_eq!(attested.status("no.such.check"), None);
}

#[test]
fn an_openssl_ed25519_envelope_verifies() {
    let attested = verify(ED25519_DSSE, &[ed25519().unwrap()], &Limits::default()).unwrap();
    assert_eq!(
        attested.digest.as_slice(),
        digest(&SHA256, STATEMENT).as_ref()
    );
}

#[test]
fn a_signature_by_another_key_is_unsigned() {
    assert_eq!(
        verify(COSIGN_BUNDLE, &[ed25519().unwrap()], &Limits::default()),
        Err(Error::Unsigned)
    );
    assert_eq!(
        verify(ED25519_DSSE, &[p256().unwrap()], &Limits::default()),
        Err(Error::Unsigned)
    );
    assert_eq!(
        verify(COSIGN_BUNDLE, &[], &Limits::default()),
        Err(Error::Unsigned)
    );
}

#[test]
fn one_changed_payload_byte_breaks_the_signature() {
    assert_eq!(
        verify(TAMPERED, &[p256().unwrap()], &Limits::default()),
        Err(Error::Unsigned)
    );
}
