// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Enrolment: a small certificate authority that issues X.509-SVIDs,
//! and the certificate signing request a connector sends it.
//!
//! The connector makes a P-256 key and sends [`request`]'s output, which
//! proves it holds the key. The gateway checks it with
//! [`requested_key`] and has its [`Ca`] [`issue`](Ca::issue) a short-lived
//! SVID for the SPIFFE ID the enrolment allows. Keys are ECDSA P-256 and
//! signatures ECDSA with SHA-256, the profile SPIRE issues by default.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod keys;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair};
use tunnelward_proto::is_spiffe_id;

use crate::x509::{self, BIT_STRING, SEQUENCE, ecdsa_sha256, oid, seq, tlv};
pub use keys::{
    key_matches, new_key, pem, public_key, request, requested_key, sign, validity, verify,
};
use keys::{load_key, signed};

// Extension identifiers.
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];

/// How far back a certificate's validity starts, for clock skew.
const BACKDATE: u64 = 60;

/// Why an enrolment step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrolError {
    /// A certificate, request or key that does not parse, or is not
    /// ECDSA P-256.
    Malformed(&'static str),
    /// A request whose signature does not verify.
    BadSignature,
    /// The CA key is not the key in the CA certificate.
    KeyMismatch,
    /// The SPIFFE ID is not one.
    NotSpiffe,
    /// The clock is before 1970, or randomness or signing failed.
    Unavailable(&'static str),
}

impl std::fmt::Display for EnrolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "{what} does not parse as ECDSA P-256"),
            Self::BadSignature => f.write_str("the request's signature does not verify"),
            Self::KeyMismatch => f.write_str("the CA key is not the CA certificate's key"),
            Self::NotSpiffe => f.write_str("not a SPIFFE ID"),
            Self::Unavailable(what) => f.write_str(what),
        }
    }
}

impl std::error::Error for EnrolError {}

fn unix(at: SystemTime) -> Result<u64, EnrolError> {
    at.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| EnrolError::Unavailable("the clock is before 1970"))
}

/// One extension: its identifier, whether it is critical, its value.
fn extension(id: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let flag = if critical {
        tlv(0x01, &[0xff])
    } else {
        Vec::new()
    };
    seq(&[&oid(id), &flag, &tlv(0x04, value)])
}

/// A key identifier: the first 20 bytes of the SHA-256 of the public
/// key (RFC 7093, method 1).
fn key_id(public_key: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, public_key).as_ref()[..20].to_vec()
}

/// The subject and authority key identifier extensions RFC 5280 asks
/// of a conforming CA.
fn key_ids(subject_key: &[u8], authority_key: &[u8]) -> [Vec<u8>; 2] {
    [
        extension(SUBJECT_KEY_ID, false, &tlv(0x04, &key_id(subject_key))),
        extension(
            AUTHORITY_KEY_ID,
            false,
            &seq(&[&tlv(0x80, &key_id(authority_key))]),
        ),
    ]
}

/// A random positive 16-byte serial number.
fn serial() -> Result<Vec<u8>, EnrolError> {
    let mut serial = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut serial)
        .map_err(|_| EnrolError::Unavailable("no randomness for the serial"))?;
    serial[0] = (serial[0] & 0x7f) | 0x40; // positive, no leading zero byte
    Ok(tlv(0x02, &serial))
}

/// A signing CA: its certificate, its key, and its subject as encoded.
pub struct Ca {
    cert: Vec<u8>,
    key: EcdsaKeyPair,
    subject: Vec<u8>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca").finish_non_exhaustive()
    }
}

impl Ca {
    /// A new self-signed CA named `CN=<name>`, valid for `lifetime` from
    /// `now`, that may sign leaf certificates only: its certificate and
    /// its PKCS#8 key, both DER.
    ///
    /// # Errors
    ///
    /// Randomness, signing or the clock failed.
    pub fn generate(
        name: &str,
        lifetime: Duration,
        now: SystemTime,
    ) -> Result<(Vec<u8>, Vec<u8>), EnrolError> {
        let pkcs8 = new_key()?;
        let key = load_key(&pkcs8)?;
        let subject = seq(&[&tlv(
            0x31,
            &seq(&[&oid(COMMON_NAME), &tlv(0x0c, name.as_bytes())]),
        )]);
        let now = unix(now)?;
        let extensions = [
            // cA TRUE, pathLenConstraint 0.
            extension(
                BASIC_CONSTRAINTS,
                true,
                &seq(&[&tlv(0x01, &[0xff]), &tlv(0x02, &[0])]),
            ),
            // keyCertSign and cRLSign.
            extension(KEY_USAGE, true, &tlv(BIT_STRING, &[1, 0x06])),
        ];
        let point = key.public_key().as_ref();
        let extensions = [extensions.concat(), key_ids(point, point).concat()];
        let tbs = tbs(
            &subject,
            &subject,
            (now.saturating_sub(BACKDATE), now + lifetime.as_secs()),
            point,
            &extensions.concat(),
        )?;
        Ok((signed(&key, &tbs)?, pkcs8))
    }

    /// The CA from its certificate and PKCS#8 key, both DER.
    ///
    /// # Errors
    ///
    /// Either does not parse as ECDSA P-256, or the key is not the
    /// certificate's.
    pub fn load(cert: &[u8], pkcs8: &[u8]) -> Result<Self, EnrolError> {
        let key = load_key(pkcs8)?;
        let tbs = x509::tbs(cert).ok_or(EnrolError::Malformed("the CA certificate"))?;
        let point =
            x509::p256_point(tbs.spki).ok_or(EnrolError::Malformed("the CA certificate"))?;
        if point != key.public_key().as_ref() {
            return Err(EnrolError::KeyMismatch);
        }
        Ok(Self {
            subject: tbs.subject.to_vec(),
            cert: cert.to_vec(),
            key,
        })
    }

    /// The CA certificate, DER.
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.cert
    }

    /// An X.509-SVID for `spiffe_id` certifying the P-256 point
    /// `public_key`, valid for `lifetime` from `now` (backdated a
    /// minute): a client certificate with an empty subject, the SPIFFE ID
    /// as its one, critical, alternative name, and no CA rights.
    ///
    /// # Errors
    ///
    /// [`EnrolError::NotSpiffe`], a key that is not a P-256 point, or
    /// randomness, signing or the clock failed.
    pub fn issue(
        &self,
        spiffe_id: &str,
        public_key: &[u8],
        lifetime: Duration,
        now: SystemTime,
    ) -> Result<Vec<u8>, EnrolError> {
        if !is_spiffe_id(spiffe_id) {
            return Err(EnrolError::NotSpiffe);
        }
        if public_key.len() != 65 || public_key[0] != 4 {
            return Err(EnrolError::Malformed("the public key"));
        }
        let now = unix(now)?;
        let extensions = [
            extension(BASIC_CONSTRAINTS, true, &seq(&[])),
            // digitalSignature.
            extension(KEY_USAGE, true, &tlv(BIT_STRING, &[7, 0x80])),
            extension(EXT_KEY_USAGE, false, &seq(&[&oid(CLIENT_AUTH)])),
            extension(
                SUBJECT_ALT_NAME,
                true,
                &seq(&[&tlv(0x86, spiffe_id.as_bytes())]),
            ),
        ];
        let issuer_key = self.key.public_key().as_ref();
        let extensions = [
            extensions.concat(),
            key_ids(public_key, issuer_key).concat(),
        ];
        let tbs = tbs(
            &self.subject,
            &seq(&[]),
            (now.saturating_sub(BACKDATE), now + lifetime.as_secs()),
            public_key,
            &extensions.concat(),
        )?;
        signed(&self.key, &tbs)
    }
}

/// A v3 `TBSCertificate`.
fn tbs(
    issuer: &[u8],
    subject: &[u8],
    (from, until): (u64, u64),
    public_key: &[u8],
    extensions: &[u8],
) -> Result<Vec<u8>, EnrolError> {
    Ok(seq(&[
        &tlv(0xa0, &tlv(0x02, &[2])),
        &serial()?,
        &ecdsa_sha256(),
        issuer,
        &seq(&[&x509::time(from), &x509::time(until)]),
        subject,
        &x509::p256_spki(public_key),
        &tlv(0xa3, &tlv(SEQUENCE, extensions)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    type Res = Result<(), Box<dyn std::error::Error>>;

    const ID: &str = "spiffe://example.org/connector";

    fn ca() -> Result<Ca, EnrolError> {
        let (cert, key) = Ca::generate("Test CA", Duration::from_secs(86_400), SystemTime::now())?;
        Ca::load(&cert, &key)
    }

    #[test]
    fn a_request_yields_its_key_and_the_issued_svid_names_the_id() -> Res {
        let ca = ca()?;
        let key = new_key()?;
        let wanted = requested_key(&request(&key)?)?;
        let now = SystemTime::now();
        let svid = ca.issue(ID, &wanted, Duration::from_secs(3600), now)?;
        assert_eq!(crate::spiffe_id(&svid)?, ID);
        assert_eq!(public_key(&svid), Some(wanted.as_slice()));
        assert!(key_matches(&svid, &key));
        assert!(!key_matches(&svid, &new_key()?));
        assert_eq!(validity(&svid), Some((unix(now)? - 60, unix(now)? + 3600)));
        Ok(())
    }

    #[test]
    fn the_ca_key_must_match_its_certificate() -> Res {
        let (cert, _) = Ca::generate("A", Duration::from_secs(60), SystemTime::now())?;
        assert_eq!(
            Ca::load(&cert, &new_key()?).err(),
            Some(EnrolError::KeyMismatch)
        );
        Ok(())
    }

    #[test]
    fn only_spiffe_ids_and_p256_points_are_issued() -> Res {
        let ca = ca()?;
        let key = requested_key(&request(&new_key()?)?)?;
        let hour = Duration::from_secs(3600);
        let now = SystemTime::now();
        assert_eq!(
            ca.issue("https://x", &key, hour, now),
            Err(EnrolError::NotSpiffe)
        );
        assert!(ca.issue(ID, &key[1..], hour, now).is_err());
        Ok(())
    }
}
