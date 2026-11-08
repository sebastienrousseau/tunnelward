// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tunnelward workload identity: the SPIFFE ID in an X.509-SVID.
//!
//! [`spiffe_id`] reads a certificate's subject alternative names and
//! returns its one URI when it is a SPIFFE ID, as the X.509-SVID
//! specification requires. It does not verify the certificate: call it
//! on a certificate the TLS handshake already verified.

mod der;
#[cfg(unix)]
mod proto;
#[cfg(unix)]
pub mod workload;

use tunnelward_proto::is_spiffe_id;

const SEQUENCE: u8 = 0x30;
const OID: u8 = 0x06;
const OCTET_STRING: u8 = 0x04;
/// `[3] EXPLICIT Extensions` in a `TBSCertificate`.
const EXTENSIONS: u8 = 0xa3;
/// `uniformResourceIdentifier [6] IA5String` in a `GeneralName`.
const URI: u8 = 0x86;
/// id-ce-subjectAltName, 2.5.29.17.
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

/// Why a certificate is not an X.509-SVID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvidError {
    /// Not a DER certificate this reader understands.
    Malformed,
    /// No URI in the subject alternative names.
    NoSpiffeId,
    /// More than one URI; an X.509-SVID carries exactly one.
    SeveralUris,
    /// The one URI is not a SPIFFE ID.
    NotSpiffe(String),
}

impl std::fmt::Display for SvidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => f.write_str("the certificate does not parse"),
            Self::NoSpiffeId => f.write_str("the certificate names no SPIFFE ID"),
            Self::SeveralUris => f.write_str("the certificate names more than one URI"),
            Self::NotSpiffe(uri) => write!(f, "the certificate's URI {uri:?} is not a SPIFFE ID"),
        }
    }
}

impl std::error::Error for SvidError {}

/// The SPIFFE ID in the X.509-SVID `cert` (DER).
///
/// # Errors
///
/// [`SvidError`] says why `cert` is not an SVID.
pub fn spiffe_id(cert: &[u8]) -> Result<String, SvidError> {
    let uris = uris(cert).ok_or(SvidError::Malformed)?;
    match uris.as_slice() {
        [] => Err(SvidError::NoSpiffeId),
        [one] if is_spiffe_id(one) => Ok(one.clone()),
        [one] => Err(SvidError::NotSpiffe(one.clone())),
        _ => Err(SvidError::SeveralUris),
    }
}

/// Every URI in `cert`'s subject alternative names; `None` if `cert` does
/// not parse or has two alternative-name extensions.
fn uris(cert: &[u8]) -> Option<Vec<String>> {
    let certificate = der::items(der::whole(cert, SEQUENCE)?)?;
    let [(SEQUENCE, tbs), (SEQUENCE, _), (0x03, _)] = certificate.as_slice() else {
        return None;
    };
    let extensions: Vec<&[u8]> = der::items(tbs)?
        .into_iter()
        .filter_map(|(tag, value)| (tag == EXTENSIONS).then_some(value))
        .collect();
    match extensions.as_slice() {
        [] => Some(Vec::new()),
        [one] => alt_name_uris(der::whole(one, SEQUENCE)?),
        _ => None,
    }
}

/// The URIs in the subjectAltName among `extensions`.
fn alt_name_uris(extensions: &[u8]) -> Option<Vec<String>> {
    let mut names: Option<&[u8]> = None;
    for (tag, extension) in der::items(extensions)? {
        let (id, value) = extension_parts(tag, extension)?;
        if id == SUBJECT_ALT_NAME && names.replace(value).is_some() {
            return None;
        }
    }
    match names {
        None => Some(Vec::new()),
        Some(names) => general_name_uris(der::whole(names, SEQUENCE)?),
    }
}

/// An extension's identifier and value; `None` when it does not parse.
fn extension_parts(tag: u8, extension: &[u8]) -> Option<(&[u8], &[u8])> {
    if tag != SEQUENCE {
        return None;
    }
    match der::items(extension)?.as_slice() {
        [(OID, id), (OCTET_STRING, value)] | [(OID, id), (0x01, _), (OCTET_STRING, value)] => {
            Some((id, value))
        }
        _ => None,
    }
}

/// The URIs among `general_names`; `None` if one is not ASCII.
fn general_name_uris(general_names: &[u8]) -> Option<Vec<String>> {
    der::items(general_names)?
        .into_iter()
        .filter(|(tag, _)| *tag == URI)
        .map(|(_, uri)| {
            uri.is_ascii()
                .then(|| String::from_utf8_lossy(uri).into_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A certificate shell around `general_names`: tbs, algorithm, bits.
    fn cert_with(general_names: &[u8]) -> Vec<u8> {
        let tlv = |tag: u8, content: &[u8]| {
            let mut out = vec![tag, u8::try_from(content.len()).unwrap_or(0)];
            out.extend_from_slice(content);
            out
        };
        let names = tlv(SEQUENCE, general_names);
        let san = [tlv(OID, SUBJECT_ALT_NAME), tlv(OCTET_STRING, &names)].concat();
        let extensions = tlv(EXTENSIONS, &tlv(SEQUENCE, &tlv(SEQUENCE, &san)));
        let tbs = tlv(SEQUENCE, &extensions);
        tlv(
            SEQUENCE,
            &[tbs, tlv(SEQUENCE, &[]), tlv(0x03, &[0])].concat(),
        )
    }

    #[test]
    fn a_uri_that_is_not_spiffe_is_named() {
        let cert = cert_with(&[&[URI, 9][..], b"https://x"].concat());
        assert_eq!(
            spiffe_id(&cert),
            Err(SvidError::NotSpiffe("https://x".into()))
        );
    }

    #[test]
    fn a_non_ascii_uri_is_malformed() {
        let cert = cert_with(&[URI, 2, 0xc3, 0xa9]);
        assert_eq!(spiffe_id(&cert), Err(SvidError::Malformed));
    }

    #[test]
    fn errors_read_as_sentences() {
        assert_eq!(
            SvidError::NoSpiffeId.to_string(),
            "the certificate names no SPIFFE ID"
        );
    }
}
