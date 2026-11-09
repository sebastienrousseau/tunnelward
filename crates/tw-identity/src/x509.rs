// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Writing the DER an enrolment CA needs, and reading back the few
//! fields of a certificate it checks: the times, the subject and the
//! public key. Definite lengths, low tag numbers, nothing more.

use crate::der;

pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const BIT_STRING: u8 = 0x03;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

// Object identifiers, DER-encoded without tag and length.
pub(crate) const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// One DER element: `tag`, its length, then `content`.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | u8::try_from(bytes.len() - skip).unwrap_or(0));
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub(crate) fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

pub(crate) fn oid(id: &[u8]) -> Vec<u8> {
    tlv(0x06, id)
}

/// A BIT STRING with no unused bits.
pub(crate) fn bits(content: &[u8]) -> Vec<u8> {
    tlv(BIT_STRING, &[&[0][..], content].concat())
}

/// `ecdsa-with-SHA256` as an `AlgorithmIdentifier`.
pub(crate) fn ecdsa_sha256() -> Vec<u8> {
    seq(&[&oid(ECDSA_WITH_SHA256)])
}

/// A P-256 `SubjectPublicKeyInfo` around the uncompressed point `key`.
pub(crate) fn p256_spki(key: &[u8]) -> Vec<u8> {
    seq(&[&seq(&[&oid(EC_PUBLIC_KEY), &oid(PRIME256V1)]), &bits(key)])
}

/// The uncompressed point in a P-256 `SubjectPublicKeyInfo`'s content;
/// `None` for any other key.
pub(crate) fn p256_point(spki: &[u8]) -> Option<&[u8]> {
    let items = der::items(spki)?;
    let [(SEQUENCE, algorithm), (BIT_STRING, key)] = items.as_slice() else {
        return None;
    };
    let expected = [oid(EC_PUBLIC_KEY), oid(PRIME256V1)].concat();
    let point = key.strip_prefix(&[0])?;
    (*algorithm == expected.as_slice() && point.len() == 65 && point[0] == 4).then_some(point)
}

/// One TLV as encoded, beside its parts. Signatures cover the encoded
/// bytes, so they are kept.
pub(crate) struct Raw<'a> {
    pub(crate) encoded: &'a [u8],
    pub(crate) tag: u8,
    pub(crate) content: &'a [u8],
    /// What follows the TLV.
    pub(crate) rest: &'a [u8],
}

/// The first TLV in `input`.
pub(crate) fn raw(input: &[u8]) -> Option<Raw<'_>> {
    let (tag, content, rest) = der::next(input)?;
    Some(Raw {
        encoded: &input[..input.len() - rest.len()],
        tag,
        content,
        rest,
    })
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian
/// (Howard Hinnant's `civil_from_days`).
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + u64::from(month <= 2), month, day)
}

/// (year, month, day) to days since 1970-01-01, for years from 1970
/// (Howard Hinnant's `days_from_civil`).
fn days(year: u64, month: u64, day: u64) -> Option<u64> {
    let y = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe).checked_sub(719_468)
}

/// `secs` since 1970 as an X.509 time: `UTCTime` up to 2049,
/// `GeneralizedTime` from 2050, as RFC 5280 requires.
pub(crate) fn time(secs: u64) -> Vec<u8> {
    let (year, month, day) = civil(secs / 86_400);
    let rest = secs % 86_400;
    let clock = format!(
        "{month:02}{day:02}{:02}{:02}{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    );
    if year < 2050 {
        tlv(UTC_TIME, format!("{:02}{clock}", year % 100).as_bytes())
    } else {
        tlv(GENERALIZED_TIME, format!("{year:04}{clock}").as_bytes())
    }
}

/// An X.509 time back to seconds since 1970; `None` unless it is the
/// `Z` form RFC 5280 requires, from 1970.
pub(crate) fn read_time(tag: u8, text: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(text).ok()?.strip_suffix('Z')?;
    let (year, rest) = year(tag, text)?;
    let [month, day, h, m, s] = fields(rest)?;
    let date = days(year, month, day).filter(|_| in_range([month, day, h, m, s]))?;
    Some(date * 86_400 + h * 3600 + m * 60 + s)
}

/// `MMDDHHMMSS` as five numbers.
fn fields(rest: &str) -> Option<[u64; 5]> {
    let mut out = [0; 5];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = number(rest.get(2 * i..2 * i + 2)?)?;
    }
    (rest.len() == 10).then_some(out)
}

/// The year, and the `MMDDHHMMSS` after it.
fn year(tag: u8, text: &str) -> Option<(u64, &str)> {
    match (tag, text.len()) {
        (UTC_TIME, 12) => {
            let yy: u64 = number(&text[..2])?;
            Some((if yy < 50 { 2000 + yy } else { 1900 + yy }, &text[2..]))
        }
        (GENERALIZED_TIME, 14) => Some((number(&text[..4])?, &text[4..])),
        _ => None,
    }
}

fn in_range([month, day, h, m, s]: [u64; 5]) -> bool {
    (1..=12).contains(&month) && (1..=31).contains(&day) && h < 24 && m < 60 && s < 60
}

fn number(digits: &str) -> Option<u64> {
    digits
        .bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| digits.parse().ok())?
}

/// The parts of a certificate's `TBSCertificate`, by position.
pub(crate) struct Tbs<'a> {
    /// The subject `Name`, exactly as encoded.
    pub(crate) subject: &'a [u8],
    /// The `SubjectPublicKeyInfo`'s content.
    pub(crate) spki: &'a [u8],
    /// `notBefore` and `notAfter`, seconds since 1970.
    pub(crate) validity: (u64, u64),
}

/// Reads a v3 certificate's subject, key and validity.
pub(crate) fn tbs(cert: &[u8]) -> Option<Tbs<'_>> {
    let certificate = der::items(der::whole(cert, SEQUENCE)?)?;
    let [(SEQUENCE, tbs), (SEQUENCE, _), (BIT_STRING, _)] = certificate.as_slice() else {
        return None;
    };
    let mut rest = *tbs;
    let mut fields = Vec::with_capacity(7);
    while fields.len() < 7 {
        let field = raw(rest)?;
        fields.push((field.encoded, field.tag, field.content));
        rest = field.rest;
    }
    let [
        (_, 0xa0, _),
        _,
        _,
        _,
        (_, SEQUENCE, validity),
        (subject, SEQUENCE, _),
        (_, SEQUENCE, spki),
    ] = fields.as_slice()
    else {
        return None;
    };
    let times = der::items(validity)?;
    let [(t1, from), (t2, until)] = times.as_slice() else {
        return None;
    };
    let validity = (read_time(*t1, from)?, read_time(*t2, until)?);
    Some(Tbs {
        subject,
        spki,
        validity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_use_the_short_and_long_forms() {
        assert_eq!(tlv(0x04, &[1, 2]), vec![0x04, 2, 1, 2]);
        assert_eq!(&tlv(0x04, &[0; 200])[..3], &[0x04, 0x81, 200]);
        assert_eq!(&tlv(0x04, &[0; 300])[..4], &[0x04, 0x82, 0x01, 0x2c]);
    }

    #[test]
    fn dates_match_known_days_both_ways() {
        for (day, date) in [
            (0, (1970, 1, 1)),
            (11_016, (2000, 2, 29)),
            (20_765, (2026, 11, 8)),
            (29_220, (2050, 1, 1)),
        ] {
            assert_eq!(civil(day), date);
            assert_eq!(days(date.0, date.1, date.2), Some(day));
        }
    }

    #[test]
    fn times_switch_form_at_2050_and_read_back() {
        let at = 20_765 * 86_400 + 3_723;
        assert_eq!(time(at), tlv(UTC_TIME, b"261108010203Z"));
        let later = 29_220 * 86_400 + 59;
        assert_eq!(time(later), tlv(GENERALIZED_TIME, b"20500101000059Z"));
        for secs in [0, at, later, 29_219 * 86_400 + 86_399] {
            let encoded = time(secs);
            assert_eq!(read_time(encoded[0], &encoded[2..]), Some(secs));
        }
    }

    #[test]
    fn times_out_of_form_are_refused() {
        assert_eq!(read_time(UTC_TIME, b"261108010203"), None, "no Z");
        assert_eq!(read_time(UTC_TIME, b"261308010203Z"), None, "month 13");
        assert_eq!(read_time(UTC_TIME, b"2611080102+3Z"), None, "not digits");
        assert_eq!(read_time(GENERALIZED_TIME, b"261108010203Z"), None);
        assert_eq!(read_time(UTC_TIME, b"691231235959Z"), None, "before 1970");
    }
}
