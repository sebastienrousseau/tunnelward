// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! RFC 3339 timestamps, as Go's `time.Time` writes them in JSON.

/// `text` (`2026-11-06T10:00:00.5+01:00`) as whole seconds since 1970,
/// fractions dropped; `None` unless it is RFC 3339 with a year from 1970
/// to 9999.
pub(crate) fn parse(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    let [year, month, day, hour, minute, second] = fields(b)?;
    let offset = zone(skip_fraction(b.get(19..)?)?)?;
    let local = days(year, month, day)? * 86_400 + hour * 3600 + minute * 60 + second;
    local.checked_add_signed(-offset)
}

/// Year, month, day, hour, minute and second, each in range.
fn fields(b: &[u8]) -> Option<[u64; 6]> {
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    let shaped = separators
        .iter()
        .all(|(at, c)| b.get(*at).map(u8::to_ascii_uppercase) == Some(*c));
    if !shaped {
        return None;
    }
    let spans = [(0, 4), (5, 2), (8, 2), (11, 2), (14, 2), (17, 2)];
    let mut out = [0; 6];
    for (slot, (at, len)) in out.iter_mut().zip(spans) {
        *slot = num(b, at, len)?;
    }
    let [year, month, day, hour, minute, second] = out;
    let date = (1..=12).contains(&month) && (1..=month_days(year, month)).contains(&day);
    (date && hour < 24 && minute < 60 && second <= 60).then_some(out)
}

/// What follows an optional `.digits` fraction; `None` for a bare dot.
fn skip_fraction(rest: &[u8]) -> Option<&[u8]> {
    let Some((b'.', frac)) = rest.split_first() else {
        return Some(rest);
    };
    let digits = frac.iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    frac.get(digits..)
}

/// The zone's offset in seconds: `Z` or `±HH:MM`.
fn zone(rest: &[u8]) -> Option<i64> {
    let sign = match rest {
        [b'Z' | b'z'] => return Some(0),
        [b'+', _, _, b':', _, _] => 1,
        [b'-', _, _, b':', _, _] => -1,
        _ => return None,
    };
    let (h, m) = (num(rest, 1, 2)?, num(rest, 4, 2)?);
    if h > 23 || m > 59 {
        return None;
    }
    i64::try_from(h * 3600 + m * 60)
        .ok()
        .map(|secs| sign * secs)
}

/// `len` ASCII digits at `at`.
fn num(b: &[u8], at: usize, len: usize) -> Option<u64> {
    let digits = b.get(at..at + len)?;
    digits.iter().try_fold(0_u64, |acc, c| {
        c.is_ascii_digit().then(|| acc * 10 + u64::from(c - b'0'))
    })
}

fn month_days(year: u64, month: u64) -> u64 {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_go_writes() {
        assert_eq!(parse("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse("2000-02-29T12:34:56Z"), Some(951_827_696));
        assert_eq!(parse("2026-11-06T10:00:00.123456789Z"), Some(1_793_959_200));
        assert_eq!(parse("2026-11-06T11:00:00+01:00"), Some(1_793_959_200));
        assert_eq!(parse("2026-11-06T09:30:00.5-00:30"), Some(1_793_959_200));
    }

    #[test]
    fn refuses_what_is_not_rfc_3339() {
        let bad = [
            "",
            "2026-11-06",
            "2026-11-06 10:00:00Z",
            "2026-13-06T10:00:00Z",
            "2026-02-29T10:00:00Z",
            "2026-11-06T24:00:00Z",
            "2026-11-06T10:00:00",
            "2026-11-06T10:00:00.Z",
            "2026-11-06T10:00:00+0100",
            "1969-12-31T23:59:59Z",
            "2026-11-06T10:00:00Zjunk",
            "1970-01-01T00:00:00+01:00",
        ];
        for text in bad {
            assert_eq!(parse(text), None, "{text}");
        }
    }
}
