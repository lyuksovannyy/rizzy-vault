//! Timestamps in import files, turned into the Unix milliseconds of `import.created_ms` and
//! `pwhist/<id>/ms` (ADR 0018 §7). Nothing here reads a clock (ADR 0016 R1).
//!
//! Accepted: RFC 3339 date-times (`2024-01-31T12:34:56Z`, with an optional fraction and a
//! `Z` or `±hh:mm` offset), as Bitwarden and `KeePass` write them, and integer Unix seconds or
//! milliseconds, as 1Password and Firefox write them. Only times from 1970-01-01 to
//! 9999-12-31 are kept; anything else is "unreadable", and the item's creation time then
//! comes from its first write (ADR 0018 §9).

/// 9999-12-31T23:59:59.999Z, in Unix milliseconds: the latest time kept.
pub(crate) const MAX_TIME_MS: u64 = 253_402_300_799_999;

/// Days from 1970-01-01 to the given proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The proleptic Gregorian date of a day count from 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

/// `true` in a leap year.
const fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Days in `month` of `year`.
const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Reads exactly `n` ASCII digits at the start of `s`.
fn digits(s: &str, n: usize) -> Option<(i64, &str)> {
    let head = s.get(..n)?;
    if !head.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((head.parse().ok()?, s.get(n..)?))
}

/// Consumes `c` at the start of `s`.
fn lit(s: &str, c: char) -> Option<&str> {
    s.strip_prefix(c)
}

/// An RFC 3339 date-time as Unix milliseconds. A leap second (`:60`) reads as `:59.999`.
pub(crate) fn rfc3339_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    let (year, s) = digits(s, 4)?;
    let s = lit(s, '-')?;
    let (month, s) = digits(s, 2)?;
    let s = lit(s, '-')?;
    let (day, s) = digits(s, 2)?;
    let s = s.strip_prefix(['T', 't', ' '])?;
    let (hour, s) = digits(s, 2)?;
    let s = lit(s, ':')?;
    let (minute, s) = digits(s, 2)?;
    let s = lit(s, ':')?;
    let (mut second, mut s) = digits(s, 2)?;
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut millis = 0i64;
    if let Some(rest) = s.strip_prefix('.') {
        let len = rest.bytes().take_while(u8::is_ascii_digit).count();
        if len == 0 || len > 9 {
            return None;
        }
        let frac = rest.get(..len)?;
        let first3: String = frac.chars().chain("000".chars()).take(3).collect();
        millis = first3.parse().ok()?;
        s = rest.get(len..)?;
    }
    if second == 60 {
        second = 59;
        millis = 999;
    }
    let offset_minutes = if s == "Z" || s == "z" {
        0
    } else {
        let (sign, rest) = match s.as_bytes().first()? {
            b'+' => (1, s.get(1..)?),
            b'-' => (-1, s.get(1..)?),
            _ => return None,
        };
        let (oh, rest) = digits(rest, 2)?;
        let rest = lit(rest, ':')?;
        let (om, rest) = digits(rest, 2)?;
        if !rest.is_empty() || oh > 23 || om > 59 {
            return None;
        }
        sign * (oh * 60 + om)
    };
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second - offset_minutes * 60;
    let ms = seconds.checked_mul(1_000)?.checked_add(millis)?;
    u64::try_from(ms).ok().filter(|ms| *ms <= MAX_TIME_MS)
}

/// Unix seconds as milliseconds, if in range.
pub(crate) fn seconds_ms(seconds: u64) -> Option<u64> {
    seconds.checked_mul(1_000).filter(|ms| *ms <= MAX_TIME_MS)
}

/// Unix milliseconds, if in range.
pub(crate) fn millis(ms: u64) -> Option<u64> {
    Some(ms).filter(|ms| *ms <= MAX_TIME_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            rfc3339_ms("2024-02-29T12:34:56.789Z"),
            Some(1_709_210_096_789)
        );
        assert_eq!(
            rfc3339_ms("2024-02-29T12:34:56.7Z"),
            Some(1_709_210_096_700)
        );
        assert_eq!(
            rfc3339_ms("2024-02-29T14:34:56+02:00"),
            Some(1_709_210_096_000)
        );
        assert_eq!(rfc3339_ms("2016-12-31T23:59:60Z"), Some(1_483_228_799_999));
        assert_eq!(rfc3339_ms("9999-12-31T23:59:59.999Z"), Some(MAX_TIME_MS));
        for bad in [
            "",
            "2023-02-29T00:00:00Z",
            "2024-13-01T00:00:00Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:00:00",
            "2024-01-01T00:00:00.Z",
            "2024-01-01T00:00:00.1234567890Z",
            "1969-12-31T23:59:59Z",
            "2024-01-01T00:00:00+2:00",
            "2024-1-01T00:00:00Z",
            "２０２４-01-01T00:00:00Z",
        ] {
            assert_eq!(rfc3339_ms(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn civil_round_trip() {
        for days in [-1_000_000i64, -1, 0, 1, 19_782, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, i64::from(m), i64::from(d)), days);
        }
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    #[test]
    fn integers() {
        assert_eq!(seconds_ms(1_700_000_000), Some(1_700_000_000_000));
        assert_eq!(seconds_ms(u64::MAX), None);
        assert_eq!(millis(MAX_TIME_MS + 1), None);
    }
}
