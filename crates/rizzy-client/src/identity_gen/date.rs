// SPDX-License-Identifier: AGPL-3.0-only

//! Civil (proleptic Gregorian) dates for the identity generator ([ADR 0079] §4 step 4).
//!
//! A birthday is a civil date with no time zone, so the arithmetic is on day numbers, not
//! instants. [`days_from_civil`] and [`civil_from_days`] are the public-domain algorithms of
//! H. Hinnant ("chrono-Compatible Low-Level Date Algorithms"), written out here with no
//! dependency and checked against each other over the whole supported range in the tests.
//!
//! [ADR 0079]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0079-identity-generator.md

use core::fmt;

/// The earliest year a [`CivilDate`] may have: four digits, so `YYYY` always has four.
pub const MIN_YEAR: i32 = 1000;
/// The latest year a [`CivilDate`] may have.
pub const MAX_YEAR: i32 = 9999;

/// A valid proleptic-Gregorian calendar date with a four-digit year.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CivilDate {
    /// The year, [`MIN_YEAR`]..=[`MAX_YEAR`].
    year: i32,
    /// The month, 1–12.
    month: u8,
    /// The day of the month.
    day: u8,
}

/// Whether `year` is a Gregorian leap year.
#[must_use]
pub(crate) const fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// The number of days in `month` (1–12) of `year`; 0 for a month out of range.
#[must_use]
pub(crate) const fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

impl CivilDate {
    /// The date `year-month-day`, or `None` if it is not a real date or the year is outside
    /// [`MIN_YEAR`]..=[`MAX_YEAR`].
    #[must_use]
    pub const fn new(year: i32, month: u8, day: u8) -> Option<Self> {
        if year < MIN_YEAR || year > MAX_YEAR || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        Some(Self { year, month, day })
    }

    /// Parses the RFC 3339 `full-date` form `YYYY-MM-DD` (exactly ten ASCII bytes).
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let b = text.as_bytes();
        if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
            return None;
        }
        let num = |range: core::ops::Range<usize>| -> Option<u32> {
            let digits = b.get(range)?;
            let mut n = 0u32;
            for d in digits {
                if !d.is_ascii_digit() {
                    return None;
                }
                n = n * 10 + u32::from(d - b'0');
            }
            Some(n)
        };
        let year = i32::try_from(num(0..4)?).ok()?;
        let month = u8::try_from(num(5..7)?).ok()?;
        let day = u8::try_from(num(8..10)?).ok()?;
        Self::new(year, month, day)
    }

    /// The year.
    #[must_use]
    pub const fn year(self) -> i32 {
        self.year
    }

    /// The month, 1–12.
    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }

    /// The day of the month, 1–31.
    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }

    /// This date `years` years earlier; 29 February becomes 28 February in a common year
    /// ([ADR 0079] §4 step 4). `None` below [`MIN_YEAR`].
    ///
    /// [ADR 0079]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0079-identity-generator.md
    #[must_use]
    pub fn minus_years(self, years: u16) -> Option<Self> {
        let year = self.year.checked_sub(i32::from(years))?;
        let day = self.day.min(days_in_month(year, self.month));
        Self::new(year, self.month, day)
    }

    /// The day number: days since 1970-01-01 (negative before it).
    #[must_use]
    pub const fn days(self) -> i64 {
        days_from_civil(self.year, self.month, self.day)
    }

    /// The date of day number `days`, or `None` outside the supported years.
    #[must_use]
    pub fn from_days(days: i64) -> Option<Self> {
        let (year, month, day) = civil_from_days(days)?;
        Self::new(year, month, day)
    }

    /// The completed age in years on `today` of a person born on this date: a 29 February
    /// birthday is reached on 1 March in a common year. `None` if `today` is earlier.
    #[must_use]
    pub fn age_on(self, today: Self) -> Option<u32> {
        let mut years = today.year.checked_sub(self.year)?;
        if (today.month, today.day) < (self.month, self.day) {
            years -= 1;
        }
        u32::try_from(years).ok()
    }
}

impl fmt::Display for CivilDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// Days since 1970-01-01 of a valid proleptic-Gregorian date (Hinnant's `days_from_civil`).
const fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let y = if month <= 2 {
        year as i64 - 1
    } else {
        year as i64
    };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = month as i64;
    let mp = if m > 2 { m - 3 } else { m + 9 }; // March = 0
    let doy = (153 * mp + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// The civil date of a day number (Hinnant's `civil_from_days`); `None` if the year does not
/// fit an `i32`.
fn civil_from_days(days: i64) -> Option<(i32, u8, u8)> {
    let z = days.checked_add(719_468)?;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = yoe + era * 400 + i64::from(month <= 2);
    Some((
        i32::try_from(year).ok()?,
        u8::try_from(month).ok()?,
        u8::try_from(day).ok()?,
    ))
}
