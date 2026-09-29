//! Integer conversions between the protocol's unsigned types and SQL's signed 64-bit integer.
//!
//! Both engines store integers as signed 64-bit values (SQLite `INTEGER`, PostgreSQL `BIGINT`,
//! ADR 0011 point 4). The protocol's sequence numbers are `u64` and its epochs `u32` (CRYPTO.md
//! §4.4). Bit-casting a `u64` above `i64::MAX` into a negative `i64` would break every `<`, `>`
//! and `MAX` in SQL, so it is refused instead: [`u64_to_sql`] fails on it, and the schema's
//! `CHECK (x >= 0)` constraints refuse a negative value that got past a caller. Honest values
//! never come near the limit (a `device_seq` grows by one per op; an HLC is milliseconds shifted
//! left by 16 bits, about 2^57 today), so the refusal only ever meets a forged value.

use crate::error::Error;

/// A `u64` as an SQL integer.
///
/// # Errors
///
/// [`Error::OutOfRange`] naming `what` when `value` is above `i64::MAX`.
pub fn u64_to_sql(value: u64, what: &'static str) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::OutOfRange { what })
}

/// An SQL integer read back as a `u64`.
///
/// # Errors
///
/// [`Error::OutOfRange`] naming `what` when `value` is negative, which the schema's `CHECK`
/// constraints never let in.
pub fn sql_to_u64(value: i64, what: &'static str) -> Result<u64, Error> {
    u64::try_from(value).map_err(|_| Error::OutOfRange { what })
}

/// A `u32` as an SQL integer. Always fits.
#[must_use]
pub fn u32_to_sql(value: u32) -> i64 {
    i64::from(value)
}

/// An SQL integer read back as a `u32`.
///
/// # Errors
///
/// [`Error::OutOfRange`] naming `what` when `value` is negative or above `u32::MAX`.
pub fn sql_to_u32(value: i64, what: &'static str) -> Result<u32, Error> {
    u32::try_from(value).map_err(|_| Error::OutOfRange { what })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_round_trips_up_to_i64_max_and_refuses_above() {
        for v in [0, 1, u64::from(u32::MAX), 1 << 57, i64::MAX.unsigned_abs()] {
            let sql = u64_to_sql(v, "v").unwrap();
            assert_eq!(sql_to_u64(sql, "v").unwrap(), v);
        }
        for v in [i64::MAX.unsigned_abs() + 1, u64::MAX] {
            assert!(matches!(
                u64_to_sql(v, "v"),
                Err(Error::OutOfRange { what: "v" })
            ));
        }
        assert!(sql_to_u64(-1, "v").is_err());
        assert!(sql_to_u64(i64::MIN, "v").is_err());
    }

    #[test]
    fn u32_round_trips_and_refuses_out_of_range() {
        for v in [0, 1, u32::MAX] {
            assert_eq!(sql_to_u32(u32_to_sql(v), "e").unwrap(), v);
        }
        assert!(sql_to_u32(-1, "e").is_err());
        assert!(sql_to_u32(i64::from(u32::MAX) + 1, "e").is_err());
    }
}
