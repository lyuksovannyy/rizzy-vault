//! Text helpers shared by the readers: the input gate (size cap, byte-order mark, UTF-8), a
//! zeroizing string of fixed capacity, and small parsers of decimal numbers.

use zeroize::Zeroizing;

use crate::error::ImportError;

/// The UTF-8 byte-order mark, which some exporters write first.
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// Checks `input` against `max_len`, drops a leading byte-order mark, and checks that the rest
/// is UTF-8. Every text reader starts here.
///
/// # Errors
/// [`ImportError::TooLarge`] over the cap, [`ImportError::Encoding`] if it is not UTF-8.
pub(crate) fn utf8_input(input: &[u8], max_len: usize) -> Result<&str, ImportError> {
    if input.len() > max_len {
        return Err(ImportError::TooLarge);
    }
    let body = input.strip_prefix(BOM).unwrap_or(input);
    core::str::from_utf8(body).map_err(|_| ImportError::Encoding)
}

/// A zeroizing string with room for `capacity` bytes, allocated once. Readers size it to the
/// raw source text, which unescaping only shortens, so it never reallocates and leaves no
/// copy behind (CRYPTO.md §12.2).
pub(crate) fn with_capacity(capacity: usize) -> Zeroizing<String> {
    Zeroizing::new(String::with_capacity(capacity))
}

/// A zeroizing copy of `text`, allocated at its exact size.
pub(crate) fn copy(text: &str) -> Zeroizing<String> {
    let mut out = with_capacity(text.len());
    out.push_str(text);
    out
}

/// Parses an unsigned decimal integer: ASCII digits only, no sign, no leading `+`, at most
/// 20 digits. `None` otherwise or on overflow.
pub(crate) fn parse_u64(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > 20 {
        return None;
    }
    let mut value: u64 = 0;
    for b in text.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(value)
}

/// Parses a signed decimal integer: an optional `-`, then as [`parse_u64`]. `None` otherwise
/// or out of range.
pub(crate) fn parse_i64(text: &str) -> Option<i64> {
    match text.strip_prefix('-') {
        Some(digits) => {
            let magnitude = parse_u64(digits)?;
            0i64.checked_sub_unsigned(magnitude)
        }
        None => i64::try_from(parse_u64(text)?).ok(),
    }
}

/// `true` for the spellings of "true" the text formats use for a flag: `true`, `yes`, `1`,
/// in any case.
pub(crate) fn is_truthy(text: &str) -> bool {
    let text = text.trim();
    text.eq_ignore_ascii_case("true") || text.eq_ignore_ascii_case("yes") || text == "1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_gate() {
        assert_eq!(utf8_input(b"abc", 3), Ok("abc"));
        assert_eq!(utf8_input(b"abcd", 3), Err(ImportError::TooLarge));
        assert_eq!(utf8_input(b"\xEF\xBB\xBFabc", 6), Ok("abc"));
        assert_eq!(utf8_input(b"\xFF", 6), Err(ImportError::Encoding));
    }

    #[test]
    fn integers() {
        assert_eq!(parse_u64("0"), Some(0));
        assert_eq!(parse_u64("18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_u64("18446744073709551616"), None);
        assert_eq!(parse_u64(""), None);
        assert_eq!(parse_u64("+1"), None);
        assert_eq!(parse_u64("1.0"), None);
        assert_eq!(parse_i64("-5"), Some(-5));
        assert_eq!(parse_i64("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(parse_i64("-9223372036854775809"), None);
        assert_eq!(parse_i64("9223372036854775808"), None);
    }

    #[test]
    fn flags() {
        assert!(is_truthy("TRUE"));
        assert!(is_truthy(" yes "));
        assert!(is_truthy("1"));
        assert!(!is_truthy("0"));
        assert!(!is_truthy(""));
    }
}
