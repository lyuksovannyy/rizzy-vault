//! The field-key grammar of ADR 0018 §7 (RFC 5234 ABNF):
//!
//! ```text
//! field_key = fixed / element
//! fixed     = name 1*( "." name )                    ; login.password
//! element   = name "/" elem [ "/" name ]              ; uri/<id>/value, tag/<hex>
//! name      = %x61-7A *31( %x61-7A / DIGIT / "_" )    ; 1-32 bytes
//! elem      = 1*64( 2hexlc )                          ; a random 16-byte id is 32 digits
//! hexlc     = DIGIT / %x61-66
//! ```
//!
//! The length rules are in the productions: a `name` is 1–32 bytes, an `elem` an even number
//! of lowercase hex digits from 2 to 128. The 1–160-byte bound on the whole key is a separate
//! check (ADR 0018 §10, §5 rule 2), made by the callers. The grammar is ASCII only, so a key
//! it accepts is valid UTF-8.
//!
//! The productions cannot overlap: a `name` holds no `.` or `/`, so the byte after the first
//! `name` decides between `fixed` and `element`, and each later token is read to its end.

/// Whether `b` may follow the first byte of a `name`: `%x61-7A / DIGIT / "_"`.
const fn is_name_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
}

/// Whether `b` is a `hexlc`: `DIGIT / %x61-66`.
const fn is_hexlc(b: u8) -> bool {
    b.is_ascii_digit() || matches!(b, b'a'..=b'f')
}

/// Longest `name`, in bytes.
const NAME_MAX: usize = 32;

/// Longest `elem`, in hex digits.
const ELEM_MAX: usize = 128;

/// Reads a `name` starting at `start`. Returns the offset just past it, or the offset of the
/// first byte that breaks it.
fn name(key: &[u8], start: usize) -> Result<usize, usize> {
    match key.get(start) {
        Some(b) if b.is_ascii_lowercase() => {}
        _ => return Err(start),
    }
    let tail = key.get(start + 1..).unwrap_or_default();
    let len = 1 + tail.iter().take_while(|&&b| is_name_byte(b)).count();
    if len > NAME_MAX {
        Err(start + NAME_MAX)
    } else {
        Ok(start + len)
    }
}

/// Reads an `elem` starting at `start`. Returns the offset just past it, or the offset of the
/// first byte that breaks it.
fn elem(key: &[u8], start: usize) -> Result<usize, usize> {
    let tail = key.get(start..).unwrap_or_default();
    let len = tail.iter().take_while(|&&b| is_hexlc(b)).count();
    if len == 0 {
        Err(start)
    } else if len > ELEM_MAX {
        Err(start + ELEM_MAX)
    } else if len % 2 == 1 {
        // An odd digit count: the byte where the last digit's pair belongs.
        Err(start + len)
    } else {
        Ok(start + len)
    }
}

/// Checks `key` against the grammar. `None` if it matches, otherwise the offset of the first
/// byte the grammar refuses (`key.len()` when the key ends too early).
pub(super) fn grammar_error(key: &[u8]) -> Option<usize> {
    let mut at = match name(key, 0) {
        Ok(end) => end,
        Err(bad) => return Some(bad),
    };
    match key.get(at) {
        Some(b'.') => {
            // fixed = name 1*( "." name )
            while key.get(at) == Some(&b'.') {
                at = match name(key, at + 1) {
                    Ok(end) => end,
                    Err(bad) => return Some(bad),
                };
            }
        }
        Some(b'/') => {
            // element = name "/" elem [ "/" name ]
            at = match elem(key, at + 1) {
                Ok(end) => end,
                Err(bad) => return Some(bad),
            };
            if key.get(at) == Some(&b'/') {
                at = match name(key, at + 1) {
                    Ok(end) => end,
                    Err(bad) => return Some(bad),
                };
            }
        }
        // A lone `name` is neither production.
        _ => return Some(at),
    }
    (at != key.len()).then_some(at)
}

#[cfg(test)]
mod tests {
    //! The grammar on the keys of ADR 0018 §7's table and the §12 negative cases (odd hex count,
    //! a 33-byte name, uppercase hex), each boundary of `name` and `elem`, the offset of the
    //! first refused byte, and, as a property, agreement with an independent regular-language
    //! matcher written from the ABNF.

    use proptest::prelude::*;

    use super::grammar_error;

    fn ok(key: &str) {
        assert_eq!(grammar_error(key.as_bytes()), None, "{key}");
    }

    fn bad(key: &str, at: usize) {
        assert_eq!(grammar_error(key.as_bytes()), Some(at), "{key}");
    }

    #[test]
    fn the_keys_of_the_table_match() {
        let id = "00112233445566778899aabbccddeeff";
        for key in [
            "item.type",
            "item.name",
            "item.notes",
            "item.favorite",
            "import.created_ms",
            "login.username",
            "login.password",
            "login.totp",
            "card.exp_month",
            "identity.drivers_license",
            "vault.name",
            "tag/61",
            "tag/6162",
            "a.b.c.d",
            "x9_.y",
        ] {
            ok(key);
        }
        for attr in ["label", "kind", "value", "order"] {
            ok(&format!("field/{id}/{attr}"));
        }
        ok(&format!("uri/{id}/match"));
        ok(&format!("pwhist/{id}/ms"));
        ok(&format!("share/{id}/secret"));
    }

    #[test]
    fn negative_cases() {
        // ADR 0018 §12: an odd hex count, a 33-byte name, uppercase hex.
        bad("uri/abc/value", 7);
        bad(&format!("{}.a", "a".repeat(33)), 32);
        bad("tag/6A", 5);
        bad("tag/AA", 4);
        bad("tag/a", 5);
        // A lone name, empty parts, stray separators, a bad first byte.
        bad("notes", 5);
        bad("", 0);
        bad("item.", 5);
        bad(".item", 0);
        bad("item..name", 5);
        bad("item.name.", 10);
        bad("tag/", 4);
        bad("tag/61/", 7);
        bad("tag/61/value/x", 12);
        bad("tag/61.x", 6);
        bad("item.name/61", 9);
        bad("Item.name", 0);
        bad("1tem.name", 0);
        bad("_tem.name", 0);
        bad("item.Name", 5);
        bad("item.na-me", 7);
        bad("@lifecycle", 0);
        bad("item.name\u{e9}", 9);
        bad("item.name\0", 9);
    }

    #[test]
    fn boundaries() {
        let n32 = "a".repeat(32);
        ok(&format!("{n32}.{n32}"));
        bad(&format!("{n32}b.x"), 32);
        let hex128 = "ab".repeat(64);
        ok(&format!("tag/{hex128}"));
        ok(&format!("x/{hex128}/{n32}"));
        bad(&format!("tag/{hex128}00"), 4 + 128);
        bad(&format!("tag/{}", "a".repeat(127)), 4 + 127);
        ok("tag/00");
    }

    /// An independent matcher: split on the separators and check each token, instead of
    /// scanning byte by byte.
    fn oracle(key: &str) -> bool {
        let name = |s: &str| {
            let b = s.as_bytes();
            (1..=32).contains(&b.len())
                && b.first().is_some_and(u8::is_ascii_lowercase)
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
        };
        let elem = |s: &str| {
            let b = s.as_bytes();
            (2..=128).contains(&b.len())
                && b.len().is_multiple_of(2)
                && b.iter()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        };
        let slash: Vec<&str> = key.split('/').collect();
        match slash.as_slice() {
            [single] => {
                let parts: Vec<&str> = single.split('.').collect();
                parts.len() >= 2 && parts.iter().all(|p| name(p))
            }
            [n, e] => name(n) && elem(e),
            [n, e, m] => name(n) && elem(e) && name(m),
            _ => false,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 4_000, failure_persistence: None, ..ProptestConfig::default() })]

        /// Keys over a small alphabet that reaches every production and every failure.
        #[test]
        fn agrees_with_the_oracle(key in "[a-fA_0-9./]{0,40}") {
            prop_assert_eq!(grammar_error(key.as_bytes()).is_none(), oracle(&key));
            if let Some(at) = grammar_error(key.as_bytes()) {
                prop_assert!(at <= key.len());
            }
        }

        #[test]
        fn never_panics_on_bytes(key in prop::collection::vec(any::<u8>(), 0..300)) {
            if let Some(at) = grammar_error(&key) {
                prop_assert!(at <= key.len());
            }
        }
    }
}
