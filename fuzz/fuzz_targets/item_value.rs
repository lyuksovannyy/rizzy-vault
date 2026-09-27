//! Fuzzes the item value decoder (ADR 0018 §6, §10): never panics, and a value it accepts is
//! the one encoding of that value. Part of CRYPTO.md §15 item 7 ("item-record parsers …: the
//! value decoder") and ADR 0018 §12.
//!
//! For each input:
//!
//! - [`ValueRef::decode`]: if it accepts, `encode()` gives back exactly the input bytes (each
//!   value has one encoding), Cleared is exactly the empty input, and the input is at most
//!   `MAX_VALUE_LEN` bytes. If it refuses, the input is not empty: a refusal means only "show as
//!   unsupported value", and Cleared is never unsupported.
//! - [`Value::copy_from_encoded`]: any input up to `MAX_VALUE_LEN` bytes is carried verbatim,
//!   supported or not, because an invalid value never rejects its record (ADR 0018 §6, §11).
//! - [`read_value`] and [`CustomFieldKind`]: reading the value against every expected type, and
//!   as a custom field of every kind, never panics.
//!
//! In production the decoder runs on values inside decrypted records, so fuzzing it on raw
//! bytes covers a malicious writer who holds the item key (from M9, a vault member). The fuzzed
//! values are not real secrets; `expose_secret()` is called only to compare them.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::item::schema::{CustomFieldKind, Expected, read_value};
use rizzy_core::item::value::{MAX_VALUE_LEN, Value, ValueRef};

fuzz_target!(|data: &[u8]| {
    match ValueRef::decode(data) {
        Ok(value) => {
            assert!(data.len() <= MAX_VALUE_LEN);
            assert_eq!(value.is_cleared(), data.is_empty());
            let again = value.encode().expect("a decoded value encodes");
            assert_eq!(again.expose_secret(), data);
            for kind in [
                CustomFieldKind::Text,
                CustomFieldKind::Hidden,
                CustomFieldKind::Boolean,
                CustomFieldKind::Unknown,
            ] {
                let _ = kind.accepts(&value);
            }
        }
        Err(_) => assert!(!data.is_empty(), "Cleared is never unsupported"),
    }
    match Value::copy_from_encoded(data) {
        Ok(carried) => assert_eq!(carried.expose_secret(), data),
        Err(_) => assert!(data.len() > MAX_VALUE_LEN),
    }
    for expected in [
        Expected::Text,
        Expected::Bool,
        Expected::U64,
        Expected::Enum,
        Expected::SortKey,
        Expected::Bytes { len: 32 },
        Expected::CustomFieldValue,
        Expected::TagMarker,
    ] {
        if let Some(value) = read_value(expected, data) {
            assert!(expected.accepts(&value));
        }
    }
});
