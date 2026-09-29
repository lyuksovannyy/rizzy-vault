//! Fuzzes the field-key grammar of the item record (ADR 0018 §7), which the record parser
//! applies to every key of every op and snapshot (§5 rules 2 and 3) and writers apply before
//! encrypting (§10). Keys are user content (a tag's name is in its key), so the check must
//! never panic, and every way of reaching it must agree.
//!
//! The record layer has no grammar of its own: it calls `rizzy-core`'s schema-layer parser,
//! [`FieldKeyRef::parse`], which the `item_key` target fuzzes for its parts and rebuilding.
//! This target checks the record layer's side of that contract. What runs on each input:
//!
//! - [`FieldKey::new`] on the input, when it is UTF-8. An accepted key is 1–160 bytes of ASCII,
//!   is never `@lifecycle`, and holds exactly the input.
//! - The input, as raw bytes whatever they are, as the key of the one write of an op, next to a
//!   Cleared value. [`parse_op`] must accept that op exactly when [`FieldKey::new`] accepts the
//!   key: the parser and the writers' check are one rule.
//! - [`FieldKeyRef::parse`] on the input must accept exactly when the record layer does: the
//!   record layer and the schema layer accept the same keys, so a key the record layer carries
//!   is always one the schema layer can classify. Since [`FieldKey::new`] calls that parser,
//!   this checks the wiring between the layers, not the grammar; the grammar is checked against
//!   an independent ABNF matcher by `rizzy-core`'s `grammar_agrees_with_the_abnf` properties.
//!
//! Part of CRYPTO.md §15 item 7, "item-record parsers" (ADR 0018 §12: the key grammar).
//!
//! ```text
//! cargo +nightly fuzz run record_key
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::item::key::FieldKeyRef;
use rizzy_sync::record::{FieldKey, MAX_KEY_LEN, parse_op};

fuzz_target!(|data: &[u8]| {
    let accepted = core::str::from_utf8(data)
        .ok()
        .and_then(|text| FieldKey::new(text).ok());
    if let Some(key) = accepted {
        assert_eq!(key.expose_secret().as_bytes(), data);
        assert!((1..=MAX_KEY_LEN).contains(&data.len()));
        assert!(data.is_ascii());
        assert!(!key.is_lifecycle());
    }
    assert_eq!(FieldKeyRef::parse(data).is_ok(), accepted.is_some());

    let Ok(len) = u32::try_from(data.len()) else {
        return;
    };
    // op data: kind 0x01, lifecycle Active, one write of `data` with a Cleared value.
    let op = [
        &[0x01, 0x01, 0x00, 0x01][..],
        &len.to_be_bytes(),
        data,
        &[0x00; 4],
    ]
    .concat();
    assert_eq!(parse_op(&op).is_ok(), accepted.is_some());
});
