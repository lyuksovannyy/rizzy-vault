//! Fuzzes the field-key grammar (ADR 0018 §7, §10) and the tag keys built on it: never panic,
//! and an accepted key is exactly what its parts rebuild. Part of CRYPTO.md §15 item 7
//! ("item-record parsers …: the key grammar") and ADR 0018 §12.
//!
//! For each input:
//!
//! - [`FieldKeyRef::parse`]: if it accepts, the key is at most `MAX_KEY_LEN` bytes, copying it
//!   and rebuilding it from its parts give the input bytes (a fixed key from its names, an
//!   element key through [`FieldKey::element`] from its list, decoded element and attribute),
//!   and [`classify`] never panics. The record layer applies this parser to every key of every
//!   record (ADR 0018 §5 rules 2 and 3), so a panic is a remote crash and a wrong answer splits
//!   replicas.
//! - [`tag_name`]: for an accepted `tag/<hex>` key, a name it returns gives the same key again
//!   through [`tag_key`], and [`classify`] calls the key a known tag exactly when [`tag_name`]
//!   accepts it, so no writer check lets a key through that is not shown as a tag.
//! - [`tag_key`] on UTF-8 input: an accepted name gives a key that parses, and reads back to a
//!   name that gives the same key.
//!
//! Keys hold user content (tag names). The fuzzed keys are not real data.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::item::key::{FieldKey, FieldKeyRef, KeyKind, MAX_KEY_LEN};
use rizzy_core::item::schema::{KeyClass, classify};
use rizzy_core::item::tag::{tag_key, tag_name};

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = FieldKeyRef::parse(data) {
        assert!(data.len() <= MAX_KEY_LEN);
        assert_eq!(key.as_bytes(), data);
        assert_eq!(FieldKey::from_ref(key).as_bytes(), data);
        let _ = classify(key);
        match key.kind() {
            KeyKind::Fixed => {
                let names: Vec<&str> = key.fixed_names().expect("a fixed key").collect();
                assert!(names.len() >= 2);
                assert_eq!(names.join(".").as_bytes(), data);
            }
            KeyKind::Element => {
                let element = key.element_bytes().expect("an element key has an element");
                let list = key.list().expect("an element key has a list");
                let rebuilt = FieldKey::element(list, &element, key.attribute())
                    .expect("the parts of a key rebuild it");
                assert_eq!(rebuilt.as_bytes(), data);
            }
        }
        if let Ok(name) = tag_name(key) {
            let again = tag_key(&name).expect("a tag name read back is valid");
            assert_eq!(again.as_bytes(), data);
        }
        if key.list() == Some("tag") && key.attribute().is_none() {
            assert_eq!(
                matches!(classify(key), KeyClass::Known(_)),
                tag_name(key).is_ok()
            );
        }
    }
    if let Ok(text) = core::str::from_utf8(data)
        && let Ok(key) = tag_key(text)
    {
        let parsed = FieldKeyRef::parse(key.as_bytes()).expect("a tag key fits the grammar");
        let name = tag_name(parsed).expect("a tag key reads back");
        assert_eq!(tag_key(&name).expect("stable").as_bytes(), key.as_bytes());
    }
});
