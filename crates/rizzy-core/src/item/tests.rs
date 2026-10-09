//! Unit tests of the item schema (ADR 0018 §6–§9, §11 and the schema-layer parts of §12): one
//! test group per rule, each rejection with the input that breaks only that rule, the
//! redacted `Debug` output of every type that holds a key or value, and a simulated newer
//! client (§11).

use core::cmp::Ordering;

use super::display::{
    Candidate, DEFAULT_TRASH_RETENTION_MS, FieldDisplay, Lifecycle, created_ms, displayed_value,
    hlc_ms, modified_ms, purge_due_ms, resolve_field, resolve_lifecycle, trashed_at_ms,
};
use super::key::{
    ELEMENT_ID_LEN, ElementId, FieldKey, FieldKeyRef, KeyError, KeyKind, MAX_KEY_LEN, hex_digit,
    hex_value, is_lower_hex,
};
use super::order::{
    AttributeRole, ListEntry, OrderError, attribute_role, compare_list_entries, element_exists,
    evenly_spaced, sort_key_between,
};
use super::schema::{
    self, Applies, Concealment, CustomFieldKind, Expected, FIXED_KEYS, KeyClass, KeySpec,
    ReservedFor, WriteError, WriteMode, WriteSource, Writers, check_carried, check_create,
    check_write, classify, read_value,
};
use super::tag::{TagError, tag_key, tag_name};
use super::types::{ItemType, ItemTypeClass, SupportedType, effective_vault_settings};
use super::value::{
    MAX_SORT_KEY_LEN, MAX_VALUE_LEN, SortKey, Value, ValueError, ValueRef, ValueType,
};
use super::{
    ITEM_SCHEMA_VERSION, LIFECYCLE_ACTIVE, LIFECYCLE_KEY, LIFECYCLE_TRASHED, SchemaVersion,
};
use crate::ids::{DeviceId, ItemId};
use crate::secret::wipe_hooks;
use crate::test_util::seeded_rng;

/// A 16-byte element id in hex: 32 digits.
const ID: &str = "000102030405060708090a0b0c0d0e0f";

/// `list/ID/attribute`.
fn element_key(list: &str, attribute: &str) -> String {
    format!("{list}/{ID}/{attribute}")
}

/// Parses a key that must be valid.
fn key(text: &str) -> FieldKeyRef<'_> {
    FieldKeyRef::parse_str(text).unwrap_or_else(|e| panic!("{text:?}: {e:?}"))
}

/// The parse error of a key that must be invalid.
fn key_err(bytes: &[u8]) -> KeyError {
    match FieldKeyRef::parse(bytes) {
        Ok(_) => panic!("{:?} accepted", String::from_utf8_lossy(bytes)),
        Err(e) => e,
    }
}

/// A candidate with device id `[device; 16]`.
fn cand(hlc: u64, device: u8, seq: u64, value: &[u8]) -> Candidate<'_> {
    Candidate {
        hlc,
        device_id: DeviceId::from_bytes([device; 16]),
        seq,
        value,
    }
}

// ---------------------------------------------------------------------------------------------
// §7 grammar
// ---------------------------------------------------------------------------------------------

#[test]
fn grammar_accepts_fixed_keys() {
    for text in [
        "a.b",
        "item.type",
        "login.password",
        "a.b.c.d",
        "a1_b.c_2",
        "z9.y_",
        &format!("{}.{}", "a".repeat(32), "b".repeat(32)),
    ] {
        let k = key(text);
        assert_eq!(k.kind(), KeyKind::Fixed, "{text}");
        assert_eq!(k.as_str(), text);
        assert_eq!(k.as_bytes(), text.as_bytes());
        assert_eq!(k.list(), None);
        assert_eq!(k.element(), None);
        assert_eq!(k.attribute(), None);
        let names: Vec<&str> = k.fixed_names().expect("fixed").collect();
        assert_eq!(names.join("."), text);
        assert_eq!(k.namespace(), names[0]);
    }
}

#[test]
fn grammar_accepts_element_keys() {
    let uri = element_key("uri", "value");
    let k = key(&uri);
    assert_eq!(k.kind(), KeyKind::Element);
    assert_eq!(k.list(), Some("uri"));
    assert_eq!(k.namespace(), "uri");
    assert_eq!(k.element(), Some(ID));
    assert_eq!(k.attribute(), Some("value"));
    assert!(k.fixed_names().is_none());

    for (text, list, element) in [
        ("tag/61", "tag", "61"),
        ("tag/6162", "tag", "6162"),
        ("a/00", "a", "00"),
        ("x_1/abcdef", "x_1", "abcdef"),
    ] {
        let k = key(text);
        assert_eq!(k.list(), Some(list));
        assert_eq!(k.element(), Some(element));
        assert_eq!(k.attribute(), None, "{text}");
    }
    // The longest `elem`: 64 bytes, 128 digits.
    let long = format!("t/{}", "ab".repeat(64));
    assert_eq!(key(&long).element().map(str::len), Some(128));
}

#[test]
fn grammar_length_rule_is_separate() {
    // 160 bytes exactly: accepted. 161: rejected, although the grammar alone allows it
    // (ADR 0018 §7, §10; §12 "rule 2 a 161-byte key").
    let fixed_160 = format!(
        "{}.{}.{}.{}.{}",
        "a".repeat(32),
        "b".repeat(32),
        "c".repeat(32),
        "d".repeat(32),
        "e".repeat(28)
    );
    assert_eq!(fixed_160.len(), MAX_KEY_LEN);
    key(&fixed_160);
    let fixed_161 = format!("{fixed_160}f");
    assert_eq!(fixed_161.len(), 161);
    assert_eq!(key_err(fixed_161.as_bytes()), KeyError::Length);
    // An element key that the grammar allows but that is 161 bytes.
    let element_161 = format!("{}/{}", "a".repeat(32), "ab".repeat(64));
    assert_eq!(element_161.len(), 161);
    assert_eq!(key_err(element_161.as_bytes()), KeyError::Length);
    assert_eq!(key_err(b""), KeyError::Length);
}

#[test]
fn grammar_rejects_bad_names() {
    // ADR 0018 §12: "a 33-byte name".
    let name_33 = format!("{}.b", "a".repeat(33));
    assert_eq!(key_err(name_33.as_bytes()), KeyError::Name);
    let attribute_33 = format!("uri/{ID}/{}", "a".repeat(33));
    assert_eq!(key_err(attribute_33.as_bytes()), KeyError::Name);
    for text in [
        "Login.password",
        "login.Password",
        "_a.b",
        "1a.b",
        "a..b",
        "a.b.",
        ".a.b",
        "a-b.c",
        "a.b c",
        "a.b\u{e9}",
        "\u{e9}a.b",
        "@lifecycle",
        "a.b\0",
        "a.b/00",
        "/00",
        "A/00",
        "a/00/",
        "a/00/B",
        "a/00/1x",
    ] {
        assert_eq!(key_err(text.as_bytes()), KeyError::Name, "{text:?}");
    }
    assert_eq!(key_err(&[b'a', b'.', 0xff]), KeyError::Name);
    assert_eq!(key_err(LIFECYCLE_KEY.as_bytes()), KeyError::Name);
}

#[test]
fn grammar_rejects_bad_elements() {
    // ADR 0018 §12: an odd hex count (`uri/abc/value`) and uppercase hex.
    for text in [
        "uri/abc/value",
        "uri/ABCD/value",
        "uri/0A/value",
        "tag/",
        "tag/0g",
        "tag/6",
        "a//b",
        "a/ 0",
        "a/0x",
    ] {
        assert_eq!(key_err(text.as_bytes()), KeyError::Element, "{text:?}");
    }
    // 130 digits (65 bytes) in a key that is still short enough.
    let long = format!("t/{}", "ab".repeat(65));
    assert!(long.len() <= MAX_KEY_LEN);
    assert_eq!(key_err(long.as_bytes()), KeyError::Element);
}

#[test]
fn grammar_rejects_bad_shapes() {
    for text in [
        "a",
        "notes",
        "item",
        "a/00/b/c",
        "a/00/b/",
        "uri/00/value/x",
    ] {
        assert_eq!(key_err(text.as_bytes()), KeyError::Shape, "{text:?}");
    }
}

#[test]
fn lifecycle_key_sorts_before_every_grammar_key() {
    // `@` (0x40) is below every first byte a `name` may have (a-z), so `@lifecycle` is the
    // first register of a live snapshot (ADR 0018 §3).
    for first in b'a'..=b'z' {
        assert!(LIFECYCLE_KEY.as_bytes()[0] < first);
    }
}

#[test]
fn element_builder_matches_the_grammar() {
    let id = ElementId::from_bytes(core::array::from_fn(|i| u8::try_from(i).unwrap()));
    let built = id.key("uri", "value").unwrap();
    assert_eq!(built.as_str(), element_key("uri", "value"));
    assert_eq!(built.as_bytes(), element_key("uri", "value").as_bytes());
    let view = built.as_key();
    assert_eq!(view.list(), Some("uri"));
    assert_eq!(view.element(), Some(ID));
    assert_eq!(view.attribute(), Some("value"));

    let tag = FieldKey::element("tag", b"ab", None).unwrap();
    assert_eq!(tag.as_str(), "tag/6162");
    assert_eq!(tag.as_key().attribute(), None);

    assert_eq!(
        FieldKey::element("Uri", &[1], Some("value")).map(|_| ()),
        Err(KeyError::Name)
    );
    assert_eq!(
        FieldKey::element("uri", &[], Some("value")).map(|_| ()),
        Err(KeyError::Element)
    );
    assert_eq!(
        FieldKey::element("uri", &[1], Some("Value")).map(|_| ()),
        Err(KeyError::Name)
    );
    assert_eq!(
        FieldKey::element("uri", &[1], Some("a/b")).map(|_| ()),
        Err(KeyError::Shape)
    );
    // 65 bytes is 130 digits: too long for `elem`, though the key fits 160 bytes.
    assert_eq!(
        FieldKey::element("t", &[1; 65], None).map(|_| ()),
        Err(KeyError::Element)
    );
    // Over 160 bytes: refused before anything is allocated.
    assert_eq!(
        FieldKey::element(&"a".repeat(32), &[1; 64], None).map(|_| ()),
        Err(KeyError::Length)
    );
    assert_eq!(
        FieldKey::element("t", &vec![1; 1 << 20], None).map(|_| ()),
        Err(KeyError::Length)
    );
}

#[test]
fn owned_keys_copy_parsed_keys() {
    let text = element_key("field", "label");
    let owned = FieldKey::parse(text.as_bytes()).unwrap();
    assert_eq!(owned.as_str(), text);
    let view = owned.as_key();
    assert_eq!(view.list(), Some("field"));
    assert_eq!(view.attribute(), Some("label"));
    assert_eq!(FieldKey::parse(b"Bad").map(|_| ()), Err(KeyError::Name));
    let copy = FieldKey::from_ref(key("login.totp"));
    assert_eq!(copy.as_str(), "login.totp");
    assert_eq!(copy.as_key().kind(), KeyKind::Fixed);
}

#[test]
fn element_ids_come_from_the_injected_rng() {
    let a = ElementId::generate(&mut seeded_rng(1));
    let b = ElementId::generate(&mut seeded_rng(1));
    let c = ElementId::generate(&mut seeded_rng(2));
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.as_bytes().len(), ELEMENT_ID_LEN);
    let k = a.key("pwhist", "ms").unwrap();
    assert_eq!(k.as_key().element().map(str::len), Some(32));
}

#[test]
fn element_bytes_invert_the_builder() {
    let bytes: Vec<u8> = (0..=255).step_by(5).collect();
    let bytes = &bytes[..40];
    let built = FieldKey::element("x", bytes, Some("y")).unwrap();
    let out = built.as_key().element_bytes().unwrap();
    assert_eq!(out.as_slice(), bytes);
    assert_eq!(out.capacity(), bytes.len());
    assert!(key("a.b").element_bytes().is_none());
}

#[test]
fn hex_helpers_are_exact_for_every_byte() {
    for b in 0..=u8::MAX {
        let expected = b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
        assert_eq!(is_lower_hex(b) == 1, expected, "{b:#04x}");
        assert!(is_lower_hex(b) <= 1);
    }
    for n in 0..16u8 {
        let digit = hex_digit(n);
        assert_eq!(digit, b"0123456789abcdef"[usize::from(n)]);
        assert_eq!(hex_value(digit), n);
        // Only the low four bits count.
        assert_eq!(hex_digit(n | 0xf0), digit);
    }
}

#[test]
fn key_types_never_print_the_key() {
    let text = "tag/73656372657420746167";
    let parsed = key(text);
    let owned = FieldKey::parse(text.as_bytes()).unwrap();
    let id = ElementId::from_bytes([0x5a; ELEMENT_ID_LEN]);
    let out = format!("{parsed:?} {owned:?} {id:?} {parsed:#?} {owned:#?} {id:#?}");
    assert!(!out.contains("7365"), "{out}");
    assert!(!out.contains("tag"), "{out}");
    assert!(!out.contains("5a"), "{out}");
    assert!(!out.contains("90"), "{out}");
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn key_errors_carry_no_input() {
    for e in [
        KeyError::Length,
        KeyError::Name,
        KeyError::Element,
        KeyError::Shape,
    ] {
        let text = e.to_string();
        assert!(!text.is_empty());
        assert!(!text.contains('/'), "{text}");
    }
}

// ---------------------------------------------------------------------------------------------
// §7 tags
// ---------------------------------------------------------------------------------------------

#[test]
fn tag_keys_are_the_hex_of_the_nfc_name() {
    for (name, expected) in [
        ("a", "tag/61"),
        ("ab", "tag/6162"),
        ("Work", "tag/576f726b"),
        ("work", "tag/776f726b"),
        ("Work/Email", "tag/576f726b2f456d61696c"),
        // Precomposed é, and e + combining acute: one key (NFC).
        ("\u{e9}", "tag/c3a9"),
        ("e\u{301}", "tag/c3a9"),
        // A compatibility ligature stays (NFC, not NFKC).
        ("\u{fb01}", "tag/efac81"),
        // No trimming.
        (" a ", "tag/206120"),
        // A format character (Cf) is not Cc.
        ("a\u{200b}", "tag/61e2808b"),
    ] {
        assert_eq!(tag_key(name).unwrap().as_str(), expected, "{name:?}");
    }
}

#[test]
fn tag_names_are_1_to_64_bytes_after_nfc() {
    let max = "a".repeat(64);
    let k = tag_key(&max).unwrap();
    assert_eq!(k.as_str().len(), 4 + 128);
    assert_eq!(tag_key(&"a".repeat(65)).map(|_| ()), Err(TagError::Length));
    assert_eq!(tag_key("").map(|_| ()), Err(TagError::Length));
    // 32 × U+0344 is 64 bytes, but NFC expands each to U+0308 U+0301: 128 bytes.
    let expanding = "\u{344}".repeat(32);
    assert_eq!(expanding.len(), 64);
    assert_eq!(tag_key(&expanding).map(|_| ()), Err(TagError::Length));
    // 65 bytes of NFD that NFC composes to 64 or fewer are accepted.
    let composing = "e\u{301}".repeat(21) + "ab";
    assert_eq!(composing.len(), 65);
    assert!(tag_key(&composing).is_ok());
}

#[test]
fn tag_names_contain_no_cc() {
    for name in ["\u{7}", "a\tb", "a\nb", "\u{7f}", "x\u{85}", "\u{9f}", "\0"] {
        assert_eq!(
            tag_key(name).map(|_| ()),
            Err(TagError::Control),
            "{name:?}"
        );
    }
}

#[test]
fn tag_name_reads_back_what_tag_key_wrote() {
    for name in [
        "a",
        "Work/Email",
        "\u{e9}t\u{e9}",
        "\u{1f600}",
        &"z".repeat(64),
    ] {
        let k = tag_key(name).unwrap();
        let back = tag_name(k.as_key()).unwrap();
        assert_eq!(back.as_str(), name);
        assert_eq!(tag_key(&back).unwrap().as_str(), k.as_str());
    }
    // An NFD name reads back as its NFC form.
    let k = tag_key("e\u{301}").unwrap();
    assert_eq!(tag_name(k.as_key()).unwrap().as_str(), "\u{e9}");
}

#[test]
fn tag_name_refuses_keys_no_writer_produces() {
    for text in ["item.name", "tag/61/color", "uri/61/value", "tags/61"] {
        assert_eq!(
            tag_name(key(text)).map(|_| ()),
            Err(TagError::NotTagKey),
            "{text}"
        );
    }
    // Not UTF-8.
    assert_eq!(tag_name(key("tag/ff")).map(|_| ()), Err(TagError::Encoding));
    assert_eq!(tag_name(key("tag/c3")).map(|_| ()), Err(TagError::Encoding));
    // e + combining acute: UTF-8, but not NFC.
    assert_eq!(
        tag_name(key("tag/65cc81")).map(|_| ()),
        Err(TagError::NotNormalized)
    );
    // A C0 control.
    assert_eq!(tag_name(key("tag/07")).map(|_| ()), Err(TagError::Control));
}

// ---------------------------------------------------------------------------------------------
// §6 values
// ---------------------------------------------------------------------------------------------

#[test]
fn value_type_ids() {
    for (t, id) in ValueType::ALL.iter().zip(1u8..) {
        assert_eq!(t.id(), id);
        assert_eq!(ValueType::from_id(id), Some(*t));
    }
    for id in [0x00, 0x07, 0x08, 0x80, 0xff] {
        assert_eq!(ValueType::from_id(id), None);
    }
    let known = (0..=u8::MAX)
        .filter(|id| ValueType::from_id(*id).is_some())
        .count();
    assert_eq!(known, 6);
}

#[test]
fn values_encode_as_type_byte_and_payload() {
    assert_eq!(Value::cleared().expose_secret(), b"");
    assert_eq!(Value::text("").unwrap().expose_secret(), [0x01]);
    assert_eq!(
        Value::text("p\u{e4}ss").unwrap().expose_secret(),
        b"\x01p\xc3\xa4ss"
    );
    // Text is stored as entered: NFD stays NFD, spaces stay.
    assert_eq!(
        Value::text(" e\u{301} ").unwrap().expose_secret(),
        b"\x01 e\xcc\x81 "
    );
    assert_eq!(
        Value::bytes(&[0, 0xff]).unwrap().expose_secret(),
        [0x02, 0x00, 0xff]
    );
    assert_eq!(Value::bytes(&[]).unwrap().expose_secret(), [0x02]);
    assert_eq!(Value::bool(false).expose_secret(), [0x03, 0x00]);
    assert_eq!(Value::bool(true).expose_secret(), [0x03, 0x01]);
    assert_eq!(
        Value::u64(0x0102_0304_0506_0708).expose_secret(),
        [0x04, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(
        Value::enumeration(0xf001).expose_secret(),
        [0x05, 0xf0, 0x01]
    );
    let sort = SortKey::from_slice(&[0x80, 0x01]).unwrap();
    assert_eq!(Value::sort_key(&sort).expose_secret(), [0x06, 0x80, 0x01]);
}

#[test]
fn values_decode_to_their_type() {
    assert!(matches!(ValueRef::decode(b""), Ok(ValueRef::Cleared)));
    assert!(matches!(ValueRef::decode(b"\x01"), Ok(ValueRef::Text(""))));
    assert!(matches!(
        ValueRef::decode(b"\x01hi"),
        Ok(ValueRef::Text("hi"))
    ));
    assert!(matches!(
        ValueRef::decode(b"\x02"),
        Ok(ValueRef::Bytes(b""))
    ));
    assert!(matches!(
        ValueRef::decode(b"\x02\x00\xff"),
        Ok(ValueRef::Bytes([0, 0xff]))
    ));
    assert!(matches!(
        ValueRef::decode(b"\x03\x00"),
        Ok(ValueRef::Bool(false))
    ));
    assert!(matches!(
        ValueRef::decode(b"\x03\x01"),
        Ok(ValueRef::Bool(true))
    ));
    assert!(matches!(
        ValueRef::decode(&[4, 0, 0, 0, 0, 0, 0, 1, 0]),
        Ok(ValueRef::U64(256))
    ));
    assert!(matches!(
        ValueRef::decode(&[5, 0xf0, 0x01]),
        Ok(ValueRef::Enum(0xf001))
    ));
    assert!(matches!(
        ValueRef::decode(&[6, 0x00, 0x01]),
        Ok(ValueRef::SortKey([0, 1]))
    ));
    let max_sort = [&[6u8][..], &[0xff; MAX_SORT_KEY_LEN]].concat();
    assert!(matches!(
        ValueRef::decode(&max_sort),
        Ok(ValueRef::SortKey(_))
    ));
}

#[test]
fn malformed_and_unknown_values_are_errors_not_rejections() {
    for (encoded, expected) in [
        (vec![0x00], ValueError::UnknownType),
        (vec![0x00, 1, 2], ValueError::UnknownType),
        (vec![0x07], ValueError::UnknownType),
        (vec![0xff, 0x01], ValueError::UnknownType),
        (vec![0x01, 0xff], ValueError::Malformed),
        (vec![0x01, b'a', 0xc3], ValueError::Malformed),
        (vec![0x03], ValueError::Malformed),
        (vec![0x03, 0x02], ValueError::Malformed),
        (vec![0x03, 0x01, 0x00], ValueError::Malformed),
        (vec![0x04, 0, 0, 0, 0, 0, 0, 1], ValueError::Malformed),
        (vec![0x04, 0, 0, 0, 0, 0, 0, 0, 1, 0], ValueError::Malformed),
        (vec![0x05, 1], ValueError::Malformed),
        (vec![0x05, 1, 2, 3], ValueError::Malformed),
        (vec![0x06], ValueError::Malformed),
        (vec![0x06, 0x00], ValueError::Malformed),
        (vec![0x06, 0x01, 0x00], ValueError::Malformed),
        (
            [&[6u8][..], &[1; MAX_SORT_KEY_LEN + 1]].concat(),
            ValueError::Malformed,
        ),
    ] {
        assert_eq!(
            ValueRef::decode(&encoded).map(|_| ()),
            Err(expected),
            "{encoded:02x?}"
        );
        // Carried verbatim anyway (ADR 0018 §6, §11).
        let carried = Value::copy_from_encoded(&encoded).unwrap();
        assert_eq!(carried.expose_secret(), encoded.as_slice());
        assert!(!carried.is_cleared());
        assert_eq!(carried.decode().map(|_| ()), Err(expected));
    }
}

#[test]
fn the_value_limit_includes_the_type_byte() {
    let max_payload = vec![b'a'; MAX_VALUE_LEN - 1];
    let text = core::str::from_utf8(&max_payload).unwrap();
    let v = Value::text(text).unwrap();
    assert_eq!(v.len(), MAX_VALUE_LEN);
    assert!(matches!(v.decode(), Ok(ValueRef::Text(_))));
    let over = format!("{text}a");
    assert_eq!(Value::text(&over).map(|_| ()), Err(ValueError::TooLong));
    assert_eq!(
        Value::bytes(over.as_bytes()).map(|_| ()),
        Err(ValueError::TooLong)
    );
    let mut encoded = vec![0x01];
    encoded.extend_from_slice(over.as_bytes());
    assert_eq!(encoded.len(), MAX_VALUE_LEN + 1);
    assert_eq!(
        ValueRef::decode(&encoded).map(|_| ()),
        Err(ValueError::TooLong)
    );
    assert_eq!(
        Value::copy_from_encoded(&encoded).map(|_| ()),
        Err(ValueError::TooLong)
    );
    // Oversize is checked before the type: an unknown type of 65,537 bytes is TooLong.
    encoded[0] = 0x09;
    assert_eq!(
        ValueRef::decode(&encoded).map(|_| ()),
        Err(ValueError::TooLong)
    );
}

#[test]
fn empty_means_cleared_only() {
    assert!(Value::cleared().is_cleared());
    assert!(Value::cleared().is_empty());
    assert!(ValueRef::decode(b"").unwrap().is_cleared());
    // An empty Text is non-empty (one byte).
    let empty_text = Value::text("").unwrap();
    assert!(!empty_text.is_cleared());
    assert!(!empty_text.decode().unwrap().is_cleared());
    assert_eq!(ValueRef::Cleared.value_type(), None);
    assert_eq!(ValueRef::Text("").value_type(), Some(ValueType::Text));
}

#[test]
fn decoded_values_encode_back_to_the_same_bytes() {
    let sort = SortKey::from_slice(&[3]).unwrap();
    for v in [
        Value::cleared(),
        Value::text("x").unwrap(),
        Value::bytes(&[1, 2]).unwrap(),
        Value::bool(true),
        Value::u64(7),
        Value::enumeration(3),
        Value::sort_key(&sort),
    ] {
        let again = v.decode().unwrap().encode().unwrap();
        assert_eq!(again.expose_secret(), v.expose_secret());
    }
    // A SortKey view that breaks the rules does not encode.
    assert_eq!(
        ValueRef::SortKey(&[1, 0]).encode().map(|_| ()),
        Err(ValueError::Malformed)
    );
    assert_eq!(
        ValueRef::SortKey(&[]).encode().map(|_| ()),
        Err(ValueError::Malformed)
    );
}

#[test]
fn sort_key_payloads() {
    assert!(SortKey::from_slice(&[1]).is_ok());
    assert!(SortKey::from_slice(&[0, 1]).is_ok());
    assert!(SortKey::from_slice(&[0xff; MAX_SORT_KEY_LEN]).is_ok());
    for bad in [&[][..], &[0], &[1, 0], &[0xff; MAX_SORT_KEY_LEN + 1]] {
        assert_eq!(
            SortKey::from_slice(bad).map(|_| ()),
            Err(ValueError::Malformed)
        );
    }
    assert_eq!(SortKey::from_slice(&[7, 9]).unwrap().as_bytes(), [7, 9]);
}

#[test]
fn value_types_never_print_the_value() {
    let v = Value::text("hunter2").unwrap();
    let r = v.decode().unwrap();
    let s = SortKey::from_slice(b"zz").unwrap();
    let out = format!(
        "{v:?} {r:?} {s:?} {v:#?} {r:#?} {s:#?} {:?}",
        ValueRef::U64(424_242)
    );
    assert!(!out.contains("hunter2"), "{out}");
    assert!(!out.contains("zz"), "{out}");
    assert!(!out.contains("424242"), "{out}");
    assert!(out.contains("Text([REDACTED])"), "{out}");
    for e in [
        ValueError::TooLong,
        ValueError::UnknownType,
        ValueError::Malformed,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

/// CRYPTO.md §15 item 9: an owned value is wiped when it is dropped.
#[test]
fn owned_values_are_wiped_on_drop() {
    let ((), log) = wipe_hooks::capture(|| {
        drop(Value::text("correct horse").unwrap());
        drop(SortKey::from_slice(&[1, 2, 3]).unwrap());
    });
    assert!(
        log.iter()
            .any(|o| o.site == "SecretBytes" && o.len == 14 && o.held_data && o.wiped),
        "{log:?}"
    );
    assert!(
        log.iter()
            .any(|o| o.site == "SecretBytes" && o.len == 3 && o.held_data && o.wiped),
        "{log:?}"
    );
    assert!(log.iter().all(|o| o.wiped));
}

// ---------------------------------------------------------------------------------------------
// §8 item types
// ---------------------------------------------------------------------------------------------

#[test]
fn item_type_registry() {
    for (id, class) in [
        (0x0000, ItemTypeClass::Invalid),
        (0x0001, ItemTypeClass::Supported(SupportedType::Login)),
        (0x0002, ItemTypeClass::Supported(SupportedType::SecureNote)),
        (0x0003, ItemTypeClass::Supported(SupportedType::Card)),
        (0x0004, ItemTypeClass::Supported(SupportedType::Identity)),
        (0x0005, ItemTypeClass::ReservedM3),
        (0x0009, ItemTypeClass::ReservedM3),
        (0x000A, ItemTypeClass::Unassigned),
        (0x000B, ItemTypeClass::Unassigned),
        (0xEFFF, ItemTypeClass::Unassigned),
        (0xF000, ItemTypeClass::ReservedSystem),
        (
            0xF001,
            ItemTypeClass::Supported(SupportedType::VaultSettings),
        ),
        (0xF002, ItemTypeClass::ReservedSystem),
        (0xFFFF, ItemTypeClass::ReservedSystem),
    ] {
        let t = ItemType::from_id(id);
        assert_eq!(t.id(), id);
        assert_eq!(t.class(), class, "{id:#06x}");
    }
    for t in [
        SupportedType::Login,
        SupportedType::SecureNote,
        SupportedType::Card,
        SupportedType::Identity,
        SupportedType::VaultSettings,
    ] {
        assert_eq!(t.item_type().supported(), Some(t));
        assert_eq!(t.is_user_item(), t != SupportedType::VaultSettings);
    }
    for t in [
        ItemType::INVALID,
        ItemType::SSH_KEY,
        ItemType::API_CREDENTIAL,
        ItemType::SOFTWARE_LICENSE,
        ItemType::WIFI,
        ItemType::BANK_ACCOUNT,
        // `0x000A`, released to unassigned by ADR 0039 §1 (it was the standalone-passkey
        // candidate ADR 0018 reserved).
        ItemType::from_id(0x000A),
        ItemType::from_id(0x1234),
    ] {
        assert_eq!(t.supported(), None, "{:#06x}", t.id());
    }
    assert_eq!(ItemType::VAULT_SETTINGS.id(), 0xF001);
}

/// ADR 0018 §2: the item type, the custom-field kind and the lifecycle are decoded values, so
/// `Debug` prints none of them (nor what a field displays).
#[test]
fn decoded_schema_values_never_print() {
    let out = format!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {:#?}",
        ItemType::CARD,
        ItemType::CARD.class(),
        SupportedType::Identity,
        CustomFieldKind::Hidden,
        Lifecycle::Trashed,
        resolve_lifecycle(&[cand(2, 2, 1, &[LIFECYCLE_TRASHED])]),
        resolve_field(&[cand(1, 1, 1, b""), cand(2, 2, 1, b"\x01x")]),
    );
    for leak in [
        "3", "Card", "Identity", "Hidden", "Trashed", "Active", "conflict", "cleared", "true",
    ] {
        assert!(!out.contains(leak), "{leak}: {out}");
    }
    assert_eq!(out.matches("[REDACTED]").count(), 7, "{out}");
}

#[test]
fn an_item_without_a_valid_type_is_unsupported() {
    assert_eq!(
        ItemType::from_displayed(Some(ValueRef::Enum(1))),
        Some(ItemType::LOGIN)
    );
    assert_eq!(ItemType::from_displayed(None), None);
    assert_eq!(ItemType::from_displayed(Some(ValueRef::Cleared)), None);
    assert_eq!(ItemType::from_displayed(Some(ValueRef::Text("1"))), None);
    assert_eq!(ItemType::from_displayed(Some(ValueRef::U64(1))), None);
}

#[test]
fn the_lowest_vault_settings_id_counts() {
    let ids = [[3u8; 16], [1; 16], [2; 16]].map(ItemId::from_bytes);
    assert_eq!(
        effective_vault_settings(ids),
        Some(ItemId::from_bytes([1; 16]))
    );
    assert_eq!(effective_vault_settings([]), None);
}

// ---------------------------------------------------------------------------------------------
// §7 key registry
// ---------------------------------------------------------------------------------------------

#[test]
fn every_fixed_key_fits_the_grammar_and_is_listed_once() {
    let mut names: Vec<&str> = FIXED_KEYS.iter().map(|(k, _)| *k).collect();
    for (k, spec) in FIXED_KEYS {
        assert_eq!(classify(key(k)), KeyClass::Known(spec), "{k}");
        assert_eq!(key(k).kind(), KeyKind::Fixed);
    }
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), FIXED_KEYS.len());
}

#[test]
fn fixed_keys_belong_to_their_types() {
    let spec = |k: &str| match classify(key(k)) {
        KeyClass::Known(spec) => spec,
        other => panic!("{k}: {other:?}"),
    };
    for k in [
        schema::ITEM_TYPE,
        schema::ITEM_NAME,
        schema::ITEM_NOTES,
        schema::ITEM_FAVORITE,
        schema::IMPORT_CREATED_MS,
    ] {
        assert_eq!(spec(k).applies, Applies::All, "{k}");
    }
    for k in [
        schema::LOGIN_USERNAME,
        schema::LOGIN_PASSWORD,
        schema::LOGIN_TOTP,
    ] {
        assert_eq!(spec(k).applies, Applies::Only(SupportedType::Login), "{k}");
    }
    let card = FIXED_KEYS
        .iter()
        .filter(|(k, _)| k.starts_with("card."))
        .count();
    let identity = FIXED_KEYS
        .iter()
        .filter(|(k, _)| k.starts_with("identity."))
        .count();
    assert_eq!((card, identity), (7, 18));
    for (k, s) in FIXED_KEYS {
        let expected = match k.split('.').next() {
            Some("card") => Applies::Only(SupportedType::Card),
            Some("identity") => Applies::Only(SupportedType::Identity),
            Some("vault") => Applies::Only(SupportedType::VaultSettings),
            Some("login") => Applies::Only(SupportedType::Login),
            _ => Applies::All,
        };
        assert_eq!(s.applies, expected, "{k}");
        // Every fixed key but the four below is Text.
        let value = match k {
            schema::ITEM_TYPE => Expected::Enum,
            schema::ITEM_FAVORITE => Expected::Bool,
            schema::IMPORT_CREATED_MS => Expected::U64,
            _ => Expected::Text,
        };
        assert_eq!(s.expected, value, "{k}");
    }
    assert!(Applies::All.includes(SupportedType::VaultSettings));
    assert!(!Applies::Only(SupportedType::Card).includes(SupportedType::Login));
}

#[test]
fn concealed_by_default_is_the_adr_list() {
    let concealed: Vec<&str> = FIXED_KEYS
        .iter()
        .filter(|(_, s)| s.concealed(CustomFieldKind::Text))
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(
        concealed,
        [
            schema::LOGIN_PASSWORD,
            schema::LOGIN_TOTP,
            schema::CARD_NUMBER,
            schema::CARD_CODE,
            schema::CARD_PIN,
            schema::IDENTITY_SSN,
            schema::IDENTITY_PASSPORT_NUMBER,
        ]
    );
    let field_value = element_key("field", "value");
    let KeyClass::Known(spec) = classify(key(&field_value)) else {
        panic!("field value")
    };
    assert_eq!(spec.concealment, Concealment::IfHiddenField);
    assert!(!spec.concealed(CustomFieldKind::Text));
    assert!(!spec.concealed(CustomFieldKind::Boolean));
    assert!(spec.concealed(CustomFieldKind::Hidden));
    assert!(spec.concealed(CustomFieldKind::Unknown));
    let share = element_key("share", "secret");
    let KeyClass::Known(spec) = classify(key(&share)) else {
        panic!("share secret")
    };
    assert!(spec.concealed(CustomFieldKind::Text));
    // The field label is never concealed.
    let KeyClass::Known(spec) = classify(key(&element_key("field", "label"))) else {
        panic!("label")
    };
    assert!(!spec.concealed(CustomFieldKind::Hidden));
}

#[test]
fn list_keys_are_classified() {
    use Concealment::{Concealed, IfHiddenField, Shown};
    use Writers::{Any, NotInM1};
    let login = Applies::Only(SupportedType::Login);
    let all = Applies::All;
    // Every column of the ADR 0018 §7 table, for every known list key.
    for (list, attribute, expected, applies, writers, concealment) in [
        ("field", "label", Expected::Text, all, Any, Shown),
        ("field", "kind", Expected::Enum, all, Any, Shown),
        (
            "field",
            "value",
            Expected::CustomFieldValue,
            all,
            Any,
            IfHiddenField,
        ),
        ("field", "order", Expected::SortKey, all, Any, Shown),
        ("uri", "value", Expected::Text, login, Any, Shown),
        // Writable from M2 (ADR 0037 §4, Accepted): `0x0000`-`0x0006`, unlike `share/secret`.
        ("uri", "match", Expected::Enum, login, Any, Shown),
        ("uri", "order", Expected::SortKey, login, Any, Shown),
        ("pwhist", "value", Expected::Text, login, Any, Shown),
        ("pwhist", "ms", Expected::U64, login, Any, Shown),
        (
            "share",
            "secret",
            Expected::Bytes { len: 32 },
            all,
            NotInM1,
            Concealed,
        ),
        // ADR 0039 §1: the `passkey/<id>/…` list on Login.
        ("passkey", "rp_id", Expected::Text, login, Any, Shown),
        (
            "passkey",
            "user_handle",
            Expected::BytesMax {
                len: schema::PASSKEY_USER_HANDLE_MAX_LEN,
            },
            login,
            Any,
            Shown,
        ),
        (
            "passkey",
            "credential_id",
            Expected::BytesMax {
                len: schema::PASSKEY_CREDENTIAL_ID_MAX_LEN,
            },
            login,
            Any,
            Shown,
        ),
        (
            "passkey",
            "private_key",
            Expected::Bytes {
                len: schema::PASSKEY_PRIVATE_KEY_LEN,
            },
            login,
            Any,
            Concealed,
        ),
        (
            "passkey",
            "public_key_cose",
            Expected::BytesMax {
                len: schema::PASSKEY_PUBLIC_KEY_COSE_MAX_LEN,
            },
            login,
            Any,
            Shown,
        ),
        ("passkey", "alg", Expected::Enum, login, Any, Shown),
        ("passkey", "discoverable", Expected::Bool, login, Any, Shown),
        ("passkey", "created_ms", Expected::U64, login, Any, Shown),
    ] {
        assert_eq!(
            classify(key(&element_key(list, attribute))),
            KeyClass::Known(KeySpec {
                expected,
                applies,
                writers,
                concealment,
            }),
            "{list}/{attribute}"
        );
    }
    for tag in ["tag/61", "tag/6162", "tag/c3a9", "tag/efac81"] {
        assert_eq!(
            classify(key(tag)),
            KeyClass::Known(KeySpec {
                expected: Expected::TagMarker,
                applies: all,
                writers: Any,
                concealment: Shown,
            }),
            "{tag}"
        );
    }
}

/// ADR 0018 §7 "Reserved prefixes", §11: keys outside the M1 schema are reserved or unknown.
#[test]
fn keys_outside_the_m1_schema_are_classified() {
    for (text, class) in [
        (
            element_key("share", "label"),
            KeyClass::Reserved(ReservedFor::M5Share),
        ),
        (
            format!("share/{ID}"),
            KeyClass::Reserved(ReservedFor::M5Share),
        ),
        (
            // `passkey/<id>/credential` is not one of ADR 0039 §1's eight attribute names
            // (`rp_id`, `user_handle`, `credential_id`, `private_key`, `public_key_cose`,
            // `alg`, `discoverable`, `created_ms`): unlike the reserved prefixes below, the
            // `passkey/` list is now assigned (ADR 0039 §1), so an attribute outside its table
            // is simply unknown, not "a later milestone defines it".
            element_key("passkey", "credential"),
            KeyClass::Unknown,
        ),
        (
            "passkey.rp_id".to_owned(),
            KeyClass::Reserved(ReservedFor::PasskeyDotKeys),
        ),
        (
            element_key("attachment", "name"),
            KeyClass::Reserved(ReservedFor::M3Attachments),
        ),
        (
            "ssh.private_key".to_owned(),
            KeyClass::Reserved(ReservedFor::M3Types),
        ),
        (
            "api.key".to_owned(),
            KeyClass::Reserved(ReservedFor::M3Types),
        ),
        (
            "license.key".to_owned(),
            KeyClass::Reserved(ReservedFor::M3Types),
        ),
        (
            "wifi.ssid".to_owned(),
            KeyClass::Reserved(ReservedFor::M3Types),
        ),
        (
            "bank.iban".to_owned(),
            KeyClass::Reserved(ReservedFor::M3Types),
        ),
        ("login.passkey_hint".to_owned(), KeyClass::Unknown),
        ("item.color".to_owned(), KeyClass::Unknown),
        ("attachment.x".to_owned(), KeyClass::Unknown),
        (element_key("ssh", "x"), KeyClass::Unknown),
        (element_key("uri", "label"), KeyClass::Unknown),
        (element_key("pwhist", "order"), KeyClass::Unknown),
        (element_key("field", "color"), KeyClass::Unknown),
        (format!("field/{ID}"), KeyClass::Unknown),
        ("tag/61/color".to_owned(), KeyClass::Unknown),
        (element_key("notes", "value"), KeyClass::Unknown),
        // `tag/<hex>` keys no §7 writer produces: a Cc name (NUL, DEL, a C1 control), hex that
        // is not UTF-8, and an NFD name (`e` and a combining acute).
        ("tag/00".to_owned(), KeyClass::Unknown),
        ("tag/7f".to_owned(), KeyClass::Unknown),
        ("tag/c280".to_owned(), KeyClass::Unknown),
        ("tag/ff".to_owned(), KeyClass::Unknown),
        ("tag/65cc81".to_owned(), KeyClass::Unknown),
    ] {
        assert_eq!(classify(key(&text)), class, "{text}");
    }
}

#[test]
fn expected_values() {
    let all = [
        ValueRef::Text("t"),
        ValueRef::Bytes(&[0; 32]),
        ValueRef::Bytes(&[0; 31]),
        ValueRef::Bool(false),
        ValueRef::Bool(true),
        ValueRef::U64(1),
        ValueRef::Enum(1),
        ValueRef::SortKey(&[1]),
    ];
    let accepted = |e: Expected| -> Vec<usize> {
        all.iter()
            .enumerate()
            .filter(|(_, v)| e.accepts(v))
            .map(|(i, _)| i)
            .collect()
    };
    assert_eq!(accepted(Expected::Text), [0]);
    assert_eq!(accepted(Expected::Bytes { len: 32 }), [1]);
    assert_eq!(accepted(Expected::Bool), [3, 4]);
    assert_eq!(accepted(Expected::TagMarker), [4]);
    assert_eq!(accepted(Expected::U64), [5]);
    assert_eq!(accepted(Expected::Enum), [6]);
    assert_eq!(accepted(Expected::SortKey), [7]);
    assert_eq!(accepted(Expected::CustomFieldValue), [0, 3, 4]);
    for e in [
        Expected::Text,
        Expected::TagMarker,
        Expected::Bytes { len: 32 },
    ] {
        assert!(e.accepts(&ValueRef::Cleared));
    }
}

#[test]
fn read_value_shows_unsupported_values() {
    assert!(matches!(
        read_value(Expected::Text, b"\x01ok"),
        Some(ValueRef::Text("ok"))
    ));
    assert!(matches!(
        read_value(Expected::Text, b""),
        Some(ValueRef::Cleared)
    ));
    // A type the key does not expect, a malformed payload, an unknown type.
    assert!(read_value(Expected::Text, b"\x03\x01").is_none());
    assert!(read_value(Expected::Bool, b"\x03\x02").is_none());
    assert!(read_value(Expected::Text, b"\x07abc").is_none());
    assert!(read_value(Expected::TagMarker, b"\x03\x00").is_none());
}

#[test]
fn custom_field_kinds() {
    for (value, kind) in [
        (Some(ValueRef::Enum(1)), CustomFieldKind::Text),
        (Some(ValueRef::Enum(2)), CustomFieldKind::Hidden),
        (Some(ValueRef::Enum(3)), CustomFieldKind::Boolean),
        (Some(ValueRef::Enum(0)), CustomFieldKind::Unknown),
        (Some(ValueRef::Enum(4)), CustomFieldKind::Unknown),
        (Some(ValueRef::Cleared), CustomFieldKind::Unknown),
        (Some(ValueRef::Text("1")), CustomFieldKind::Unknown),
        (None, CustomFieldKind::Unknown),
    ] {
        assert_eq!(CustomFieldKind::from_displayed(value), kind);
    }
    assert_eq!(CustomFieldKind::Text.id(), Some(1));
    assert_eq!(CustomFieldKind::Hidden.id(), Some(2));
    assert_eq!(CustomFieldKind::Boolean.id(), Some(3));
    assert_eq!(CustomFieldKind::Unknown.id(), None);
    assert!(!CustomFieldKind::Text.displays_as_hidden());
    assert!(CustomFieldKind::Hidden.displays_as_hidden());
    assert!(!CustomFieldKind::Boolean.displays_as_hidden());
    assert!(CustomFieldKind::Unknown.displays_as_hidden());
    let text = ValueRef::Text("x");
    let flag = ValueRef::Bool(true);
    assert!(CustomFieldKind::Text.accepts(&text) && !CustomFieldKind::Text.accepts(&flag));
    assert!(CustomFieldKind::Hidden.accepts(&text) && !CustomFieldKind::Hidden.accepts(&flag));
    assert!(!CustomFieldKind::Boolean.accepts(&text) && CustomFieldKind::Boolean.accepts(&flag));
    assert!(CustomFieldKind::Unknown.accepts(&text) && CustomFieldKind::Unknown.accepts(&flag));
    assert!(CustomFieldKind::Boolean.accepts(&ValueRef::Cleared));
    assert!(!CustomFieldKind::Text.accepts(&ValueRef::U64(1)));
}

// ---------------------------------------------------------------------------------------------
// Writer checks (§2 "Flow", §6–§8, §10)
// ---------------------------------------------------------------------------------------------

/// Encoded values for the writer checks.
const TEXT: &[u8] = b"\x01x";
/// An empty Text.
const EMPTY_TEXT: &[u8] = b"\x01";
/// Cleared.
const CLEARED: &[u8] = b"";
/// Bool `0x01`.
const TRUE: &[u8] = b"\x03\x01";
/// Bool `0x00`.
const FALSE: &[u8] = b"\x03\x00";
/// Bytes, 32 zero bytes: a passkey private key's length (ES256 and `EdDSA` both).
const BYTES_32: &[u8] = b"\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
/// Bytes, one byte of payload: short enough for every `BytesMax` passkey attribute.
const BYTES_SHORT: &[u8] = b"\x02\xab";
/// Enum 1, a passkey's ES256 alg id ([`schema::PASSKEY_ALG_ES256`]).
const PASSKEY_ALG_ES256: &[u8] = b"\x05\x00\x01";
/// Enum 1, the Login type.
const LOGIN_TYPE: &[u8] = b"\x05\x00\x01";
/// Enum 3, the Card type.
const CARD_TYPE: &[u8] = b"\x05\x00\x03";
/// Enum `0xF001`, the vault-settings type.
const VAULT_TYPE: &[u8] = b"\x05\xf0\x01";
/// U64 1.
const U64_ONE: &[u8] = b"\x04\0\0\0\0\0\0\0\x01";
/// Enum 2.
const ENUM_TWO: &[u8] = b"\x05\x00\x02";
/// `SortKey` `0x80`.
const SORT: &[u8] = b"\x06\x80";

/// One writer-check case: item type, op, key, encoded value, expected result.
type WriteCase<'a> = (
    ItemType,
    WriteMode,
    &'a str,
    &'a [u8],
    Result<(), WriteError>,
);

/// Runs every case through `check_write`.
fn check_cases(cases: &[WriteCase<'_>]) {
    for (t, mode, k, v, expected) in cases {
        assert_eq!(
            check_write(*t, *mode, k.as_bytes(), v),
            *expected,
            "{k:?} {mode:?} {v:02x?}"
        );
    }
}

#[test]
fn writers_may_write_the_m1_schema() {
    use WriteMode::{Create, Edit, Import};
    let (login, vault) = (ItemType::LOGIN, ItemType::VAULT_SETTINGS);
    let (uri_value, uri_order, uri_match) = (
        element_key("uri", "value"),
        element_key("uri", "order"),
        element_key("uri", "match"),
    );
    let (field_value, field_kind) = (element_key("field", "value"), element_key("field", "kind"));
    let pwhist_ms = element_key("pwhist", "ms");
    check_cases(&[
        (login, Create, schema::ITEM_TYPE, LOGIN_TYPE, Ok(())),
        (login, Import, schema::ITEM_TYPE, LOGIN_TYPE, Ok(())),
        (login, Import, schema::IMPORT_CREATED_MS, U64_ONE, Ok(())),
        (login, Create, schema::LOGIN_PASSWORD, TEXT, Ok(())),
        (login, Edit, schema::LOGIN_PASSWORD, TEXT, Ok(())),
        (login, Edit, schema::LOGIN_PASSWORD, CLEARED, Ok(())),
        (login, Edit, schema::ITEM_FAVORITE, FALSE, Ok(())),
        (login, Create, &uri_value, TEXT, Ok(())),
        (login, Edit, &uri_order, SORT, Ok(())),
        // `uri/<id>/match` from M2 (ADR 0037 §4, Accepted): writable like any other Enum key.
        (login, Create, &uri_match, ENUM_TWO, Ok(())),
        (login, Edit, &uri_match, ENUM_TWO, Ok(())),
        (login, Edit, &uri_match, CLEARED, Ok(())),
        (login, Edit, &pwhist_ms, U64_ONE, Ok(())),
        (login, Create, "tag/61", TRUE, Ok(())),
        (login, Edit, "tag/61", CLEARED, Ok(())),
        (login, Edit, &field_value, TRUE, Ok(())),
        (login, Edit, &field_value, TEXT, Ok(())),
        (login, Edit, &field_kind, ENUM_TWO, Ok(())),
        (vault, Create, schema::ITEM_TYPE, VAULT_TYPE, Ok(())),
        (vault, Create, schema::VAULT_NAME, TEXT, Ok(())),
        (
            ItemType::SECURE_NOTE,
            Edit,
            schema::ITEM_NOTES,
            TEXT,
            Ok(()),
        ),
        (ItemType::CARD, Create, schema::ITEM_TYPE, CARD_TYPE, Ok(())),
        (ItemType::CARD, Edit, schema::CARD_PIN, TEXT, Ok(())),
        (ItemType::IDENTITY, Edit, schema::IDENTITY_SSN, TEXT, Ok(())),
    ]);
}

/// ADR 0037 §4: `uri/<id>/match`'s assigned values are `0x0000`-`0x0006`; `0x0007`-`0xFFFF` are
/// "unassigned... a new mode needs a line in this table via an ADR update, like any other
/// ADR 0018 enum extension" — not a write-time rejection here. This module only checks the wire
/// *type* (Enum), same as every other Enum key (`field/<id>/kind`, `item.type`'s own value
/// aside): an unassigned mode is written like any other out-of-range enum and is this build's
/// job (`rizzy-match`'s `MatchMode::from_wire`) to treat as unsupported when read, never this
/// layer's to reject.
#[test]
fn uri_match_accepts_every_enum_value_including_unassigned_ones() {
    use WriteMode::Edit;
    let login = ItemType::LOGIN;
    let uri_match = element_key("uri", "match");
    for value in [
        0x0000_u16, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0xffff,
    ] {
        let encoded = [&[0x05u8][..], &value.to_be_bytes()].concat();
        assert_eq!(
            check_write(login, Edit, uri_match.as_bytes(), &encoded),
            Ok(()),
            "{value:#06x}"
        );
    }
}

#[test]
fn writers_are_refused_bad_keys_and_values() {
    use WriteMode::{Create, Edit};
    let login = ItemType::LOGIN;
    let long_key = "a".repeat(161);
    let mut big = vec![0x01];
    big.extend(core::iter::repeat_n(b'a', MAX_VALUE_LEN));
    check_cases(&[
        (
            login,
            Edit,
            "Bad.key",
            TEXT,
            Err(WriteError::Key(KeyError::Name)),
        ),
        (
            login,
            Edit,
            LIFECYCLE_KEY,
            &[1],
            Err(WriteError::Key(KeyError::Name)),
        ),
        (
            login,
            Edit,
            &long_key,
            TEXT,
            Err(WriteError::Key(KeyError::Length)),
        ),
        (
            login,
            Edit,
            schema::ITEM_NOTES,
            &big,
            Err(WriteError::ValueTooLong),
        ),
        (
            login,
            Edit,
            schema::ITEM_FAVORITE,
            &[3, 2],
            Err(WriteError::MalformedValue),
        ),
        (
            login,
            Edit,
            schema::ITEM_NAME,
            &[9, 1],
            Err(WriteError::MalformedValue),
        ),
        (
            login,
            Edit,
            schema::ITEM_NAME,
            EMPTY_TEXT,
            Err(WriteError::EmptyText),
        ),
        (
            login,
            Create,
            schema::LOGIN_PASSWORD,
            CLEARED,
            Err(WriteError::BlankInCreate),
        ),
        (
            login,
            WriteMode::Import,
            schema::ITEM_NAME,
            CLEARED,
            Err(WriteError::BlankInCreate),
        ),
    ]);
}

#[test]
fn writers_are_refused_keys_outside_the_m1_schema() {
    use WriteMode::{Create, Edit};
    let login = ItemType::LOGIN;
    let (share_note, uri_value) = (element_key("share", "note"), element_key("uri", "value"));
    check_cases(&[
        (
            login,
            Edit,
            "login.passkey_hint",
            TEXT,
            Err(WriteError::UnknownKey),
        ),
        (login, Edit, "ssh.key", TEXT, Err(WriteError::ReservedKey)),
        (login, Edit, &share_note, TEXT, Err(WriteError::ReservedKey)),
        (
            ItemType::SSH_KEY,
            Edit,
            schema::ITEM_NAME,
            TEXT,
            Err(WriteError::UnsupportedItemType),
        ),
        (
            ItemType::from_id(0x0100),
            Create,
            schema::ITEM_NAME,
            TEXT,
            Err(WriteError::UnsupportedItemType),
        ),
        (
            ItemType::INVALID,
            Edit,
            schema::ITEM_NAME,
            TEXT,
            Err(WriteError::UnsupportedItemType),
        ),
        (
            login,
            Edit,
            schema::CARD_NUMBER,
            TEXT,
            Err(WriteError::WrongItemType),
        ),
        (
            ItemType::CARD,
            Edit,
            &uri_value,
            TEXT,
            Err(WriteError::WrongItemType),
        ),
        (
            login,
            Edit,
            schema::VAULT_NAME,
            TEXT,
            Err(WriteError::WrongItemType),
        ),
    ]);
}

/// ADR 0018 §7: a `tag/<hex>` key is written as a tag only if its hex is the UTF-8 of an NFC
/// name without a Cc code point. Every other `tag/<hex>` key is unknown, so it is never written
/// with a value, and a client that skipped NFC cannot add a second register for one tag.
#[test]
fn writers_are_refused_tag_keys_no_tag_name_produces() {
    use WriteMode::{Create, Edit};
    let login = ItemType::LOGIN;
    // NUL, DEL and a C1 control (all Cc), hex that is not UTF-8, and NFD `é`.
    for k in ["tag/00", "tag/7f", "tag/c280", "tag/ff", "tag/65cc81"] {
        check_cases(&[
            (login, Create, k, TRUE, Err(WriteError::UnknownKey)),
            (login, Edit, k, TRUE, Err(WriteError::UnknownKey)),
        ]);
    }
    // The NFC spelling of the same name is a tag.
    check_cases(&[(login, Create, "tag/c3a9", TRUE, Ok(()))]);
    assert_eq!(
        tag_key("e\u{301}").unwrap().as_bytes(),
        b"tag/c3a9".as_slice()
    );
}

/// ADR 0018 §7, "Types" column, for list keys: `uri/…` and `pwhist/…` belong to a Login only,
/// `field/…`, `tag/…` and `share/…` to every type.
#[test]
fn list_keys_belong_to_their_types() {
    use WriteMode::Edit;
    let login_only = [
        (element_key("uri", "value"), TEXT),
        (element_key("uri", "order"), SORT),
        (element_key("pwhist", "value"), TEXT),
        (element_key("pwhist", "ms"), U64_ONE),
        (element_key("passkey", "rp_id"), TEXT),
        (element_key("passkey", "user_handle"), BYTES_SHORT),
        (element_key("passkey", "credential_id"), BYTES_SHORT),
        (element_key("passkey", "private_key"), BYTES_32),
        (element_key("passkey", "public_key_cose"), BYTES_SHORT),
        (element_key("passkey", "alg"), PASSKEY_ALG_ES256),
        (element_key("passkey", "discoverable"), TRUE),
        (element_key("passkey", "created_ms"), U64_ONE),
    ];
    let everywhere = [
        (element_key("field", "label"), TEXT),
        (element_key("field", "kind"), ENUM_TWO),
        (element_key("field", "value"), TEXT),
        (element_key("field", "order"), SORT),
        ("tag/61".to_owned(), TRUE),
    ];
    for t in [
        ItemType::SECURE_NOTE,
        ItemType::CARD,
        ItemType::IDENTITY,
        ItemType::VAULT_SETTINGS,
    ] {
        for (k, v) in &login_only {
            check_cases(&[(t, Edit, k, v, Err(WriteError::WrongItemType))]);
        }
        // The type is checked before who writes the key.
        check_cases(&[(
            t,
            Edit,
            &element_key("uri", "match"),
            ENUM_TWO,
            Err(WriteError::WrongItemType),
        )]);
    }
    for t in [
        ItemType::LOGIN,
        ItemType::SECURE_NOTE,
        ItemType::CARD,
        ItemType::IDENTITY,
        ItemType::VAULT_SETTINGS,
    ] {
        for (k, v) in &everywhere {
            check_cases(&[(t, Edit, k, v, Ok(()))]);
        }
        let secret = [&[2u8][..], &[0; 32]].concat();
        check_cases(&[(
            t,
            Edit,
            &element_key("share", "secret"),
            &secret,
            Err(WriteError::NotWritable),
        )]);
    }
    for (k, v) in &login_only {
        check_cases(&[(ItemType::LOGIN, Edit, k, v, Ok(()))]);
    }
}

/// ADR 0018 §6: "Removing a list element writes [Cleared] to each attribute of the element that
/// the writer holds", including an attribute a newer client added, or the element would keep
/// existing. So in an edit, Cleared may go to any grammar key, known, unknown or reserved; a
/// value may not, and a create op writes no Cleared at all. `uri/<id>/match` is one of them from
/// M2 (ADR 0037, Accepted); `share/<id>/secret` stays unwritten (M5's).
#[test]
fn removing_an_element_clears_attributes_this_client_does_not_know() {
    use WriteMode::{Create, Edit};
    let login = ItemType::LOGIN;
    let uri_label = element_key("uri", "label");
    let share_note = element_key("share", "note");
    let attachment = element_key("attachment", "name");
    let field_color = element_key("field", "color");
    check_cases(&[
        // Known, unknown and reserved attributes of removed elements.
        (login, Edit, &element_key("uri", "value"), CLEARED, Ok(())),
        (login, Edit, &uri_label, CLEARED, Ok(())),
        (login, Edit, &field_color, CLEARED, Ok(())),
        (login, Edit, &share_note, CLEARED, Ok(())),
        (login, Edit, &attachment, CLEARED, Ok(())),
        (login, Edit, "tag/65cc81", CLEARED, Ok(())),
        (login, Edit, "login.passkey_hint", CLEARED, Ok(())),
        (login, Edit, "ssh.key", CLEARED, Ok(())),
        // Never a value, never in a create op, never on an unsupported type.
        (login, Edit, &uri_label, TEXT, Err(WriteError::UnknownKey)),
        (login, Edit, &share_note, TEXT, Err(WriteError::ReservedKey)),
        (
            login,
            Create,
            &uri_label,
            CLEARED,
            Err(WriteError::BlankInCreate),
        ),
        (
            ItemType::SSH_KEY,
            Edit,
            &uri_label,
            CLEARED,
            Err(WriteError::UnsupportedItemType),
        ),
        // `uri/<id>/match` follows the general §6 removal rule from M2 (ADR 0037, Accepted);
        // `share/<id>/secret` is M5's to clear, so it stays `NotWritable` here.
        (login, Edit, &element_key("uri", "match"), CLEARED, Ok(())),
        (
            login,
            Edit,
            &element_key("share", "secret"),
            CLEARED,
            Err(WriteError::NotWritable),
        ),
    ]);
    // Why it matters: a URI whose `label` (a content attribute a newer client added) is not
    // cleared keeps existing. `match` and `order` are layout attributes, so a stale `match`
    // does not keep it.
    let sort = SORT;
    let removed = [
        (Some("value"), CLEARED),
        (Some("label"), CLEARED),
        (Some("order"), sort),
        (Some("match"), ENUM_TWO),
    ];
    assert!(!element_exists(removed));
    let label_kept = [
        (Some("value"), CLEARED),
        (Some("label"), TEXT),
        (Some("order"), sort),
    ];
    assert!(element_exists(label_kept));
}

/// A restore (ADR 0018 §3 "Surfacing") or a duplicate (§10 "The way out") as a new item copies
/// the displayed values byte for byte: unknown and reserved keys, unsupported values and empty
/// Texts included, which would otherwise be lost (§6, §11). A known key still obeys its types
/// and writers.
#[test]
fn restore_and_duplicate_carry_keys_and_values_verbatim() {
    use WriteMode::{Create, Edit, Import};
    let login = ItemType::LOGIN;
    let newer_value: &[u8] = &[0x07, 0xde, 0xad];
    let uri_label = element_key("uri", "label");
    let share_note = element_key("share", "note");
    let mut big = vec![0x01];
    big.extend(core::iter::repeat_n(b'a', MAX_VALUE_LEN));
    let carried =
        |t: ItemType, mode: WriteMode, k: &str, v: &[u8]| check_carried(t, mode, k.as_bytes(), v);
    for mode in [Create, Edit] {
        assert_eq!(
            carried(login, mode, "login.passkey_hint", newer_value),
            Ok(())
        );
        assert_eq!(carried(login, mode, &uri_label, TEXT), Ok(()));
        assert_eq!(carried(login, mode, "ssh.key", TEXT), Ok(()));
        assert_eq!(carried(login, mode, &share_note, newer_value), Ok(()));
        assert_eq!(carried(login, mode, "tag/65cc81", TRUE), Ok(()));
        // Unsupported values and an empty Text of a known key are not decoded.
        assert_eq!(
            carried(login, mode, schema::LOGIN_PASSWORD, newer_value),
            Ok(())
        );
        assert_eq!(
            carried(login, mode, schema::LOGIN_PASSWORD, EMPTY_TEXT),
            Ok(())
        );
        assert_eq!(carried(login, mode, "tag/61", FALSE), Ok(()));
        // Refusals that hold for any source.
        assert_eq!(
            carried(login, mode, "Bad.key", &big),
            Err(WriteError::Key(KeyError::Name))
        );
        assert_eq!(
            carried(login, mode, "login.passkey_hint", &big),
            Err(WriteError::ValueTooLong)
        );
        assert_eq!(
            carried(ItemType::from_id(0x0042), mode, &uri_label, TEXT),
            Err(WriteError::UnsupportedItemType)
        );
        assert_eq!(
            carried(login, mode, schema::CARD_NUMBER, TEXT),
            Err(WriteError::WrongItemType)
        );
        // `share/<id>/secret` stays `NotInM1`; `uri/<id>/match` moved to `Any` in M2.
        assert_eq!(
            carried(login, mode, &element_key("share", "secret"), ENUM_TWO),
            Err(WriteError::NotWritable)
        );
        assert_eq!(
            carried(login, mode, &element_key("uri", "match"), ENUM_TWO),
            Ok(())
        );
        assert_eq!(
            carried(login, mode, schema::IMPORT_CREATED_MS, U64_ONE),
            Err(WriteError::NotWritable)
        );
    }
    // A carried Cleared carries nothing: it is checked as an entered one.
    assert_eq!(
        carried(login, Create, &uri_label, CLEARED),
        Err(WriteError::BlankInCreate)
    );
    assert_eq!(carried(login, Edit, &uri_label, CLEARED), Ok(()));
    // `item.type`: only in a create op, and the Enum of the new item's own type.
    assert_eq!(
        carried(login, Create, schema::ITEM_TYPE, LOGIN_TYPE),
        Ok(())
    );
    assert_eq!(
        carried(login, Edit, schema::ITEM_TYPE, LOGIN_TYPE),
        Err(WriteError::NotWritable)
    );
    assert_eq!(
        carried(login, Create, schema::ITEM_TYPE, CARD_TYPE),
        Err(WriteError::UnexpectedValue)
    );
    assert_eq!(
        carried(login, Create, schema::ITEM_TYPE, TEXT),
        Err(WriteError::UnexpectedValue)
    );
    for malformed in [&b"\x05\x00"[..], &b"\x07\x00\x01"[..]] {
        assert_eq!(
            carried(login, Create, schema::ITEM_TYPE, malformed),
            Err(WriteError::MalformedValue)
        );
    }
    // `import.created_ms` is an importer's.
    assert_eq!(
        carried(login, Import, schema::IMPORT_CREATED_MS, U64_ONE),
        Ok(())
    );
}

#[test]
fn writers_are_refused_keys_they_do_not_write() {
    use WriteMode::{Create, Edit};
    let login = ItemType::LOGIN;
    let share_secret = element_key("share", "secret");
    let secret = [&[2u8][..], &[0; 32]].concat();
    check_cases(&[
        (
            login,
            Edit,
            schema::ITEM_TYPE,
            LOGIN_TYPE,
            Err(WriteError::NotWritable),
        ),
        (
            login,
            Create,
            schema::IMPORT_CREATED_MS,
            U64_ONE,
            Err(WriteError::NotWritable),
        ),
        (
            login,
            Edit,
            &share_secret,
            &secret,
            Err(WriteError::NotWritable),
        ),
        (
            login,
            Edit,
            schema::ITEM_FAVORITE,
            TEXT,
            Err(WriteError::UnexpectedValue),
        ),
        (
            login,
            Create,
            schema::ITEM_TYPE,
            CARD_TYPE,
            Err(WriteError::UnexpectedValue),
        ),
        (
            login,
            Edit,
            "tag/61",
            FALSE,
            Err(WriteError::UnexpectedValue),
        ),
    ]);
}

#[test]
fn a_create_op_writes_its_type() {
    use WriteSource::{Carried, Entered};
    let t = Value::enumeration(1);
    let name = Value::text("Bank").unwrap();
    let writes = [
        (Entered, schema::ITEM_NAME.as_bytes(), name.expose_secret()),
        (Entered, schema::ITEM_TYPE.as_bytes(), t.expose_secret()),
    ];
    assert_eq!(
        check_create(ItemType::LOGIN, WriteMode::Create, writes),
        Ok(())
    );
    assert_eq!(
        check_create(
            ItemType::LOGIN,
            WriteMode::Create,
            [(Entered, schema::ITEM_NAME.as_bytes(), name.expose_secret())]
        ),
        Err(WriteError::MissingItemType)
    );
    // A failing write is reported before the missing type.
    assert_eq!(
        check_create(
            ItemType::LOGIN,
            WriteMode::Create,
            [(Entered, schema::CARD_PIN.as_bytes(), name.expose_secret())]
        ),
        Err(WriteError::WrongItemType)
    );
    // A restore as a new item: the type the user confirms is entered, the late registers'
    // displayed values are carried, a newer client's key and an unsupported value included.
    let uri_label = element_key("uri", "label");
    let newer_value: &[u8] = &[0x07, 0xde, 0xad];
    let restore = [
        (Entered, schema::ITEM_TYPE.as_bytes(), t.expose_secret()),
        (Carried, schema::ITEM_NAME.as_bytes(), name.expose_secret()),
        (Carried, b"login.passkey_hint".as_slice(), newer_value),
        (Carried, uri_label.as_bytes(), TEXT),
    ];
    assert_eq!(
        check_create(ItemType::LOGIN, WriteMode::Create, restore),
        Ok(())
    );
    // A carried `item.type` counts too.
    assert_eq!(
        check_create(
            ItemType::LOGIN,
            WriteMode::Create,
            [(Carried, schema::ITEM_TYPE.as_bytes(), t.expose_secret())]
        ),
        Ok(())
    );
    // The same unknown key, entered, is refused: this client invents no value for it.
    assert_eq!(
        check_create(
            ItemType::LOGIN,
            WriteMode::Create,
            [
                (Entered, schema::ITEM_TYPE.as_bytes(), t.expose_secret()),
                (Entered, uri_label.as_bytes(), TEXT),
            ]
        ),
        Err(WriteError::UnknownKey)
    );
    // A carried `uri/<id>/match` is accepted from M2 (ADR 0037, Accepted): it is `Writers::Any`.
    let uri_match = element_key("uri", "match");
    assert_eq!(
        check_create(
            ItemType::LOGIN,
            WriteMode::Create,
            [
                (Entered, schema::ITEM_TYPE.as_bytes(), t.expose_secret()),
                (Carried, uri_match.as_bytes(), ENUM_TWO),
            ]
        ),
        Ok(())
    );
}

#[test]
fn write_errors_carry_no_input() {
    for e in [
        WriteError::Key(KeyError::Shape),
        WriteError::ValueTooLong,
        WriteError::MalformedValue,
        WriteError::UnknownKey,
        WriteError::ReservedKey,
        WriteError::UnsupportedItemType,
        WriteError::WrongItemType,
        WriteError::NotWritable,
        WriteError::UnexpectedValue,
        WriteError::EmptyText,
        WriteError::BlankInCreate,
        WriteError::MissingItemType,
    ] {
        assert!(!e.to_string().is_empty(), "{e:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// §6 display
// ---------------------------------------------------------------------------------------------

#[test]
fn an_empty_register_displays_nothing() {
    assert_eq!(resolve_field(&[]), None);
    assert_eq!(resolve_lifecycle(&[]), None);
    assert!(displayed_value(Expected::Text, &[]).is_none());
}

#[test]
fn the_highest_hlc_device_seq_displays() {
    let a = cand(10, 1, 1, b"\x01a");
    let b = cand(20, 1, 2, b"\x01b");
    let c = cand(20, 2, 1, b"\x01c");
    let d = cand(20, 2, 5, b"\x01d");
    assert_eq!(
        resolve_field(&[a]),
        Some(FieldDisplay {
            displayed: 0,
            conflict: false,
            cleared_by: None
        })
    );
    // HLC first.
    assert_eq!(resolve_field(&[b, a]).unwrap().displayed, 0);
    assert_eq!(resolve_field(&[a, b]).unwrap().displayed, 1);
    // Then device id, bytewise.
    assert_eq!(resolve_field(&[c, b]).unwrap().displayed, 0);
    assert_eq!(resolve_field(&[b, c]).unwrap().displayed, 1);
    // Then seq, for two current values of one device after a faulty context.
    assert_eq!(resolve_field(&[d, c]).unwrap().displayed, 0);
    assert_eq!(resolve_field(&[c, d]).unwrap().displayed, 1);
    assert!(resolve_field(&[a, b]).unwrap().conflict);
}

#[test]
fn byte_identical_values_are_one_value() {
    let a = cand(10, 1, 1, b"\x01same");
    let b = cand(30, 2, 1, b"\x01same");
    let c = cand(20, 3, 1, b"\x01same");
    let shown = resolve_field(&[a, b, c]).unwrap();
    assert_eq!(shown.displayed, 1);
    assert!(!shown.conflict);
    // A prefix is not identical.
    let d = cand(5, 4, 1, b"\x01sam");
    assert!(resolve_field(&[a, b, d]).unwrap().conflict);
}

#[test]
fn cleared_never_displays_over_a_concurrent_edit() {
    // Owner decision 4: the edit displays, marked as a conflict.
    let edit = cand(10, 1, 1, b"\x01kept");
    let clear = cand(20, 2, 1, b"");
    let older_clear = cand(15, 3, 1, b"");
    let shown = resolve_field(&[clear, edit, older_clear]).unwrap();
    assert_eq!(shown.displayed, 1);
    assert!(shown.conflict);
    assert_eq!(shown.cleared_by, Some(0));
    // With only cleared values the field has no value, and no conflict.
    let shown = resolve_field(&[older_clear, clear]).unwrap();
    assert_eq!(
        shown,
        FieldDisplay {
            displayed: 1,
            conflict: false,
            cleared_by: None
        }
    );
    // An unsupported value is non-empty, so it too displays over a Cleared one.
    let unknown = cand(1, 9, 1, b"\x09?");
    let shown = resolve_field(&[clear, unknown]).unwrap();
    assert_eq!(shown.displayed, 1);
    assert_eq!(shown.cleared_by, Some(0));
    // A cleared value above an older non-empty one of the same field is still no display.
    let highest_edit = cand(30, 1, 2, b"\x01new");
    let shown = resolve_field(&[edit, highest_edit, clear]).unwrap();
    assert_eq!(shown.displayed, 1);
    assert_eq!(shown.cleared_by, Some(2));
}

#[test]
fn displayed_value_reads_against_the_key() {
    let good = [cand(1, 1, 1, b"\x04\0\0\0\0\0\0\0\x07")];
    assert!(matches!(
        displayed_value(Expected::U64, &good),
        Some(ValueRef::U64(7))
    ));
    assert!(displayed_value(Expected::Text, &good).is_none());
}

#[test]
fn active_wins() {
    let active = [LIFECYCLE_ACTIVE];
    let trashed = [LIFECYCLE_TRASHED];
    let edit = cand(10, 1, 1, &active);
    let trash = cand(20, 2, 1, &trashed);
    let only_trash = resolve_lifecycle(&[trash]).unwrap();
    assert_eq!(only_trash.shown, Lifecycle::Trashed);
    assert_eq!(only_trash.trashed_by, None);
    let both = resolve_lifecycle(&[trash, edit]).unwrap();
    assert_eq!(both.shown, Lifecycle::Active);
    assert_eq!(both.displayed, 1);
    assert_eq!(both.trashed_by, Some(0));
    let only_active = resolve_lifecycle(&[edit]).unwrap();
    assert_eq!(
        (only_active.shown, only_active.trashed_by),
        (Lifecycle::Active, None)
    );
    // Values the record layer would have rejected are ignored.
    let junk = cand(99, 9, 9, b"\x03");
    assert_eq!(resolve_lifecycle(&[junk]), None);
    assert_eq!(resolve_lifecycle(&[junk, trash]).unwrap().displayed, 1);
}

// ---------------------------------------------------------------------------------------------
// §9 times
// ---------------------------------------------------------------------------------------------

#[test]
fn times_come_from_the_hlc() {
    let ms = 1_700_000_000_000u64;
    let hlc = |ms: u64, counter: u64| (ms << 16) | counter;
    assert_eq!(hlc_ms(hlc(ms, 0xffff)), ms);
    let ty = Value::enumeration(1);
    let item_type = [
        cand(hlc(ms + 5, 0), 2, 1, ty.expose_secret()),
        cand(hlc(ms, 3), 1, 1, ty.expose_secret()),
    ];
    assert_eq!(created_ms(&item_type, &[]), Some(ms));
    let imported = Value::u64(42);
    let import = [cand(hlc(ms, 0), 1, 1, imported.expose_secret())];
    assert_eq!(created_ms(&item_type, &import), Some(42));
    // Not set: Cleared or unsupported.
    assert_eq!(created_ms(&item_type, &[cand(1, 1, 1, b"")]), Some(ms));
    assert_eq!(created_ms(&item_type, &[cand(1, 1, 1, b"\x01x")]), Some(ms));
    assert_eq!(created_ms(&[], &[]), None);

    let name = Value::text("n").unwrap();
    let lifecycle_values = [cand(hlc(ms + 900, 0), 1, 3, &[LIFECYCLE_ACTIVE])];
    let names = [
        cand(hlc(ms + 100, 0), 1, 1, name.expose_secret()),
        cand(hlc(ms + 50, 0), 2, 1, b""),
    ];
    let registers: [(&[u8], &[Candidate<'_>]); 3] = [
        (LIFECYCLE_KEY.as_bytes(), &lifecycle_values),
        (schema::ITEM_NAME.as_bytes(), &names),
        (schema::ITEM_TYPE.as_bytes(), &item_type),
    ];
    // @lifecycle's later HLC does not count.
    assert_eq!(modified_ms(registers), Some(ms + 100));
    assert_eq!(modified_ms([]), None);
}

#[test]
fn trashed_at_runs_while_trashed() {
    let active = [LIFECYCLE_ACTIVE];
    let trashed = [LIFECYCLE_TRASHED];
    let t1 = cand(100 << 16, 1, 1, &trashed);
    let t2 = cand(200 << 16, 2, 1, &trashed);
    let edit = cand(300 << 16, 3, 1, &active);
    assert_eq!(trashed_at_ms(&[t1, t2]), Some(200));
    assert_eq!(trashed_at_ms(&[t1, t2, edit]), None);
    assert_eq!(trashed_at_ms(&[]), None);
    assert_eq!(DEFAULT_TRASH_RETENTION_MS, 2_592_000_000);
    assert_eq!(purge_due_ms(200, DEFAULT_TRASH_RETENTION_MS), 2_592_000_200);
    assert_eq!(
        purge_due_ms(u64::MAX - 1, DEFAULT_TRASH_RETENTION_MS),
        u64::MAX
    );
}

#[test]
fn candidates_never_print_their_value() {
    let c = cand(1, 0xab, 2, b"\x01hunter2");
    let out = format!("{c:?}");
    assert!(!out.contains("hunter2"), "{out}");
    assert!(out.contains("[REDACTED]"));
    assert!(out.contains("hlc"));
}

// ---------------------------------------------------------------------------------------------
// §6 list elements and order
// ---------------------------------------------------------------------------------------------

#[test]
fn layout_attributes_never_make_an_element_exist() {
    for a in ["order", "match", "kind"] {
        assert_eq!(attribute_role(Some(a)), AttributeRole::Layout, "{a}");
    }
    for a in [
        Some("value"),
        Some("label"),
        Some("secret"),
        Some("ms"),
        Some("anything"),
        None,
    ] {
        assert_eq!(attribute_role(a), AttributeRole::Content, "{a:?}");
    }
    let sort = b"\x06\x80";
    assert!(!element_exists([
        (Some("order"), &sort[..]),
        (Some("kind"), &b"\x05\0\x01"[..])
    ]));
    assert!(!element_exists([
        (Some("order"), &sort[..]),
        (Some("value"), &b""[..])
    ]));
    assert!(element_exists([
        (Some("order"), &sort[..]),
        (Some("value"), &b"\x01x"[..])
    ]));
    assert!(element_exists([(None, &b"\x03\x01"[..])]));
    assert!(!element_exists([(None, &b""[..])]));
    // Non-empty is enough: an unsupported value makes the element exist.
    assert!(element_exists([(None, &b"\x03\x00"[..])]));
    assert!(!element_exists(core::iter::empty()));
}

#[test]
fn lists_sort_by_order_then_element_id() {
    let entry = |order: Option<&'static [u8]>, element: &'static str| ListEntry { order, element };
    let tied_second = entry(Some(&b"\x06\x10"[..]), "ff");
    let high_00 = entry(Some(&b"\x06\x20"[..]), "00");
    let tied_first = entry(Some(&b"\x06\x10"[..]), "fe");
    let none_00 = entry(None, "00");
    let none_01 = entry(None, "01");
    // An unreadable or cleared order counts as none.
    let text_02 = entry(Some(&b"\x01text"[..]), "02");
    let cleared_03 = entry(Some(&b""[..]), "03");
    let mut list = [
        none_01,
        cleared_03,
        high_00,
        text_02,
        none_00,
        tied_second,
        tied_first,
    ];
    list.sort_by(compare_list_entries);
    let ids: Vec<&str> = list.iter().map(|x| x.element).collect();
    assert_eq!(ids, ["fe", "ff", "00", "00", "01", "02", "03"]);
    assert_eq!(
        compare_list_entries(&tied_second, &tied_second),
        Ordering::Equal
    );
    assert_eq!(tied_second.sort_key(), Some(&[0x10][..]));
    assert_eq!(text_02.sort_key(), None);
    let out = format!("{tied_second:?}");
    assert!(!out.contains("ff"), "{out}");
}

#[test]
fn sort_keys_between_neighbours() {
    let between = |lo: Option<&[u8]>, hi: Option<&[u8]>| {
        sort_key_between(lo, hi).map(|k| k.as_bytes().to_vec())
    };
    assert_eq!(between(None, None), Ok(vec![0x80]));
    assert_eq!(between(None, Some(&[0x80])), Ok(vec![0x40]));
    assert_eq!(between(Some(&[0x80]), None), Ok(vec![0xc0]));
    assert_eq!(between(Some(&[1]), Some(&[3])), Ok(vec![2]));
    assert_eq!(between(Some(&[1]), Some(&[2])), Ok(vec![1, 0x80]));
    assert_eq!(
        between(Some(&[5]), Some(&[5, 0, 1])),
        Ok(vec![5, 0, 0, 0x80])
    );
    assert_eq!(between(Some(&[0xff]), None), Ok(vec![0xff, 0x80]));
    assert_eq!(between(None, Some(&[1])), Ok(vec![0, 0x80]));
    assert_eq!(between(None, Some(&[0, 0, 1])), Ok(vec![0, 0, 0, 0x80]));
    assert_eq!(
        between(Some(&[1, 0xff]), Some(&[2])),
        Ok(vec![1, 0xff, 0x80])
    );
    // Errors.
    assert_eq!(between(Some(&[2]), Some(&[2])), Err(OrderError::NoRoom));
    assert_eq!(between(Some(&[3]), Some(&[2])), Err(OrderError::NotOrdered));
    for bad in [&[][..], &[0], &[1, 0], &[1; 65]] {
        assert_eq!(between(Some(bad), None), Err(OrderError::InvalidNeighbour));
        assert_eq!(between(None, Some(bad)), Err(OrderError::InvalidNeighbour));
    }
    // 64 bytes 0x01, and the same ending in 0x02: nothing of at most 64 bytes lies between.
    let lo = [1u8; 64];
    let mut hi = [1u8; 64];
    hi[63] = 2;
    assert_eq!(between(Some(&lo), Some(&hi)), Err(OrderError::NoRoom));
    for e in [
        OrderError::InvalidNeighbour,
        OrderError::NotOrdered,
        OrderError::NoRoom,
        OrderError::TooMany,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn repeated_inserts_stay_ordered_until_a_rewrite() {
    // Always at the front, always at the back, always just after the first element.
    for pattern in 0..3 {
        let mut keys: Vec<Vec<u8>> = vec![vec![0x80]];
        loop {
            let (lo, hi) = match pattern {
                0 => (None, keys.first().cloned()),
                1 => (keys.last().cloned(), None),
                _ => (keys.first().cloned(), keys.get(1).cloned()),
            };
            match sort_key_between(lo.as_deref(), hi.as_deref()) {
                Ok(k) => {
                    let k = k.as_bytes().to_vec();
                    assert!(lo.as_deref().is_none_or(|lo| lo < k.as_slice()));
                    assert!(hi.as_deref().is_none_or(|hi| k.as_slice() < hi));
                    assert!(k.len() <= MAX_SORT_KEY_LEN && k.last() != Some(&0));
                    keys.push(k);
                    keys.sort();
                }
                Err(e) => {
                    assert_eq!(e, OrderError::NoRoom, "pattern {pattern}");
                    break;
                }
            }
            assert!(keys.len() < 20_000, "pattern {pattern} never ran out");
        }
        // The front and middle patterns run out after about 8 inserts per byte of the 64; the
        // back pattern never does before 64 × 8 either.
        assert!(keys.len() > 300, "pattern {pattern}: {}", keys.len());
    }
}

#[test]
fn a_rewrite_spaces_keys_evenly() {
    assert!(evenly_spaced(0).unwrap().is_empty());
    let one: Vec<Vec<u8>> = evenly_spaced(1)
        .unwrap()
        .iter()
        .map(|k| k.as_bytes().to_vec())
        .collect();
    assert_eq!(one, [vec![0x80]]);
    for (n, max_len) in [
        (3, 1),
        (255, 1),
        (256, 2),
        (4096, 2),
        (65_535, 2),
        (65_536, 3),
    ] {
        let keys = evenly_spaced(n).unwrap();
        assert_eq!(keys.len(), n);
        for pair in keys.windows(2) {
            assert!(pair[0].as_bytes() < pair[1].as_bytes(), "n = {n}");
        }
        assert!(
            keys.iter().all(|k| k.as_bytes().len() <= max_len),
            "n = {n}"
        );
        assert!(keys.iter().all(|k| k.as_bytes().last() != Some(&0)));
    }
    let byte_keys: Vec<u8> = evenly_spaced(255)
        .unwrap()
        .iter()
        .map(|k| k.as_bytes()[0])
        .collect();
    assert_eq!(byte_keys, (1..=255).collect::<Vec<u8>>());
    if let Ok(big) = usize::try_from(1u64 << 32) {
        assert_eq!(evenly_spaced(big).map(|_| ()), Err(OrderError::TooMany));
    }
}

// ---------------------------------------------------------------------------------------------
// §11 forward compatibility
// ---------------------------------------------------------------------------------------------

#[test]
fn schema_versions() {
    assert_eq!(ITEM_SCHEMA_VERSION, 1);
    assert_eq!(SchemaVersion::classify(0), SchemaVersion::Invalid);
    assert_eq!(SchemaVersion::classify(1), SchemaVersion::Supported);
    assert_eq!(SchemaVersion::classify(2), SchemaVersion::Unknown);
    assert_eq!(SchemaVersion::classify(0xFFFE), SchemaVersion::Unknown);
    assert_eq!(SchemaVersion::classify(0xFFFF), SchemaVersion::Invalid);
}

/// A simulated newer client (ADR 0018 §11): it writes a key this client does not know, with a
/// value type this client does not know, into a Login item. This client carries both, displays
/// the value as unsupported without rejecting anything, and never writes the key itself.
#[test]
fn a_newer_clients_key_and_value_are_carried() {
    let newer_key = "login.passkey_hint";
    let newer_value = [0x07, 0xde, 0xad];
    let k = key(newer_key);
    assert_eq!(classify(k), KeyClass::Unknown);
    let owned = FieldKey::from_ref(k);
    assert_eq!(owned.as_bytes(), newer_key.as_bytes());
    assert_eq!(
        ValueRef::decode(&newer_value).map(|_| ()),
        Err(ValueError::UnknownType)
    );
    let carried = Value::copy_from_encoded(&newer_value).unwrap();
    assert_eq!(carried.expose_secret(), newer_value);
    // Display still works: the newer value is non-empty and conflicts with a concurrent Text.
    let ours = Value::text("mine").unwrap();
    let shown = resolve_field(&[
        cand(2, 1, 1, &newer_value),
        cand(1, 2, 1, ours.expose_secret()),
    ])
    .unwrap();
    assert_eq!(shown.displayed, 0);
    assert!(shown.conflict);
    assert!(read_value(Expected::Text, &newer_value).is_none());
    // A newer item type is unsupported but still an item.
    assert_eq!(ItemType::from_id(0x0042).supported(), None);
    // This client never invents a value for the key.
    assert_eq!(
        check_write(
            ItemType::LOGIN,
            WriteMode::Edit,
            newer_key.as_bytes(),
            ours.expose_secret()
        ),
        Err(WriteError::UnknownKey)
    );
    // It may clear it in an edit (§6 element removal), and carry it byte for byte into a
    // restored or duplicated item.
    assert_eq!(
        check_write(ItemType::LOGIN, WriteMode::Edit, newer_key.as_bytes(), b""),
        Ok(())
    );
    assert_eq!(
        check_carried(
            ItemType::LOGIN,
            WriteMode::Create,
            owned.as_bytes(),
            carried.expose_secret()
        ),
        Ok(())
    );
}
