//! Property tests of the item schema (ADR 0018 §12, the schema-layer round trips): the value
//! decoder and the key grammar never panic and are canonical (decode then encode, and parse
//! then rebuild, are the identity); every key the grammar generates parses, and the parser
//! agrees with an independent matcher of the ABNF; tag keys round-trip through their names;
//! sort keys land strictly between their neighbours; and the display rules do not depend on the
//! order the register's values are listed in.

use core::fmt::Write as _;

use proptest::prelude::*;

use super::display::{Candidate, resolve_field, resolve_lifecycle};
use super::key::{FieldKey, FieldKeyRef, KeyKind, MAX_KEY_LEN};
use super::order::{evenly_spaced, sort_key_between};
use super::schema::classify;
use super::tag::{tag_key, tag_name};
use super::value::{MAX_SORT_KEY_LEN, SortKey, Value, ValueRef, is_sort_key};
use crate::ids::DeviceId;

/// A `name` of the grammar.
fn name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,31}"
}

/// An `elem`: 1–64 random bytes, as lowercase hex.
fn elem() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..=64)
}

/// A key the grammar generates, possibly over the 160-byte limit.
fn grammar_key() -> impl Strategy<Value = String> {
    let fixed = proptest::collection::vec(name(), 2..6).prop_map(|names| names.join("."));
    let element = (name(), elem(), proptest::option::of(name())).prop_map(|(list, id, attr)| {
        let hex = id.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        match attr {
            Some(attr) => format!("{list}/{hex}/{attr}"),
            None => format!("{list}/{hex}"),
        }
    });
    prop_oneof![fixed, element]
}

/// A well-formed value of any type, encoded.
fn typed_value() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(Vec::new()),
        any::<String>().prop_map(|t| Value::text(&t).unwrap().expose_secret().to_vec()),
        proptest::collection::vec(any::<u8>(), 0..100)
            .prop_map(|b| Value::bytes(&b).unwrap().expose_secret().to_vec()),
        any::<bool>().prop_map(|b| Value::bool(b).expose_secret().to_vec()),
        any::<u64>().prop_map(|v| Value::u64(v).expose_secret().to_vec()),
        any::<u16>().prop_map(|v| Value::enumeration(v).expose_secret().to_vec()),
        sort_key_payload().prop_map(|k| {
            Value::sort_key(&SortKey::from_slice(&k).unwrap())
                .expose_secret()
                .to_vec()
        }),
    ]
}

/// A valid `SortKey` payload: 1–64 bytes, last byte not `0x00`.
fn sort_key_payload() -> impl Strategy<Value = Vec<u8>> {
    (
        proptest::collection::vec(any::<u8>(), 0..MAX_SORT_KEY_LEN),
        1..=u8::MAX,
    )
        .prop_map(|(mut body, last)| {
            body.push(last);
            body
        })
}

/// Register values with distinct dots: `(hlc, device, value)`, the `seq` being the index.
fn register() -> impl Strategy<Value = Vec<(u64, u8, Vec<u8>)>> {
    proptest::collection::vec(
        (
            0u64..8,
            0u8..4,
            prop_oneof![
                Just(Vec::new()),
                Just(b"\x01a".to_vec()),
                Just(b"\x01b".to_vec()),
                Just(b"\x03\x02".to_vec()),
            ],
        ),
        0..8,
    )
}

/// The candidates of `values`, with `seq` = index + 1 so that every dot is distinct.
fn candidates(values: &[(u64, u8, Vec<u8>)]) -> Vec<Candidate<'_>> {
    values
        .iter()
        .zip(1u64..)
        .map(|((hlc, device, value), seq)| Candidate {
            hlc: *hlc,
            device_id: DeviceId::from_bytes([*device; 16]),
            seq,
            value,
        })
        .collect()
}

proptest! {
    /// "The value decoder" (§12): never panics on any bytes, and a value it accepts encodes back
    /// to exactly the same bytes (one encoding per value).
    #[test]
    fn value_decoding_is_canonical(encoded in proptest::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(value) = ValueRef::decode(&encoded) {
            let again = value.encode().unwrap();
            prop_assert_eq!(again.expose_secret(), encoded.as_slice());
            prop_assert_eq!(value.is_cleared(), encoded.is_empty());
        } else {
            prop_assert!(!encoded.is_empty());
        }
        let carried = Value::copy_from_encoded(&encoded).unwrap();
        prop_assert_eq!(carried.expose_secret(), encoded.as_slice());
    }

    /// Every well-formed value decodes and encodes back unchanged.
    #[test]
    fn typed_values_round_trip(encoded in typed_value()) {
        let value = ValueRef::decode(&encoded).unwrap();
        let again = value.encode().unwrap();
        prop_assert_eq!(again.expose_secret(), encoded.as_slice());
        if let ValueRef::SortKey(payload) = value {
            prop_assert!(is_sort_key(payload));
        }
    }

    /// "The key grammar" (§12): never panics on any bytes; an accepted key is at most 160
    /// bytes, and its parts rebuild it exactly.
    #[test]
    fn key_parsing_is_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(key) = FieldKeyRef::parse(&bytes) {
            prop_assert!(bytes.len() <= MAX_KEY_LEN);
            prop_assert_eq!(key.as_bytes(), bytes.as_slice());
            rebuilds(key)?;
            let _ = classify(key);
        }
    }

    /// Every key the grammar generates parses, unless it is over 160 bytes.
    #[test]
    fn grammar_keys_parse(text in grammar_key()) {
        match FieldKeyRef::parse_str(&text) {
            Ok(key) => {
                prop_assert!(text.len() <= MAX_KEY_LEN);
                rebuilds(key)?;
            }
            Err(e) => {
                prop_assert!(text.len() > MAX_KEY_LEN, "{:?}", e);
            }
        }
    }

    /// Changing one byte of a valid key to a byte outside the grammar's alphabet is rejected.
    #[test]
    fn foreign_bytes_are_rejected(
        text in grammar_key(),
        at in any::<prop::sample::Index>(),
        byte in prop_oneof![b'A'..=b'Z', b'!'..=b'-', 0x80u8..=0xff, Just(b'@')],
    ) {
        let mut bytes = text.into_bytes();
        let i = at.index(bytes.len());
        bytes[i] = byte;
        prop_assert!(FieldKeyRef::parse(&bytes).is_err());
    }

    /// Tag keys round-trip: the key of a valid name reads back as the NFC name, and that name
    /// gives the same key again.
    #[test]
    fn tag_keys_round_trip(name in "\\PC{1,20}") {
        if let Ok(key) = tag_key(&name) {
            let back = tag_name(key.as_key()).unwrap();
            let again = tag_key(&back).unwrap();
            prop_assert_eq!(again.as_str(), key.as_str());
            prop_assert!(!back.is_empty() && back.len() <= 64);
        }
    }

    /// A sort key strictly between two neighbours, whenever the bounds leave room within 64
    /// bytes, which they always do when both are at most 32 bytes long.
    #[test]
    fn sort_keys_fall_between(a in proptest::option::of(sort_key_payload()),
                              b in proptest::option::of(sort_key_payload())) {
        let (lo, hi) = match (&a, &b) {
            (Some(x), Some(y)) if x > y => (b.as_deref(), a.as_deref()),
            _ => (a.as_deref(), b.as_deref()),
        };
        match sort_key_between(lo, hi) {
            Ok(key) => {
                let k = key.as_bytes();
                prop_assert!(is_sort_key(k));
                prop_assert!(lo.is_none_or(|lo| lo < k));
                prop_assert!(hi.is_none_or(|hi| k < hi));
            }
            Err(e) => {
                let short = lo.is_none_or(|k| k.len() <= 32) && hi.is_none_or(|k| k.len() <= 32);
                prop_assert!(lo == hi || !short, "{:?}", e);
            }
        }
    }

    /// A rewrite gives strictly ascending, valid keys.
    #[test]
    fn evenly_spaced_keys_ascend(n in 0usize..700) {
        let keys = evenly_spaced(n).unwrap();
        prop_assert_eq!(keys.len(), n);
        for pair in keys.windows(2) {
            prop_assert!(pair[0].as_bytes() < pair[1].as_bytes());
        }
    }

    /// The displayed value, the conflict mark and the "cleared on X" value do not depend on the
    /// order of the register's values (ADR 0018 §6: display is a function of the register).
    #[test]
    fn display_is_order_independent(values in register(), rotate in 0usize..8) {
        let forward = candidates(&values);
        let mut shuffled = forward.clone();
        shuffled.reverse();
        let len = shuffled.len().max(1);
        shuffled.rotate_left(rotate % len);
        let shown = |c: &[Candidate<'_>]| {
            resolve_field(c).map(|d| {
                let value = c[d.displayed].value.to_vec();
                let cleared = d.cleared_by.map(|i| (c[i].hlc, c[i].device_id, c[i].seq));
                (value, d.conflict, cleared)
            })
        };
        prop_assert_eq!(shown(&forward), shown(&shuffled));
        let lifecycle = |c: &[Candidate<'_>]| {
            resolve_lifecycle(c)
                .map(|d| (d.shown, c[d.displayed].seq, d.trashed_by.map(|i| c[i].seq)))
        };
        prop_assert_eq!(lifecycle(&forward), lifecycle(&shuffled));
        // A non-empty value displays whenever there is one.
        if let Some(d) = resolve_field(&forward) {
            let any_non_empty = forward.iter().any(|c| !c.value.is_empty());
            prop_assert_eq!(!forward[d.displayed].value.is_empty(), any_non_empty);
        }
    }
}

/// Rebuilds `key` from its parts through the owned builders and checks the bytes are equal.
fn rebuilds(key: FieldKeyRef<'_>) -> Result<(), TestCaseError> {
    let owned = FieldKey::from_ref(key);
    prop_assert_eq!(owned.as_bytes(), key.as_bytes());
    match key.kind() {
        KeyKind::Fixed => {
            let names: Vec<&str> = key.fixed_names().unwrap().collect();
            prop_assert!(names.len() >= 2);
            prop_assert_eq!(names.join("."), key.as_str());
            prop_assert_eq!(key.namespace(), names[0]);
        }
        KeyKind::Element => {
            let element = key.element_bytes().unwrap();
            let rebuilt =
                FieldKey::element(key.list().unwrap(), &element, key.attribute()).unwrap();
            prop_assert_eq!(rebuilt.as_bytes(), key.as_bytes());
            prop_assert_eq!(key.namespace(), key.list().unwrap());
        }
    }
    Ok(())
}

/// The bytes a near-miss edit writes: the grammar's alphabet (`a`–`f` are both `name` and
/// `elem` bytes, `g` and `z` `name` bytes only), both separators, and the bytes next to them in
/// ASCII (`` ` `` and `{` around `a`–`z`, `-` and `:` around `.`, `/` and the digits), `A` and
/// `@`.
const NEAR_BYTES: &[u8] = b"abfgz09_./@A`{-:";

/// A key one edit away from one the grammar generates: a byte changed, inserted or removed
/// (or none, when the removal falls past the end), so that the oracle comparison lands on the
/// accept/reject boundary and not mostly on random rejections. [`grammar_key`] reaches both
/// limits: an `elem` of up to 128 digits and keys over 160 bytes.
fn near_miss_key() -> impl Strategy<Value = Vec<u8>> {
    (
        grammar_key(),
        any::<prop::sample::Index>(),
        prop::sample::select(NEAR_BYTES),
        0u8..3,
    )
        .prop_map(|(text, at, byte, edit)| {
            let mut bytes = text.into_bytes();
            let i = at.index(bytes.len() + 1);
            match (edit, i < bytes.len()) {
                (0, true) => bytes[i] = byte,
                (0 | 1, _) => bytes.insert(i, byte),
                (_, true) => {
                    bytes.remove(i);
                }
                (_, false) => {}
            }
            bytes
        })
}

/// A key at the length limits: an element key whose `elem` has 120–132 digits of either
/// parity (the grammar allows an even 2–128), or a fixed key of four to eight names, 7–263
/// bytes, so that the 128-digit `elem` limit and the 160-byte key limit are crossed both ways.
fn long_key() -> impl Strategy<Value = Vec<u8>> {
    let element = (name(), "[0-9a-f]{120,132}", proptest::option::of(name())).prop_map(
        |(list, hex, attr)| match attr {
            Some(attr) => format!("{list}/{hex}/{attr}"),
            None => format!("{list}/{hex}"),
        },
    );
    let fixed = proptest::collection::vec(name(), 4..=8).prop_map(|names| names.join("."));
    prop_oneof![element, fixed].prop_map(String::into_bytes)
}

proptest! {
    // The only check of the grammar parser against a matcher written separately from the ABNF
    // (ADR 0018 §7, frozen with the version-1 vectors, §5 "Frozen rules"): this parser is the
    // record layer's key check too (`rizzy-sync`, §5 rules 2 and 3), so it gets more cases than
    // the default 256.
    #![proptest_config(ProptestConfig {
        cases: 4_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// The parser agrees with an independent matcher written from the ABNF ([`abnf_oracle`]),
    /// over a small alphabet that reaches every production and every failure, `@` included.
    #[test]
    fn grammar_agrees_with_the_abnf(key in "[a-fA_0-9./@]{0,40}") {
        prop_assert_eq!(FieldKeyRef::parse_str(&key).is_ok(), abnf_oracle(key.as_bytes()));
    }

    /// The parser agrees with the ABNF matcher near the boundary ([`near_miss_key`]), at the
    /// length limits ([`long_key`]) and on arbitrary bytes, UTF-8 or not.
    #[test]
    fn grammar_agrees_with_the_abnf_at_the_edges(
        key in prop_oneof![
            near_miss_key(),
            long_key(),
            proptest::collection::vec(any::<u8>(), 0..200),
        ],
    ) {
        prop_assert_eq!(FieldKeyRef::parse(&key).is_ok(), abnf_oracle(&key));
    }
}

/// An independent matcher of the ADR 0018 §7 ABNF and the §10 length limit: it splits the key
/// on its separators and checks each token, where the parser scans it once. It works on bytes,
/// so a key that is not UTF-8 is simply one no token accepts.
fn abnf_oracle(key: &[u8]) -> bool {
    let name = |b: &[u8]| {
        (1..=32).contains(&b.len())
            && b.first().is_some_and(u8::is_ascii_lowercase)
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
    };
    let elem = |b: &[u8]| {
        (2..=128).contains(&b.len())
            && b.len().is_multiple_of(2)
            && b.iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    };
    let grammar = match key.split(|c| *c == b'/').collect::<Vec<_>>().as_slice() {
        [single] => {
            let parts: Vec<&[u8]> = single.split(|c| *c == b'.').collect();
            parts.len() >= 2 && parts.iter().all(|p| name(p))
        }
        [n, e] => name(n) && elem(e),
        [n, e, m] => name(n) && elem(e) && name(m),
        _ => false,
    };
    grammar && (1..=MAX_KEY_LEN).contains(&key.len())
}
