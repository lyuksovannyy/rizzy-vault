//! `items.json`: the schema layer of the item record (ADR 0018 §2): the value encoding of §6,
//! with the values a reader shows as unsupported, the field-key grammar of §7 and its §10
//! length limit, with rejected keys, and tag keys from tag names (§7, owner decision 7).
//!
//! These are the byte rules both layers share: every value inside an `ITEM_OP` or
//! `ITEM_SNAPSHOT` record is one of these encodings, and every key the record parser accepts
//! passes this grammar (ADR 0018 §5 rules 2 and 3). The record layouts themselves (§3–§5) are
//! `rizzy-sync`'s and are not here. Which keys the M1 schema *knows* is deliberately not a
//! vector output: new keys need no version bump (ADR 0018 §7, §11), and a tier A vector changes
//! only with one.
//!
//! The replay checks each output against the specification independently of the API: a value
//! is its type byte followed by its payload in the §2 encoding; a key's parts rebuild it; a tag
//! key is `tag/` and the lowercase hex of the name normalised by `unicode-normalization`
//! directly.

use chacha20::ChaCha20Rng;
use serde_json::{Map, Value as Json};
use unicode_normalization::UnicodeNormalization as _;

use super::{Obj, Vector, boolean, bytes, num, random, random_vec, text, to_hex, u64_of};
use crate::item::key::{FieldKeyRef, KeyKind};
use crate::item::tag::{tag_key, tag_name};
use crate::item::value::{SortKey, Value, ValueRef};

/// The `kind` of every vector in this file.
const KIND: &str = "item";

/// Builds vector `item/<name>/<index>` from its inputs.
fn vector(name: &str, index: usize, inputs: Obj) -> Vector {
    Vector::build(compute, KIND, name, index, inputs)
}

/// Draws the inputs of every vector, in a fixed order, from the file's seeded RNG.
#[expect(
    clippy::too_many_lines,
    reason = "one flat table of test vectors reads best as one function"
)]
pub(super) fn generate(rng: &mut ChaCha20Rng) -> Vec<Vector> {
    let mut out = Vec::new();

    // §6: one vector per value type, and the edge cases a writer meets.
    let random_u64 = u64::from_be_bytes(random::<8>(rng));
    let random_enum = u16::from_be_bytes(random::<2>(rng));
    let mut sort_key = random_vec(rng, 20);
    if let Some(last) = sort_key.last_mut() {
        *last |= 1;
    }
    let values = [
        Obj::new().text("type", "cleared"),
        Obj::new().text("type", "text").text("text", ""),
        Obj::new()
            .text("type", "text")
            .text("text", "correct horse battery staple"),
        // As entered: NFD stays NFD, and spaces stay.
        Obj::new()
            .text("type", "text")
            .text("text", " e\u{301}t\u{e9} "),
        Obj::new()
            .text("type", "text")
            .text("text", "\u{1f511} otpauth://totp/x"),
        Obj::new()
            .text("type", "bytes")
            .bytes("payload", &random::<32>(rng)),
        Obj::new().text("type", "bytes").bytes("payload", &[]),
        Obj::new().text("type", "bool").bool("bool", false),
        Obj::new().text("type", "bool").bool("bool", true),
        Obj::new().text("type", "u64").u64("u64", random_u64),
        Obj::new().text("type", "u64").u64("u64", u64::MAX),
        Obj::new()
            .text("type", "enum")
            .num("enum", u32::from(random_enum)),
        Obj::new().text("type", "enum").num("enum", 0xF001),
        Obj::new()
            .text("type", "sort-key")
            .bytes("payload", &[0x80]),
        Obj::new()
            .text("type", "sort-key")
            .bytes("payload", &sort_key),
    ];
    for (i, inputs) in values.into_iter().enumerate() {
        out.push(vector("value", i, inputs));
    }

    // §6: values a reader shows as "unsupported value" (never a rejected record).
    let unsupported: [Vec<u8>; 14] = [
        vec![0x00],
        [&[0x07u8][..], &random::<4>(rng)].concat(),
        vec![0xff],
        vec![0x01, b'a', 0xc3],
        vec![0x03],
        vec![0x03, 0x02],
        vec![0x03, 0x01, 0x00],
        vec![0x04, 0, 0, 0, 0, 0, 0, 1],
        vec![0x04, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        vec![0x05, 0x01],
        vec![0x05, 0x00, 0x01, 0x00],
        vec![0x06],
        vec![0x06, 0x80, 0x00],
        [&[0x06u8][..], &[0x01; 65]].concat(),
    ];
    for (i, encoded) in unsupported.iter().enumerate() {
        out.push(vector(
            "value/unsupported",
            i,
            Obj::new().bytes("encoded", encoded),
        ));
    }

    // §7: accepted keys. The Login keys pin the §4 order of §12's Login create; the tags are
    // §12's `tag/61` and `tag/6162`; the rest are the length edges.
    let element = to_hex(&random::<16>(rng));
    let accepted = [
        "item.type".to_owned(),
        "login.password".to_owned(),
        "login.totp".to_owned(),
        "login.username".to_owned(),
        "a.b".to_owned(),
        format!("uri/{element}/value"),
        format!("uri/{element}/match"),
        format!("field/{element}/order"),
        format!("share/{element}/secret"),
        "tag/61".to_owned(),
        "tag/6162".to_owned(),
        // A 32-byte name, and a fixed key of exactly 160 bytes.
        format!("{}.b", "a".repeat(32)),
        format!(
            "{}.{}.{}.{}.{}",
            "a".repeat(32),
            "b".repeat(32),
            "c".repeat(32),
            "d".repeat(32),
            "e".repeat(28)
        ),
        // The longest `elem`, 128 digits.
        format!("x/{}", to_hex(&random_vec(rng, 64))),
    ];
    for (i, key) in accepted.iter().enumerate() {
        out.push(vector("field-key", i, Obj::new().text("key", key)));
    }

    // §7, §10: rejected keys. ADR 0018 §12 names an odd hex count, a 33-byte name, uppercase
    // hex and a 161-byte key; the rest break one production each.
    let rejected: [Vec<u8>; 16] = [
        b"uri/abc/value".to_vec(),
        format!("{}.b", "a".repeat(33)).into_bytes(),
        format!("uri/{}/value", element.to_uppercase()).into_bytes(),
        format!(
            "{}.{}.{}.{}.{}",
            "a".repeat(32),
            "b".repeat(32),
            "c".repeat(32),
            "d".repeat(32),
            "e".repeat(29)
        )
        .into_bytes(),
        Vec::new(),
        b"@lifecycle".to_vec(),
        b"notes".to_vec(),
        b"Login.password".to_vec(),
        b"a..b".to_vec(),
        b"1a.b".to_vec(),
        b"tag/".to_vec(),
        b"a/00/b/c".to_vec(),
        b"a.b/00".to_vec(),
        "\u{e9}.b".as_bytes().to_vec(),
        vec![b'a', b'.', b'b', 0x00],
        format!("x/{}", "ab".repeat(65)).into_bytes(),
    ];
    for (i, key) in rejected.iter().enumerate() {
        out.push(vector("field-key/reject", i, Obj::new().bytes("key", key)));
    }

    // §7: tag keys from names (NFC, no Cc, 1–64 bytes).
    let tags = [
        "a".to_owned(),
        "ab".to_owned(),
        "Work/Email".to_owned(),
        "e\u{301}".to_owned(),
        "\u{e9}".to_owned(),
        "\u{fb01}".to_owned(),
        "\u{1f511} keys".to_owned(),
        "z".repeat(64),
    ];
    for (i, name) in tags.iter().enumerate() {
        out.push(vector("tag-key", i, Obj::new().text("name", name)));
    }
    let tag_rejects = [
        String::new(),
        "z".repeat(65),
        "a\u{7}".to_owned(),
        "\u{85}".to_owned(),
        "\u{344}".repeat(32),
    ];
    for (i, name) in tag_rejects.iter().enumerate() {
        out.push(vector("tag-key/reject", i, Obj::new().text("name", name)));
    }
    out
}

/// The value a `value` vector's inputs describe, through the API, and the same value built
/// from the §6 table and the §2 integer encoding.
fn build_value(m: &Map<String, Json>) -> (Value, Vec<u8>) {
    let with_type = |id: u8, payload: &[u8]| [&[id][..], payload].concat();
    match text(m, "type") {
        "cleared" => (Value::cleared(), Vec::new()),
        "text" => {
            let t = text(m, "text");
            (Value::text(t).expect("fits"), with_type(0x01, t.as_bytes()))
        }
        "bytes" => {
            let b = bytes(m, "payload");
            (Value::bytes(&b).expect("fits"), with_type(0x02, &b))
        }
        "bool" => {
            let b = boolean(m, "bool");
            (Value::bool(b), with_type(0x03, &[u8::from(b)]))
        }
        "u64" => {
            let v = u64_of(m, "u64");
            (Value::u64(v), with_type(0x04, &v.to_be_bytes()))
        }
        "enum" => {
            let v: u16 = num(m, "enum");
            (Value::enumeration(v), with_type(0x05, &v.to_be_bytes()))
        }
        "sort-key" => {
            let k = bytes(m, "payload");
            let key = SortKey::from_slice(&k).expect("a valid sort key");
            (Value::sort_key(&key), with_type(0x06, &k))
        }
        other => panic!("unknown value type {other}"),
    }
}

/// Computes one vector's outputs through the API, and checks them against the ADR 0018 §6
/// and §7 formulas.
pub(super) fn compute(name: &str, m: &Map<String, Json>) -> Map<String, Json> {
    match name {
        "value" => {
            let (value, expected) = build_value(m);
            assert_eq!(value.expose_secret(), expected.as_slice());
            let decoded = value.decode().expect("a well-formed value decodes");
            let again = decoded.encode().expect("re-encodes");
            assert_eq!(again.expose_secret(), value.expose_secret());
            Obj::new().bytes("encoded", value.expose_secret()).done()
        }
        "value/unsupported" => {
            let encoded = bytes(m, "encoded");
            assert!(!encoded.is_empty(), "Cleared is never unsupported");
            assert!(ValueRef::decode(&encoded).is_err(), "must be unsupported");
            // Carried verbatim anyway (ADR 0018 §6, §11).
            let carried = Value::copy_from_encoded(&encoded).expect("within the limit");
            assert_eq!(carried.expose_secret(), encoded.as_slice());
            Obj::new().bool("supported", false).done()
        }
        "field-key" => {
            let key_text = text(m, "key");
            let key = FieldKeyRef::parse_str(key_text).expect("accepted");
            assert!(key_text.len() <= 160);
            let out = Obj::new();
            match key.kind() {
                KeyKind::Fixed => {
                    let names: Vec<&str> = key.fixed_names().expect("fixed").collect();
                    assert!(names.len() >= 2);
                    assert_eq!(names.join("."), key_text);
                    out.text("kind", "fixed")
                        .null("list")
                        .null("element")
                        .null("attribute")
                        .done()
                }
                KeyKind::Element => {
                    let (list, element) =
                        (key.list().expect("a list"), key.element().expect("an elem"));
                    assert!(element.len().is_multiple_of(2) && (2..=128).contains(&element.len()));
                    let rebuilt = match key.attribute() {
                        Some(a) => format!("{list}/{element}/{a}"),
                        None => format!("{list}/{element}"),
                    };
                    assert_eq!(rebuilt, key_text);
                    let out = out
                        .text("kind", "element")
                        .text("list", list)
                        .text("element", element);
                    match key.attribute() {
                        Some(a) => out.text("attribute", a).done(),
                        None => out.null("attribute").done(),
                    }
                }
            }
        }
        "field-key/reject" => {
            assert!(
                FieldKeyRef::parse(&bytes(m, "key")).is_err(),
                "must be rejected"
            );
            Obj::new().bool("accepted", false).done()
        }
        "tag-key" => {
            let tag = text(m, "name");
            let key = tag_key(tag).expect("accepted");
            let normalized: String = tag.nfc().collect();
            assert_eq!(
                key.as_str(),
                format!("tag/{}", to_hex(normalized.as_bytes()))
            );
            assert_eq!(
                tag_name(key.as_key()).expect("reads back").as_str(),
                normalized
            );
            Obj::new()
                .text("key", key.as_str())
                .bytes("normalized", normalized.as_bytes())
                .done()
        }
        "tag-key/reject" => {
            assert!(tag_key(text(m, "name")).is_err(), "must be rejected");
            Obj::new().bool("accepted", false).done()
        }
        other => panic!("unknown item vector {other}"),
    }
}
