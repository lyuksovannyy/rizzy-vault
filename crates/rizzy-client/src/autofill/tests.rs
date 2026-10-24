// SPDX-License-Identifier: AGPL-3.0-only

//! The pure W1–W5 checks of [`super::check_custom_fields`] (ADR 0076 §2.3) on a new item's
//! writes: no vault needed.

use rizzy_core::item::schema::{
    ATTR_AUTOCOMPLETE, ATTR_KIND, ATTR_LABEL, ATTR_ORDER, ATTR_VALUE, CUSTOM_KIND_BOOLEAN,
    CUSTOM_KIND_HIDDEN, CUSTOM_KIND_TEXT, ITEM_NAME,
};
use rizzy_core::item::value::{SortKey, Value};

use super::{CheckMode, check_custom_fields};
use crate::error::ClientError;

const A: &str = "00112233445566778899aabbccddeeff";
const B: &str = "ffeeddccbbaa99887766554433221100";

fn key(element: &str, attribute: &str) -> String {
    format!("field/{element}/{attribute}")
}

fn t(s: &str) -> Value {
    Value::text(s).unwrap()
}

fn check(writes: &[(String, Value)], mode: CheckMode) -> Result<(), ClientError> {
    let pairs: Vec<(&str, &[u8])> = writes
        .iter()
        .map(|(k, v)| (k.as_str(), v.expose_secret()))
        .collect();
    check_custom_fields(&pairs, mode)
}

fn field(element: &str, label: Option<&str>, kind: u16, id: Option<&str>) -> Vec<(String, Value)> {
    let mut out = vec![
        (key(element, ATTR_KIND), Value::enumeration(kind)),
        (
            key(element, ATTR_VALUE),
            if kind == CUSTOM_KIND_BOOLEAN {
                Value::bool(true)
            } else {
                t("v")
            },
        ),
    ];
    if let Some(label) = label {
        out.push((key(element, ATTR_LABEL), t(label)));
    }
    if let Some(id) = id {
        out.push((key(element, ATTR_AUTOCOMPLETE), t(id)));
    }
    out
}

#[test]
fn a_valid_field_passes() {
    for mode in [CheckMode::Write, CheckMode::Import] {
        assert_eq!(
            check(
                &field(A, Some("Member"), CUSTOM_KIND_TEXT, Some("member")),
                mode
            ),
            Ok(())
        );
        assert_eq!(
            check(
                &field(A, Some("PIN"), CUSTOM_KIND_HIDDEN, Some("pin")),
                mode
            ),
            Ok(())
        );
        assert_eq!(
            check(&field(A, Some("No id"), CUSTOM_KIND_BOOLEAN, None), mode),
            Ok(())
        );
    }
    // Writes outside the custom-field list are not this check's.
    assert_eq!(
        check(&[(ITEM_NAME.to_owned(), t("x"))], CheckMode::Write),
        Ok(())
    );
}

#[test]
fn w1_and_w2() {
    for (id, err) in [
        ("Member", ClientError::AutocompleteInvalid),
        ("a b", ClientError::AutocompleteInvalid),
        ("\u{e9}", ClientError::AutocompleteInvalid),
        ("username", ClientError::AutocompleteReserved),
        ("email", ClientError::AutocompleteReserved),
        ("section-x", ClientError::AutocompleteReserved),
        ("one-time-code", ClientError::AutocompleteReserved),
    ] {
        for mode in [CheckMode::Write, CheckMode::Import] {
            assert_eq!(
                check(&field(A, Some("L"), CUSTOM_KIND_TEXT, Some(id)), mode),
                Err(err),
                "{id:?}"
            );
        }
    }
    // A non-Text id is not an id.
    let mut writes = field(A, Some("L"), CUSTOM_KIND_TEXT, None);
    writes.push((key(A, ATTR_AUTOCOMPLETE), Value::bool(true)));
    assert_eq!(
        check(&writes, CheckMode::Write),
        Err(ClientError::InvalidEdit)
    );
}

#[test]
fn w3_duplicates_in_one_op() {
    let mut writes = field(A, Some("One"), CUSTOM_KIND_TEXT, Some("acct"));
    writes.extend(field(B, Some("Two"), CUSTOM_KIND_HIDDEN, Some("acct")));
    assert_eq!(
        check(&writes, CheckMode::Write),
        Err(ClientError::AutocompleteDuplicate)
    );
    assert_eq!(
        check(&writes, CheckMode::Import),
        Err(ClientError::AutocompleteDuplicate)
    );
}

#[test]
fn w4_kind() {
    for kind in [CUSTOM_KIND_BOOLEAN, 9] {
        assert_eq!(
            check(&field(A, Some("L"), kind, Some("acct")), CheckMode::Write),
            Err(ClientError::AutocompleteKind)
        );
    }
    // No kind at all reads as unknown.
    let writes = vec![
        (key(A, ATTR_LABEL), t("L")),
        (key(A, ATTR_VALUE), t("v")),
        (key(A, ATTR_AUTOCOMPLETE), t("acct")),
    ];
    assert_eq!(
        check(&writes, CheckMode::Write),
        Err(ClientError::AutocompleteKind)
    );
}

#[test]
fn w5_label() {
    for label in [None, Some(" "), Some("\t\u{a0}")] {
        assert_eq!(
            check(&field(A, label, CUSTOM_KIND_TEXT, None), CheckMode::Write),
            Err(ClientError::LabelRequired),
            "{label:?}"
        );
        // An import keeps an empty name (§2.4)...
        assert_eq!(
            check(&field(A, label, CUSTOM_KIND_TEXT, None), CheckMode::Import),
            Ok(())
        );
        // ...unless the field has an id.
        assert_eq!(
            check(
                &field(A, label, CUSTOM_KIND_TEXT, Some("acct")),
                CheckMode::Import
            ),
            Err(ClientError::LabelRequired)
        );
    }
    // An order-only write is a layout write, not an edit.
    let order = Value::sort_key(&SortKey::from_slice(&[0x80]).unwrap());
    assert_eq!(
        check(&[(key(A, ATTR_ORDER), order)], CheckMode::Write),
        Ok(())
    );
    // A write that leaves nothing displayed is a removal.
    assert_eq!(
        check(&[(key(A, ATTR_VALUE), Value::cleared())], CheckMode::Write),
        Ok(())
    );
}

#[test]
fn errors_carry_neither_id_nor_label() {
    let err = check(
        &field(A, Some("Secret label"), CUSTOM_KIND_TEXT, Some("Secret-Id")),
        CheckMode::Write,
    )
    .unwrap_err();
    let text = format!("{err} {err:?} {}", err.code());
    assert!(!text.contains("Secret"));
}
