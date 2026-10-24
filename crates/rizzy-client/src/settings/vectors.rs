// SPDX-License-Identifier: AGPL-3.0-only

//! Known-answer vectors of the `ACCOUNT_SETTINGS` plaintext (ADR 0042 §8; CRYPTO.md §15 item
//! 1(A)).
//!
//! **Where they live.** Like the item-record vectors (`rizzy-sync`'s `record/vectors.rs`), these
//! are layout-level Rust test constants: the codec is `rizzy-client`'s and `rizzy-match`'s, which
//! `rizzy-core`'s JSON generator cannot depend on (ADR 0016). The committed hex was written by an
//! independent Python writer from the ADR 0042 §2–§3 layout, not by this crate's encoder. The one
//! envelope-level vector, `envelope/ACCOUNT_SETTINGS/0` in `rizzy-core`'s `envelopes.json`, carries
//! a real encoded record as its plaintext; [`the_core_envelope_vector_carries_a_real_record`]
//! parses it here and re-encodes it byte for byte.
//!
//! - **Positive** (ADR 0042 §8 "Normative"): an empty record; a matching-only record with no
//!   groups; one with disabled and user groups; one with unknown tags, preserved through decode
//!   and re-encode. Each must decode, re-encode to the same hex, and (where built through the
//!   typed API) the typed value must encode to the hex.
//! - **Negative** (ADR 0042 §8, one violation each): truncated entry, duplicate tag, oversize
//!   entry, too many entries, duplicate `group_id`, a one-domain user group, a public-suffix
//!   domain, `match_default` out of range, `flag = 1`, and `format_version ≠ 1` (parked:
//!   `settings_update_required`, not rejected), plus tags out of order, tag `0x0000`/`0xFFFF` and a
//!   trailing byte.

use rizzy_match::{GroupId, MatchMode, user_group};

use super::*;

/// The positive vectors: name, hex.
const POSITIVE: &[(&str, &str)] = &[
    ("empty", "00010000"),
    ("matching-only", "00010001000100000006000200000000"),
    (
        "matching-groups",
        "000100010001000000570001000211111111111111111111111111111111222222222222222222222222\
         222222220001a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000020000000b6578616d706c652e636f6d000000\
         0b6578616d706c652e6e657400",
    ),
    (
        "unknown-tags",
        "0001000300010000000600010000000000050000000268697ffe00000000",
    ),
];

/// The negative vectors that fit a constant: name, hex, expected error.
const NEGATIVE: &[(&str, &str, ClientError)] = &[
    (
        "truncated-entry",
        "0001000100010000000600020000",
        ClientError::InvalidServerResponse,
    ),
    (
        "duplicate-tag",
        "000100020002000000016100020000000162",
        ClientError::InvalidServerResponse,
    ),
    (
        "tags-out-of-order",
        "00010002000300000000000200000000",
        ClientError::InvalidServerResponse,
    ),
    (
        "tag-0000",
        "00010001000000000000",
        ClientError::InvalidServerResponse,
    ),
    (
        "tag-ffff",
        "00010001ffff00000000",
        ClientError::InvalidServerResponse,
    ),
    (
        "trailing-byte",
        "0001000000",
        ClientError::InvalidServerResponse,
    ),
    (
        "duplicate-group-id",
        "00010001000100000066000100000002a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000020000000b6578616d\
         706c652e636f6d0000000b6578616d706c652e6e657400a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000200\
         00000b6578616d706c652e6f72670000000972697a7a792e64657600",
        ClientError::InvalidServerResponse,
    ),
    (
        "one-domain-group",
        "00010001000100000028000100000001a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000010000000b6578616d\
         706c652e636f6d00",
        ClientError::InvalidServerResponse,
    ),
    (
        "public-suffix",
        "00010001000100000031000100000001a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000200000005636f2e75\
         6b0000000b6578616d706c652e636f6d00",
        ClientError::InvalidServerResponse,
    ),
    (
        "match-default-0000",
        "00010001000100000006000000000000",
        ClientError::InvalidServerResponse,
    ),
    (
        "match-default-0007",
        "00010001000100000006000700000000",
        ClientError::InvalidServerResponse,
    ),
    (
        "flag-1",
        "00010001000100000037000100000001a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000020000000b6578616d\
         706c652e636f6d0000000b6578616d706c652e6e657401",
        ClientError::InvalidServerResponse,
    ),
    (
        "format-version-2",
        "00020000",
        ClientError::SettingsUpdateRequired,
    ),
];

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn positive(name: &str) -> Vec<u8> {
    hex(POSITIVE.iter().find(|(n, _)| *n == name).unwrap().1)
}

#[test]
fn every_positive_vector_decodes_and_re_encodes_to_the_same_bytes() {
    for (name, h) in POSITIVE {
        let bytes = hex(h);
        let record =
            AccountSettingsRecord::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(record.encode().unwrap().as_slice(), bytes, "{name}");
    }
}

#[test]
fn the_typed_records_encode_to_the_positive_vectors() {
    // Empty: the absent record, also what `settings_seq = 0` reads as.
    let empty = AccountSettingsRecord::default();
    assert_eq!(empty.encode().unwrap().as_slice(), positive("empty"));
    assert_eq!(empty.matching(), &MatchingSettings::default());

    // Matching only: Host as the default, nothing else.
    let mut only = AccountSettingsRecord::default();
    only.apply(&Edit::Default(MatchMode::Host)).unwrap();
    assert_eq!(only.encode().unwrap().as_slice(), positive("matching-only"));

    // Disabled and user groups, added in the reverse order of the encoding.
    let mut groups = AccountSettingsRecord::default();
    groups
        .apply(&Edit::Disable(GroupId::from_bytes([0x22; 16])))
        .unwrap();
    groups
        .apply(&Edit::Disable(GroupId::from_bytes([0x11; 16])))
        .unwrap();
    groups
        .apply(&Edit::Add(
            user_group(
                GroupId::from_bytes([0xa0; 16]),
                ["Example.NET", "example.com."],
            )
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        groups.encode().unwrap().as_slice(),
        positive("matching-groups")
    );
    let decoded = AccountSettingsRecord::decode(&positive("matching-groups")).unwrap();
    assert_eq!(decoded, groups);
    assert_eq!(decoded.matching().match_default(), MatchMode::BaseDomain);
    assert_eq!(decoded.matching().disabled_global().len(), 2);
    assert_eq!(
        decoded.matching().user_groups()[0].domains(),
        ["example.com", "example.net"]
    );
}

#[test]
fn unknown_tags_are_preserved_through_an_edit() {
    let mut record = AccountSettingsRecord::decode(&positive("unknown-tags")).unwrap();
    assert_eq!(record.unknown_tags().collect::<Vec<_>>(), [0x0005, 0x7ffe]);
    record.apply(&Edit::Default(MatchMode::Exact)).unwrap();
    let mut expected = positive("unknown-tags");
    // Only the match default changes: entry 1's value starts at byte 10.
    expected[11] = 0x04;
    assert_eq!(record.encode().unwrap().as_slice(), expected);
}

#[test]
fn every_negative_vector_fails_with_its_error() {
    for (name, h, expected) in NEGATIVE {
        assert_eq!(
            AccountSettingsRecord::decode(&hex(h)).unwrap_err(),
            *expected,
            "{name}"
        );
    }
}

#[test]
fn an_oversize_entry_and_too_many_entries_are_rejected() {
    // One unknown entry of MAX_SETTINGS_ENTRY_LEN + 1 bytes.
    let mut oversize = hex("0001 0001 0005");
    let len = u32::try_from(MAX_SETTINGS_ENTRY_LEN + 1).unwrap();
    oversize.extend_from_slice(&len.to_be_bytes());
    oversize.resize(oversize.len() + MAX_SETTINGS_ENTRY_LEN + 1, 0);
    assert_eq!(
        AccountSettingsRecord::decode(&oversize).unwrap_err(),
        ClientError::InvalidServerResponse
    );
    // Exactly MAX_SETTINGS_ENTRY_LEN is fine.
    let mut largest = hex("0001 0001 0005");
    let len = u32::try_from(MAX_SETTINGS_ENTRY_LEN).unwrap();
    largest.extend_from_slice(&len.to_be_bytes());
    largest.resize(largest.len() + MAX_SETTINGS_ENTRY_LEN, 0);
    let record = AccountSettingsRecord::decode(&largest).unwrap();
    assert_eq!(record.encode().unwrap().as_slice(), largest);

    // n = 257 entries: refused from the count alone. The tags start at 0x0100, clear of the
    // recognised 0x0001 and 0x0004 (ADR 0079 Open question 7), so every entry is unknown.
    let mut many = hex("0001");
    many.extend_from_slice(&(MAX_SETTINGS_ENTRIES + 1).to_be_bytes());
    for tag in 0x0100..=(0x0100 + MAX_SETTINGS_ENTRIES) {
        many.extend_from_slice(&tag.to_be_bytes());
        many.extend_from_slice(&[0, 0, 0, 0]);
    }
    assert_eq!(
        AccountSettingsRecord::decode(&many).unwrap_err(),
        ClientError::InvalidServerResponse
    );
    // n = 256 is the bound.
    let mut most = hex("0001");
    most.extend_from_slice(&MAX_SETTINGS_ENTRIES.to_be_bytes());
    for tag in 0x0100..(0x0100 + MAX_SETTINGS_ENTRIES) {
        most.extend_from_slice(&tag.to_be_bytes());
        most.extend_from_slice(&[0, 0, 0, 0]);
    }
    let record = AccountSettingsRecord::decode(&most).unwrap();
    assert_eq!(record.encode().unwrap().as_slice(), most);
    // And an edit that adds the matching tag to a full record is refused on write.
    let mut full = record;
    full.apply(&Edit::Default(MatchMode::Host)).unwrap();
    assert_eq!(
        full.encode().unwrap_err(),
        ClientError::SettingsLimitReached
    );
}

/// The plaintext of `envelope/ACCOUNT_SETTINGS/0` (CRYPTO.md §15 item 1(A); ADR 0042 "On
/// acceptance" item 3) is a real record: it decodes here and re-encodes byte for byte.
#[test]
fn the_core_envelope_vector_carries_a_real_record() {
    const ENVELOPES: &str = include_str!("../../../rizzy-core/tests/vectors/envelopes.json");
    let file: serde_json::Value = serde_json::from_str(ENVELOPES).unwrap();
    let vector = file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "ACCOUNT_SETTINGS")
        .unwrap();
    let plaintext = hex(vector["inputs"]["plaintext"].as_str().unwrap());
    let record = AccountSettingsRecord::decode(&plaintext).unwrap();
    assert_eq!(record.encode().unwrap().as_slice(), plaintext);
    let matching = record.matching();
    assert_eq!(matching.match_default(), MatchMode::Host);
    assert_eq!(matching.disabled_global().len(), 2);
    assert_eq!(matching.user_groups().len(), 1);
    assert_eq!(record.unknown_tags().count(), 0);
}
