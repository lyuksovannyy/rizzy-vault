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
//! - **Negative** (ADR 0042 §8, one violation each, with ADR 0097 §1's severities): an
//!   unreadable record (`settings_unreadable`) for a truncated entry, a duplicate tag, an
//!   oversize entry, too many entries, tags out of order, tag `0x0000`/`0xFFFF` and a trailing
//!   byte; a parked one (`settings_update_required`) for `format_version ≠ 1`; an unreadable
//!   section, the record reading and re-encoding byte for byte, for a duplicate `group_id`, a
//!   one-domain user group and `match_default` out of range (tag `0x0001`).
//! - **Website icons**, tag `0x0005` ([ADR 0099] §1; written by an independent Python writer from
//!   that layout): on (`0x01`), off (`0x00`), and off beside a matching section; negative: an
//!   empty value, two bytes, `0x02`, `0xFF` and the two bytes "hi" (an unknown tag's value until
//!   `0x0005` was assigned, so the `unknown-tags` vector moved to tag `0x0006`), each an
//!   unreadable section. An unreadable section and a parked record read the setting **off**; an
//!   absent tag and the absent record read on.
//!
//! [ADR 0099]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0099-website-icons-opt-in.md

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
        "0001000300010000000600010000000000060000000268697ffe00000000",
    ),
    ("website-icons-on", "0001000100050000000101"),
    ("website-icons-off", "0001000100050000000100"),
    (
        "matching-and-website-icons-off",
        "0001000200010000000600020000000000050000000100",
    ),
];

/// How a negative vector fails ([ADR 0097] §1, §4): the whole record, or one section only.
///
/// [ADR 0097]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0097-website-matching-corrections.md
#[derive(Clone, Copy, Debug)]
enum Bad {
    /// The record is unreadable (`settings_unreadable`) or parked (`settings_update_required`).
    Record(ClientError),
    /// The record reads; this recognised tag is an unreadable section, kept verbatim.
    Section(u16),
}

/// The negative vectors that fit a constant: name, hex, how it fails.
const NEGATIVE: &[(&str, &str, Bad)] = &[
    (
        "truncated-entry",
        "0001000100010000000600020000",
        Bad::Record(ClientError::SettingsUnreadable),
    ),
    (
        "duplicate-tag",
        "000100020002000000016100020000000162",
        Bad::Record(ClientError::SettingsUnreadable),
    ),
    (
        "tags-out-of-order",
        "00010002000300000000000200000000",
        Bad::Record(ClientError::SettingsUnreadable),
    ),
    (
        "tag-0000",
        "00010001000000000000",
        Bad::Record(ClientError::SettingsUnreadable),
    ),
    (
        "tag-ffff",
        "00010001ffff00000000",
        Bad::Record(ClientError::SettingsUnreadable),
    ),
    (
        "trailing-byte",
        "0001000000",
        Bad::Record(ClientError::SettingsUnreadable),
    ),
    (
        "website-icons-empty",
        "00010001000500000000",
        Bad::Section(TAG_WEBSITE_ICONS),
    ),
    (
        "website-icons-two-bytes",
        "000100010005000000020100",
        Bad::Section(TAG_WEBSITE_ICONS),
    ),
    (
        "website-icons-02",
        "0001000100050000000102",
        Bad::Section(TAG_WEBSITE_ICONS),
    ),
    (
        "website-icons-ff",
        "00010001000500000001ff",
        Bad::Section(TAG_WEBSITE_ICONS),
    ),
    (
        "website-icons-former-unknown-value",
        "000100010005000000026869",
        Bad::Section(TAG_WEBSITE_ICONS),
    ),
    (
        "duplicate-group-id",
        "00010001000100000066000100000002a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000020000000b6578616d\
         706c652e636f6d0000000b6578616d706c652e6e657400a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000200\
         00000b6578616d706c652e6f72670000000972697a7a792e64657600",
        Bad::Section(TAG_MATCHING),
    ),
    (
        "one-domain-group",
        "00010001000100000028000100000001a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000010000000b6578616d\
         706c652e636f6d00",
        Bad::Section(TAG_MATCHING),
    ),
    (
        "match-default-0000",
        "00010001000100000006000000000000",
        Bad::Section(TAG_MATCHING),
    ),
    (
        "match-default-0007",
        "00010001000100000006000700000000",
        Bad::Section(TAG_MATCHING),
    ),
    (
        "format-version-2",
        "00020000",
        Bad::Record(ClientError::SettingsUpdateRequired),
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
    assert_eq!(empty.matching().unwrap(), &MatchingSettings::default());

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
    assert_eq!(
        decoded.matching().unwrap().match_default(),
        MatchMode::BaseDomain
    );
    assert_eq!(decoded.matching().unwrap().disabled_global().len(), 2);
    assert_eq!(
        decoded.matching().unwrap().user_groups()[0].domains(),
        ["example.com", "example.net"]
    );
}

#[test]
fn unknown_tags_are_preserved_through_an_edit() {
    let mut record = AccountSettingsRecord::decode(&positive("unknown-tags")).unwrap();
    assert_eq!(record.unknown_tags().collect::<Vec<_>>(), [0x0006, 0x7ffe]);
    record.apply(&Edit::Default(MatchMode::Exact)).unwrap();
    let mut expected = positive("unknown-tags");
    // Only the match default changes: entry 1's value starts at byte 10.
    expected[11] = 0x04;
    assert_eq!(record.encode().unwrap().as_slice(), expected);
}

#[test]
fn the_website_icons_vectors_read_as_their_layout_says() {
    use crate::icons::IconsSetting;

    // Absent tag, absent record: on (the default, ADR 0099 §1).
    let empty = AccountSettingsRecord::decode(&positive("empty")).unwrap();
    assert!(empty.website_icons().is_on());
    assert!(AccountSettingsRecord::default().website_icons().is_on());
    assert!(
        AccountSettingsRecord::decode(&positive("matching-only"))
            .unwrap()
            .website_icons()
            .is_on()
    );

    let on = AccountSettingsRecord::decode(&positive("website-icons-on")).unwrap();
    assert!(on.website_icons().is_on());
    assert_eq!(on.unknown_tags().count(), 0);
    let off = AccountSettingsRecord::decode(&positive("website-icons-off")).unwrap();
    assert!(!off.website_icons().is_on());
    let both = AccountSettingsRecord::decode(&positive("matching-and-website-icons-off")).unwrap();
    assert!(!both.website_icons().is_on());
    assert_eq!(both.matching().unwrap().match_default(), MatchMode::Host);

    // Typed writes: off is written as 0x00, never as a missing tag; on as 0x01.
    let mut typed = AccountSettingsRecord::default();
    typed.apply(&Edit::WebsiteIcons(false)).unwrap();
    assert_eq!(
        typed.encode().unwrap().as_slice(),
        positive("website-icons-off")
    );
    typed.apply(&Edit::WebsiteIcons(true)).unwrap();
    assert_eq!(
        typed.encode().unwrap().as_slice(),
        positive("website-icons-on")
    );
    let mut mixed = AccountSettingsRecord::default();
    mixed.apply(&Edit::WebsiteIcons(false)).unwrap();
    mixed.apply(&Edit::Default(MatchMode::Host)).unwrap();
    assert_eq!(
        mixed.encode().unwrap().as_slice(),
        positive("matching-and-website-icons-off")
    );
    // An edit elsewhere keeps the explicit off.
    let mut kept = off.clone();
    kept.apply(&Edit::Default(MatchMode::Exact)).unwrap();
    assert!(!kept.website_icons().is_on());

    // A setting that cannot be read reads off, never the default: an unreadable 0x0005 section
    // (ADR 0097 §1 (c)) and a parked record.
    for (name, h, _) in NEGATIVE
        .iter()
        .filter(|(n, _, _)| n.starts_with("website-icons"))
    {
        let read = AccountSettingsRecord::decode(&hex(h));
        assert!(
            !IconsSetting::from_read(read.as_ref().map_err(|e| *e)).is_on(),
            "{name}"
        );
    }
    let parked = AccountSettingsRecord::decode(&hex("0002 0000"));
    assert_eq!(parked, Err(ClientError::SettingsUpdateRequired));
    assert!(!IconsSetting::from_read(parked.as_ref().map_err(|e| *e)).is_on());
    assert!(IconsSetting::from_read(Ok(&on)).is_on());
    assert!(!IconsSetting::from_read(Ok(&off)).is_on());
}

/// ADR 0097 §4.2 (replacing ADR 0042 §8 in part): a user group that fails only a content rule
/// is inert, not a reject. These two were negative vectors of ADR 0042 §8; they now decode, the
/// group is inert and outside the view, and the record re-encodes byte for byte.
const INERT: &[(&str, &str)] = &[
    (
        "public-suffix",
        "00010001000100000031000100000001a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000200000005636f2e75\
         6b0000000b6578616d706c652e636f6d00",
    ),
    (
        "flag-1",
        "00010001000100000037000100000001a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000020000000b6578616d\
         706c652e636f6d0000000b6578616d706c652e6e657401",
    ),
];

#[test]
fn a_content_rule_failure_reads_as_an_inert_group_adr0097() {
    for (name, h) in INERT {
        let bytes = hex(h);
        let record =
            AccountSettingsRecord::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(
            record.matching().unwrap().user_groups().is_empty(),
            "{name}"
        );
        assert_eq!(record.matching().unwrap().inert_groups().len(), 1, "{name}");
        assert_eq!(
            record.encode().unwrap().as_slice(),
            bytes.as_slice(),
            "{name}"
        );
    }
}

#[test]
fn every_negative_vector_fails_with_its_error() {
    for (name, h, expected) in NEGATIVE {
        let bytes = hex(h);
        match *expected {
            Bad::Record(e) => {
                assert_eq!(
                    AccountSettingsRecord::decode(&bytes).unwrap_err(),
                    e,
                    "{name}"
                );
            }
            Bad::Section(tag) => {
                // ADR 0097 §1 (c), §4.4: the record reads, the section is kept byte for byte.
                let record =
                    AccountSettingsRecord::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(
                    record.unreadable_sections().collect::<Vec<_>>(),
                    [tag],
                    "{name}"
                );
                assert_eq!(
                    record.encode().unwrap().as_slice(),
                    bytes.as_slice(),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn an_oversize_entry_and_too_many_entries_are_rejected() {
    // One unknown entry of MAX_SETTINGS_ENTRY_LEN + 1 bytes.
    let mut oversize = hex("0001 0001 0006");
    let len = u32::try_from(MAX_SETTINGS_ENTRY_LEN + 1).unwrap();
    oversize.extend_from_slice(&len.to_be_bytes());
    oversize.resize(oversize.len() + MAX_SETTINGS_ENTRY_LEN + 1, 0);
    assert_eq!(
        AccountSettingsRecord::decode(&oversize).unwrap_err(),
        ClientError::SettingsUnreadable
    );
    // Exactly MAX_SETTINGS_ENTRY_LEN is fine.
    let mut largest = hex("0001 0001 0006");
    let len = u32::try_from(MAX_SETTINGS_ENTRY_LEN).unwrap();
    largest.extend_from_slice(&len.to_be_bytes());
    largest.resize(largest.len() + MAX_SETTINGS_ENTRY_LEN, 0);
    let record = AccountSettingsRecord::decode(&largest).unwrap();
    assert_eq!(record.encode().unwrap().as_slice(), largest);

    // n = 257 entries: refused from the count alone. The tags start at 0x0100, clear of the
    // recognised 0x0001, 0x0004 (ADR 0079 Open question 7) and 0x0005 (ADR 0099), so every
    // entry is unknown.
    let mut many = hex("0001");
    many.extend_from_slice(&(MAX_SETTINGS_ENTRIES + 1).to_be_bytes());
    for tag in 0x0100..=(0x0100 + MAX_SETTINGS_ENTRIES) {
        many.extend_from_slice(&tag.to_be_bytes());
        many.extend_from_slice(&[0, 0, 0, 0]);
    }
    assert_eq!(
        AccountSettingsRecord::decode(&many).unwrap_err(),
        ClientError::SettingsUnreadable
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
    let matching = record.matching().unwrap();
    assert_eq!(matching.match_default(), MatchMode::Host);
    assert_eq!(matching.disabled_global().len(), 2);
    assert_eq!(matching.user_groups().len(), 1);
    assert_eq!(record.unknown_tags().count(), 0);
}
