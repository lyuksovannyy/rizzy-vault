// SPDX-License-Identifier: AGPL-3.0-only

//! Known-answer vectors of the vault directory, `ACCOUNT_SETTINGS` tag `0x0002` (ADR 0081 §A2
//! and its implementation plan; CRYPTO.md §15 item 1).
//!
//! **Where they live.** Layout-level Rust test constants, like the settings vectors
//! (`crate::settings::vectors`): the codec is this crate's. The committed hex was written by an
//! independent Python writer from the ADR 0081 §A2 layout, not by this crate's encoder.
//!
//! - **Positive:** the Personal vault only; the Personal vault and two owned vaults, one shared
//!   (bit 0 with its membership pin); a joined (kind 3) entry; an unknown kind kept verbatim.
//!   Each decodes and re-encodes to the same hex; the typed constructions encode to it.
//! - **Negative**, one violation each: no kind-1 entry, two kind-1 entries, unsorted, duplicate
//!   ids, a reserved flag bit (owned and Personal), wrong body lengths (Personal, shared without
//!   its pin, an unshared one with trailing bytes, a short joined entry), a joined entry without
//!   bit 0, kind 0, 129 entries, a trailing byte, `format = 2`, no entry, a truncated entry.

use super::*;

/// The positive vectors: name, hex.
const POSITIVE: &[(&str, &str)] = &[
    (
        "personal-only",
        "0100011111111111111111111111111111111101000100",
    ),
    (
        "personal-and-owned",
        "0100031111111111111111111111111111111101000100222222222222222222222222222222220200010033\
         333333333333333333333333333333020029010000000000000007ababababababababababababababababab\
         ababababababababababababababab",
    ),
    (
        "joined",
        "01000211111111111111111111111111111111010001004444444444444444444444444444444403003901a1\
         a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000009cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
         cdcdcdcdcdcdcdcdcdcdcd",
    ),
    (
        "unknown-kind",
        "0100021111111111111111111111111111111101000100555555555555555555555555555555557f0005dead\
         beef01",
    ),
];

/// The negative vectors, one violation each: name, hex. The 129-entry case is built in
/// [`one_entry_over_the_limit_is_rejected`].
const NEGATIVE: &[(&str, &str)] = &[
    (
        "no-personal",
        "0100012222222222222222222222222222222202000100",
    ),
    (
        "two-personal",
        "01000211111111111111111111111111111111010001002222222222222222222222222222222201000100",
    ),
    (
        "unsorted",
        "01000222222222222222222222222222222222020001001111111111111111111111111111111101000100",
    ),
    (
        "duplicate",
        "01000211111111111111111111111111111111010001001111111111111111111111111111111102000100",
    ),
    (
        "reserved-flag-owned",
        "01000211111111111111111111111111111111010001002222222222222222222222222222222202000102",
    ),
    (
        "reserved-flag-personal",
        "0100011111111111111111111111111111111101000101",
    ),
    (
        "personal-body-length",
        "010001111111111111111111111111111111110100020000",
    ),
    (
        "shared-without-pin",
        "01000211111111111111111111111111111111010001002222222222222222222222222222222202000101",
    ),
    (
        "owned-trailing-pin",
        "0100021111111111111111111111111111111101000100222222222222222222222222222222220200290000\
         000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "joined-flags-zero",
        "01000211111111111111111111111111111111010001004444444444444444444444444444444403003900a1\
         a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000009cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
         cdcdcdcdcdcdcdcdcdcdcd",
    ),
    (
        "joined-short",
        "0100021111111111111111111111111111111101000100444444444444444444444444444444440300380100\
         0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
         00000000000000000000",
    ),
    (
        "kind-zero",
        "01000211111111111111111111111111111111010001002222222222222222222222222222222200000100",
    ),
    (
        "trailing-byte",
        "010001111111111111111111111111111111110100010000",
    ),
    ("format-2", "0200011111111111111111111111111111111101000100"),
    ("empty", "010000"),
    ("truncated", "01000111111111111111111111111111111111010001"),
];

/// Hex to bytes.
fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// The hex of `name`.
fn positive(name: &str) -> Vec<u8> {
    unhex(POSITIVE.iter().find(|(n, _)| *n == name).unwrap().1)
}

fn id(byte: u8) -> VaultId {
    VaultId::from_bytes([byte; 16])
}

#[test]
fn every_positive_vector_round_trips() {
    for (name, hex) in POSITIVE {
        let bytes = unhex(hex);
        let parsed = VaultDirectory::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(parsed.encode().unwrap(), bytes, "{name}");
    }
}

#[test]
fn the_typed_directories_encode_to_the_vectors() {
    let personal = VaultDirectory::personal_only(id(0x11));
    assert_eq!(personal.encode().unwrap(), positive("personal-only"));
    assert_eq!(personal.personal(), Some(id(0x11)));

    let owned = personal.with_owned(id(0x22)).unwrap();
    let shared = VaultDirectory::from_entries(
        owned
            .entries()
            .iter()
            .cloned()
            .chain([DirectoryEntry {
                vault_id: id(0x33),
                kind: DirectoryKind::Owned(Some(MembershipPin {
                    membership_seq: 7,
                    membership_hash: [0xab; 32],
                })),
            }])
            .collect(),
    );
    assert_eq!(shared.encode().unwrap(), positive("personal-and-owned"));
    assert_eq!(shared.owned_count(), 3);

    let joined = VaultDirectory::decode(&positive("joined")).unwrap();
    assert_eq!(
        joined.entry(id(0x44)).unwrap().kind,
        DirectoryKind::Joined {
            owner: rizzy_core::ids::AccountId::from_bytes([0xa1; 16]),
            pin: MembershipPin {
                membership_seq: 9,
                membership_hash: [0xcd; 32],
            },
        }
    );
    assert_eq!(joined.owned_count(), 1, "a joined vault is not owned");

    let unknown = VaultDirectory::decode(&positive("unknown-kind")).unwrap();
    assert_eq!(
        unknown.entry(id(0x55)).unwrap().kind,
        DirectoryKind::Unknown {
            kind: 0x7f,
            body: vec![0xde, 0xad, 0xbe, 0xef, 0x01],
        }
    );
    // An edit keeps the unknown entry byte for byte.
    let edited = unknown.with_owned(id(0x66)).unwrap();
    let again = VaultDirectory::decode(&edited.encode().unwrap()).unwrap();
    assert_eq!(again.entry(id(0x55)), unknown.entry(id(0x55)));
}

#[test]
fn only_the_personal_and_unshared_owned_kinds_open() {
    for (name, hex) in POSITIVE {
        let parsed = VaultDirectory::decode(&unhex(hex)).unwrap();
        for entry in parsed.entries() {
            let expected = matches!(
                entry.kind,
                DirectoryKind::Personal | DirectoryKind::Owned(None)
            );
            assert_eq!(entry.kind.openable(), expected, "{name}");
        }
    }
}

#[test]
fn every_negative_vector_is_rejected() {
    for (name, hex) in NEGATIVE {
        assert_eq!(
            VaultDirectory::decode(&unhex(hex)),
            Err(ClientError::InvalidServerResponse),
            "{name}"
        );
    }
}

#[test]
fn one_entry_over_the_limit_is_rejected() {
    let build = |n: u16| {
        let mut out = vec![1u8];
        out.extend_from_slice(&n.to_be_bytes());
        for i in 0..u128::from(n) {
            out.extend_from_slice(&(i + 1).to_be_bytes());
            out.push(if i == 0 { 1 } else { 2 });
            out.extend_from_slice(&[0, 1, 0]);
        }
        out
    };
    let limit = u16::try_from(rizzy_proto::limits::MAX_DIRECTORY_ENTRIES).unwrap();
    assert!(VaultDirectory::decode(&build(limit)).is_ok());
    assert_eq!(
        VaultDirectory::decode(&build(limit + 1)),
        Err(ClientError::InvalidServerResponse)
    );
}

#[test]
fn the_settings_record_carries_the_directory_and_keeps_tag_0x0003() {
    // ADR 0081 §0 item 6: 0x0002 is the directory, 0x0003 (Part B's contact pins) is unknown to
    // this build and travels verbatim.
    let dir = positive("personal-and-owned");
    let mut plaintext = vec![0, 1, 0, 2];
    plaintext.extend_from_slice(&[0, 2]);
    plaintext.extend_from_slice(&u32::try_from(dir.len()).unwrap().to_be_bytes());
    plaintext.extend_from_slice(&dir);
    plaintext.extend_from_slice(&[0, 3, 0, 0, 0, 2, 0xc0, 0xde]);
    let record = AccountSettingsRecord::decode(&plaintext).unwrap();
    assert_eq!(
        record.vault_directory().unwrap(),
        &VaultDirectory::decode(&dir).unwrap()
    );
    assert_eq!(record.unknown_tags().collect::<Vec<_>>(), vec![3]);
    assert_eq!(record.encode().unwrap().as_slice(), plaintext.as_slice());
    // A violation inside the tag rejects the whole record, as ADR 0042 §2 does.
    let mut broken = plaintext.clone();
    let at = 4 + 2 + 4 + 3 + 16;
    broken[at] = 0;
    assert_eq!(
        AccountSettingsRecord::decode(&broken),
        Err(ClientError::InvalidServerResponse)
    );
}
