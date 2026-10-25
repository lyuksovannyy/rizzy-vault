// SPDX-License-Identifier: AGPL-3.0-only

//! Codec, edit and cache tests of the account settings record (ADR 0042 §2–§5). The flows
//! against the fake server are in `crate::tests::settings`.

use chacha20::ChaCha20Rng;
use proptest::prelude::*;
use rand_core::SeedableRng as _;
use rizzy_match::{GroupId, MatchMode};

use super::*;

#[test]
fn edits_that_change_nothing_are_refused() {
    let mut record = AccountSettingsRecord::default();
    let id = GroupId::from_bytes([1; 16]);
    assert_eq!(
        record.apply(&Edit::Remove(id)).unwrap_err(),
        ClientError::InvalidInput
    );
    assert_eq!(
        record.apply(&Edit::Enable(id)).unwrap_err(),
        ClientError::InvalidInput
    );
    record.apply(&Edit::Disable(id)).unwrap();
    assert_eq!(
        record.apply(&Edit::Disable(id)).unwrap_err(),
        ClientError::InvalidInput
    );
    record.apply(&Edit::Enable(id)).unwrap();
    assert!(record.matching().disabled_global().is_empty());
    // The tag stays present once written, even back at the defaults, so the bytes round-trip.
    assert_eq!(
        record.encode().unwrap().as_slice(),
        [0, 1, 0, 1, 0, 1, 0, 0, 0, 6, 0, 1, 0, 0, 0, 0]
    );
}

#[test]
fn edit_errors_map_to_stable_codes() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let resolve = |rng: &mut ChaCha20Rng, domains: &[&str]| {
        Edit::resolve(
            rng,
            SettingsEdit::AddUserGroup(domains.iter().map(|d| (*d).to_owned()).collect()),
        )
    };
    for suffix in ["co.uk", "github.io", "www.example.com"] {
        assert_eq!(
            resolve(&mut rng, &[suffix, "example.org"]).unwrap_err(),
            ClientError::EquivalenceDomainRejected,
            "{suffix}"
        );
    }
    assert_eq!(
        resolve(&mut rng, &["example.org"]).unwrap_err(),
        ClientError::InvalidInput
    );
    assert_eq!(
        resolve(&mut rng, &["exa mple.org", "example.com"]).unwrap_err(),
        ClientError::InvalidInput
    );
    let mut record = AccountSettingsRecord::default();
    assert_eq!(
        record
            .apply(&Edit::Default(MatchMode::AccountDefault))
            .unwrap_err(),
        ClientError::InvalidInput
    );
    for i in 0..rizzy_match::error::MAX_USER_GROUPS {
        let mut id = [0u8; 16];
        id[..2].copy_from_slice(&i.to_be_bytes());
        let group = user_group(GroupId::from_bytes(id), ["a.example", "b.example"]).unwrap();
        record.apply(&Edit::Add(group)).unwrap();
    }
    let group = user_group(GroupId::from_bytes([0xff; 16]), ["a.example", "b.example"]).unwrap();
    assert_eq!(
        record.apply(&Edit::Add(group)).unwrap_err(),
        ClientError::SettingsLimitReached
    );
}

#[test]
fn debug_shows_no_settings_content() {
    let mut record = AccountSettingsRecord::default();
    let group = user_group(
        GroupId::from_bytes([0xab; 16]),
        ["private-bank.example", "other.example"],
    )
    .unwrap();
    record.apply(&Edit::Add(group)).unwrap();
    let shown = format!("{record:?}");
    assert!(!shown.contains("private-bank"), "{shown}");
}

fn arb_record() -> impl Strategy<Value = AccountSettingsRecord> {
    (
        any::<bool>(),
        1u16..=6,
        proptest::collection::btree_set(any::<[u8; 16]>(), 0..4),
        // Tags a reader keeps verbatim. 0x0002 (the vault directory, ADR 0081 §A2), 0x0003 (contact
        // pins, reserved by ADR 0081 §B2) and 0x0004 (identity-generator defaults, ADR 0079) have
        // their own layouts now, so random bytes under them are rightly refused by `decode`.
        proptest::collection::btree_map(
            5u16..0xfffe,
            proptest::collection::vec(any::<u8>(), 0..16),
            0..4,
        ),
    )
        .prop_map(|(present, default, disabled, unknown)| {
            let mut record = AccountSettingsRecord::default();
            if present {
                record
                    .apply(&Edit::Default(MatchMode::from_wire(default).unwrap()))
                    .unwrap();
                for id in disabled {
                    record
                        .apply(&Edit::Disable(GroupId::from_bytes(id)))
                        .unwrap();
                }
            }
            record.unknown = unknown
                .into_iter()
                .map(|(tag, value)| (tag, Zeroizing::new(value)))
                .collect();
            record
        })
}

proptest! {
    /// ADR 0042 §8: encode → decode → encode is the identity.
    #[test]
    fn encode_decode_encode_is_the_identity(record in arb_record()) {
        let first = record.encode().unwrap();
        let decoded = AccountSettingsRecord::decode(&first).unwrap();
        prop_assert_eq!(&decoded, &record);
        prop_assert_eq!(decoded.encode().unwrap(), first);
    }

    /// Untrusted plaintext never panics, and whatever decodes re-encodes to the same bytes.
    #[test]
    fn decode_never_panics_and_is_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
        if let Ok(record) = AccountSettingsRecord::decode(&bytes) {
            prop_assert_eq!(record.encode().unwrap().to_vec(), bytes);
        }
    }

    /// Mutations of a valid record are either rejected or decode to something canonical.
    #[test]
    fn mutated_records_never_panic(record in arb_record(), at in any::<usize>(), byte in any::<u8>()) {
        let mut bytes = record.encode().unwrap().to_vec();
        if !bytes.is_empty() {
            let i = at % bytes.len();
            bytes[i] = byte;
        }
        if let Ok(decoded) = AccountSettingsRecord::decode(&bytes) {
            prop_assert_eq!(decoded.encode().unwrap().to_vec(), bytes);
        }
    }
}
