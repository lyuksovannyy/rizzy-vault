// SPDX-License-Identifier: AGPL-3.0-only

//! Unit tests of the vault catalog and the directory edits (ADR 0081 §A2, §A3, §A5, §A10;
//! INV-101, INV-102). The flows against the fake server are in `crate::tests::vaults`.

use super::*;

fn id(byte: u8) -> VaultId {
    VaultId::from_bytes([byte; 16])
}

/// A directory of the Personal vault `0x11…` and the owned vaults `owned`.
fn directory(owned: &[u8]) -> VaultDirectory {
    let mut d = VaultDirectory::personal_only(id(0x11));
    for o in owned {
        d = d.with_owned(id(*o)).unwrap();
    }
    d
}

#[test]
fn an_honest_answer_opens_every_listed_vault() {
    let d = directory(&[0x22, 0x33]);
    let catalog = VaultCatalog::check(Some(&d), &[id(0x11), id(0x22), id(0x33)]);
    assert!(catalog.alarms().is_empty());
    assert_eq!(catalog.personal(), Some(id(0x11)));
    assert_eq!(
        catalog.open_vaults().collect::<Vec<_>>(),
        vec![id(0x11), id(0x22), id(0x33)]
    );
    assert!(catalog.has_directory());
}

#[test]
fn a_withheld_vault_and_an_unlisted_one_raise_alarms() {
    // INV-102: the server hides 0x22 and serves 0x44, which the directory does not list.
    let d = directory(&[0x22]);
    let catalog = VaultCatalog::check(Some(&d), &[id(0x11), id(0x44)]);
    assert_eq!(
        catalog.alarms(),
        &[
            VaultAlarm::Withheld(id(0x22)),
            VaultAlarm::Unlisted(id(0x44))
        ]
    );
    assert_eq!(catalog.open_vaults().collect::<Vec<_>>(), vec![id(0x11)]);
    assert!(
        !catalog.is_open(id(0x44)),
        "an unlisted vault is never opened"
    );
    let withheld = catalog
        .entries()
        .iter()
        .find(|e| e.vault_id == id(0x22))
        .unwrap();
    assert_eq!(withheld.status, VaultStatus::Withheld);
    // Withholding the Personal vault itself is an alarm too.
    let catalog = VaultCatalog::check(Some(&d), &[id(0x22)]);
    assert_eq!(catalog.alarms(), &[VaultAlarm::Withheld(id(0x11))]);
}

#[test]
fn the_legacy_rule_names_a_single_vault_personal() {
    // ADR 0081 §A2 "Before a directory exists", §A10.
    let one = VaultCatalog::check(None, &[id(0x77)]);
    assert!(one.alarms().is_empty());
    assert_eq!(one.personal(), Some(id(0x77)));
    assert!(!one.has_directory());
    let two = VaultCatalog::check(None, &[id(0x77), id(0x78)]);
    assert_eq!(two.alarms(), &[VaultAlarm::NoDirectory]);
    assert_eq!(two.personal(), None);
    assert_eq!(two.open_vaults().count(), 0);
}

#[test]
fn part_b_and_unknown_kinds_are_listed_but_never_opened() {
    // ADR 0081 §A12: a shared owned vault, a joined vault and an unknown kind need a newer
    // build; their self-grants are not withheld when the server serves none for them.
    let pin = MembershipPin {
        membership_seq: 1,
        membership_hash: [0; 32],
    };
    let d = VaultDirectory::from_entries(vec![
        DirectoryEntry {
            vault_id: id(0x11),
            kind: DirectoryKind::Personal,
        },
        DirectoryEntry {
            vault_id: id(0x22),
            kind: DirectoryKind::Owned(Some(pin)),
        },
        DirectoryEntry {
            vault_id: id(0x33),
            kind: DirectoryKind::Joined {
                owner: rizzy_core::ids::AccountId::from_bytes([1; 16]),
                pin,
            },
        },
        DirectoryEntry {
            vault_id: id(0x44),
            kind: DirectoryKind::Unknown {
                kind: 9,
                body: Vec::new(),
            },
        },
    ]);
    let catalog = VaultCatalog::check(Some(&d), &[id(0x11), id(0x22), id(0x33)]);
    assert!(catalog.alarms().is_empty());
    assert_eq!(catalog.open_vaults().collect::<Vec<_>>(), vec![id(0x11)]);
    assert!(
        catalog
            .entries()
            .iter()
            .filter(|e| e.vault_id != id(0x11))
            .all(|e| e.status == VaultStatus::NeedsUpdate)
    );
}

#[test]
fn directory_edits_keep_the_personal_vault_and_the_cap() {
    let d = directory(&[0x22]);
    // INV-101: the Personal vault is never removed; only an unshared owned vault is.
    assert_eq!(
        d.without(id(0x11)),
        Err(ClientError::PersonalVaultProtected)
    );
    assert_eq!(d.without(id(0x99)), Err(ClientError::UnknownVault));
    assert_eq!(d.without(id(0x22)).unwrap(), directory(&[]));
    assert_eq!(d.with_owned(id(0x22)), Err(ClientError::InvalidInput));
    // 64 owned vaults, the Personal vault included.
    let mut full = VaultDirectory::personal_only(id(0x11));
    for n in 0..u8::try_from(rizzy_proto::limits::MAX_OWNED_VAULTS - 1).unwrap() {
        full = full.with_owned(id(0x80 + n)).unwrap();
    }
    assert_eq!(full.owned_count(), 64);
    assert_eq!(
        full.with_owned(id(0x20)),
        Err(ClientError::VaultLimitReached)
    );
}

#[test]
fn a_dropped_vault_is_reported_once_the_directory_says_so() {
    let before = VaultCatalog::check(
        Some(&directory(&[0x22, 0x33])),
        &[id(0x11), id(0x22), id(0x33)],
    );
    let after = VaultCatalog::check(Some(&directory(&[0x33])), &[id(0x11), id(0x33)]);
    assert_eq!(after.dropped_since(&before), vec![id(0x22)]);
    // Without a directory nothing is dropped on the strength of the server's answer alone.
    let legacy = VaultCatalog::check(None, &[id(0x11)]);
    assert!(legacy.dropped_since(&before).is_empty());
}
