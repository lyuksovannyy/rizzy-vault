// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the vault directory, `ACCOUNT_SETTINGS` tag `0x0002` (ADR 0081 §A2): `rizzy-client`'s
//! [`VaultDirectory::decode`], alone and inside a settings record, and the completeness check
//! over what a server serves ([`VaultCatalog::check`]). The directory is authenticated, but
//! written by any client of the account, a newer or a buggy one, so it is parsed as untrusted
//! input.
//!
//! For each input:
//!
//! - the parser never panics and fails only with `invalid_server_response`;
//! - one value has one encoding: whatever parses encodes back to the input, byte for byte;
//! - a parsed directory holds 1 to 128 entries, strictly ascending, exactly one Personal vault;
//! - the edits a host makes (add an owned vault, remove one) either are refused with a stable
//!   error or leave a directory that encodes and parses back to itself, the Personal vault and
//!   every entry this build does not open kept;
//! - the catalog of the directory against any served set opens only listed, openable vaults
//!   that were served, and raises an alarm for every listed openable vault not served and every
//!   served vault not listed (INV-102);
//! - the same bytes as the value of tag `0x0002` in a settings record parse the same way.
//!
//! ```text
//! cargo +nightly fuzz run client_vault_directory
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_client::ClientError;
use rizzy_client::rizzy_core::ids::VaultId;
use rizzy_client::settings::AccountSettingsRecord;
use rizzy_client::vaults::{
    DirectoryKind, VaultAlarm, VaultCatalog, VaultDirectory, VaultStatus,
};

/// The invariants of a parsed directory.
fn assert_shape(d: &VaultDirectory) {
    let entries = d.entries();
    assert!(!entries.is_empty() && entries.len() <= 128);
    assert!(entries.windows(2).all(|w| w[0].vault_id < w[1].vault_id));
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == DirectoryKind::Personal)
            .count(),
        1
    );
    assert!(d.personal().is_some());
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks which ids count as served; the rest is the tag's value.
    let (selector, value) = match data.split_first() {
        Some((s, rest)) => (*s, rest),
        None => (0, data),
    };
    let parsed = VaultDirectory::decode(value);
    // The same value inside a settings record.
    let mut record = vec![0, 1, 0, 1, 0, 2];
    record.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    record.extend_from_slice(value);
    match (AccountSettingsRecord::decode(&record), &parsed) {
        (Ok(r), Ok(d)) => assert_eq!(r.vault_directory(), Some(d)),
        (Err(e), Err(_)) => assert_eq!(e, ClientError::InvalidServerResponse),
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => panic!("the record and the tag disagree"),
    }
    let directory = match parsed {
        Ok(d) => d,
        Err(e) => {
            assert_eq!(e, ClientError::InvalidServerResponse);
            return;
        }
    };
    assert_shape(&directory);
    assert_eq!(directory.encode().unwrap(), value, "one encoding per value");

    // The host's edits.
    let fresh = VaultId::from_bytes([0xfe; 16]);
    match directory.with_owned(fresh) {
        Ok(more) => {
            assert_shape(&more);
            let again = VaultDirectory::decode(&more.encode().unwrap()).unwrap();
            assert_eq!(again, more);
            assert_eq!(more.personal(), directory.personal());
            for e in directory.entries() {
                assert_eq!(more.entry(e.vault_id), Some(e));
            }
        }
        Err(e) => assert!(matches!(
            e,
            ClientError::InvalidInput | ClientError::VaultLimitReached
        )),
    }
    for entry in directory.entries() {
        match directory.without(entry.vault_id) {
            Ok(fewer) => {
                assert_eq!(entry.kind, DirectoryKind::Owned(None));
                assert_shape(&fewer);
                assert_eq!(fewer.entries().len() + 1, directory.entries().len());
            }
            Err(ClientError::PersonalVaultProtected) => {
                assert_eq!(entry.kind, DirectoryKind::Personal);
            }
            Err(e) => {
                assert_eq!(e, ClientError::UnknownVault);
                assert!(!entry.kind.openable());
            }
        }
    }

    // The completeness check against a served set chosen by the selector, plus one stranger.
    let mut served: Vec<VaultId> = directory
        .entries()
        .iter()
        .enumerate()
        .filter(|(i, _)| selector & (1 << (i % 8)) != 0)
        .map(|(_, e)| e.vault_id)
        .collect();
    if selector & 0x80 != 0 && directory.entry(fresh).is_none() {
        served.push(fresh);
    }
    let catalog = VaultCatalog::check(Some(&directory), &served);
    for e in catalog.entries() {
        let listed = directory.entry(e.vault_id).unwrap();
        match e.status {
            VaultStatus::Open => {
                assert!(listed.kind.openable() && served.contains(&e.vault_id));
            }
            VaultStatus::Withheld => {
                assert!(listed.kind.openable() && !served.contains(&e.vault_id));
                assert!(catalog.alarms().contains(&VaultAlarm::Withheld(e.vault_id)));
            }
            VaultStatus::NeedsUpdate => assert!(!listed.kind.openable()),
        }
    }
    for v in &served {
        if directory.entry(*v).is_none() {
            assert!(catalog.alarms().contains(&VaultAlarm::Unlisted(*v)));
            assert!(!catalog.is_open(*v));
        }
    }
});
