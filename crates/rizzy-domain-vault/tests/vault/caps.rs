// SPDX-License-Identifier: AGPL-3.0-only

//! The write-time caps on wrap-set rows (ADR 0092 §2, §8 tests 3 and 4): the vault cap and the
//! account cap at and past their boundaries, the whole request refused with nothing written,
//! writes that add no row never refused, the settings item of a new vault at the account cap,
//! and healing, which only the vault cap binds. Small caps come from the test-only
//! `VaultDomain::with_wrap_caps`.

#![expect(
    clippy::unwrap_used,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code"
)]

use rizzy_core::ids::VaultId;
use rizzy_domain_vault::{
    HealingError, VaultDomain, VaultError, VaultKind, WrapCaps, create_vault,
};
use rizzy_proto::error::ErrorCode;
use rizzy_proto::objects::{ItemKeyWrap, KeyEnvelope, VaultSelfGrant};
use rizzy_proto::vault::{HealingRequest, Record, UploadRequest, UploadResponse, UploadResult};
use rizzy_proto::wire::{Id, List};
use rizzy_storage::lock_account;

use crate::common::{ACCOUNT, Device, Directory, Env, NOW, OpSpec, VAULT, block_on, item, sign_op};

/// A second vault of the account.
const VAULT_2: VaultId = VaultId::from_bytes([0xb2; 16]);
/// A third vault of the account.
const VAULT_3: VaultId = VaultId::from_bytes([0xb3; 16]);

/// A domain over `env`'s database with caps of `vault` rows per vault and `account` rows per
/// account.
fn capped(env: &Env, vault: u64, account: u64) -> VaultDomain<Directory> {
    env.domain_with_quota(rizzy_domain_vault::Quota::default())
        .with_wrap_caps(WrapCaps {
            vault_rows: vault,
            account_rows: account,
        })
}

/// Creates owned vault `vault_id` of the account, as a `vault_create` commit would.
async fn new_vault(env: &Env, vault_id: VaultId) {
    let mut tx = env.db.begin_write().await.unwrap();
    lock_account(&mut tx, ACCOUNT.as_bytes()).await.unwrap();
    let grant = VaultSelfGrant {
        vault_id: Id::from_bytes(vault_id.to_bytes()),
        account_key_epoch: 0,
        vault_key_epoch: 0,
        envelope: KeyEnvelope::new(vec![0x5a; 98]).unwrap(),
    };
    create_vault(&mut tx, ACCOUNT, &grant, VaultKind::Owned, NOW)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// Op `seq` of `device` (chained after `seq - 1`) on item `n`, carrying a wrap when
/// `wrapped`: the item's first op adds its wrap-set row, a later one with the same item key adds
/// none.
fn op(device: &Device, vault: VaultId, n: u8, seq: u64, wrapped: bool) -> Record {
    let mut spec = OpSpec::new(item(n), seq, seq - 1);
    if wrapped {
        spec.wrap = Some(vec![0x77; 98]);
    }
    Record::Op(sign_op(device, vault, &spec))
}

/// Uploads `records` to `vault` through `domain`.
async fn upload(
    domain: &VaultDomain<Directory>,
    vault: VaultId,
    records: Vec<Record>,
) -> Result<UploadResponse, VaultError> {
    let request = UploadRequest {
        vault_id: Id::from_bytes(vault.to_bytes()),
        records: List::new(records).unwrap(),
    };
    domain.upload(ACCOUNT, None, &request, NOW).await
}

/// Whether every record of the answer was stored.
fn stored(answer: Result<UploadResponse, VaultError>) -> bool {
    answer
        .unwrap()
        .results
        .into_vec()
        .iter()
        .all(|r| *r == UploadResult::Stored)
}

#[test]
fn the_vault_cap_refuses_the_whole_request_past_it() {
    block_on(async {
        let env = Env::new(1).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        let domain = capped(&env, 3, 100);
        // Exactly at the cap: accepted.
        let three = vec![
            op(&a, VAULT, 1, 1, true),
            op(&a, VAULT, 2, 2, true),
            op(&a, VAULT, 3, 3, true),
        ];
        assert!(stored(upload(&domain, VAULT, three).await));
        // An edit with no new row, then a fourth row: the whole request is refused, and the
        // edit is not stored either.
        let past = vec![op(&a, VAULT, 1, 4, false), op(&a, VAULT, 4, 5, true)];
        assert!(matches!(
            upload(&domain, VAULT, past).await,
            Err(VaultError::RotationLimit)
        ));
        assert_eq!(VaultError::RotationLimit.code(), ErrorCode::RotationLimit);
        // At the cap, writes that add no row are accepted: an op without a wrap and one under an
        // existing item key. The edit refused above was not stored, so it stores now.
        let no_rows = vec![op(&a, VAULT, 1, 4, false), op(&a, VAULT, 2, 5, true)];
        assert!(stored(upload(&domain, VAULT, no_rows).await));
    });
}

#[test]
fn the_account_cap_counts_every_owned_vault() {
    block_on(async {
        let env = Env::new(2).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        new_vault(&env, VAULT_2).await;
        let domain = capped(&env, 100, 4);
        let first = vec![op(&a, VAULT, 1, 1, true), op(&a, VAULT, 2, 2, true)];
        assert!(stored(upload(&domain, VAULT, first).await));
        // Exactly at the account cap over two vaults: accepted.
        let second = vec![op(&a, VAULT_2, 1, 1, true), op(&a, VAULT_2, 2, 2, true)];
        assert!(stored(upload(&domain, VAULT_2, second).await));
        // One row past it, in either vault: refused.
        assert!(matches!(
            upload(&domain, VAULT_2, vec![op(&a, VAULT_2, 3, 3, true)]).await,
            Err(VaultError::RotationLimit)
        ));
        assert!(matches!(
            upload(&domain, VAULT, vec![op(&a, VAULT, 3, 3, true)]).await,
            Err(VaultError::RotationLimit)
        ));
        // A new vault at the account cap: creating it adds no row, its settings item (its first
        // op, which carries the item's wrap, ADR 0081 §A3 step 3) is refused.
        new_vault(&env, VAULT_3).await;
        assert!(matches!(
            upload(&domain, VAULT_3, vec![op(&a, VAULT_3, 1, 1, true)]).await,
            Err(VaultError::RotationLimit)
        ));
        // A write that adds no row is never refused at the cap.
        assert!(stored(
            upload(&domain, VAULT, vec![op(&a, VAULT, 1, 3, false)]).await
        ));
        // The default caps are the compiled-in ones of ADR 0092 §1.
        assert_eq!(WrapCaps::default(), WrapCaps::STANDARD);
        assert_eq!(WrapCaps::STANDARD.vault_rows, 65_536);
        assert_eq!(WrapCaps::STANDARD.account_rows, 65_536);
    });
}

/// A healing request of `vault` restoring rows for items `items`, with no records.
fn heal_rows(vault: VaultId, items: &[u8]) -> HealingRequest {
    let wraps = items
        .iter()
        .map(|n| ItemKeyWrap {
            item_id: Id::from_bytes(item(*n).to_bytes()),
            item_key_id: Id::from_bytes([0x4c; 16]),
            vault_key_epoch: 0,
            envelope: KeyEnvelope::new(vec![0x78; 98]).unwrap(),
        })
        .collect();
    HealingRequest {
        vault_id: Id::from_bytes(vault.to_bytes()),
        item_key_wraps: List::new(wraps).unwrap(),
        records: List::new(Vec::new()).unwrap(),
        self_grant: None,
    }
}

#[test]
fn healing_is_bound_by_the_vault_cap_only() {
    block_on(async {
        let env = Env::new(3).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        new_vault(&env, VAULT_2).await;
        let domain = capped(&env, 3, 2);
        let first = vec![op(&a, VAULT, 1, 1, true), op(&a, VAULT, 2, 2, true)];
        assert!(stored(upload(&domain, VAULT, first).await));
        // Healing past the account cap (2 + 3 rows): accepted.
        domain
            .heal(ACCOUNT, None, None, &heal_rows(VAULT_2, &[1, 2, 3]), NOW)
            .await
            .unwrap();
        // Healing past the vault cap: refused, nothing written.
        assert!(matches!(
            domain
                .heal(ACCOUNT, None, None, &heal_rows(VAULT, &[3, 4]), NOW)
                .await,
            Err(HealingError::Refused(ErrorCode::RotationLimit))
        ));
        domain
            .heal(ACCOUNT, None, None, &heal_rows(VAULT, &[3]), NOW)
            .await
            .unwrap();
        // Above the account cap now: an ordinary row-adding upload is refused, a write that
        // adds no row is accepted, so the account can always shrink.
        assert!(matches!(
            upload(&domain, VAULT_2, vec![op(&a, VAULT_2, 9, 1, true)]).await,
            Err(VaultError::RotationLimit)
        ));
        assert!(stored(
            upload(&domain, VAULT, vec![op(&a, VAULT, 1, 3, false)]).await
        ));
    });
}
