//! Healing step 3b (ADR 0032 §2–§3): a lagging self-grant and the wrap set at its epoch, sent
//! in a healing request without records, on real SQLite (or PostgreSQL, `common::Slot`) with real
//! envelopes from `rizzy-core`. One test per refusal of §3, the repair's writes, the repeat
//! rules, and a vault whose epoch moved further than the account epoch.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code"
)]

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use rizzy_core::envelope::purpose::{ItemKeyWrapCtx, VaultKeySelfGrantCtx};
use rizzy_core::ids::ItemId;
use rizzy_core::keys::{AccountKey, ItemKey, VaultKey};
use rizzy_domain_vault::{AccountKeyState, AuthorStatus, HealingError};
use rizzy_proto::error::ErrorCode;
use rizzy_proto::objects::{ItemKeyWrap, KeyEnvelope, VaultSelfGrant};
use rizzy_proto::vault::{HealingRequest, Record, UploadResult};
use rizzy_proto::wire::{Id, List};

use crate::common::{
    ACCOUNT, Device, Env, ITEM_KEY_ID, NOW, OpSpec, VAULT, block_on, item, ops_of, sign_op,
};

/// The keys of the healed account: the account key after the rotation (epoch 1), the vault key
/// before it (epoch 0) and the one after it.
struct Keys {
    /// The seeded RNG every envelope draws from.
    rng: ChaCha20Rng,
    /// The account key the held signed state names.
    account: AccountKey,
    /// The vault key before the rotation the restore undid.
    old_vault: VaultKey,
    /// The vault key after it.
    new_vault: VaultKey,
}

impl Keys {
    /// Keys from `seed`, the new vault key at `new_epoch`.
    fn new(seed: u64, new_epoch: u32) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let account = AccountKey::generate(&mut rng, 1);
        let old_vault = VaultKey::generate(&mut rng, VAULT, 0);
        let new_vault = VaultKey::generate(&mut rng, VAULT, new_epoch);
        Self {
            rng,
            account,
            old_vault,
            new_vault,
        }
    }

    /// The held state's account key, as the `auth` domain reports it.
    fn state(&self) -> AccountKeyState {
        AccountKeyState {
            account_key_epoch: 1,
            account_key_id: *self.account.key_id().unwrap().as_bytes(),
        }
    }

    /// A real wrap of a fresh item key of `item`, under the old or the new vault key.
    fn wrap(&mut self, new: bool, item: ItemId) -> ItemKeyWrap {
        let vault_key = if new {
            &self.new_vault
        } else {
            &self.old_vault
        };
        let item_key = ItemKey::generate(&mut self.rng, 0);
        let envelope = vault_key
            .wrap_item_key(
                &mut self.rng,
                &ItemKeyWrapCtx {
                    vault_id: VAULT,
                    item_id: item,
                    vault_key_epoch: vault_key.epoch(),
                },
                &item_key,
            )
            .unwrap();
        ItemKeyWrap {
            item_id: Id::from_bytes(item.to_bytes()),
            item_key_id: Id::from_bytes(ITEM_KEY_ID),
            vault_key_epoch: vault_key.epoch(),
            envelope: KeyEnvelope::new(envelope).unwrap(),
        }
    }

    /// The healer's self-grant: the new vault key under the held state's account key.
    fn grant(&mut self) -> VaultSelfGrant {
        grant_under(&mut self.rng, &self.account, 1, &self.new_vault)
    }
}

/// A step-3b request: `grant`, `wraps` and no records.
fn step_3b(grant: VaultSelfGrant, wraps: Vec<ItemKeyWrap>) -> HealingRequest {
    HealingRequest {
        vault_id: Id::from_bytes(VAULT.to_bytes()),
        item_key_wraps: List::new(wraps).unwrap(),
        records: List::empty(),
        self_grant: Some(grant),
    }
}

/// A restored vault: its self-grant under the account key of epoch 0 (the restore undid a
/// rotation the held state names), two wrap-set rows and two ops at vault epoch 0 that carry
/// those wraps, the healer `a` enrolled.
async fn restored(keys: &mut Keys, a: &Device) -> Env {
    let env = Env::new(2).await;
    env.enrol(&[a]);
    env.directory.set_account_key(keys.state());
    let mut records = Vec::new();
    for (seq, n) in [(1u64, 1u8), (2, 2)] {
        let wrap = keys.wrap(false, item(n));
        let spec = OpSpec {
            wrap: Some(wrap.envelope.as_slice().to_vec()),
            ..OpSpec::new(item(n), seq, seq - 1)
        };
        records.push(Record::Op(sign_op(a, VAULT, &spec)));
    }
    env.store(records).await;
    env
}

/// The refusal code of a healing call.
fn refused(result: Result<rizzy_proto::vault::HealingResponse, HealingError>) -> ErrorCode {
    match result {
        Err(HealingError::Refused(code)) => code,
        other => panic!("not a refusal: {other:?}"),
    }
}

#[test]
fn a_lagging_self_grant_is_repaired_with_its_wrap_set() {
    block_on(async {
        let mut keys = Keys::new(31, 1);
        let a = Device::new(1);
        let env = restored(&mut keys, &a).await;
        let grant = keys.grant();
        // Item 1's row re-wrapped; item 2's row is not carried (deleted); item 3 has no stored
        // row (left out: step 4 re-publishes it with its records).
        let wraps = vec![keys.wrap(true, item(1)), keys.wrap(true, item(3))];
        let new_row = wraps[0].clone();
        env.domain
            .heal(ACCOUNT, Some(a.id), &step_3b(grant.clone(), wraps), NOW)
            .await
            .unwrap();
        assert_eq!(env.domain.self_grant(ACCOUNT, VAULT).await.unwrap(), grant);
        let pages = env.fetch_all(&[]).await;
        assert_eq!(
            pages[0].response.item_key_wraps.as_slice(),
            &[new_row],
            "the carried row replaced, the other row below the epoch deleted"
        );
        // The record wraps below the new epoch are gone; the signed hashes stay.
        assert!(ops_of(&pages).iter().all(|op| op.key_wrap.is_none()));
        // The stale-epoch reference is the healed epoch again.
        let stale = sign_op(&a, VAULT, &OpSpec::new(item(1), 3, 2));
        assert_eq!(
            env.upload(vec![Record::Op(stale)]).await,
            vec![UploadResult::Rejected {
                error: ErrorCode::StaleEpoch
            }]
        );
        let current = sign_op(
            &a,
            VAULT,
            &OpSpec {
                epoch: 1,
                ..OpSpec::new(item(1), 3, 2)
            },
        );
        env.store(vec![Record::Op(current)]).await;
        // The repair does not lag any more: the same request is a repeat that stores nothing,
        // and another device's valid grant at the stored epochs is one too (first repair wins).
        let wraps = vec![keys.wrap(true, item(1))];
        env.domain
            .heal(ACCOUNT, Some(a.id), &step_3b(grant.clone(), wraps), NOW)
            .await
            .unwrap();
        let other = keys.grant();
        env.domain
            .heal(ACCOUNT, Some(a.id), &step_3b(other, Vec::new()), NOW)
            .await
            .unwrap();
        assert_eq!(env.domain.self_grant(ACCOUNT, VAULT).await.unwrap(), grant);
        // A non-lagging grant at another epoch is not a valid repeat.
        let mut further = Keys::new(31, 2);
        let further_grant = further.grant();
        assert_eq!(
            refused(
                env.domain
                    .heal(
                        ACCOUNT,
                        Some(a.id),
                        &step_3b(further_grant, Vec::new()),
                        NOW
                    )
                    .await
            ),
            ErrorCode::InvalidRequest
        );
    });
}

#[test]
fn only_a_durable_device_of_the_held_set_repairs() {
    block_on(async {
        let mut keys = Keys::new(32, 1);
        let a = Device::new(1);
        let env = restored(&mut keys, &a).await;
        let revoked = Device::new(2);
        env.directory.set(
            &revoked,
            AuthorStatus::Revoked {
                last_accepted_device_seq: 0,
            },
        );
        let suspended = Device::new(3);
        env.directory.set(&suspended, AuthorStatus::Suspended);
        let web = Device::web(4, NOW + 3_600_000);
        env.enrol(&[&web]);
        for healer in [None, Some(revoked.id), Some(suspended.id), Some(web.id)] {
            let request = step_3b(keys.grant(), vec![keys.wrap(true, item(1))]);
            assert_eq!(
                refused(env.domain.heal(ACCOUNT, healer, &request, NOW).await),
                ErrorCode::Unauthorized
            );
        }
        // Nothing was stored: the restored grant is still served.
        let stored = env.domain.self_grant(ACCOUNT, VAULT).await.unwrap();
        assert_eq!(stored.account_key_epoch, 0);
    });
}

#[test]
fn each_check_of_the_lag_rule_refuses() {
    block_on(async {
        let mut keys = Keys::new(33, 1);
        let a = Device::new(1);
        let env = restored(&mut keys, &a).await;
        let heal = |request: HealingRequest| {
            let env = &env;
            async move { refused(env.domain.heal(ACCOUNT, Some(a.id), &request, NOW).await) }
        };
        // A wrong `key_id`: the grant under another account key.
        let other_account = AccountKey::generate(&mut keys.rng, 1);
        let wrong_key = grant_under(&mut keys.rng, &other_account, 1, &keys.new_vault);
        assert_eq!(
            heal(step_3b(wrong_key, Vec::new())).await,
            ErrorCode::InvalidRequest
        );
        // An `account_key_epoch` that is not the state's.
        let mut wrong_epoch = keys.grant();
        wrong_epoch.account_key_epoch = 2;
        assert_eq!(
            heal(step_3b(wrong_epoch, Vec::new())).await,
            ErrorCode::InvalidRequest
        );
        // A `vault_key_epoch` not above the stored one (0).
        let mut same = Keys::new(33, 0);
        let not_above = same.grant();
        assert_eq!(
            heal(step_3b(not_above, Vec::new())).await,
            ErrorCode::InvalidRequest
        );
        // Records in a step-3b request.
        let mut with_records = step_3b(keys.grant(), Vec::new());
        with_records.records = List::new(vec![Record::Op(sign_op(
            &a,
            VAULT,
            &OpSpec::new(item(1), 3, 2),
        ))])
        .unwrap();
        assert_eq!(heal(with_records).await, ErrorCode::InvalidRequest);
        // A wrap re-wrapped under the old vault key's id, and one at another epoch.
        let mut old_key = keys.wrap(false, item(1));
        old_key.vault_key_epoch = 1;
        assert_eq!(
            heal(step_3b(keys.grant(), vec![old_key])).await,
            ErrorCode::InvalidRequest
        );
        let wrong_wrap_epoch = keys.wrap(false, item(1));
        assert_eq!(
            heal(step_3b(keys.grant(), vec![wrong_wrap_epoch])).await,
            ErrorCode::InvalidRequest
        );
        // Without a held state the `auth` domain reports no account key.
        let env_without = Env::new(3).await;
        env_without.enrol(&[&a]);
        let request = step_3b(keys.grant(), Vec::new());
        assert_eq!(
            refused(
                env_without
                    .domain
                    .heal(ACCOUNT, Some(a.id), &request, NOW)
                    .await
            ),
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            env.domain
                .self_grant(ACCOUNT, VAULT)
                .await
                .unwrap()
                .account_key_epoch,
            0
        );
    });
}

#[test]
fn a_vault_epoch_ahead_of_the_account_epoch_heals_but_not_below_a_record() {
    block_on(async {
        let a = Device::new(1);
        // An earlier restore and rotation left records at vault epoch 3 while the vault row
        // and the self-grant were rolled back to 0.
        let mut keys = Keys::new(34, 4);
        let env = restored(&mut keys, &a).await;
        let ahead = sign_op(
            &a,
            VAULT,
            &OpSpec {
                epoch: 3,
                ..OpSpec::new(item(1), 3, 2)
            },
        );
        env.store(vec![Record::Op(ahead)]).await;
        // A grant at vault epoch 2 is below a stored record: refused.
        let low = Keys::new(34, 2);
        let low_grant = grant_under(&mut keys.rng, &keys.account, 1, &low.new_vault);
        assert_eq!(
            refused(
                env.domain
                    .heal(ACCOUNT, Some(a.id), &step_3b(low_grant, Vec::new()), NOW)
                    .await
            ),
            ErrorCode::InvalidRequest
        );
        // Vault epoch 4 under account epoch 1: no fixed delta between the two.
        let grant = keys.grant();
        env.domain
            .heal(
                ACCOUNT,
                Some(a.id),
                &step_3b(grant.clone(), Vec::new()),
                NOW,
            )
            .await
            .unwrap();
        assert_eq!(env.domain.self_grant(ACCOUNT, VAULT).await.unwrap(), grant);
        // The record at epoch 3 is now below the vault's epoch: its successor is refused stale.
        let stale = sign_op(
            &a,
            VAULT,
            &OpSpec {
                epoch: 3,
                ..OpSpec::new(item(1), 4, 3)
            },
        );
        assert_eq!(
            env.upload(vec![Record::Op(stale)]).await,
            vec![UploadResult::Rejected {
                error: ErrorCode::StaleEpoch
            }]
        );
    });
}

/// The self-grant of `vault` under `account` at `account_key_epoch`.
fn grant_under(
    rng: &mut ChaCha20Rng,
    account: &AccountKey,
    account_key_epoch: u32,
    vault: &VaultKey,
) -> VaultSelfGrant {
    let envelope = account
        .wrap_vault_key(
            rng,
            &VaultKeySelfGrantCtx {
                account_id: ACCOUNT,
                vault_id: VAULT,
                account_key_epoch,
                vault_key_epoch: vault.epoch(),
            },
            vault,
        )
        .unwrap();
    VaultSelfGrant {
        vault_id: Id::from_bytes(VAULT.to_bytes()),
        account_key_epoch,
        vault_key_epoch: vault.epoch(),
        envelope: KeyEnvelope::new(envelope).unwrap(),
    }
}
