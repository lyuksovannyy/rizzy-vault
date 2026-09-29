//! The vault half of a key rotation (ADR 0025 §3–§5; CRYPTO.md §11.6 step 9; ADR 0012 §6), on
//! real SQLite (or PostgreSQL, see `common::Slot`), with real envelopes from `rizzy-core`: the
//! self-grant under a fresh account key, the wrap set under the old and the new vault key.
//!
//! `apply_rotation` runs the way `rizzy-server`'s bridge runs it: in a write transaction that
//! holds the account lock, committed only when it succeeds.

#![expect(
    clippy::unwrap_used,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code"
)]

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use rizzy_core::envelope::purpose::{ItemKeyWrapCtx, VaultKeySelfGrantCtx};
use rizzy_core::ids::ItemId;
use rizzy_core::keys::{AccountKey, ItemKey, VaultKey};
use rizzy_domain_vault::VaultError;
use rizzy_domain_vault::port::recovery_vaults;
use rizzy_domain_vault::rotation::apply_rotation;
use rizzy_proto::change::{VaultRotation, VaultRotationUpload, WrapLocator};
use rizzy_proto::error::ErrorCode;
use rizzy_proto::objects::{ItemKeyWrap, KeyEnvelope, VaultSelfGrant};
use rizzy_proto::vault::{
    FetchResponse, HealingRequest, Record, SeqEntry, SeqVector, UploadResult,
};
use rizzy_proto::wire::{Id, List};
use rizzy_storage::lock_account;

use crate::common::{
    ACCOUNT, Device, Env, ITEM_KEY_ID, NOW, OpSpec, VAULT, block_on, item, ops_of, sign_op,
    sign_snapshot,
};

/// The keys of a test account: the new account key and the old and new vault keys.
struct Keys {
    /// The seeded RNG every envelope draws from.
    rng: ChaCha20Rng,
    /// The account key after the rotation, epoch 1.
    account: AccountKey,
    /// The vault key before the rotation, epoch 0.
    old_vault: VaultKey,
    /// The vault key after the rotation.
    new_vault: VaultKey,
}

impl Keys {
    /// Keys from seed `seed`; the new vault key at `new_epoch`.
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

    /// The new account key's id.
    fn account_key_id(&self) -> [u8; 16] {
        *self.account.key_id().unwrap().as_bytes()
    }

    /// A real `ITEM_KEY_WRAP` of a fresh item key of `item` under `key`.
    fn wrap(&mut self, key: &VaultKeyChoice, item: ItemId) -> Vec<u8> {
        let vault_key = match key {
            VaultKeyChoice::Old => &self.old_vault,
            VaultKeyChoice::New => &self.new_vault,
        };
        let item_key = ItemKey::generate(&mut self.rng, 0);
        vault_key
            .wrap_item_key(
                &mut self.rng,
                &ItemKeyWrapCtx {
                    vault_id: VAULT,
                    item_id: item,
                    vault_key_epoch: vault_key.epoch(),
                },
                &item_key,
            )
            .unwrap()
    }

    /// The new self-grant: the new vault key under the new account key.
    fn grant(&mut self) -> VaultSelfGrant {
        let envelope = self
            .account
            .wrap_vault_key(
                &mut self.rng,
                &VaultKeySelfGrantCtx {
                    account_id: ACCOUNT,
                    vault_id: VAULT,
                    account_key_epoch: 1,
                    vault_key_epoch: self.new_vault.epoch(),
                },
                &self.new_vault,
            )
            .unwrap();
        VaultSelfGrant {
            vault_id: Id::from_bytes(VAULT.to_bytes()),
            account_key_epoch: 1,
            vault_key_epoch: self.new_vault.epoch(),
            envelope: KeyEnvelope::new(envelope).unwrap(),
        }
    }
}

/// Which vault key a test wrap is under.
enum VaultKeyChoice {
    /// The vault key before the rotation.
    Old,
    /// The vault key after it.
    New,
}

/// The locator of item `n`'s carried test wrap.
fn locator(n: u8) -> WrapLocator {
    WrapLocator {
        item_id: Id::from_bytes(item(n).to_bytes()),
        item_key_id: Id::from_bytes(ITEM_KEY_ID),
    }
}

/// A re-wrap of item `n`'s row under the new vault key.
fn rewrap(keys: &mut Keys, n: u8) -> ItemKeyWrap {
    let envelope = keys.wrap(&VaultKeyChoice::New, item(n));
    ItemKeyWrap {
        item_id: Id::from_bytes(item(n).to_bytes()),
        item_key_id: Id::from_bytes(ITEM_KEY_ID),
        vault_key_epoch: keys.new_vault.epoch(),
        envelope: KeyEnvelope::new(envelope).unwrap(),
    }
}

/// A cursor from `(device, seq)` pairs.
fn cursor(entries: &[(&Device, u64)]) -> SeqVector {
    let mut entries: Vec<SeqEntry> = entries
        .iter()
        .map(|(d, seq)| SeqEntry {
            device_id: Id::from_bytes(d.id.to_bytes()),
            seq: *seq,
        })
        .collect();
    entries.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    SeqVector::new(entries).unwrap()
}

/// The vault half of one vault, before it is wrapped into an upload.
#[derive(Clone)]
struct Half {
    /// The new self-grant.
    grant: VaultSelfGrant,
    /// The cursor.
    cursor: SeqVector,
    /// The re-wrapped rows.
    wraps: Vec<ItemKeyWrap>,
    /// The dropped rows.
    dropped: Vec<WrapLocator>,
}

impl Half {
    /// The upload of this one vault.
    fn upload(&self) -> VaultRotationUpload {
        VaultRotationUpload::new(vec![VaultRotation {
            self_grant: self.grant.clone(),
            cursor: self.cursor.clone(),
            item_key_wraps: List::new(self.wraps.clone()).unwrap(),
            dropped: List::new(self.dropped.clone()).unwrap(),
        }])
        .unwrap()
    }
}

/// Runs the vault half as the bridge does: one write transaction under the account lock,
/// committed on success and rolled back on a refusal.
async fn apply(
    env: &Env,
    upload: &VaultRotationUpload,
    account_key_epoch: u32,
    account_key_id: [u8; 16],
) -> Result<(), VaultError> {
    let mut tx = env.db.begin_write().await.unwrap();
    lock_account(&mut tx, ACCOUNT.as_bytes()).await.unwrap();
    let result = apply_rotation(
        &mut tx,
        ACCOUNT,
        account_key_epoch,
        &account_key_id,
        upload,
        NOW,
    )
    .await;
    if result.is_ok() {
        tx.commit().await.unwrap();
    } else {
        tx.rollback().await.unwrap();
    }
    result
}

/// Everything a client could see of the vault: its self-grant and a complete Fetch from zero.
async fn observe(env: &Env) -> (VaultSelfGrant, Vec<FetchResponse>) {
    let grant = env.domain.self_grant(ACCOUNT, VAULT).await.unwrap();
    let pages = env
        .fetch_all(&[])
        .await
        .into_iter()
        .map(|p| p.response)
        .collect();
    (grant, pages)
}

/// A vault where A stored ops 1–2 on item 1 (op 1 carrying a wrap under the old vault key) and
/// a snapshot covering them, and B stored op 1 on item 2 carrying a wrap. The wrap set holds
/// the rows of items 1 and 2.
async fn populated(keys: &mut Keys) -> (Env, Device, Device) {
    let env = Env::new(1).await;
    let (a, b) = (Device::new(1), Device::new(2));
    env.enrol(&[&a, &b]);
    let wrap_1 = keys.wrap(&VaultKeyChoice::Old, item(1));
    let wrap_2 = keys.wrap(&VaultKeyChoice::Old, item(2));
    env.store(vec![
        Record::Op(sign_op(
            &a,
            VAULT,
            &OpSpec {
                wrap: Some(wrap_1),
                ..OpSpec::new(item(1), 1, 0)
            },
        )),
        Record::Op(sign_op(&a, VAULT, &OpSpec::new(item(1), 2, 1))),
        Record::Snapshot(sign_snapshot(&a, item(1), 1, &[(&a, 2)], 0)),
        Record::Op(sign_op(
            &b,
            VAULT,
            &OpSpec {
                wrap: Some(wrap_2),
                ..OpSpec::new(item(2), 1, 0)
            },
        )),
    ])
    .await;
    (env, a, b)
}

/// ADR 0025 §5: a rotation commits; afterwards Fetch serves every row at the new epoch and no
/// record wrap, the self-grant is the new one, an old-epoch upload gets `stale_epoch` and a
/// new-epoch one is stored. A dropped row is gone.
#[test]
fn a_rotation_rewrites_the_wrap_set_and_raises_the_epoch() {
    block_on(async {
        let mut keys = Keys::new(1, 1);
        let (env, a, b) = populated(&mut keys).await;
        let before = env.fetch_all(&[]).await;
        assert!(ops_of(&before).iter().any(|op| op.key_wrap.is_some()));
        let half = Half {
            grant: keys.grant(),
            cursor: cursor(&[(&a, 2), (&b, 1)]),
            wraps: vec![rewrap(&mut keys, 1)],
            dropped: vec![locator(2)],
        };
        let key_id = keys.account_key_id();
        apply(&env, &half.upload(), 1, key_id).await.unwrap();

        let (grant, pages) = observe(&env).await;
        assert_eq!(grant, half.grant);
        for page in &pages {
            assert_eq!(page.item_key_wraps.as_slice(), half.wraps.as_slice());
            assert!(page.ops.iter().all(|op| op.key_wrap.is_none()));
            assert!(page.covers.iter().all(|s| s.key_wrap.is_none()));
        }
        assert_eq!(pages.iter().map(|p| p.ops.len()).sum::<usize>(), 3);

        // The new self-grant opens under the new account key at the new epochs.
        let opened = keys
            .account
            .unwrap_vault_key(
                &VaultKeySelfGrantCtx {
                    account_id: ACCOUNT,
                    vault_id: VAULT,
                    account_key_epoch: 1,
                    vault_key_epoch: 1,
                },
                grant.envelope.as_slice(),
            )
            .unwrap();
        assert!(opened.matches_key_id(&keys.new_vault.key_id().unwrap()));

        // Uploaded after, at the old epoch: `stale_epoch` (ADR 0021 §9); at the new one: stored.
        let stale = sign_op(&a, VAULT, &OpSpec::new(item(1), 3, 2));
        assert_eq!(
            env.upload(vec![Record::Op(stale)]).await,
            vec![UploadResult::Rejected {
                error: ErrorCode::StaleEpoch
            }]
        );
        let fresh = sign_op(
            &a,
            VAULT,
            &OpSpec {
                epoch: 1,
                ..OpSpec::new(item(1), 3, 2)
            },
        );
        env.store(vec![Record::Op(fresh)]).await;
    });
}

/// ADR 0025 §5: one test per §3 refusal. Each leaves every vault row as it was.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one case per refusal of ADR 0025 §3, in the ADR's order"
)]
fn every_refusal_leaves_the_vault_unchanged() {
    block_on(async {
        let mut keys = Keys::new(2, 1);
        let (env, a, b) = populated(&mut keys).await;
        let good = Half {
            grant: keys.grant(),
            cursor: cursor(&[(&a, 2), (&b, 1)]),
            wraps: vec![rewrap(&mut keys, 1), rewrap(&mut keys, 2)],
            dropped: Vec::new(),
        };
        let key_id = keys.account_key_id();
        let before = observe(&env).await;

        let other_key = Keys::new(99, 1);
        let mut foreign_grant = good.grant.clone();
        foreign_grant.envelope = {
            let mut k = Keys::new(98, 1);
            k.grant().envelope
        };
        let mut old_key_wraps = good.clone();
        old_key_wraps.wraps[0].envelope =
            KeyEnvelope::new(keys.wrap(&VaultKeyChoice::Old, item(1))).unwrap();
        let mut mixed_key_ids = good.clone();
        mixed_key_ids.wraps[1].envelope = {
            let mut k = Keys::new(97, 1);
            KeyEnvelope::new(k.wrap(&VaultKeyChoice::New, item(2))).unwrap()
        };
        drop(other_key);

        let invalid: Vec<(&str, Half, u32)> = vec![
            (
                "grant at another account_key_epoch",
                Half {
                    grant: VaultSelfGrant {
                        account_key_epoch: 2,
                        ..good.grant.clone()
                    },
                    ..good.clone()
                },
                1,
            ),
            (
                "grant at the stored vault_key_epoch",
                Half {
                    grant: VaultSelfGrant {
                        vault_key_epoch: 0,
                        ..good.grant.clone()
                    },
                    wraps: good
                        .wraps
                        .iter()
                        .map(|w| ItemKeyWrap {
                            vault_key_epoch: 0,
                            ..w.clone()
                        })
                        .collect(),
                    ..good.clone()
                },
                1,
            ),
            (
                "grant under another account key",
                Half {
                    grant: foreign_grant,
                    ..good.clone()
                },
                1,
            ),
            (
                "grant not an envelope",
                Half {
                    grant: VaultSelfGrant {
                        envelope: KeyEnvelope::new(vec![1; 98]).unwrap(),
                        ..good.grant.clone()
                    },
                    ..good.clone()
                },
                1,
            ),
            (
                "a wrap at another epoch",
                Half {
                    wraps: vec![
                        ItemKeyWrap {
                            vault_key_epoch: 2,
                            ..good.wraps[0].clone()
                        },
                        good.wraps[1].clone(),
                    ],
                    ..good.clone()
                },
                1,
            ),
            (
                "a wrap of the wrong length",
                Half {
                    wraps: vec![
                        ItemKeyWrap {
                            envelope: good.grant.envelope.clone(),
                            ..good.wraps[0].clone()
                        },
                        good.wraps[1].clone(),
                    ],
                    ..good.clone()
                },
                1,
            ),
            ("a re-wrap under the old vault key", old_key_wraps, 1),
            ("re-wraps under two keys", mixed_key_ids, 1),
            (
                "a row re-wrapped twice",
                Half {
                    wraps: vec![good.wraps[0].clone(), good.wraps[0].clone()],
                    dropped: vec![locator(2)],
                    ..good.clone()
                },
                1,
            ),
            (
                "a re-wrap of a row not stored",
                Half {
                    wraps: vec![good.wraps[0].clone(), good.wraps[1].clone(), {
                        let mut w = rewrap(&mut keys, 3);
                        w.envelope = good.wraps[0].envelope.clone();
                        w
                    }],
                    ..good.clone()
                },
                1,
            ),
            (
                "a dropped row not stored",
                Half {
                    dropped: vec![locator(3)],
                    ..good.clone()
                },
                1,
            ),
            (
                "a row both re-wrapped and dropped",
                Half {
                    dropped: vec![locator(2)],
                    ..good.clone()
                },
                1,
            ),
            (
                "a row dropped twice",
                Half {
                    wraps: vec![good.wraps[0].clone()],
                    dropped: vec![locator(2), locator(2)],
                    ..good.clone()
                },
                1,
            ),
            // The state's account_key_epoch is not the grant's.
            ("the new state at another epoch", good.clone(), 2),
        ];
        for (name, half, epoch) in &invalid {
            let err = apply(&env, &half.upload(), *epoch, key_id)
                .await
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidRequest, "{name}");
            assert_eq!(observe(&env).await, before, "{name}");
        }
        // The signed account_key_id is not the grant's header key id.
        let err = apply(&env, &good.upload(), 1, [0; 16]).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidRequest);
        // Shape: no entry for the vault, or an entry for a vault the account does not own.
        let err = apply(
            &env,
            &VaultRotationUpload::new(Vec::new()).unwrap(),
            1,
            key_id,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidRequest);
        let mut foreign = good.clone();
        foreign.grant.vault_id = Id::from_bytes([0xb2; 16]);
        let err = apply(&env, &foreign.upload(), 1, key_id).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidRequest);

        let conflicts: Vec<(&str, Half)> = vec![
            (
                "a stored row in neither list",
                Half {
                    wraps: vec![good.wraps[0].clone()],
                    ..good.clone()
                },
            ),
            (
                "a cursor below a head",
                Half {
                    cursor: cursor(&[(&a, 1), (&b, 1)]),
                    ..good.clone()
                },
            ),
            (
                "a cursor above a head (the server is behind)",
                Half {
                    cursor: cursor(&[(&a, 3), (&b, 1)]),
                    ..good.clone()
                },
            ),
            (
                "a cursor without a device",
                Half {
                    cursor: cursor(&[(&a, 2)]),
                    ..good.clone()
                },
            ),
            (
                "a cursor with a device the server holds nothing from",
                Half {
                    cursor: cursor(&[(&a, 2), (&b, 1), (&Device::new(3), 1)]),
                    ..good.clone()
                },
            ),
        ];
        for (name, half) in &conflicts {
            let err = apply(&env, &half.upload(), 1, key_id).await.unwrap_err();
            assert_eq!(err.code(), ErrorCode::StateConflict, "{name}");
            assert_eq!(observe(&env).await, before, "{name}");
        }

        // An op stored after the rotator's Fetch: its cursor is below the head now.
        env.store(vec![Record::Op(sign_op(
            &b,
            VAULT,
            &OpSpec::new(item(2), 2, 1),
        ))])
        .await;
        let err = apply(&env, &good.upload(), 1, key_id).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::StateConflict);
        // A row healed in after the Fetch: in neither list.
        let healed = keys.wrap(&VaultKeyChoice::Old, item(4));
        env.domain
            .heal(
                ACCOUNT,
                &HealingRequest {
                    vault_id: Id::from_bytes(VAULT.to_bytes()),
                    item_key_wraps: List::new(vec![ItemKeyWrap {
                        item_id: Id::from_bytes(item(4).to_bytes()),
                        item_key_id: Id::from_bytes(ITEM_KEY_ID),
                        vault_key_epoch: 0,
                        envelope: KeyEnvelope::new(healed).unwrap(),
                    }])
                    .unwrap(),
                    records: List::empty(),
                },
                NOW,
            )
            .await
            .unwrap();
        let caught_up = Half {
            cursor: cursor(&[(&a, 2), (&b, 2)]),
            ..good.clone()
        };
        let err = apply(&env, &caught_up.upload(), 1, key_id)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::StateConflict);
        // With every row and the exact heads, the same keys commit.
        let complete = Half {
            dropped: vec![locator(4)],
            ..caught_up
        };
        apply(&env, &complete.upload(), 1, key_id).await.unwrap();
    });
}

/// ADR 0025 §3 check 2 and open question 6: after a restore rolled the vault's epoch back, a
/// rotation above the rolled-back value commits (`>`, not `= + 1`), and one at or below the
/// stored epoch never does, so an epoch is never reused with another key.
#[test]
fn a_rotation_may_skip_epochs_but_never_reuse_one() {
    block_on(async {
        let mut keys = Keys::new(3, 3);
        let (env, a, b) = populated(&mut keys).await;
        let half = Half {
            grant: keys.grant(),
            cursor: cursor(&[(&a, 2), (&b, 1)]),
            wraps: vec![rewrap(&mut keys, 1), rewrap(&mut keys, 2)],
            dropped: Vec::new(),
        };
        let key_id = keys.account_key_id();
        apply(&env, &half.upload(), 1, key_id).await.unwrap();
        assert_eq!(
            env.domain
                .self_grant(ACCOUNT, VAULT)
                .await
                .unwrap()
                .vault_key_epoch,
            3
        );
        // Epoch 3 again, with other keys (a second rotation re-using it): refused.
        let mut again = Keys::new(4, 3);
        let reuse = Half {
            grant: again.grant(),
            wraps: vec![rewrap(&mut again, 1), rewrap(&mut again, 2)],
            ..half
        };
        let err = apply(&env, &reuse.upload(), 1, again.account_key_id())
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidRequest);
    });
}

/// ADR 0025 §4 "A revoked device's ops … A junk wrap it planted is `dropped` and cannot block
/// its revocation": a row that opens under no key the rotator holds is dropped, and the
/// rotation commits.
#[test]
fn a_planted_junk_wrap_is_dropped_and_does_not_block() {
    block_on(async {
        let mut keys = Keys::new(5, 1);
        let (env, a, b) = populated(&mut keys).await;
        let junk = Device::new(9);
        env.enrol(&[&junk]);
        env.store(vec![Record::Op(sign_op(
            &junk,
            VAULT,
            &OpSpec {
                wrap: Some(vec![0xee; 127]),
                ..OpSpec::new(item(9), 1, 0)
            },
        ))])
        .await;
        let half = Half {
            grant: keys.grant(),
            cursor: cursor(&[(&a, 2), (&b, 1), (&junk, 1)]),
            wraps: vec![rewrap(&mut keys, 1), rewrap(&mut keys, 2)],
            dropped: vec![locator(9)],
        };
        apply(&env, &half.upload(), 1, keys.account_key_id())
            .await
            .unwrap();
        let (_, pages) = observe(&env).await;
        assert_eq!(pages[0].item_key_wraps.as_slice(), half.wraps.as_slice());
    });
}

/// ADR 0025 open question 4, decided: after a rotation, healing does not fill a row below the
/// current `vault_key_epoch`.
#[test]
fn healing_below_the_current_epoch_fills_nothing() {
    block_on(async {
        let mut keys = Keys::new(6, 1);
        let (env, a, b) = populated(&mut keys).await;
        let half = Half {
            grant: keys.grant(),
            cursor: cursor(&[(&a, 2), (&b, 1)]),
            wraps: vec![rewrap(&mut keys, 1), rewrap(&mut keys, 2)],
            dropped: Vec::new(),
        };
        apply(&env, &half.upload(), 1, keys.account_key_id())
            .await
            .unwrap();
        let old = keys.wrap(&VaultKeyChoice::Old, item(5));
        let new = rewrap(&mut keys, 6);
        env.domain
            .heal(
                ACCOUNT,
                &HealingRequest {
                    vault_id: Id::from_bytes(VAULT.to_bytes()),
                    item_key_wraps: List::new(vec![
                        ItemKeyWrap {
                            item_id: Id::from_bytes(item(5).to_bytes()),
                            item_key_id: Id::from_bytes(ITEM_KEY_ID),
                            vault_key_epoch: 0,
                            envelope: KeyEnvelope::new(old).unwrap(),
                        },
                        new.clone(),
                    ])
                    .unwrap(),
                    records: List::empty(),
                },
                NOW,
            )
            .await
            .unwrap();
        let (_, pages) = observe(&env).await;
        let rows = pages[0].item_key_wraps.as_slice();
        assert!(rows.iter().all(|w| w.vault_key_epoch == 1));
        assert!(rows.contains(&new));
        assert_eq!(rows.len(), 3);
    });
}

/// ADR 0025 open question 4, decided, for the wraps records carry: a healed op below the
/// current `vault_key_epoch` that carries a wrap (here for a row the rotation dropped) is stored
/// without it, and its wrap fills no row, so no row under the superseded vault key returns.
#[test]
fn a_healed_old_epoch_record_brings_back_no_old_wrap() {
    block_on(async {
        let mut keys = Keys::new(8, 1);
        let (env, a, b) = populated(&mut keys).await;
        let half = Half {
            grant: keys.grant(),
            cursor: cursor(&[(&a, 2), (&b, 1)]),
            wraps: vec![rewrap(&mut keys, 1)],
            dropped: vec![locator(2)],
        };
        apply(&env, &half.upload(), 1, keys.account_key_id())
            .await
            .unwrap();
        let old = keys.wrap(&VaultKeyChoice::Old, item(2));
        let healed = sign_op(
            &b,
            VAULT,
            &OpSpec {
                wrap: Some(old),
                ..OpSpec::new(item(2), 2, 1)
            },
        );
        env.domain
            .heal(
                ACCOUNT,
                &HealingRequest {
                    vault_id: Id::from_bytes(VAULT.to_bytes()),
                    item_key_wraps: List::empty(),
                    records: List::new(vec![Record::Op(healed)]).unwrap(),
                },
                NOW,
            )
            .await
            .unwrap();
        let (_, pages) = observe(&env).await;
        for page in &pages {
            assert_eq!(page.item_key_wraps.as_slice(), half.wraps.as_slice());
            assert!(page.ops.iter().all(|op| op.key_wrap.is_none()));
        }
        assert_eq!(pages.iter().map(|p| p.ops.len()).sum::<usize>(), 4);
    });
}

/// ADR 0025 §1: the recovery answer's vaults carry the self-grant, the heads and the whole wrap
/// set; the heads are the cursor a rotation needs.
#[test]
fn recovery_vaults_are_a_rotation_cursor() {
    block_on(async {
        let mut keys = Keys::new(7, 1);
        let (env, a, b) = populated(&mut keys).await;
        let mut tx = env.db.begin_read().await.unwrap();
        let vaults = recovery_vaults(tx.conn(), ACCOUNT).await.unwrap();
        tx.finish().await.unwrap();
        assert_eq!(vaults.len(), 1);
        let vault = &vaults[0];
        assert_eq!(vault.vault_id, Id::from_bytes(VAULT.to_bytes()));
        assert_eq!(vault.self_grant.vault_key_epoch, 0);
        assert_eq!(vault.heads, cursor(&[(&a, 2), (&b, 1)]));
        assert_eq!(vault.item_key_wraps.len(), 2);
        let half = Half {
            grant: keys.grant(),
            cursor: vault.heads.clone(),
            wraps: vec![rewrap(&mut keys, 1), rewrap(&mut keys, 2)],
            dropped: Vec::new(),
        };
        apply(&env, &half.upload(), 1, keys.account_key_id())
            .await
            .unwrap();
    });
}

/// Upload-versus-rotation runs, `RIZZY_TEST_RACE_RUNS` or 1,000 (the ADR 0025 §5 figure).
fn race_runs() -> u32 {
    std::env::var("RIZZY_TEST_RACE_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
}

/// ADR 0025 §5: racing an upload against a rotation built from the state before it, exactly one
/// of "upload stored, rotation refused (`state_conflict`)" or "rotation committed, upload
/// `stale_epoch`" happens, never both and never neither. The order is varied with yields; the
/// test requires both outcomes to occur.
#[test]
fn an_upload_racing_a_rotation_is_ordered() {
    block_on(async {
        let env = Env::new(1).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        let mut seq = 0u64;
        let (mut upload_first, mut rotation_first) = (0u32, 0u32);
        for run in 0..race_runs() {
            // Every run rotates once, so run `r` starts at vault epoch `r`.
            let epoch = run;
            let mut keys = Keys::new(u64::from(run) + 100, epoch + 1);
            let key_id = keys.account_key_id();
            let half = Half {
                grant: keys.grant(),
                cursor: if seq == 0 {
                    SeqVector::default()
                } else {
                    cursor(&[(&a, seq)])
                },
                wraps: Vec::new(),
                dropped: Vec::new(),
            };
            let op = sign_op(
                &a,
                VAULT,
                &OpSpec {
                    epoch,
                    ..OpSpec::new(item(1), seq + 1, seq)
                },
            );
            let lead = run % 4;
            let (uploaded, rotated) = join2(
                Box::pin(async {
                    for _ in 0..lead {
                        tokio::task::yield_now().await;
                    }
                    env.upload(vec![Record::Op(op)]).await
                }),
                Box::pin(async {
                    for _ in 0..(3 - lead) {
                        tokio::task::yield_now().await;
                    }
                    apply(&env, &half.upload(), 1, key_id).await
                }),
            )
            .await;
            match (uploaded.as_slice(), rotated) {
                ([UploadResult::Stored], Err(e)) if e.code() == ErrorCode::StateConflict => {
                    upload_first += 1;
                    seq += 1;
                    // Rotate again from the new state, so every run starts one epoch higher.
                    let retry = Half {
                        cursor: cursor(&[(&a, seq)]),
                        ..half
                    };
                    apply(&env, &retry.upload(), 1, key_id).await.unwrap();
                }
                (
                    [
                        UploadResult::Rejected {
                            error: ErrorCode::StaleEpoch,
                        },
                    ],
                    Ok(()),
                ) => rotation_first += 1,
                (other, rotated) => panic!("run {run}: {other:?} and {rotated:?}"),
            }
        }
        assert!(upload_first >= 1 && rotation_first >= 1);
    });
}

/// Polls two futures concurrently on the current task until both finish (`tokio::join!`
/// without its `macros` feature).
async fn join2<A: std::future::Future, B: std::future::Future>(
    a: A,
    b: B,
) -> (A::Output, B::Output) {
    use std::task::Poll;
    let mut a = std::pin::pin!(a);
    let mut b = std::pin::pin!(b);
    let (mut ra, mut rb) = (None, None);
    std::future::poll_fn(|cx| {
        if ra.is_none()
            && let Poll::Ready(v) = a.as_mut().poll(cx)
        {
            ra = Some(v);
        }
        if rb.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            rb = Some(v);
        }
        if ra.is_some() && rb.is_some() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    (ra.unwrap(), rb.unwrap())
}

/// ADR 0025 §5 "restore drill": E → E+1 → restore → heal → E+2. The restore rolls the vault back
/// to epoch 0 and loses A's op 3 at epoch 1, which carries its item's wrap; A heals it; the next
/// rotation, above every epoch the rotator saw (2, `>` the stored 0), covers the healed row and
/// commits; afterwards every row is at epoch 2, and healing an epoch-1 record brings back no row
/// under the superseded key.
#[test]
fn the_restore_drill_heals_then_rotates_past_the_rollback() {
    block_on(async {
        let mut keys = Keys::new(9, 1);
        let (env, a, b) = populated(&mut keys).await;
        let dump = env.db.dump().await.unwrap();
        let first = Half {
            grant: keys.grant(),
            cursor: cursor(&[(&a, 2), (&b, 1)]),
            wraps: vec![rewrap(&mut keys, 1), rewrap(&mut keys, 2)],
            dropped: Vec::new(),
        };
        apply(&env, &first.upload(), 1, keys.account_key_id())
            .await
            .unwrap();
        let wrap_3 = keys.wrap(&VaultKeyChoice::New, item(3));
        let op_3 = Record::Op(sign_op(
            &a,
            VAULT,
            &OpSpec {
                epoch: 1,
                wrap: Some(wrap_3),
                ..OpSpec::new(item(3), 3, 2)
            },
        ));
        env.store(vec![op_3.clone()]).await;

        // The restore: back to the dump taken before the rotation, epoch 0, op 3 lost.
        let mut slot = env.into_slot();
        let db = slot.fresh_db().await;
        db.restore(&dump, rizzy_storage::RestoreGeneration([2; 16]), 2)
            .await
            .unwrap();
        let env = crate::common::Env::over(slot, db);
        env.enrol(&[&a, &b]);
        assert_eq!(
            env.domain
                .self_grant(ACCOUNT, VAULT)
                .await
                .unwrap()
                .vault_key_epoch,
            0
        );
        let heal = |records: Vec<Record>| HealingRequest {
            vault_id: Id::from_bytes(VAULT.to_bytes()),
            item_key_wraps: List::empty(),
            records: List::new(records).unwrap(),
        };
        env.domain
            .heal(ACCOUNT, &heal(vec![op_3]), NOW)
            .await
            .unwrap();
        let (_, pages) = observe(&env).await;
        assert_eq!(pages[0].item_key_wraps.len(), 3);

        // E+2: above every epoch the rotator saw, so never a reuse of epoch 1.
        let mut second_keys = Keys::new(10, 2);
        let second = Half {
            grant: second_keys.grant(),
            cursor: cursor(&[(&a, 3), (&b, 1)]),
            wraps: vec![
                rewrap(&mut second_keys, 1),
                rewrap(&mut second_keys, 2),
                rewrap(&mut second_keys, 3),
            ],
            dropped: Vec::new(),
        };
        apply(&env, &second.upload(), 1, second_keys.account_key_id())
            .await
            .unwrap();
        let old = keys.wrap(&VaultKeyChoice::New, item(4));
        let op_4 = Record::Op(sign_op(
            &a,
            VAULT,
            &OpSpec {
                epoch: 1,
                wrap: Some(old),
                ..OpSpec::new(item(4), 4, 3)
            },
        ));
        env.domain
            .heal(ACCOUNT, &heal(vec![op_4]), NOW)
            .await
            .unwrap();
        let (grant, pages) = observe(&env).await;
        assert_eq!(grant, second.grant);
        for page in &pages {
            assert_eq!(page.item_key_wraps.as_slice(), second.wraps.as_slice());
            assert!(page.ops.iter().all(|op| op.key_wrap.is_none()));
        }
    });
}

/// ADR 0025 §1 and §5: a recovery rotation uses the heads the recovery
/// answer returned as its cursor; an op stored between `/recovery/complete` and the commit
/// makes the cursor stale, and the rotation is refused with `state_conflict`, nothing changed.
#[test]
fn a_recovery_cursor_behind_an_op_stored_since_is_refused() {
    block_on(async {
        let mut keys = Keys::new(11, 1);
        let (env, _, b) = populated(&mut keys).await;
        let mut tx = env.db.begin_read().await.unwrap();
        let vaults = recovery_vaults(tx.conn(), ACCOUNT).await.unwrap();
        tx.finish().await.unwrap();
        env.store(vec![Record::Op(sign_op(
            &b,
            VAULT,
            &OpSpec::new(item(2), 2, 1),
        ))])
        .await;
        let before = observe(&env).await;
        let half = Half {
            grant: keys.grant(),
            cursor: vaults[0].heads.clone(),
            wraps: vec![rewrap(&mut keys, 1), rewrap(&mut keys, 2)],
            dropped: Vec::new(),
        };
        let err = apply(&env, &half.upload(), 1, keys.account_key_id())
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::StateConflict);
        assert_eq!(observe(&env).await, before);
    });
}
