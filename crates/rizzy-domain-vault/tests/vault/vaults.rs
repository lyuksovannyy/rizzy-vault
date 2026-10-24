// SPDX-License-Identifier: AGPL-3.0-only

//! Several vaults per account (ADR 0081 Part A, §A3, §A5, §A9): an owned vault created with
//! its first self-grant up to `MAX_OWNED_VAULTS`, each refusal of a malformed grant or a taken
//! id, and a delete that cascades and releases exactly the vault's counted bytes while the
//! Personal vault and other accounts' vaults are refused (INV-101).

#![expect(
    clippy::unwrap_used,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code"
)]

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use rizzy_core::attachment::CHUNK_SIZE;
use rizzy_core::envelope::purpose::VaultKeySelfGrantCtx;
use rizzy_core::ids::{AttachmentId, VaultId};
use rizzy_core::keys::{AccountKey, VaultKey};
use rizzy_domain_vault::{
    NewAttachment, VaultError, VaultKind, create_owned_vault, create_vault, delete_vault, port,
};
use rizzy_proto::limits::MAX_OWNED_VAULTS;
use rizzy_proto::objects::{KeyEnvelope, VaultSelfGrant};
use rizzy_proto::wire::Id;
use rizzy_storage::lock_account;

use crate::common::{ACCOUNT, Env, NOW, OTHER_ACCOUNT, VAULT, block_on, item};

/// The account key of the held state, at epoch 0.
struct Keys {
    rng: ChaCha20Rng,
    account: AccountKey,
}

impl Keys {
    fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let account = AccountKey::generate(&mut rng, 0);
        Self { rng, account }
    }

    fn key_id(&self) -> [u8; 16] {
        *self.account.key_id().unwrap().as_bytes()
    }

    /// A real `VAULT_KEY_SELF_GRANT` of a fresh vault `vault` at `vault_epoch`, under the
    /// account key at `account_epoch` in the context.
    fn grant(&mut self, vault: VaultId, account_epoch: u32, vault_epoch: u32) -> VaultSelfGrant {
        let key = VaultKey::generate(&mut self.rng, vault, vault_epoch);
        let envelope = self
            .account
            .wrap_vault_key(
                &mut self.rng,
                &VaultKeySelfGrantCtx {
                    account_id: ACCOUNT,
                    vault_id: vault,
                    account_key_epoch: account_epoch,
                    vault_key_epoch: vault_epoch,
                },
                &key,
            )
            .unwrap();
        VaultSelfGrant {
            vault_id: Id::from_bytes(vault.to_bytes()),
            account_key_epoch: account_epoch,
            vault_key_epoch: vault_epoch,
            envelope: KeyEnvelope::new(envelope).unwrap(),
        }
    }
}

fn vault(n: u8) -> VaultId {
    VaultId::from_bytes([0xd0, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
}

/// `create_owned_vault` in its own transaction under the account lock, committed on success.
async fn create(env: &Env, keys: &Keys, grant: &VaultSelfGrant) -> Result<(), VaultError> {
    let mut tx = env.db.begin_write().await.unwrap();
    lock_account(&mut tx, ACCOUNT.as_bytes()).await.unwrap();
    let result = create_owned_vault(&mut tx, ACCOUNT, grant, 0, &keys.key_id(), NOW).await;
    if result.is_ok() {
        tx.commit().await.unwrap();
    }
    result
}

/// `delete_vault` in its own transaction under the account lock, committed on success.
async fn delete(
    env: &Env,
    account: rizzy_core::ids::AccountId,
    v: VaultId,
) -> Result<u64, VaultError> {
    let mut tx = env.db.begin_write().await.unwrap();
    lock_account(&mut tx, account.as_bytes()).await.unwrap();
    let result = delete_vault(&mut tx, account, v, NOW).await;
    if result.is_ok() {
        tx.commit().await.unwrap();
    }
    result
}

/// The account's vaults as the account answer lists them.
async fn summaries(env: &Env) -> Vec<(VaultId, u8, u64)> {
    let mut r = env.db.begin_read().await.unwrap();
    let out = port::vault_summaries(r.conn(), ACCOUNT).await.unwrap();
    r.finish().await.unwrap();
    out.iter()
        .map(|s| {
            (
                VaultId::from_bytes(s.vault_id.to_bytes()),
                s.kind,
                s.bytes_used,
            )
        })
        .collect()
}

#[test]
fn owned_vaults_are_created_up_to_the_cap() {
    block_on(async {
        let env = Env::new(1).await;
        let mut keys = Keys::new(1);
        // The Personal vault counts: 63 owned vaults fit, the 64th does not.
        for n in 1..u8::try_from(MAX_OWNED_VAULTS).unwrap() {
            let grant = keys.grant(vault(n), 0, 0);
            create(&env, &keys, &grant).await.unwrap();
        }
        let listed = summaries(&env).await;
        assert_eq!(listed.len(), MAX_OWNED_VAULTS);
        assert_eq!(
            listed.iter().filter(|(_, kind, _)| *kind == 1).count(),
            1,
            "one Personal vault"
        );
        assert!(listed.iter().any(|(v, kind, _)| *v == VAULT && *kind == 1));
        let over = keys.grant(vault(200), 0, 0);
        assert!(matches!(
            create(&env, &keys, &over).await,
            Err(VaultError::Invalid)
        ));
        // Deleting one makes room again.
        delete(&env, ACCOUNT, vault(1)).await.unwrap();
        create(&env, &keys, &over).await.unwrap();
    });
}

#[test]
fn a_create_is_refused_for_a_malformed_grant_or_a_taken_id() {
    block_on(async {
        let env = Env::new(2).await;
        let mut keys = Keys::new(2);
        let invalid = |r: Result<(), VaultError>| matches!(r, Err(VaultError::Invalid));
        // Not at vault epoch 0.
        let g = keys.grant(vault(1), 0, 1);
        assert!(invalid(create(&env, &keys, &g).await));
        // Not at the new state's account-key epoch.
        let mut g = keys.grant(vault(1), 0, 0);
        g.account_key_epoch = 1;
        assert!(invalid(create(&env, &keys, &g).await));
        // Under another account key.
        let mut other = Keys::new(99);
        let g = other.grant(vault(1), 0, 0);
        assert!(invalid(create(&env, &keys, &g).await));
        // Not an envelope at all.
        let mut g = keys.grant(vault(1), 0, 0);
        g.envelope = KeyEnvelope::new(vec![0x5a; 98]).unwrap();
        assert!(invalid(create(&env, &keys, &g).await));
        // A taken id: the account's own Personal vault, or another account's vault.
        let g = keys.grant(VAULT, 0, 0);
        assert!(matches!(
            create(&env, &keys, &g).await,
            Err(VaultError::StateConflict)
        ));
        let theirs = VaultId::from_bytes([0xb2; 16]);
        {
            let mut tx = env.db.begin_write().await.unwrap();
            lock_account(&mut tx, OTHER_ACCOUNT.as_bytes())
                .await
                .unwrap();
            let grant = VaultSelfGrant {
                vault_id: Id::from_bytes(theirs.to_bytes()),
                account_key_epoch: 0,
                vault_key_epoch: 0,
                envelope: KeyEnvelope::new(vec![0x5b; 98]).unwrap(),
            };
            create_vault(&mut tx, OTHER_ACCOUNT, &grant, VaultKind::Personal, NOW)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        let g = keys.grant(theirs, 0, 0);
        assert!(matches!(
            create(&env, &keys, &g).await,
            Err(VaultError::StateConflict)
        ));
        // Nothing of the refused ones was stored.
        assert_eq!(summaries(&env).await.len(), 1);
        // A second Personal vault is refused by the partial unique index itself.
        let mut tx = env.db.begin_write().await.unwrap();
        lock_account(&mut tx, ACCOUNT.as_bytes()).await.unwrap();
        let g = keys.grant(vault(2), 0, 0);
        assert!(matches!(
            create_vault(&mut tx, ACCOUNT, &g, VaultKind::Personal, NOW).await,
            Err(VaultError::Storage(_))
        ));
    });
}

#[test]
fn a_delete_cascades_and_releases_the_vaults_bytes() {
    block_on(async {
        let env = Env::new(3).await;
        let mut keys = Keys::new(3);
        let before = env.counted().await;
        let owned = vault(1);
        let grant = keys.grant(owned, 0, 0);
        create(&env, &keys, &grant).await.unwrap();
        // An attachment in each vault: the owned one's is released, the Personal one's stays.
        let size = CHUNK_SIZE as u64 + 10;
        for (n, v) in [(1u8, owned), (2, VAULT)] {
            let new = NewAttachment {
                attachment_id: AttachmentId::from_bytes([0xe0 | n; 16]),
                vault_id: v,
                item_id: item(1),
                attachment_key_wrap: vec![n; 122],
                total_plaintext_len: size,
            };
            env.domain
                .create_attachment(ACCOUNT, &new, NOW)
                .await
                .unwrap();
        }
        let per_attachment = 122 + size + 90 * size.div_ceil(CHUNK_SIZE as u64);
        let with_both = env.counted().await;
        assert_eq!(with_both, before + 2 * per_attachment);
        let listed = summaries(&env).await;
        assert!(listed.contains(&(owned, 2, per_attachment)), "{listed:?}");

        // The Personal vault, another account's vault and an unknown one are refused.
        assert!(matches!(
            delete(&env, ACCOUNT, VAULT).await,
            Err(VaultError::Invalid)
        ));
        assert!(matches!(
            delete(&env, OTHER_ACCOUNT, owned).await,
            Err(VaultError::NotFound)
        ));
        assert!(matches!(
            delete(&env, ACCOUNT, vault(9)).await,
            Err(VaultError::NotFound)
        ));

        assert_eq!(delete(&env, ACCOUNT, owned).await.unwrap(), per_attachment);
        // The counter still equals the true sum of the rows, the owned vault's bytes gone.
        assert_eq!(env.counted().await, before + per_attachment);
        assert_eq!(summaries(&env).await.len(), 1);
        // The attachment went with the vault.
        assert!(
            env.domain
                .attachment_key_wrap(ACCOUNT, AttachmentId::from_bytes([0xe1; 16]))
                .await
                .is_err()
        );
        // A second delete finds nothing.
        assert!(matches!(
            delete(&env, ACCOUNT, owned).await,
            Err(VaultError::NotFound)
        ));
    });
}
