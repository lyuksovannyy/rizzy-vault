// SPDX-License-Identifier: AGPL-3.0-only

//! The account side of several vaults per account (ADR 0081 Part A, §A3, §A5, §A11, §D): a
//! `vault_create` or `vault_delete` rides only on `settings_seq + 1`, at most one per commit;
//! a delete needs a fresh OPAQUE session; creation counts against the per-account bucket; the
//! account answer lists the vaults. The vault domain's own checks run against the in-memory
//! [`crate::common::TestVault`] here and against the database in `rizzy-domain-vault`'s
//! `tests/vault/vaults.rs`.

use rizzy_core::keys::settings_hash;
use rizzy_domain_auth::config::FRESH_SESSION_MS;
use rizzy_domain_auth::{AuthError, Session};
use rizzy_proto::account::AccountStateQuery;
use rizzy_proto::change::CommitChangeRequest;
use rizzy_proto::objects::{AccountSettings, VaultSelfGrant};
use rizzy_proto::wire::{Id, List};

use crate::common::{Client, Env, block_on, bytes};

/// A commit of `state` alone.
fn bare(state: Vec<u8>) -> CommitChangeRequest {
    CommitChangeRequest {
        account_state: bytes(state),
        registration_upload: None,
        setup_id: None,
        account_key_server_wrap: None,
        recovery: None,
        account_settings: None,
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        bundle: None,
        identity_secret_keys: None,
        retired_secret_keys: List::empty(),
        device_grants: List::empty(),
        recovery_rewrap: None,
        vault_rotation: None,
        vault_create: None,
        vault_delete: None,
    }
}

/// A self-grant of vault `[n; 16]` at vault epoch 0 under `client`'s account-key epoch (the
/// in-memory vault port does not open it).
fn grant(client: &Client, n: u8) -> VaultSelfGrant {
    VaultSelfGrant {
        vault_id: Id::from_bytes([n; 16]),
        account_key_epoch: client.state.account_key_epoch,
        vault_key_epoch: 0,
        envelope: bytes(vec![n; 98]),
    }
}

/// The next state with `settings_seq + 1` committing to `envelope`, and the commit carrying
/// those settings; `edit` adds the vault change.
fn settings_commit(
    client: &Client,
    envelope: &[u8],
    edit: impl FnOnce(&mut CommitChangeRequest),
) -> (
    (rizzy_core::sign::AccountState, Vec<u8>),
    CommitChangeRequest,
) {
    let seq = client.state.settings_seq + 1;
    let hash = settings_hash(seq, Some(envelope)).unwrap();
    let next = client.next_state(|s| {
        s.settings_seq = seq;
        s.settings_hash = hash;
    });
    let mut commit = CommitChangeRequest {
        account_settings: Some(AccountSettings {
            settings_seq: seq,
            envelope: bytes(envelope.to_vec()),
        }),
        ..bare(next.1.clone())
    };
    edit(&mut commit);
    (next, commit)
}

/// The account answer's vaults, as `(id byte, kind)`.
async fn vaults(env: &Env, session: &Session) -> Vec<([u8; 16], u8)> {
    let view = env
        .svc
        .account_view(
            session,
            AccountStateQuery {
                known_bundle_seq: 1,
                known_settings_seq: 0,
            },
            env.now,
        )
        .await
        .unwrap();
    view.vaults
        .as_slice()
        .iter()
        .map(|v| (v.vault_id.to_bytes(), v.kind))
        .collect()
}

#[test]
fn a_vault_create_rides_only_on_a_settings_commit() {
    block_on(async {
        let mut env = Env::new(81).await;
        let mut client = env.signup("vera", "pw").await;
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let session = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        let before = vaults(&env, &session).await;
        assert_eq!(before.len(), 1, "signup's Personal vault");
        assert_eq!(before[0].1, 1);

        // Without settings moving: refused.
        let plain = client.next_state(|_| {});
        let alone = CommitChangeRequest {
            vault_create: Some(grant(&client, 0x31)),
            ..bare(plain.1)
        };
        assert!(matches!(
            env.svc
                .commit_change_request(&session, alone, env.now)
                .await,
            Err(AuthError::InvalidRequest)
        ));
        // Both vault changes in one commit: refused.
        let (_, both) = settings_commit(&client, b"dir-1", |c| {
            c.vault_create = Some(grant(&client, 0x31));
            c.vault_delete = Some(Id::from_bytes(before[0].0));
        });
        assert!(matches!(
            env.svc.commit_change_request(&session, both, env.now).await,
            Err(AuthError::InvalidRequest)
        ));
        // With the settings, over a device session: created.
        let (next, commit) = settings_commit(&client, b"dir-1", |c| {
            c.vault_create = Some(grant(&client, 0x31));
        });
        env.svc
            .commit_change_request(&session, commit.clone(), env.now)
            .await
            .unwrap();
        client.adopt(next);
        let after = vaults(&env, &session).await;
        assert_eq!(after.len(), 2);
        assert!(after.contains(&([0x31; 16], 2)));
        // A byte-identical repeat of the committed state is success, and creates nothing more.
        env.svc
            .commit_change_request(&session, commit, env.now)
            .await
            .unwrap();
        assert_eq!(vaults(&env, &session).await.len(), 2);
        // A taken id is the vault domain's `state_conflict`, and nothing is committed.
        let (_, taken) = settings_commit(&client, b"dir-2", |c| {
            c.vault_create = Some(grant(&client, 0x31));
        });
        assert!(matches!(
            env.svc
                .commit_change_request(&session, taken, env.now)
                .await,
            Err(AuthError::StateConflict)
        ));
    });
}

#[test]
fn a_vault_delete_needs_a_fresh_opaque_session() {
    block_on(async {
        let mut env = Env::new(82).await;
        let mut client = env.signup("wim", "pw").await;
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let device = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        let personal = vaults(&env, &device).await[0].0;
        let (next, commit) = settings_commit(&client, b"dir-1", |c| {
            c.vault_create = Some(grant(&client, 0x41));
        });
        env.svc
            .commit_change_request(&device, commit, env.now)
            .await
            .unwrap();
        client.adopt(next);

        let delete = |client: &Client, id: [u8; 16]| {
            settings_commit(client, b"dir-2", |c| {
                c.vault_delete = Some(Id::from_bytes(id));
            })
        };
        // A device session is not enough, nor a stale OPAQUE session.
        let (_, commit) = delete(&client, [0x41; 16]);
        assert!(matches!(
            env.svc
                .commit_change_request(&device, commit.clone(), env.now)
                .await,
            Err(AuthError::FreshSessionRequired)
        ));
        let stale = env.login(&client).await;
        let stale = env.bearer(&stale.response.session_token).await;
        env.tick(FRESH_SESSION_MS + 1);
        assert!(matches!(
            env.svc.commit_change_request(&stale, commit, env.now).await,
            Err(AuthError::FreshSessionRequired)
        ));
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;
        // The Personal vault is refused (INV-101), an unknown one is not found.
        let (_, commit) = delete(&client, personal);
        assert!(matches!(
            env.svc.commit_change_request(&fresh, commit, env.now).await,
            Err(AuthError::InvalidRequest)
        ));
        let (_, commit) = delete(&client, [0x42; 16]);
        assert!(matches!(
            env.svc.commit_change_request(&fresh, commit, env.now).await,
            Err(AuthError::NotFound)
        ));
        // The owned vault goes.
        let (next, commit) = delete(&client, [0x41; 16]);
        env.svc
            .commit_change_request(&fresh, commit, env.now)
            .await
            .unwrap();
        client.adopt(next);
        assert_eq!(vaults(&env, &fresh).await, vec![(personal, 1)]);
    });
}

#[test]
fn vault_creation_is_rate_limited_per_account() {
    block_on(async {
        let mut env = Env::with_config(83, |c| {
            c.rate_limits.vault_create_per_account.max_attempts = 2;
        })
        .await;
        let mut client = env.signup("xan", "pw").await;
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let session = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        for n in [0x51u8, 0x52] {
            let (next, commit) = settings_commit(&client, &[n], |c| {
                c.vault_create = Some(grant(&client, n));
            });
            env.svc
                .commit_change_request(&session, commit, env.now)
                .await
                .unwrap();
            client.adopt(next);
        }
        let (_, third) = settings_commit(&client, &[0x53], |c| {
            c.vault_create = Some(grant(&client, 0x53));
        });
        match env
            .svc
            .commit_change_request(&session, third.clone(), env.now)
            .await
        {
            Err(AuthError::RateLimited {
                retry_after_ms: Some(ms),
            }) => assert!(ms > 0 && ms <= 24 * 60 * 60_000),
            other => panic!("{other:?}"),
        }
        // A settings change without a vault does not count.
        let (next, plain) = settings_commit(&client, b"plain", |_| {});
        env.svc
            .commit_change_request(&session, plain, env.now)
            .await
            .unwrap();
        client.adopt(next);
        // After the window the bucket counts again.
        env.tick(24 * 60 * 60_000);
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let session = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        let (_, fourth) = settings_commit(&client, &[0x53], |c| {
            c.vault_create = Some(grant(&client, 0x53));
        });
        env.svc
            .commit_change_request(&session, fourth, env.now)
            .await
            .unwrap();
    });
}
