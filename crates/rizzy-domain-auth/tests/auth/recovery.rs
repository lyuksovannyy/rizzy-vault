// SPDX-License-Identifier: AGPL-3.0-only

//! Recovery with the Emergency Kit (CRYPTO.md §11.9; ADR 0008): the waiting period,
//! cancellation by an enrolled device, the release, and the recovery commit.

use rizzy_core::envelope::purpose::{AccountKeyRecoveryWrapCtx, AccountKeyServerWrapCtx};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{RecoveryAuthToken, RecoveryWrapKey};
use rizzy_core::opaque::{PasswordInput, client_registration_finish, client_registration_start};
use rizzy_core::secret::SecretArray;
use rizzy_core::secret_key::SecretKey;
use rizzy_core::sign::{AccountState, PublicKeyBundle};
use rizzy_domain_auth::Session;
use rizzy_domain_auth::{AccountChange, AuthError, RecoveryUpload};
use rizzy_proto::account::{AccountStateQuery, PendingRecoveryNotice};
use rizzy_proto::auth::RecoveryRegistration;
use rizzy_proto::objects::AccountKeyServerWrap;
use rizzy_proto::wire::{Fixed, List};

use crate::common::{Env, block_on, bytes, recovery_wrap};

/// 72 h in ms.
const WAIT: u64 = 72 * 3_600_000;

#[test]
fn recovery_wait_cancel_release_and_commit() {
    block_on(async {
        let mut env = Env::new(40).await;
        let mut client = env.signup("ivy", "forgotten").await;
        let token = client.recovery_token();
        let source = env.source.clone();

        // Start: a pending recovery with the 72 h wait; a repeat returns the same one.
        let pending = env
            .svc
            .recovery_start("ivy", &token, &source, env.now)
            .await
            .unwrap();
        assert!(pending.opened);
        assert_eq!(pending.available_at_ms, env.now + WAIT);
        let again = env
            .svc
            .recovery_start("ivy", &token, &source, env.now)
            .await
            .unwrap();
        assert!(!again.opened);
        assert_eq!(again.available_at_ms, pending.available_at_ms);
        // Too early.
        let early = env
            .svc
            .recovery_complete(&mut env.rng, "ivy", &token, &source, env.now)
            .await;
        assert!(matches!(early, Err(AuthError::RecoveryWaiting { .. })));

        // An enrolled device cancels it; completing then fails even after the wait.
        let device = &client.devices[0];
        let mut ds = env.device_auth(&client, device).await.unwrap();
        let session = env.signed(&client, device, &mut ds, b"").await.unwrap();
        assert!(env.svc.recovery_cancel(&session, env.now).await.unwrap());
        env.tick(WAIT);
        let cancelled = env
            .svc
            .recovery_complete(&mut env.rng, "ivy", &token, &source, env.now)
            .await;
        assert!(matches!(cancelled, Err(AuthError::Unauthorized)));

        // Start again, wait, complete: E_rec opens with the code and matches the signed state.
        env.svc
            .recovery_start("ivy", &token, &source, env.now)
            .await
            .unwrap();
        env.tick(WAIT - 1);
        assert!(matches!(
            env.svc
                .recovery_complete(&mut env.rng, "ivy", &token, &source, env.now)
                .await,
            Err(AuthError::RecoveryWaiting { .. })
        ));
        env.tick(1);
        let release = env
            .svc
            .recovery_complete(&mut env.rng, "ivy", &token, &source, env.now)
            .await
            .unwrap();
        let wrap = &release.recovery_wrap;
        let key = RecoveryWrapKey::derive(&client.recovery_code)
            .unwrap()
            .unwrap_account_key(
                &AccountKeyRecoveryWrapCtx {
                    account_id: client.account_id,
                    account_key_epoch: wrap.account_key_epoch,
                    recovery_epoch: wrap.recovery_epoch,
                },
                wrap.envelope.as_slice(),
            )
            .unwrap();
        let bundle =
            PublicKeyBundle::verify_self_signed(release.account.bundles.as_slice()[0].as_slice())
                .unwrap();
        let state = AccountState::verify(
            release.account.account_state.as_slice(),
            &bundle.identity_ed25519,
            0,
        )
        .unwrap();
        assert!(state.matches_account_key(&key));
        // It may be repeated until the commit.
        env.svc
            .recovery_complete(&mut env.rng, "ivy", &token, &source, env.now)
            .await
            .unwrap();
        let recovery_session = env.bearer(&release.session_token).await;

        // A recovery session commits nothing but a recovery.
        let bare = AccountChange::<Vec<rizzy_proto::objects::VaultSelfGrant>> {
            account_state: bytes(client.next_state(|_| {}).1),
            bundle: None,
            registration_upload: None,
            setup_id: None,
            account_key_server_wrap: None,
            identity_secret_keys: None,
            recovery: RecoveryUpload::None,
            account_settings: None,
            retired_secret_keys: rizzy_proto::wire::List::empty(),
            device_certificates: List::empty(),
            device_revocations: List::empty(),
            device_grants: List::empty(),
            vault_rotation: None,
            vault_create: None,
            vault_delete: None,
        };
        assert!(matches!(
            env.svc
                .commit_change(&recovery_session, &bare, env.now)
                .await,
            Err(AuthError::FreshSessionRequired)
        ));

        // The recovery commit, skipping the rotation: a new password, a new Secret Key and a
        // new recovery code, under the credential-replacement rule.
        let new_sk = SecretKey::generate(&mut env.rng);
        let pw_in = PasswordInput::derive_for_new_password("remembered", &new_sk).unwrap();
        let (reg_state, m1) = client_registration_start(&mut env.rng, &pw_in).unwrap();
        let (setup_id, m2) = env
            .svc
            .reregister_start(&recovery_session, &bytes(m1), env.now)
            .await
            .unwrap();
        let reg = client_registration_finish(
            &mut env.rng,
            reg_state,
            &pw_in,
            m2.as_slice(),
            KdfId::DEFAULT,
        )
        .unwrap();
        client.account_key = key;
        client.recovery_code = SecretArray::<16>::generate(&mut env.rng);
        let e_srv = reg
            .export_key
            .server_unlock_key(client.account_id)
            .unwrap()
            .wrap_account_key(
                &mut env.rng,
                &AccountKeyServerWrapCtx {
                    account_id: client.account_id,
                    account_key_epoch: 0,
                    password_epoch: 1,
                    kdf_id: KdfId::DEFAULT,
                },
                &client.account_key,
            )
            .unwrap();
        let e_rec = recovery_wrap(&mut env.rng, &client, 2);
        let next = client.next_state(|s| {
            s.password_epoch = 1;
            s.recovery_epoch = 2;
        });
        let change = AccountChange::<Vec<rizzy_proto::objects::VaultSelfGrant>> {
            account_state: bytes(next.1.clone()),
            registration_upload: Some(bytes(reg.upload)),
            setup_id: Some(setup_id),
            account_key_server_wrap: Some(AccountKeyServerWrap {
                account_key_epoch: 0,
                password_epoch: 1,
                kdf_id: 1,
                envelope: bytes(e_srv),
            }),
            recovery: RecoveryUpload::Register(RecoveryRegistration {
                recovery_wrap: e_rec,
                recovery_token_hash: Fixed::from_bytes(
                    RecoveryAuthToken::derive(&client.recovery_code)
                        .unwrap()
                        .server_hash(),
                ),
            }),
            ..bare
        };
        env.svc
            .commit_change(&recovery_session, &change, env.now)
            .await
            .unwrap();
        client.adopt(next);
        client.secret_key = new_sk;
        client.password = "remembered".to_owned();

        // Every session ended; the old code and the old password are refused; the new ones work.
        assert!(
            env.signed(&client, &client.devices[0], &mut ds, b"")
                .await
                .is_err()
        );
        assert!(matches!(
            env.svc
                .recovery_start("ivy", &token, &source, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        let new_token = client.recovery_token();
        let committed_at = env.now;
        env.tick(1_000);
        env.svc
            .recovery_start("ivy", &new_token, &source, env.now)
            .await
            .unwrap();
        env.login(&client).await;

        // ADR 0045 point 6: the next pending recovery's notice carries when this one committed.
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let session = env
            .signed(&client, &client.devices[0], &mut ds, b"")
            .await
            .unwrap();
        let notice = notice_of(&env, &session).await.unwrap();
        assert_eq!(notice.opened_at_ms, env.now);
        assert_eq!(notice.available_at_ms, env.now + WAIT);
        assert_eq!(notice.last_recovery_at_ms, Some(committed_at));
    });
}

/// The `pending_recovery` notice an `account/state` answer carries for `session` (ADR 0045).
async fn notice_of(env: &Env, session: &Session) -> Option<PendingRecoveryNotice> {
    env.svc
        .account_view(
            session,
            AccountStateQuery {
                known_bundle_seq: 0,
                known_settings_seq: 0,
            },
            env.now,
        )
        .await
        .unwrap()
        .pending_recovery
}

/// ADR 0045 points 3 and 4: the notice is the stored pending row, shown only to a device session
/// of a usable durable device (the sessions that can cancel), never to an OPAQUE login, an
/// OPAQUE session or the recovery-only session, and it clears exactly when the row does.
#[test]
fn pending_recovery_notice_reaches_only_a_cancelling_device() {
    block_on(async {
        let mut env = Env::new(42).await;
        let client = env.signup("kim", "forgotten").await;
        let token = client.recovery_token();
        let source = env.source.clone();
        let device = &client.devices[0];
        let mut ds = env.device_auth(&client, device).await.unwrap();
        let device_session = env.signed(&client, device, &mut ds, b"").await.unwrap();

        // Nothing pending: no notice.
        assert_eq!(notice_of(&env, &device_session).await, None);

        let opened_at = env.now;
        env.svc
            .recovery_start("kim", &token, &source, env.now)
            .await
            .unwrap();
        env.tick(5_000);
        let expected = PendingRecoveryNotice {
            opened_at_ms: opened_at,
            available_at_ms: opened_at + WAIT,
            last_recovery_at_ms: None,
        };
        assert_eq!(notice_of(&env, &device_session).await, Some(expected));

        // An OPAQUE login and its session: never, even as a re-authentication bound to the
        // device (point 4).
        let login = env.login(&client).await;
        assert_eq!(login.response.account.pending_recovery, None);
        let opaque = env.bearer(&login.response.session_token).await;
        assert_eq!(notice_of(&env, &opaque).await, None);
        let reauth = env
            .login_as(
                "kim",
                "forgotten",
                &client.secret_key,
                None,
                Some(&device_session),
            )
            .await
            .unwrap();
        assert_eq!(reauth.response.account.pending_recovery, None);
        let bound = env.bearer(&reauth.response.session_token).await;
        assert_eq!(notice_of(&env, &bound).await, None);

        // The recovery-only session, after the wait: never; its release neither.
        env.tick(WAIT);
        let release = env
            .svc
            .recovery_complete(&mut env.rng, "kim", &token, &source, env.now)
            .await
            .unwrap();
        assert_eq!(release.account.pending_recovery, None);
        let recovery_session = env.bearer(&release.session_token).await;
        assert_eq!(notice_of(&env, &recovery_session).await, None);
        // The device still sees it, past its availability, from a new device session.
        let mut ds = env.device_auth(&client, device).await.unwrap();
        let device_session = env.signed(&client, device, &mut ds, b"").await.unwrap();
        assert_eq!(notice_of(&env, &device_session).await, Some(expected));

        // Cancelled: the row is gone, and so is the notice.
        assert!(
            env.svc
                .recovery_cancel(&device_session, env.now)
                .await
                .unwrap()
        );
        assert_eq!(notice_of(&env, &device_session).await, None);
    });
}

/// The waiting period may be 0 (single-user instances) and at most 30 days.
#[test]
fn recovery_wait_bounds() {
    block_on(async {
        let mut env = Env::with_config(41, |c| c.recovery_wait_ms = 0).await;
        let client = env.signup("jon", "pw").await;
        let token = client.recovery_token();
        let source = env.source.clone();
        env.svc
            .recovery_start("jon", &token, &source, env.now)
            .await
            .unwrap();
        env.svc
            .recovery_complete(&mut env.rng, "jon", &token, &source, env.now)
            .await
            .unwrap();
        let mut config = rizzy_domain_auth::AuthConfig::new(crate::common::origin());
        config.recovery_wait_ms = 30 * 24 * 3_600_000 + 1;
        assert!(config.validate().is_err());
    });
}
