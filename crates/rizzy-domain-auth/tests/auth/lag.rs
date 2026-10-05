//! The lag rule and the credentials that need the user (ADR 0032 §3–§4), against real SQLite:
//! the rows a restore would leave behind the signed state are made by hand here (a column set,
//! an envelope replaced), and the full restore drills run in `rizzy-cli`'s end-to-end tests.
//!
//! - a lagging OPAQUE record answers `credentials_stale` only after KE3 verified, sets
//!   `reregister` on device authentication, and the same-password re-registration over the
//!   device session clears it;
//! - rows migration 0005 found without an `account_key_epoch` fail closed until the startup
//!   fill;
//! - a lagging recovery row refuses `recovery/start` until the repair, whose re-typed form needs
//!   the stored code at the state's `recovery_epoch` and a fresh OPAQUE session, and whose
//!   new-code form is the only one after the code changed;
//! - `E_id` and `ACCOUNT_SETTINGS` in healing step 2: repaired only while lagging, only over a
//!   device session of the held device set, only with a valid replacement; the first valid
//!   repair wins, a junk envelope under the copied `key_id` included.

use rizzy_core::envelope::purpose::AccountKeyRecoveryWrapCtx;
use rizzy_core::keys::{RecoveryAuthToken, RecoveryWrapKey};
use rizzy_core::secret::SecretArray;
use rizzy_domain_auth::{AccountChange, AuthError, RecoveryUpload, Session};
use rizzy_proto::account::PublishAccountStateRequest;
use rizzy_proto::auth::RecoveryRegistration;
use rizzy_proto::objects::{
    AccountKeyRecoveryWrap, AccountSettings, IdentitySecretKeys, VaultSelfGrant,
};
use rizzy_proto::wire::{Fixed, List};
use rizzy_storage::Conn;

use crate::common::{Client, Env, block_on, bytes, recovery_wrap};
use crate::restore::reregister;

/// Runs one statement with the account id as `$1` and `value` as `$2`.
async fn set(env: &Env, sql: &'static str, client: &Client, value: Option<i64>) {
    let mut tx = env.db.begin_write().await.unwrap();
    {
        let Conn::Sqlite(c) = tx.conn() else {
            panic!("the tests run on SQLite")
        };
        sqlx::query(sql)
            .bind(&client.account_id.as_bytes()[..])
            .bind(value)
            .execute(&mut *c)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
}

/// Reads one column of the account's row: `sql` selects one value with `$1` the account id.
async fn get_i64(env: &Env, sql: &'static str, client: &Client) -> Option<i64> {
    let mut tx = env.db.begin_write().await.unwrap();
    let value = {
        let Conn::Sqlite(c) = tx.conn() else {
            panic!("the tests run on SQLite")
        };
        sqlx::query_scalar::<_, Option<i64>>(sql)
            .bind(&client.account_id.as_bytes()[..])
            .fetch_one(&mut *c)
            .await
            .unwrap()
    };
    tx.commit().await.unwrap();
    value
}

/// The stored `E_id`.
async fn stored_e_id(env: &Env, client: &Client) -> Vec<u8> {
    let mut tx = env.db.begin_write().await.unwrap();
    let e_id = {
        let Conn::Sqlite(c) = tx.conn() else {
            panic!("the tests run on SQLite")
        };
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT e_id FROM auth_identity_keys WHERE account_id = $1",
        )
        .bind(&client.account_id.as_bytes()[..])
        .fetch_one(&mut *c)
        .await
        .unwrap()
    };
    tx.commit().await.unwrap();
    e_id
}

/// Replaces the stored `E_id`.
async fn put_e_id(env: &Env, client: &Client, e_id: &[u8]) {
    let mut tx = env.db.begin_write().await.unwrap();
    {
        let Conn::Sqlite(c) = tx.conn() else {
            panic!("the tests run on SQLite")
        };
        sqlx::query("UPDATE auth_identity_keys SET e_id = $2 WHERE account_id = $1")
            .bind(&client.account_id.as_bytes()[..])
            .bind(e_id)
            .execute(&mut *c)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
}

/// A change of `client` with only `state` and `recovery`.
fn change(state: &[u8], recovery: RecoveryUpload) -> AccountChange<Vec<VaultSelfGrant>> {
    AccountChange {
        account_state: bytes(state.to_vec()),
        bundle: None,
        registration_upload: None,
        setup_id: None,
        account_key_server_wrap: None,
        identity_secret_keys: None,
        recovery,
        account_settings: None,
        retired_secret_keys: List::empty(),
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        device_grants: List::empty(),
        vault_rotation: None,
    }
}

/// `H_rec` and `E_rec` of `client`'s recovery code at `recovery_epoch`.
fn registration(env: &mut Env, client: &Client, recovery_epoch: u32) -> RecoveryUpload {
    RecoveryUpload::Register(RecoveryRegistration {
        recovery_wrap: recovery_wrap(&mut env.rng, client, recovery_epoch),
        recovery_token_hash: Fixed::from_bytes(
            RecoveryAuthToken::derive(&client.recovery_code)
                .unwrap()
                .server_hash(),
        ),
    })
}

/// `H_rec` and `E_rec` of another recovery code `code` at `recovery_epoch`, under `client`'s
/// account key.
fn registration_of(
    env: &mut Env,
    client: &Client,
    code: &SecretArray<16>,
    recovery_epoch: u32,
) -> RecoveryUpload {
    let envelope = RecoveryWrapKey::derive(code)
        .unwrap()
        .wrap_account_key(
            &mut env.rng,
            &AccountKeyRecoveryWrapCtx {
                account_id: client.account_id,
                account_key_epoch: client.account_key.epoch(),
                recovery_epoch,
            },
            &client.account_key,
        )
        .unwrap();
    RecoveryUpload::Register(RecoveryRegistration {
        recovery_wrap: AccountKeyRecoveryWrap {
            account_key_epoch: client.account_key.epoch(),
            recovery_epoch,
            envelope: bytes(envelope),
        },
        recovery_token_hash: Fixed::from_bytes(
            RecoveryAuthToken::derive(code).unwrap().server_hash(),
        ),
    })
}

/// A fresh OPAQUE session of `client`.
async fn fresh(env: &mut Env, client: &Client) -> Session {
    let login = env.login(client).await;
    env.bearer(&login.response.session_token).await
}

/// The device session of `client`'s first device, with the `reregister` flag it answered.
async fn device_session(env: &mut Env, client: &Client) -> (Session, bool) {
    let device = &client.devices[0];
    let mut ds = env.device_auth(client, device).await.unwrap();
    let flag = ds.reregister;
    (
        env.signed(client, device, &mut ds, b"").await.unwrap(),
        flag,
    )
}

/// Step 2 as a healer sends it outside the epoch: the held state byte for byte, the device set,
/// and `e_id` and `settings`.
fn step_2(
    client: &Client,
    e_id: Option<Vec<u8>>,
    settings: Option<AccountSettings>,
) -> PublishAccountStateRequest {
    PublishAccountStateRequest {
        account_state: bytes(client.state_wire.clone()),
        device_certificates: List::new(
            client
                .devices
                .iter()
                .map(|d| bytes(d.cert_wire.clone()))
                .collect(),
        )
        .unwrap(),
        device_revocations: List::empty(),
        identity_secret_keys: e_id.map(|envelope| IdentitySecretKeys {
            identity_epoch: client.state.identity_epoch,
            envelope: bytes(envelope),
        }),
        account_settings: settings,
    }
}

/// The record lags (here: its `account_key_epoch` is not the state's): a wrong password gets
/// the one answer of §5.9, the right one `credentials_stale`; the device authentication asks for
/// the re-registration, and the same-password one over the device session ends the lag.
#[test]
fn a_lagging_record_is_stale_only_after_ke3_until_it_is_re_registered() {
    block_on(async {
        let mut env = Env::new(81).await;
        let mut client = env.signup("lag", "the password").await;
        let (_, flag) = device_session(&mut env, &client).await;
        assert!(!flag);
        set(
            &env,
            "UPDATE auth_credentials SET account_key_epoch = $2 WHERE account_id = $1",
            &client,
            Some(5),
        )
        .await;
        assert!(matches!(
            env.login_as("lag", "not the password", &client.secret_key, None, None)
                .await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            env.login_as("lag", "the password", &client.secret_key, None, None)
                .await,
            Err(AuthError::CredentialsStale)
        ));
        let (session, flag) = device_session(&mut env, &client).await;
        assert!(flag, "reregister while the record lags");
        reregister(&mut env, &mut client, &session, "the password", false)
            .await
            .unwrap();
        assert_eq!(
            get_i64(
                &env,
                "SELECT account_key_epoch FROM auth_credentials WHERE account_id = $1",
                &client
            )
            .await,
            Some(0)
        );
        env.login(&client).await;
        let (_, flag) = device_session(&mut env, &client).await;
        assert!(!flag);
    });
}

/// Rows without an `account_key_epoch` (what migration 0005 leaves) lag until the startup fill
/// writes the current state's into them; the fill is idempotent.
#[test]
fn missing_epochs_fail_closed_until_the_startup_fill() {
    block_on(async {
        let mut env = Env::new(82).await;
        let client = env.signup("fill", "the password").await;
        for sql in [
            "UPDATE auth_credentials SET account_key_epoch = $2 WHERE account_id = $1",
            "UPDATE auth_recovery SET account_key_epoch = $2 WHERE account_id = $1",
        ] {
            set(&env, sql, &client, None).await;
        }
        assert!(matches!(
            env.login_as("fill", "the password", &client.secret_key, None, None)
                .await,
            Err(AuthError::CredentialsStale)
        ));
        let source = env.source.clone();
        assert!(matches!(
            env.svc
                .recovery_start("fill", &client.recovery_token(), &source, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        assert_eq!(env.svc.fill_credential_epochs().await.unwrap(), 1);
        assert_eq!(env.svc.fill_credential_epochs().await.unwrap(), 0);
        env.login(&client).await;
        env.svc
            .recovery_start("fill", &client.recovery_token(), &source, env.now)
            .await
            .unwrap();
    });
}

/// A lagging recovery row (ADR 0032 §4 step 6): refused like a wrong code until the user repairs
/// it. The re-typed form needs a fresh OPAQUE session, a row that lags, the state's
/// `recovery_epoch` on the row and the stored code; after the code changed (a lower
/// `recovery_epoch` on the row) only the new-code form repairs, and the older code stays refused.
#[test]
fn a_lagging_recovery_row_waits_for_the_users_repair() {
    block_on(async {
        let mut env = Env::new(83).await;
        let mut client = env.signup("rec", "the password").await;
        let source = env.source.clone();
        let token = client.recovery_token();
        let state = client.state.clone();

        // Not lagging: a re-type is nothing to repair.
        let session = fresh(&mut env, &client).await;
        let retype = change(
            &client.next_state(|_| {}).1,
            registration(&mut env, &client, 1),
        );
        assert!(matches!(
            env.svc.commit_change(&session, &retype, env.now).await,
            Err(AuthError::InvalidRequest)
        ));

        set(
            &env,
            "UPDATE auth_recovery SET account_key_epoch = $2 WHERE account_id = $1",
            &client,
            Some(7),
        )
        .await;
        assert!(matches!(
            env.svc
                .recovery_start("rec", &token, &source, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        // Over a device session: a credential change needs a fresh OPAQUE session.
        let (device, _) = device_session(&mut env, &client).await;
        assert!(matches!(
            env.svc.commit_change(&device, &retype, env.now).await,
            Err(AuthError::FreshSessionRequired)
        ));
        // Another code is refused; the stored one repairs.
        let stranger = SecretArray::<16>::generate(&mut env.rng);
        let wrong = change(
            &client.next_state(|_| {}).1,
            registration_of(&mut env, &client, &stranger, 1),
        );
        assert!(matches!(
            env.svc.commit_change(&session, &wrong, env.now).await,
            Err(AuthError::InvalidRequest)
        ));
        let next = client.next_state(|_| {});
        let repair = change(&next.1, registration(&mut env, &client, 1));
        env.svc
            .commit_change(&session, &repair, env.now)
            .await
            .unwrap();
        client.adopt(next);
        env.svc
            .recovery_start("rec", &token, &source, env.now)
            .await
            .unwrap();

        // The row names an older code (a lower `recovery_epoch`): no re-type, only a new code.
        set(
            &env,
            "UPDATE auth_recovery SET recovery_epoch = $2 WHERE account_id = $1",
            &client,
            Some(0),
        )
        .await;
        assert!(matches!(
            env.svc
                .recovery_start("rec", &token, &source, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        let session = fresh(&mut env, &client).await;
        let retype = change(
            &client.next_state(|_| {}).1,
            registration(&mut env, &client, 1),
        );
        assert!(matches!(
            env.svc.commit_change(&session, &retype, env.now).await,
            Err(AuthError::InvalidRequest)
        ));
        let old_token = token;
        client.recovery_code = SecretArray::<16>::generate(&mut env.rng);
        let next = client.next_state(|s| s.recovery_epoch = 2);
        let new_code = change(&next.1, registration(&mut env, &client, 2));
        env.svc
            .commit_change(&session, &new_code, env.now)
            .await
            .unwrap();
        client.adopt(next);
        assert!(matches!(
            env.svc
                .recovery_start("rec", &old_token, &source, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        env.svc
            .recovery_start("rec", &client.recovery_token(), &source, env.now)
            .await
            .unwrap();
        assert_eq!(
            get_i64(
                &env,
                "SELECT account_key_epoch FROM auth_recovery WHERE account_id = $1",
                &client
            )
            .await,
            Some(i64::from(state.account_key_epoch))
        );
    });
}

/// `E_id` and `ACCOUNT_SETTINGS` in healing step 2 (ADR 0032 §3), outside the reconciliation
/// epoch with the held state re-sent byte for byte: a lagging `E_id` (its header `key_id` not
/// the state's `account_key_id`) is repaired only over a device session and only with an
/// envelope under that `key_id`; once it no longer lags a valid repeat stores nothing, so the
/// first valid repair wins, a junk one under the copied `key_id` included (the clients reject
/// it, CRYPTO.md §11.2 step 6). Settings that do not hash to the state's `settings_hash` are
/// refused.
#[test]
fn e_id_and_settings_follow_the_lag_rule() {
    block_on(async {
        let mut env = Env::new(84).await;
        let client = env.signup("eid", "the password").await;
        let genuine = stored_e_id(&env, &client).await;
        let mut other_key = genuine.clone();
        for b in &mut other_key[2..18] {
            *b ^= 0xff;
        }
        let mut junk = genuine.clone();
        let last = junk.len() - 1;
        junk[last] ^= 0x01;

        put_e_id(&env, &client, &other_key).await;
        // An OPAQUE session may not repair it.
        let session = fresh(&mut env, &client).await;
        assert!(matches!(
            env.svc
                .publish_account_state(
                    &session,
                    &step_2(&client, Some(genuine.clone()), None),
                    env.now
                )
                .await,
            Err(AuthError::Unauthorized)
        ));
        let (device, _) = device_session(&mut env, &client).await;
        // An envelope under another `key_id`, or another `identity_epoch`, is refused.
        assert!(matches!(
            env.svc
                .publish_account_state(
                    &device,
                    &step_2(&client, Some(other_key.clone()), None),
                    env.now
                )
                .await,
            Err(AuthError::InvalidRequest)
        ));
        let mut wrong_epoch = step_2(&client, Some(genuine.clone()), None);
        wrong_epoch
            .identity_secret_keys
            .as_mut()
            .unwrap()
            .identity_epoch = 1;
        assert!(matches!(
            env.svc
                .publish_account_state(&device, &wrong_epoch, env.now)
                .await,
            Err(AuthError::InvalidRequest)
        ));
        assert_eq!(stored_e_id(&env, &client).await, other_key);
        // A junk envelope under the copied `key_id` is the first valid repair: it wins.
        env.svc
            .publish_account_state(&device, &step_2(&client, Some(junk.clone()), None), env.now)
            .await
            .unwrap();
        assert_eq!(stored_e_id(&env, &client).await, junk);
        env.svc
            .publish_account_state(
                &device,
                &step_2(&client, Some(genuine.clone()), None),
                env.now,
            )
            .await
            .unwrap();
        assert_eq!(stored_e_id(&env, &client).await, junk);
        // Lagging again, the genuine one repairs it.
        put_e_id(&env, &client, &other_key).await;
        env.svc
            .publish_account_state(
                &device,
                &step_2(&client, Some(genuine.clone()), None),
                env.now,
            )
            .await
            .unwrap();
        assert_eq!(stored_e_id(&env, &client).await, genuine);

        // Settings that do not hash to `settings_hash` (here: any, at `settings_seq = 0`).
        let settings = AccountSettings {
            settings_seq: 1,
            envelope: bytes(vec![0x5e; 120]),
        };
        assert!(matches!(
            env.svc
                .publish_account_state(&device, &step_2(&client, None, Some(settings)), env.now)
                .await,
            Err(AuthError::InvalidRequest)
        ));
    });
}
