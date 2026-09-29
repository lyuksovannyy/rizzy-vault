//! Rows used at most once (CRYPTO.md §5.10, §5.11) stay used on every path, and a login
//! started before the OPAQUE record was replaced cannot finish after it (§11.5 step 5, INV-59).

use rizzy_core::ids::DeviceId;
use rizzy_core::opaque::{OpaqueContext, PasswordInput, client_login_finish, client_login_start};
use rizzy_domain_auth::AuthError;
use rizzy_proto::auth::{DeviceAuthFinishRequest, DeviceAuthStartRequest, LoginStartRequest};
use rizzy_proto::wire::{Fixed, Id, Text};
use rizzy_storage::Conn;

use crate::common::{Client, Env, block_on, bytes, origin, wid};
use crate::restore::reregister;

/// Starts an OPAQUE login for `client` with `password` and computes KE3, without sending it.
async fn started_login(env: &mut Env, client: &Client, password: &str) -> (Id, Vec<u8>) {
    let pw_in = PasswordInput::derive(password, &client.secret_key).unwrap();
    let (state, ke1) = client_login_start(&mut env.rng, &pw_in).unwrap();
    let start = LoginStartRequest {
        login_name: Text::new(client.name.clone()).unwrap(),
        ke1: bytes(ke1),
    };
    let started = env
        .svc
        .login_start(&mut env.rng, &start, &env.source, None, env.now)
        .await
        .unwrap();
    let context =
        OpaqueContext::for_login(&origin(), started.kdf_id, started.server_origin.as_str())
            .unwrap();
    let fin = client_login_finish(
        &mut env.rng,
        state,
        &pw_in,
        started.ke2.as_slice(),
        &context,
    )
    .unwrap();
    (started.login_id, fin.ke3)
}

/// Renames the stored certificate row of `from` to `to`, so every later read of the account's
/// devices fails as a tampered database (an internal error after the take).
async fn move_cert(env: &Env, from: DeviceId, to: DeviceId) {
    let mut tx = env.db.begin_write().await.unwrap();
    {
        let Conn::Sqlite(c) = tx.conn() else {
            panic!("the tests run on SQLite")
        };
        sqlx::query("UPDATE auth_device_certificates SET device_id = $1 WHERE device_id = $2")
            .bind(&to.as_bytes()[..])
            .bind(&from.as_bytes()[..])
            .execute(&mut *c)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
}

/// A login started with the old password, finished after a password change committed, is
/// refused: the change deleted the pending login state (§11.5 step 5, INV-59).
#[test]
fn login_started_before_a_password_change_cannot_finish() {
    block_on(async {
        let mut env = Env::new(70).await;
        let mut client = env.signup("ivy", "old password").await;
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;
        let (login_id, ke3) = started_login(&mut env, &client, "old password").await;
        reregister(&mut env, &mut client, &fresh, "new password", true)
            .await
            .unwrap();
        assert!(matches!(
            env.finish_login(login_id, ke3, None, None).await,
            Err(AuthError::Unauthorized)
        ));
        env.login(&client).await;
        // A same-password re-registration replaces the record too: the same holds.
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;
        let (login_id, ke3) = started_login(&mut env, &client, "new password").await;
        reregister(&mut env, &mut client, &fresh, "new password", false)
            .await
            .unwrap();
        assert!(matches!(
            env.finish_login(login_id, ke3, None, None).await,
            Err(AuthError::Unauthorized)
        ));
    });
}

/// A failure after the login state was taken rolls the transaction back, yet the state stays
/// used: the same KE3 cannot be replayed once the failure is gone (§5.11).
#[test]
fn login_state_is_used_once_even_after_an_internal_failure() {
    block_on(async {
        let mut env = Env::new(71).await;
        let client = env.signup("jon", "pw").await;
        let a = client.devices[0].id;
        let elsewhere = DeviceId::from_bytes([0xee; 16]);
        let (login_id, ke3) = started_login(&mut env, &client, "pw").await;
        move_cert(&env, a, elsewhere).await;
        assert!(matches!(
            env.finish_login(login_id, ke3.clone(), None, None).await,
            Err(AuthError::Internal(_))
        ));
        move_cert(&env, elsewhere, a).await;
        assert!(matches!(
            env.finish_login(login_id, ke3, None, None).await,
            Err(AuthError::Unauthorized)
        ));
        env.login(&client).await;
    });
}

/// The same for a device-auth challenge (§5.10).
#[test]
fn challenge_is_used_once_even_after_an_internal_failure() {
    block_on(async {
        let mut env = Env::new(72).await;
        let client = env.signup("kai", "pw").await;
        let device = &client.devices[0];
        let start = DeviceAuthStartRequest {
            account_id: wid(client.account_id.to_bytes()),
            device_id: wid(device.id.to_bytes()),
            reconciliation: None,
        };
        let challenge = env
            .svc
            .device_auth_start(&mut env.rng, &start, env.now)
            .await
            .unwrap()
            .challenge;
        let o = origin();
        let signature = rizzy_core::sign::DeviceAuth {
            server_origin: &o,
            account_id: client.account_id,
            device_id: device.id,
            challenge: challenge.to_bytes(),
        }
        .sign(device.keys.signing_key())
        .unwrap();
        let finish = DeviceAuthFinishRequest {
            account_id: wid(client.account_id.to_bytes()),
            device_id: wid(device.id.to_bytes()),
            challenge,
            signature: Fixed::from_bytes(signature.to_bytes()),
            reconciliation: None,
        };
        let elsewhere = DeviceId::from_bytes([0xee; 16]);
        move_cert(&env, device.id, elsewhere).await;
        assert!(matches!(
            env.svc
                .device_auth_finish(&mut env.rng, &finish, env.now)
                .await,
            Err(AuthError::Internal(_))
        ));
        move_cert(&env, elsewhere, device.id).await;
        assert!(matches!(
            env.svc
                .device_auth_finish(&mut env.rng, &finish, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        env.device_auth(&client, device).await.unwrap();
    });
}
