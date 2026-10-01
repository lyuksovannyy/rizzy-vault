//! After `secrets rotate --data-key` (CRYPTO.md §5.11 "Rotation"): `worker` re-seals the TOTP
//! rows under the account lock, and the old key is dropped once no row names it.

use std::sync::Arc;

use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_core::opaque::{EnumKey, ServerSetup};
use rizzy_core::server_seal::ServerDataKey;
use rizzy_core::totp::{TotpParams, TotpSecret};
use rizzy_domain_auth::{AuthError, Resealed, ServerSecrets};
use sqlx::Row as _;

use crate::common::{Client, Env, block_on};

/// The server's code for `secret` at `now_ms`.
fn code_at(secret: &TotpSecret, now_ms: u64) -> String {
    TotpParams::DEFAULT
        .code_at(secret, now_ms / 1000)
        .unwrap()
        .to_digits()
        .to_string()
}

/// A copy of `base`, as the server's reader would load the same file again.
fn copy(base: &ServerSecrets) -> ServerSecrets {
    let setups = base
        .setups()
        .map(|(id, s)| {
            (
                id,
                ServerSetup::from_bytes(s.to_bytes().expose_secret()).unwrap(),
            )
        })
        .collect();
    let enum_key = EnumKey::from_slice(base.enum_key().expose_secret()).unwrap();
    let data_keys = base
        .data_keys()
        .map(|k| ServerDataKey::from_slice(k.expose_secret(), k.data_key_id()).unwrap())
        .collect();
    ServerSecrets::from_parts(
        1,
        setups,
        enum_key,
        data_keys,
        base.current_data_key_id(),
        None,
    )
    .unwrap()
}

/// The ids of the data keys `secrets` holds.
fn key_ids(secrets: &ServerSecrets) -> Vec<u32> {
    secrets
        .data_keys()
        .map(ServerDataKey::data_key_id)
        .collect()
}

/// Every TOTP row: `(data_key_id, sealed_secret, last_accepted_step)`, by account and enrolment.
async fn totp_rows(env: &Env) -> Vec<(i64, Vec<u8>, Option<i64>)> {
    let mut tx = env.db.begin_read().await.unwrap();
    let rizzy_storage::Conn::Sqlite(c) = tx.conn() else {
        panic!("the tests run on SQLite")
    };
    sqlx::query(
        "SELECT data_key_id, sealed_secret, last_accepted_step FROM auth_totp_credentials \
         ORDER BY account_id, totp_credential_seq",
    )
    .fetch_all(&mut *c)
    .await
    .unwrap()
    .into_iter()
    .map(|r| (r.get(0), r.get(1), r.get(2)))
    .collect()
}

/// Signs `name` up, enrols and confirms TOTP; returns the client and its TOTP secret.
async fn with_totp(env: &mut Env, name: &str) -> (Client, TotpSecret) {
    let client = env.signup(name, "pw").await;
    let login = env.login(&client).await;
    let fresh = env.bearer(&login.response.session_token).await;
    let enrolment = env
        .svc
        .totp_enrol_start(&mut env.rng, &fresh, env.now)
        .await
        .unwrap();
    let code = code_at(&enrolment.secret, env.now);
    env.svc
        .totp_enrol_confirm(&fresh, enrolment.totp_credential_seq, &code, env.now)
        .await
        .unwrap();
    (client, enrolment.secret)
}

/// Swaps the service's secrets for `secrets`, as a restart with the rotated file does.
async fn restart_with(env: &mut Env, secrets: ServerSecrets) {
    secrets
        .check_database(&env.db, env.now)
        .await
        .unwrap()
        .unwrap();
    env.secrets = Arc::new(secrets);
    let db = env.db.clone();
    env.reopen(db, |_| {});
}

/// Whether `client` logs in with the current code of `secret` as its second factor.
async fn logs_in(env: &mut Env, client: &Client, secret: &TotpSecret) -> bool {
    let (name, password) = (client.name.clone(), client.password.clone());
    let code = code_at(secret, env.now);
    match env
        .login_as(&name, &password, &client.secret_key, Some(&code), None)
        .await
    {
        Ok(_) => true,
        Err(AuthError::SecondFactorRequired) => false,
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn reseal_moves_every_row_and_the_old_key_is_dropped() {
    block_on(async {
        let mut env = Env::new(90).await;
        let (ann, ann_secret) = with_totp(&mut env, "ann").await;
        let (bob, bob_secret) = with_totp(&mut env, "bob").await;
        let _no_totp = env.signup("cyd", "pw").await;
        let before = totp_rows(&env).await;
        assert_eq!(before.len(), 2);
        assert!(
            before
                .iter()
                .all(|(key, _, step)| *key == 1 && step.is_some())
        );

        // Nothing to do before a rotation: one read, no write.
        assert_eq!(
            env.svc
                .reseal_totp_secrets(&mut env.rng, None, 16)
                .await
                .unwrap(),
            Resealed::default()
        );

        // `secrets rotate --data-key`: key 2 is current, key 1 stays, since rows name it.
        let mut rotated = copy(&env.secrets);
        assert_eq!(
            rotated
                .rotate_data_key(&mut ChaCha20Rng::seed_from_u64(91))
                .unwrap(),
            2
        );
        assert!(
            rotated
                .drop_unused_data_keys(&env.db, env.now)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(key_ids(&rotated), vec![1, 2]);
        restart_with(&mut env, copy(&rotated)).await;

        // The old key still opens the rows it sealed.
        env.tick(30_000);
        assert!(logs_in(&mut env, &ann, &ann_secret).await);
        let stepped = totp_rows(&env).await;

        // Page by page, one account per transaction.
        let first = env
            .svc
            .reseal_totp_secrets(&mut env.rng, None, 1)
            .await
            .unwrap();
        assert_eq!((first.rows, first.failures), (1, 0));
        let after = first.next.expect("a full page names where to go on");
        let second = env
            .svc
            .reseal_totp_secrets(&mut env.rng, Some(after), 1)
            .await
            .unwrap();
        assert_eq!((second.rows, second.failures), (1, 0));
        let third = env
            .svc
            .reseal_totp_secrets(&mut env.rng, second.next, 1)
            .await
            .unwrap();
        assert_eq!(third, Resealed::default());

        // Every row names key 2 under a new envelope; the accepted steps did not move.
        let resealed = totp_rows(&env).await;
        assert_eq!(resealed.len(), 2);
        for (old, new) in stepped.iter().zip(&resealed) {
            assert_eq!(new.0, 2);
            assert_ne!(old.1, new.1);
            assert_eq!(old.2, new.2);
        }
        // Idempotent.
        assert_eq!(
            env.svc
                .reseal_totp_secrets(&mut env.rng, None, 16)
                .await
                .unwrap(),
            Resealed::default()
        );
        assert_eq!(totp_rows(&env).await, resealed);

        // A used step stays used; the next one works, for both accounts.
        assert!(!logs_in(&mut env, &ann, &ann_secret).await);
        env.tick(30_000);
        assert!(logs_in(&mut env, &ann, &ann_secret).await);
        assert!(logs_in(&mut env, &bob, &bob_secret).await);

        // A login state still sealed under key 2 is no reason to keep key 1; key 1 goes, and
        // the file without it passes the startup check and verifies codes.
        env.login_as_start_only("ann").await;
        assert_eq!(
            rotated
                .drop_unused_data_keys(&env.db, env.now)
                .await
                .unwrap(),
            vec![1]
        );
        assert_eq!(key_ids(&rotated), vec![2]);
        assert_eq!(rotated.current_data_key_id(), 2);
        assert!(
            rotated
                .drop_unused_data_keys(&env.db, env.now)
                .await
                .unwrap()
                .is_empty()
        );
        restart_with(&mut env, rotated).await;
        env.tick(30_000);
        assert!(logs_in(&mut env, &bob, &bob_secret).await);
    });
}

#[test]
fn a_row_that_names_the_old_key_keeps_it() {
    block_on(async {
        let mut env = Env::new(92).await;
        let (ann, ann_secret) = with_totp(&mut env, "ann").await;
        let (bob, bob_secret) = with_totp(&mut env, "bob").await;
        // A pending login, sealed under key 1.
        env.login_as_start_only("ann").await;

        let mut rotated = copy(&env.secrets);
        rotated
            .rotate_data_key(&mut ChaCha20Rng::seed_from_u64(93))
            .unwrap();
        restart_with(&mut env, copy(&rotated)).await;

        // One account's row no longer opens (a database writer changed it).
        let first_account: Vec<u8> = {
            let mut tx = env.db.begin_write().await.unwrap();
            let rizzy_storage::Conn::Sqlite(c) = tx.conn() else {
                panic!("the tests run on SQLite")
            };
            let account: Vec<u8> = sqlx::query(
                "SELECT account_id FROM auth_totp_credentials ORDER BY account_id LIMIT 1",
            )
            .fetch_one(&mut *c)
            .await
            .unwrap()
            .get(0);
            sqlx::query(
                "UPDATE auth_totp_credentials SET sealed_secret = $1 WHERE account_id = $2",
            )
            .bind(vec![7u8; 60])
            .bind(&account)
            .execute(&mut *c)
            .await
            .unwrap();
            tx.commit().await.unwrap();
            account
        };

        // It is skipped and counted; the other account is re-sealed.
        let done = env
            .svc
            .reseal_totp_secrets(&mut env.rng, None, 16)
            .await
            .unwrap();
        assert_eq!((done.rows, done.failures, done.next), (1, 1, None));
        let rows = totp_rows(&env).await;
        assert_eq!(rows.iter().map(|r| r.0).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(rows[0].1, vec![7u8; 60], "the broken row is left as it was");
        // The next run tries it again, and only it.
        let again = env
            .svc
            .reseal_totp_secrets(&mut env.rng, None, 16)
            .await
            .unwrap();
        assert_eq!((again.rows, again.failures), (0, 1));

        // Key 1 stays: a TOTP row names it (and, for 60 s, the login state).
        assert!(
            rotated
                .drop_unused_data_keys(&env.db, env.now)
                .await
                .unwrap()
                .is_empty()
        );
        // The healthy account logs in with its code, under the new key.
        env.tick(30_000);
        let healthy = if first_account == ann.account_id.as_bytes().to_vec() {
            (&bob, &bob_secret)
        } else {
            (&ann, &ann_secret)
        };
        assert!(logs_in(&mut env, healthy.0, healthy.1).await);

        // Once the broken row is gone, only the login state names key 1, until it expires.
        {
            let mut tx = env.db.begin_write().await.unwrap();
            let rizzy_storage::Conn::Sqlite(c) = tx.conn() else {
                panic!("the tests run on SQLite")
            };
            sqlx::query("DELETE FROM auth_totp_credentials WHERE account_id = $1")
                .bind(&first_account)
                .execute(&mut *c)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        assert!(
            rotated
                .drop_unused_data_keys(&env.db, env.now)
                .await
                .unwrap()
                .is_empty(),
            "an unexpired login state names key 1"
        );
        env.tick(60_000);
        assert_eq!(
            rotated
                .drop_unused_data_keys(&env.db, env.now)
                .await
                .unwrap(),
            vec![1]
        );
        assert_eq!(key_ids(&rotated), vec![2]);
        assert_eq!(
            rotated.check_database(&env.db, env.now).await.unwrap(),
            Ok(())
        );
    });
}
