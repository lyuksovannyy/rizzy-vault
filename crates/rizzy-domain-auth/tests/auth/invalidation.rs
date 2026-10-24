// SPDX-License-Identifier: AGPL-3.0-only

//! The database half of `rizzy-vault secrets restore` and `secrets invalidate` (ADR 0047):
//! `check_database_dry_run` commits nothing on any branch `check_database` has, and
//! `invalidate_in_database` on both cases, with a re-run after a crash before the secrets
//! file was written. On PostgreSQL too, with `RIZZY_TEST_POSTGRES_URL`
//! ([`Env::on_either_engine`]).

use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_core::opaque::{EnumKey, ServerSetup};
use rizzy_core::server_seal::ServerDataKey;
use rizzy_core::totp::{TotpParams, TotpSecret};
use rizzy_domain_auth::invalidation::{
    InvalidationCost, LossCase, PendingInvalidation, clear_pending_invalidation,
    invalidate_in_database, invalidation_cost, pending_invalidation,
};
use rizzy_domain_auth::{AuthError, ServerSecrets, StartupCheckError};
use rizzy_storage::{Database, Value};
use zeroize::Zeroizing;

use crate::common::{Client, Env, block_on};

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
        base.bootstrap_token().map(|t| Zeroizing::new(t.to_vec())),
    )
    .unwrap()
}

/// `(setup_id, ake_public_key_hash, created_at_ms, retired_at_ms)` of every recorded setup.
async fn setup_rows(db: &Database) -> Vec<Vec<Value>> {
    let dump = db.dump().await.unwrap();
    dump.tables
        .into_iter()
        .find(|t| t.table == "auth_opaque_setups")
        .unwrap()
        .rows
}

/// `(setup_id, retired)` of every recorded setup.
async fn setup_states(db: &Database) -> Vec<(i64, bool)> {
    setup_rows(db)
        .await
        .iter()
        .map(|row| {
            let Value::Integer(id) = row[0] else {
                panic!("setup_id")
            };
            (id, !matches!(row[3], Value::Null))
        })
        .collect()
}

/// `SELECT COUNT(*) FROM <table>` for a table name written in this file.
async fn count(db: &Database, query: &'static str) -> i64 {
    let mut tx = db.begin_read().await.unwrap();
    let n: i64 = rizzy_storage::on_engine!(tx.conn(), |c| sqlx::query_scalar(query)
        .fetch_one(&mut *c)
        .await
        .unwrap());
    tx.finish().await.unwrap();
    n
}

/// Pending login states.
async fn login_states(db: &Database) -> i64 {
    count(db, "SELECT COUNT(*) FROM auth_login_states").await
}

/// TOTP rows.
async fn totp_rows(db: &Database) -> i64 {
    count(db, "SELECT COUNT(*) FROM auth_totp_credentials").await
}

/// The server's code for `secret` at `now_ms`.
fn code_at(secret: &TotpSecret, now_ms: u64) -> String {
    TotpParams::DEFAULT
        .code_at(secret, now_ms / 1000)
        .unwrap()
        .to_digits()
        .to_string()
}

/// Signs `name` up and enrols and confirms TOTP.
async fn with_totp(env: &mut Env, name: &str) -> Client {
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
    client
}

/// ADR 0047 "Tests": `check_database_dry_run` gives the refusal `check_database` gives, in
/// the same order, and commits nothing on any branch, including the success path, where
/// `check_database` records the setups it does not know yet.
#[test]
fn the_dry_run_commits_nothing_on_every_branch() {
    block_on(async {
        let mut env = Env::on_either_engine(4701, |_| {}).await;
        let client = env.signup("max", "pw").await;
        env.login(&client).await;
        let _pending = env.login_as_start_only(&client.name).await;
        let before = setup_rows(&env.db).await;
        assert_eq!(before.len(), 1);

        // Another instance's file: setup 1 under a different key.
        let other = ServerSecrets::generate(&mut ChaCha20Rng::seed_from_u64(99));
        // No setup recorded: the same keys, but only a new setup 2.
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let new_setup = ServerSetup::generate(&mut rng);
        let unrecorded =
            ServerSecrets::generate_after_loss(&mut rng, 2, new_setup, Some(copy(&env.secrets)));
        // The same setup, but a data key the pending login state does not name.
        let (_, setup) = env.secrets.setups().next().unwrap();
        let setup = ServerSetup::from_bytes(setup.to_bytes().expose_secret()).unwrap();
        let enum_key = EnumKey::from_slice(env.secrets.enum_key().expose_secret()).unwrap();
        let key2 = ServerDataKey::generate(&mut ChaCha20Rng::seed_from_u64(5), 2);
        let missing =
            ServerSecrets::from_parts(1, vec![(1, setup)], enum_key, vec![key2], 2, None).unwrap();
        for (secrets, refusal) in [
            (&other, StartupCheckError::SetupMismatch { setup_id: 1 }),
            (&unrecorded, StartupCheckError::NoRecordedSetup),
            (
                &missing,
                StartupCheckError::MissingDataKey { data_key_id: 1 },
            ),
        ] {
            assert_eq!(
                secrets.check_database_dry_run(&env.db).await.unwrap(),
                Err(refusal)
            );
            assert_eq!(
                secrets.check_database(&env.db, env.now).await.unwrap(),
                Err(refusal)
            );
            assert_eq!(setup_rows(&env.db).await, before);
        }

        // The success path: a rotated file with setup 2 not recorded yet. The dry run passes and
        // records nothing; `check_database` records it.
        let mut rotated = copy(&env.secrets);
        assert_eq!(rotated.rotate_setup(&mut rng).unwrap(), 2);
        assert_eq!(
            rotated.check_database_dry_run(&env.db).await.unwrap(),
            Ok(())
        );
        assert_eq!(setup_rows(&env.db).await, before);
        assert_eq!(
            login_states(&env.db).await,
            1,
            "the dry run deletes nothing"
        );
        assert_eq!(
            rotated.records_on_missing_setups(&env.db).await.unwrap(),
            []
        );
        rotated
            .check_database(&env.db, env.now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(setup_states(&env.db).await, [(1, false), (2, false)]);

        // A retired setup still in the file: the same refusal, nothing written.
        ServerSecrets::retire_in_database(&env.db, &[1], env.now)
            .await
            .unwrap();
        let after_retire = setup_rows(&env.db).await;
        assert_eq!(
            env.secrets.check_database_dry_run(&env.db).await.unwrap(),
            Err(StartupCheckError::RetiredSetupLoaded { setup_id: 1 })
        );
        assert_eq!(
            env.secrets.check_database(&env.db, env.now).await.unwrap(),
            Err(StartupCheckError::RetiredSetupLoaded { setup_id: 1 })
        );
        assert_eq!(setup_rows(&env.db).await, after_retire);

        // The record on setup 1 is on a setup the setup-2-only file lacks: the file passes,
        // and the record is reported.
        let only_two = ServerSecrets::generate_after_loss(
            &mut rng,
            2,
            ServerSetup::from_bytes(
                rotated
                    .setups()
                    .find(|(id, _)| *id == 2)
                    .unwrap()
                    .1
                    .to_bytes()
                    .expose_secret(),
            )
            .unwrap(),
            Some(copy(&env.secrets)),
        );
        assert_eq!(
            only_two.check_database_dry_run(&env.db).await.unwrap(),
            Ok(())
        );
        assert_eq!(
            only_two.records_on_missing_setups(&env.db).await.unwrap(),
            [(1, 1)]
        );
    });
}

/// A setup-only loss (ADR 0047 steps 4–6): every setup retired, the login states deleted, no
/// TOTP row deleted, the new setup recorded under the next id; the new secrets keep the data
/// keys and the bootstrap token and pass the startup check; the account on the old setup takes
/// the missing-setup path at login. A crash before the file was written, then a re-run, mints
/// a fresh id and retires the orphan; the old file alone now reads as `RetiredSetupLoaded`,
/// which is why the re-run follows the marker.
#[test]
fn a_setup_only_loss_keeps_the_data_keys_and_resumes_after_a_crash() {
    block_on(async {
        let mut env = Env::on_either_engine(4702, |_| {}).await;
        let client = with_totp(&mut env, "max").await;
        let _pending = env.login_as_start_only(&client.name).await;
        assert_eq!(
            (totp_rows(&env.db).await, login_states(&env.db).await),
            (1, 1)
        );
        assert_eq!(pending_invalidation(&env.db).await.unwrap(), None);
        assert_eq!(
            invalidation_cost(&env.db, LossCase::SetupOnly)
                .await
                .unwrap(),
            InvalidationCost {
                accounts: 1,
                totp_enrolments: 0
            }
        );
        assert_eq!(
            invalidation_cost(&env.db, LossCase::Whole).await.unwrap(),
            InvalidationCost {
                accounts: 1,
                totp_enrolments: 1
            }
        );

        // The first attempt: step 4 commits, then the process dies before writing the file.
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let lost = ServerSetup::generate(&mut rng);
        let diagnosed = env.now;
        let mut seen = None;
        let first = invalidate_in_database(
            &env.db,
            LossCase::SetupOnly,
            &lost.public_key_hash(),
            env.now,
            diagnosed,
            |outcome| seen = Some(*outcome),
        )
        .await
        .unwrap();
        assert_eq!(seen, Some(first));
        assert_eq!(first.setup_id, 2);
        assert_eq!(
            (
                first.setups_retired,
                first.totp_rows_deleted,
                first.login_states_deleted,
                first.accounts
            ),
            (1, 0, 1, 1)
        );
        assert_eq!(setup_states(&env.db).await, [(1, true), (2, false)]);
        assert_eq!(
            (totp_rows(&env.db).await, login_states(&env.db).await),
            (1, 0)
        );
        assert_eq!(
            pending_invalidation(&env.db).await.unwrap(),
            Some(PendingInvalidation {
                case: LossCase::SetupOnly,
                setup_id: 2,
                diagnosed_at_ms: diagnosed
            })
        );
        // Diagnosing the unchanged file again would now refuse: the marker is what resumes.
        assert_eq!(
            env.secrets.check_database_dry_run(&env.db).await.unwrap(),
            Err(StartupCheckError::RetiredSetupLoaded { setup_id: 1 })
        );

        // The re-run: the burned setup 2 is retired, a fresh 3 minted, the diagnosis time kept.
        env.tick(1000);
        let setup = ServerSetup::generate(&mut rng);
        let second = invalidate_in_database(
            &env.db,
            LossCase::SetupOnly,
            &setup.public_key_hash(),
            env.now,
            diagnosed,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!((second.setup_id, second.setups_retired), (3, 1));
        assert_eq!(
            setup_states(&env.db).await,
            [(1, true), (2, true), (3, false)]
        );
        assert_eq!(
            pending_invalidation(&env.db)
                .await
                .unwrap()
                .map(|p| (p.setup_id, p.diagnosed_at_ms)),
            Some((3, diagnosed))
        );

        // Step 5: the new secrets carry everything but the setup forward.
        let old = copy(&env.secrets);
        let renewed =
            ServerSecrets::generate_after_loss(&mut rng, 3, setup, Some(copy(&env.secrets)));
        assert_eq!(renewed.setups().map(|(id, _)| id).collect::<Vec<_>>(), [3]);
        assert_eq!(renewed.current_setup_id(), 3);
        assert_eq!(
            renewed.enum_key().expose_secret(),
            old.enum_key().expose_secret()
        );
        assert_eq!(renewed.current_data_key_id(), old.current_data_key_id());
        assert!(
            renewed
                .data_keys()
                .zip(old.data_keys())
                .all(|(a, b)| a.data_key_id() == b.data_key_id()
                    && a.expose_secret() == b.expose_secret())
        );
        assert_eq!(renewed.bootstrap_token(), old.bootstrap_token());
        assert!(renewed.bootstrap_token().is_some());
        assert_eq!(
            renewed.check_database_dry_run(&env.db).await.unwrap(),
            Ok(())
        );
        // Step 6.
        clear_pending_invalidation(&env.db).await.unwrap();
        assert_eq!(pending_invalidation(&env.db).await.unwrap(), None);
        renewed
            .check_database(&env.db, env.now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(setup_rows(&env.db).await.len(), 3, "nothing new to record");

        // The account's record names setup 1, which the file no longer has: its password
        // login fails like an unknown name's, and it re-registers through a device or recovery.
        env.secrets = std::sync::Arc::new(renewed);
        let db = env.db.clone();
        env.reopen(db, |_| {});
        let refused = env
            .login_as(
                &client.name,
                &client.password,
                &client.secret_key,
                None,
                None,
            )
            .await;
        assert!(matches!(refused, Err(AuthError::Unauthorized)));
        assert_eq!(totp_rows(&env.db).await, 1, "the TOTP enrolment stays");
    });
}

/// A whole loss (ADR 0047 steps 4–6): every TOTP row deleted, no bootstrap token minted, a
/// fresh `enum_key` and data key 1; a crash before the file was written and a re-run mint a
/// fresh id each time.
#[test]
fn a_whole_loss_deletes_every_totp_row_and_mints_no_bootstrap_token() {
    block_on(async {
        let mut env = Env::on_either_engine(4703, |_| {}).await;
        with_totp(&mut env, "max").await;
        with_totp(&mut env, "ida").await;
        let _plain = env.signup("joe", "pw").await;
        assert_eq!(totp_rows(&env.db).await, 2);
        assert_eq!(
            invalidation_cost(&env.db, LossCase::Whole).await.unwrap(),
            InvalidationCost {
                accounts: 3,
                totp_enrolments: 2
            }
        );

        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let first = invalidate_in_database(
            &env.db,
            LossCase::Whole,
            &ServerSetup::generate(&mut rng).public_key_hash(),
            env.now,
            env.now,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(
            (
                first.setup_id,
                first.setups_retired,
                first.totp_rows_deleted,
                first.accounts
            ),
            (2, 1, 2, 3)
        );
        assert_eq!(totp_rows(&env.db).await, 0);
        assert_eq!(
            pending_invalidation(&env.db).await.unwrap().map(|p| p.case),
            Some(LossCase::Whole)
        );

        let setup = ServerSetup::generate(&mut rng);
        let second = invalidate_in_database(
            &env.db,
            LossCase::Whole,
            &setup.public_key_hash(),
            env.now,
            env.now,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!((second.setup_id, second.totp_rows_deleted), (3, 0));
        assert_eq!(
            setup_states(&env.db).await,
            [(1, true), (2, true), (3, false)]
        );

        let renewed = ServerSecrets::generate_after_loss(&mut rng, 3, setup, None);
        assert!(
            renewed.bootstrap_token().is_none(),
            "INV-69: no silent token"
        );
        assert_ne!(
            renewed.enum_key().expose_secret(),
            env.secrets.enum_key().expose_secret()
        );
        assert_eq!(
            renewed
                .data_keys()
                .map(ServerDataKey::data_key_id)
                .collect::<Vec<_>>(),
            [1]
        );
        assert_eq!(renewed.current_backup_key_id(), None);
        assert_eq!(
            renewed.check_database_dry_run(&env.db).await.unwrap(),
            Ok(())
        );
        clear_pending_invalidation(&env.db).await.unwrap();
        renewed
            .check_database(&env.db, env.now)
            .await
            .unwrap()
            .unwrap();
    });
}
