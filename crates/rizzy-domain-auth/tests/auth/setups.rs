//! Retiring old OPAQUE setups (ADR 0031): the `reregister` flag, only after KE3 or the device
//! signature and only for a record on a non-current setup (point 2); the echoed `setup_id`,
//! accepted and stored as echoed for a loaded non-current setup, refused with `setup_retired`
//! for a retired or unknown one, after the byte-identical-repeat check (point 3); the two steps
//! of `secrets retire-setups`, their crash safety and the startup refusal (points 5–6); an
//! account left on a retired setup, whose login answers like an unknown name's and which
//! recovers through its device (point 7).

use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_core::envelope::purpose::AccountKeyServerWrapCtx;
use rizzy_core::kdf::KdfId;
use rizzy_core::opaque::{
    ClientRegistrationFinish, EnumKey, PasswordInput, ServerSetup, client_registration_finish,
    client_registration_start,
};
use rizzy_core::server_seal::ServerDataKey;
use rizzy_core::sign::AccountState;
use rizzy_domain_auth::retirement::RetirableSetup;
use rizzy_domain_auth::{
    AccountChange, AuthError, RecoveryUpload, ServerSecrets, Session, StartupCheckError,
};
use rizzy_proto::objects::{AccountKeyServerWrap, VaultSelfGrant};
use rizzy_proto::wire::List;
use rizzy_storage::Value;

use crate::common::{Client, Env, block_on, bytes};
use crate::restore::reregister;

/// One day, ms.
const DAY: u64 = 24 * 60 * 60 * 1000;

/// A copy of `secrets`, with a new setup added when `rotate` (`rizzy-vault secrets rotate`).
fn copy(secrets: &ServerSecrets, rotate: bool) -> ServerSecrets {
    let setups = secrets
        .setups()
        .map(|(id, s)| {
            (
                id,
                ServerSetup::from_bytes(s.to_bytes().expose_secret()).unwrap(),
            )
        })
        .collect();
    let enum_key = EnumKey::from_slice(secrets.enum_key().expose_secret()).unwrap();
    let keys = secrets
        .data_keys()
        .map(|k| ServerDataKey::from_slice(k.expose_secret(), k.data_key_id()).unwrap())
        .collect();
    let mut copy = ServerSecrets::from_parts(
        1,
        setups,
        enum_key,
        keys,
        secrets.current_data_key_id(),
        None,
    )
    .unwrap();
    if rotate {
        copy.rotate_setup(&mut ChaCha20Rng::seed_from_u64(4242))
            .unwrap();
    }
    copy
}

/// The `auth_opaque_setups` rows of the database: `(setup_id, retired_at_ms)`.
async fn setup_rows(env: &Env) -> Vec<(i64, Option<i64>)> {
    let dump = env.db.dump().await.unwrap();
    let table = dump
        .tables
        .iter()
        .find(|t| t.table == "auth_opaque_setups")
        .unwrap();
    table
        .rows
        .iter()
        .map(|row| {
            let Value::Integer(id) = row[0] else {
                panic!("setup_id")
            };
            let retired = match row[3] {
                Value::Integer(t) => Some(t),
                _ => None,
            };
            (id, retired)
        })
        .collect()
}

/// The `setup_id` the record of `client` is labelled with.
async fn record_setup(env: &Env, client: &Client) -> i64 {
    let dump = env.db.dump().await.unwrap();
    let table = dump
        .tables
        .iter()
        .find(|t| t.table == "auth_credentials")
        .unwrap();
    let row = table
        .rows
        .iter()
        .find(|r| r[0] == Value::Blob(client.account_id.to_bytes().to_vec()))
        .unwrap();
    let Value::Integer(id) = row[1] else {
        panic!("setup_id")
    };
    id
}

/// How many sealed login states are pending.
async fn login_states(env: &Env) -> usize {
    let mut tx = env.db.begin_read().await.unwrap();
    let rizzy_storage::Conn::Sqlite(c) = tx.conn() else {
        panic!("SQLite")
    };
    let rows = sqlx::query("SELECT login_id FROM auth_login_states")
        .fetch_all(&mut *c)
        .await
        .unwrap();
    rows.len()
}

/// A same-password re-registration of `client` started over `session`: the `setup_id` of the
/// answer and the finished registration.
async fn start_reregistration(
    env: &mut Env,
    client: &Client,
    session: &Session,
) -> (u32, ClientRegistrationFinish) {
    let pw_in = PasswordInput::derive(&client.password, &client.secret_key).unwrap();
    let (state, m1) = client_registration_start(&mut env.rng, &pw_in).unwrap();
    let (setup_id, m2) = env
        .svc
        .reregister_start(session, &bytes(m1), env.now)
        .await
        .unwrap();
    let reg =
        client_registration_finish(&mut env.rng, state, &pw_in, m2.as_slice(), KdfId::DEFAULT)
            .unwrap();
    (setup_id, reg)
}

/// The commit of a same-password re-registration (`state_seq + 1`, nothing else changed),
/// echoing `setup_id`.
fn reregistration_change(
    env: &mut Env,
    client: &Client,
    reg: &ClientRegistrationFinish,
    setup_id: Option<u32>,
) -> (AccountChange<Vec<VaultSelfGrant>>, (AccountState, Vec<u8>)) {
    let e_srv = reg
        .export_key
        .server_unlock_key(client.account_id)
        .unwrap()
        .wrap_account_key(
            &mut env.rng,
            &AccountKeyServerWrapCtx {
                account_id: client.account_id,
                account_key_epoch: client.account_key.epoch(),
                password_epoch: client.state.password_epoch,
                kdf_id: KdfId::DEFAULT,
            },
            &client.account_key,
        )
        .unwrap();
    let next = client.next_state(|_| {});
    let change = AccountChange {
        account_state: bytes(next.1.clone()),
        bundle: None,
        registration_upload: Some(bytes(reg.upload.clone())),
        setup_id,
        account_key_server_wrap: Some(AccountKeyServerWrap {
            account_key_epoch: client.account_key.epoch(),
            password_epoch: client.state.password_epoch,
            kdf_id: 1,
            envelope: bytes(e_srv),
        }),
        identity_secret_keys: None,
        recovery: RecoveryUpload::None,
        account_settings: None,
        retired_secret_keys: List::empty(),
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        device_grants: List::empty(),
        vault_rotation: None,
    };
    (change, next)
}

/// Point 2: the flag is set only for a record on a non-current setup, after KE3 or the device
/// signature; a same-password re-registration over a device session moves the record.
#[test]
fn reregister_flag_and_the_move_to_the_current_setup() {
    block_on(async {
        let mut env = Env::new(310).await;
        let mut client = env.signup("rhea", "pw").await;
        let device_index = 0;
        assert!(!env.login(&client).await.response.reregister);
        let device = &client.devices[device_index];
        let mut ds = env.device_auth(&client, device).await.unwrap();
        assert!(!ds.reregister);

        // `secrets rotate`, then a restart: #2 is current, the record is still on #1.
        env.tick(1_000);
        let rotated = copy(&env.secrets, true);
        env.restart_with(rotated).await.unwrap();
        assert!(env.login(&client).await.response.reregister);
        assert!(env.device_auth(&client, device).await.unwrap().reregister);
        // A wrong password never reaches the flag: one answer for every failure (§5.9).
        let name = client.name.clone();
        let sk = rizzy_core::secret_key::SecretKey::from_slice(client.secret_key.expose_secret())
            .unwrap();
        assert!(matches!(
            env.login_as(&name, "wrong", &sk, None, None).await,
            Err(AuthError::Unauthorized)
        ));

        // The device session suffices for the same-password re-registration (point 7).
        let session = env
            .signed(&client, &client.devices[device_index], &mut ds, b"{}")
            .await
            .unwrap();
        reregister(&mut env, &mut client, &session, "pw", false)
            .await
            .unwrap();
        assert_eq!(record_setup(&env, &client).await, 2);
        assert!(!env.login(&client).await.response.reregister);
        let device = &client.devices[device_index];
        assert!(!env.device_auth(&client, device).await.unwrap().reregister);
    });
}

/// Point 3: the record is labelled with the echoed setup (the race of a rotation between start
/// and commit), a retired or unknown one is refused with `setup_retired`, and a byte-identical
/// repeat of an applied commit is accepted before that check.
#[test]
fn echoed_setup_ids() {
    block_on(async {
        let mut env = Env::new(311).await;
        let mut client = env.signup("sol", "pw").await;
        let mut ds = env.device_auth(&client, &client.devices[0]).await.unwrap();
        let session = env
            .signed(&client, &client.devices[0], &mut ds, b"{}")
            .await
            .unwrap();

        // Started under #1; the server restarts with #2 current before the commit.
        let (setup_id, reg) = start_reregistration(&mut env, &client, &session).await;
        assert_eq!(setup_id, 1);
        env.tick(1_000);
        let rotated = copy(&env.secrets, true);
        env.restart_with(rotated).await.unwrap();
        // The upload without its setup, or a setup without an upload, is malformed.
        let (no_setup, _) = reregistration_change(&mut env, &client, &reg, None);
        assert!(matches!(
            env.svc.commit_change(&session, &no_setup, env.now).await,
            Err(AuthError::InvalidRequest)
        ));
        // An unknown setup is refused with its own code, not `state_conflict`.
        let (unknown, _) = reregistration_change(&mut env, &client, &reg, Some(99));
        let refused = env.svc.commit_change(&session, &unknown, env.now).await;
        assert!(matches!(refused, Err(AuthError::SetupRetired)));
        assert_eq!(
            refused.unwrap_err().code(),
            rizzy_domain_auth::types::ErrorCode::SetupRetired
        );
        // The loaded, non-current #1 is accepted and stored as echoed: the login still works.
        let (applied, next) = reregistration_change(&mut env, &client, &reg, Some(setup_id));
        env.svc
            .commit_change(&session, &applied, env.now)
            .await
            .unwrap();
        client.adopt(next);
        assert_eq!(record_setup(&env, &client).await, 1);
        assert!(env.login(&client).await.response.reregister);

        // #1 is retired in the database while this service still loads it: refused all the
        // same, unless the commit repeats the applied one byte for byte.
        ServerSecrets::retire_in_database(&env.db, &[1], env.now)
            .await
            .unwrap();
        env.svc
            .commit_change(&session, &applied, env.now)
            .await
            .unwrap();
        let (again_reg_setup, again) = {
            let (id, reg) = start_reregistration(&mut env, &client, &session).await;
            assert_eq!(id, 2);
            (id, reg)
        };
        let (retired, _) = reregistration_change(&mut env, &client, &again, Some(1));
        assert!(matches!(
            env.svc.commit_change(&session, &retired, env.now).await,
            Err(AuthError::SetupRetired)
        ));
        let (current, next) =
            reregistration_change(&mut env, &client, &again, Some(again_reg_setup));
        env.svc
            .commit_change(&session, &current, env.now)
            .await
            .unwrap();
        client.adopt(next);
        assert_eq!(record_setup(&env, &client).await, 2);
    });
}

/// Point 3 at signup: the record is labelled with the echoed setup; a signup commit whose
/// setup was retired meanwhile is refused, unless it repeats the applied signup.
#[test]
fn signup_echoes_its_setup() {
    block_on(async {
        let mut env = Env::new(312).await;
        // register_start under #1, register_finish after a restart with #2 current.
        let rotated = copy(&env.secrets, true);
        let (client, finish, outcome) = env.signup_across("tara", "pw", Some(rotated)).await;
        outcome.unwrap();
        assert_eq!(finish.setup_id, 1);
        assert_eq!(record_setup(&env, &client).await, 1);
        assert!(env.login(&client).await.response.reregister);

        // Retire #1: the applied signup still repeats; a new one that echoes #1 is refused.
        ServerSecrets::retire_in_database(&env.db, &[1], env.now)
            .await
            .unwrap();
        env.svc.register_finish(&finish, env.now).await.unwrap();
        // A signup started under #2 (current here), committed after `secrets rotate`, a
        // retirement of #2 and a restart with #3 alone.
        // (#3 is recorded by a start of another process; this service still has #2 current.)
        let mut file = copy(&env.secrets, true);
        assert_eq!(file.remove_retired_setups(&env.db).await.unwrap(), vec![1]);
        file.check_database(&env.db, env.now)
            .await
            .unwrap()
            .unwrap();
        ServerSecrets::retire_in_database(&env.db, &[2], env.now)
            .await
            .unwrap();
        assert_eq!(file.remove_retired_setups(&env.db).await.unwrap(), vec![2]);
        let (_, stale, outcome) = env.signup_across("uma", "pw", Some(file)).await;
        assert_eq!(stale.setup_id, 2, "started before the restart");
        assert!(matches!(outcome, Err(AuthError::SetupRetired)));
    });
}

/// Points 5–7: the selection and its counts, step 1 (retirement times, login states), a crash
/// before step 2 refused at startup, the re-run with another grace period that finishes it
/// and keeps the first time, and the account left on the retired setup.
#[test]
fn retirement_steps_and_the_account_left_behind() {
    block_on(async {
        let mut env = Env::new(313).await;
        let mut left = env.signup("vera", "pw").await;
        env.tick(DAY);
        let rotated = copy(&env.secrets, true);
        env.restart_with(rotated).await.unwrap();
        let successor = env.now;
        let moved = env.signup("wes", "pw").await;
        assert_eq!(record_setup(&env, &moved).await, 2);
        // The worker's report (point 10): more than 90 days after the successor, not at 90.
        assert!(
            env.svc
                .retirable_setups(successor + 90 * DAY)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            env.svc
                .retirable_setups(successor + 90 * DAY + 1)
                .await
                .unwrap(),
            vec![RetirableSetup {
                setup_id: 1,
                successor_at_ms: successor,
                records: 1,
            }]
        );
        env.tick(10 * DAY);

        // Nothing is old enough for the default 90 days; 0 selects #1 with its one record.
        assert_eq!(
            env.secrets
                .plan_retirement(&env.db, env.now, 90)
                .await
                .unwrap(),
            vec![]
        );
        let plan = env
            .secrets
            .plan_retirement(&env.db, env.now, 0)
            .await
            .unwrap();
        assert_eq!(
            plan,
            vec![RetirableSetup {
                setup_id: 1,
                successor_at_ms: successor,
                records: 1,
            }]
        );
        assert!(
            env.secrets
                .plan_retirement(&env.db, env.now, 3651)
                .await
                .is_err()
        );

        // Step 1 with --grace-days 0, then a crash before step 2.
        env.login_as_start_only("vera").await;
        assert_eq!(login_states(&env).await, 1);
        let first = env.now;
        ServerSecrets::retire_in_database(&env.db, &[1], first)
            .await
            .unwrap();
        assert_eq!(login_states(&env).await, 0);
        assert_eq!(
            setup_rows(&env).await,
            vec![(1, Some(i64::try_from(first).unwrap())), (2, None)]
        );
        // The file still holding #1 (as an old secrets backup would) is refused.
        let old_file = copy(&env.secrets, false);
        assert_eq!(
            env.restart_with(old_file).await,
            Err(StartupCheckError::RetiredSetupLoaded { setup_id: 1 })
        );
        // The re-run with the default 90 selects nothing new, never rewrites the time, and
        // step 2 drops the setup.
        env.tick(DAY);
        let mut file = copy(&env.secrets, false);
        assert!(
            file.plan_retirement(&env.db, env.now, 90)
                .await
                .unwrap()
                .is_empty()
        );
        ServerSecrets::retire_in_database(&env.db, &[1], env.now)
            .await
            .unwrap();
        assert_eq!(file.remove_retired_setups(&env.db).await.unwrap(), vec![1]);
        assert_eq!(file.remove_retired_setups(&env.db).await.unwrap(), vec![]);
        assert_eq!(file.setups().map(|(id, _)| id).collect::<Vec<_>>(), vec![2]);
        assert_eq!(
            setup_rows(&env).await,
            vec![(1, Some(i64::try_from(first).unwrap())), (2, None)]
        );
        env.restart_with(file).await.unwrap();

        // The account on #1: its login answers like an unknown name's at start, and fails at
        // finish with the one `unauthorized`.
        let shape = |r: &rizzy_proto::auth::LoginStartResponse| {
            (
                r.kdf_id,
                r.ke2.as_slice().len(),
                r.server_origin.as_str().to_owned(),
            )
        };
        let real = login_start_for(&mut env, "vera").await;
        let unknown = login_start_for(&mut env, "nobody-here").await;
        assert_eq!(shape(&real), shape(&unknown));
        assert!(matches!(
            env.login_as("vera", "pw", &sk(&left), None, None).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(!env.login(&moved).await.response.reregister);

        // It recovers through its device: device authentication, then the same-password
        // re-registration over the device session (point 7).
        let mut ds = env.device_auth(&left, &left.devices[0]).await.unwrap();
        assert!(ds.reregister);
        let session = env
            .signed(&left, &left.devices[0], &mut ds, b"{}")
            .await
            .unwrap();
        reregister(&mut env, &mut left, &session, "pw", false)
            .await
            .unwrap();
        assert_eq!(record_setup(&env, &left).await, 2);
        assert!(!env.login(&left).await.response.reregister);
    });
}

/// Startup refuses a secrets file holding a setup the database retired, and the restore check
/// refuses a backup that marks a loaded setup retired (point 6).
#[test]
fn a_retired_setup_is_never_loaded_again() {
    block_on(async {
        let mut env = Env::new(314).await;
        let client = env.signup("xan", "pw").await;
        env.tick(DAY);
        let rotated = copy(&env.secrets, true);
        env.restart_with(rotated).await.unwrap();
        let before = env.db.dump().await.unwrap();
        assert_eq!(env.secrets.check_dump(&before), Ok(()));
        ServerSecrets::retire_in_database(&env.db, &[1], env.now)
            .await
            .unwrap();
        let after = env.db.dump().await.unwrap();
        // The old file (with #1) against a backup taken after the retirement.
        assert_eq!(
            env.secrets.check_dump(&after),
            Err(StartupCheckError::RetiredSetupLoaded { setup_id: 1 })
        );
        let mut file = copy(&env.secrets, false);
        file.remove_retired_setups(&env.db).await.unwrap();
        assert_eq!(file.check_dump(&after), Ok(()));
        // A backup from before the retirement, with #1 missing from the file: allowed.
        assert_eq!(file.check_dump(&before), Ok(()));
        // A malformed retirement value is a shape error, not a pass.
        let mut bad = after;
        let setups = bad
            .tables
            .iter_mut()
            .find(|t| t.table == "auth_opaque_setups")
            .unwrap();
        setups.rows[0][3] = Value::Text("x".into());
        assert_eq!(file.check_dump(&bad), Err(StartupCheckError::DumpShape));
        let _ = client;
    });
}

/// The Secret Key of `client`, copied.
fn sk(client: &Client) -> rizzy_core::secret_key::SecretKey {
    rizzy_core::secret_key::SecretKey::from_slice(client.secret_key.expose_secret()).unwrap()
}

/// `login_start` for `name` with a throwaway password.
async fn login_start_for(env: &mut Env, name: &str) -> rizzy_proto::auth::LoginStartResponse {
    let sk = rizzy_core::secret_key::SecretKey::generate(&mut env.rng);
    let pw_in = PasswordInput::derive("x", &sk).unwrap();
    let (_, ke1) = rizzy_core::opaque::client_login_start(&mut env.rng, &pw_in).unwrap();
    let req = rizzy_proto::auth::LoginStartRequest {
        login_name: rizzy_proto::wire::Text::new(name.to_owned()).unwrap(),
        ke1: bytes(ke1),
    };
    env.svc
        .login_start(&mut env.rng, &req, &env.source.clone(), None, env.now)
        .await
        .unwrap()
}
