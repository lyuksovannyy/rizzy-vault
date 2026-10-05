//! Retiring old OPAQUE setups end to end ([ADR 0031] point 11, integration): `rizzy-client`
//! against the router and the admin commands, over a real `SQLite` database and secrets file.
//!
//! - [`rotate_reregister_retire_and_recover`]: `secrets rotate` and a restart; a login and a
//!   device authentication answer `reregister`, and a same-password re-registration over a
//!   device session moves the record to the new setup; `secrets retire-setups --grace-days 0`
//!   reports the records left behind, marks the setup, drops it from the file and deletes the
//!   pending login states; a restart with the old file is refused; an account still on the
//!   retired setup gets a login answer shaped like an unknown name's, and recovers through its
//!   enrolled device and, another one, through recovery.
//! - [`a_crash_between_the_steps_fails_closed_and_a_rerun_finishes`]: step 1 alone (a crash
//!   before the file is written) with `--grace-days 0`, a refused start, then a re-run with the
//!   default 90 days that drops the setup and keeps the first retirement time.
//! - [`pending_changes_cross_a_rotation_and_a_retirement`]: a pending password change crosses
//!   `secrets rotate` and a restart and is accepted byte for byte; a pending Secret Key change
//!   crosses `retire-setups --grace-days 0` and a restart, is refused `setup_retired`, has its
//!   registration rerun and only its upload, `setup_id` and `E_srv` rebuilt, and commits with
//!   its Secret Key and the account key unchanged.
//!
//! [ADR 0031]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0031-retiring-old-opaque-setups.md

use axum::http::StatusCode;
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::credentials::{CredentialChangeInput, start_credential_change};
use rizzy_client::login::{LoginInput, start_login};
use rizzy_client::reregister::start_device_reregistration;
use rizzy_client::rizzy_proto::change::CommitChangeRequest;
use rizzy_client::store::record::{DeviceRecord, Stage};
use rizzy_domain_auth::StartupCheckError;
use rizzy_server::admin::{self, Rotate};
use rizzy_server::config::{self, Config};
use rizzy_server::server::{ServeError, open_services};
use rizzy_storage::Value;

use crate::common::{ORIGIN, Server, TempDir, block_on, config_in};
use crate::recovery::{NEW_PASSWORD, recover};
use crate::rotation::{
    Auth, Client, NAME, PASSWORD, copy_token, device_session, login_named, now_ms, post,
    post_empty, signup, signup_named,
};

/// `(setup_id, retired_at_ms)` of every recorded setup.
async fn setup_rows(server: &Server) -> Vec<(i64, Option<i64>)> {
    let dump = server.services.db.dump().await.unwrap();
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
                Value::Integer(at) => Some(at),
                _ => None,
            };
            (id, retired)
        })
        .collect()
}

/// The `setup_id` every record names, by account id.
async fn record_setups(server: &Server) -> Vec<i64> {
    let dump = server.services.db.dump().await.unwrap();
    let table = dump
        .tables
        .iter()
        .find(|t| t.table == "auth_credentials")
        .unwrap();
    let mut ids: Vec<i64> = table
        .rows
        .iter()
        .map(|row| match row[1] {
            Value::Integer(id) => id,
            _ => panic!("setup_id"),
        })
        .collect();
    ids.sort_unstable();
    ids
}

/// `login/start` for `name` with `sk`: the status and, on success, the answer's shape (its
/// `kdf_id`, KE2 length and origin), which must not tell a real name from an unknown one.
async fn login_start_shape(
    server: &Server,
    rng: &mut ChaCha20Rng,
    name: &str,
    sk: &str,
) -> (u16, usize, String) {
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: name,
        secret_key: sk,
        password: PASSWORD,
    };
    let (_, request) = start_login(rng, &input).unwrap();
    let reply = post(server, "/api/v1/login/start", &request, Auth::None).await;
    assert_eq!(reply.status, StatusCode::OK);
    let v: serde_json::Value = reply.json();
    (
        u16::try_from(v["kdf_id"].as_u64().unwrap()).unwrap(),
        v["ke2"].as_str().unwrap().len(),
        v["server_origin"].as_str().unwrap().to_owned(),
    )
}

/// Whether a whole OPAQUE login of `name` with `password` and `sk` succeeds, and its
/// `reregister` flag.
async fn try_login(
    server: &Server,
    rng: &mut ChaCha20Rng,
    name: &str,
    sk: &str,
    password: &str,
) -> Option<bool> {
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: name,
        secret_key: sk,
        password,
    };
    let (started, request) = start_login(rng, &input).unwrap();
    let reply = post(server, "/api/v1/login/start", &request, Auth::None).await;
    let (awaiting, finish) = started.finish(rng, &reply.json(), None).ok()?;
    let reply = post(server, "/api/v1/login/finish", &finish, Auth::None).await;
    if reply.status != StatusCode::OK {
        assert_eq!(reply.error(), "unauthorized");
        return None;
    }
    Some(awaiting.complete(reply.json()).unwrap().reregister())
}

/// The same-password re-registration of `client` over its device session (ADR 0031 point 2).
async fn reregister_device(server: &Server, rng: &mut ChaCha20Rng, client: &mut Client) {
    let account = client.refresh(server).await;
    let (started, request) = start_device_reregistration(rng, &client.state, PASSWORD).unwrap();
    let reply = post(
        server,
        "/api/v1/account/reregister/start",
        &request,
        Auth::Device(&mut client.session, &client.unlocked),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let pending = started
        .finish_device(rng, &reply.json(), &account, &client.unlocked)
        .unwrap();
    post_empty(
        server,
        "/api/v1/account/commit",
        pending.commit_request(),
        Auth::Device(&mut client.session, &client.unlocked),
    )
    .await;
    client.refresh(server).await;
}

/// The configuration of a test instance with a recovery wait of 0, its secrets file written by
/// `secrets init`.
fn instance(dir: &TempDir) -> Config {
    let config = config_in(dir, &[(config::RECOVERY_WAIT_HOURS, "0")]);
    admin::secrets_init(&config).unwrap();
    config
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one instance's life: rotation, re-registration, retirement, the accounts left behind"
)]
fn rotate_reregister_retire_and_recover() {
    block_on(async {
        let dir = TempDir::new();
        let config = instance(&dir);
        let server = Server::open(dir, &config, |_| {}).await;
        let mut rng = ChaCha20Rng::seed_from_u64(3101);
        // Three accounts on setup 1: carol moves, dave and alice stay behind.
        let (carol_up, carol_sk, _) = signup_named(&server, &mut rng, "carol", false).await;
        let (dave_up, dave_sk, _) = signup_named(&server, &mut rng, "dave", false).await;
        let (_alice_up, alice_sk, alice_code) = signup(&server, &mut rng, true).await;
        let mut carol = Client::signed_up(&server, carol_up).await;
        assert!(!carol.session.reregister());
        assert_eq!(
            try_login(&server, &mut rng, "carol", &carol_sk, PASSWORD).await,
            Some(false)
        );

        // `secrets rotate` with the server stopped, and a restart: setup 2 is current.
        let dir = server.stop().await;
        assert_eq!(
            admin::secrets_rotate(&config, Rotate::Setup)
                .await
                .unwrap()
                .id,
            2
        );
        let server = Server::open(dir, &config, |_| {}).await;
        assert_eq!(setup_rows(&server).await, {
            let rows = setup_rows(&server).await;
            assert_eq!(rows.iter().map(|r| r.0).collect::<Vec<_>>(), vec![1, 2]);
            rows
        });
        // Only after KE3 or the device signature: the flag.
        assert_eq!(
            try_login(&server, &mut rng, "carol", &carol_sk, PASSWORD).await,
            Some(true)
        );
        assert_eq!(
            try_login(&server, &mut rng, "carol", &carol_sk, "wrong").await,
            None
        );
        carol.session = device_session(&server, &carol.state, &carol.unlocked)
            .await
            .unwrap();
        assert!(carol.session.reregister());
        // The same-password re-registration over the device session moves carol to #2.
        reregister_device(&server, &mut rng, &mut carol).await;
        assert_eq!(record_setups(&server).await, vec![1, 1, 2]);
        assert_eq!(
            try_login(&server, &mut rng, "carol", &carol_sk, PASSWORD).await,
            Some(false)
        );
        let mut dave = Client::signed_up(&server, dave_up).await;
        assert!(dave.session.reregister());

        // A login of dave started under #1 with the right password (KE3 ready, not sent), then
        // `retire-setups --grace-days 0` with the server stopped.
        let input = LoginInput {
            server_origin: ORIGIN,
            login_name: "dave",
            secret_key: &dave_sk,
            password: PASSWORD,
        };
        let (started, request) = start_login(&mut rng, &input).unwrap();
        let reply = post(&server, "/api/v1/login/start", &request, Auth::None).await;
        let (_, pending_finish) = started.finish(&mut rng, &reply.json(), None).unwrap();
        let dir = server.stop().await;
        let old_file = std::fs::read(&config.secrets_file).unwrap();
        let report = admin::secrets_retire_setups(&config, 0).await.unwrap();
        assert_eq!(report.grace_days, 0);
        assert_eq!(
            report
                .selected
                .iter()
                .map(|s| (s.setup_id, s.records))
                .collect::<Vec<_>>(),
            vec![(1, 2)]
        );
        assert_eq!(report.removed, vec![1]);
        let printed = rizzy_server::cli::retirement_message(&report);
        assert!(printed.contains("setup 1:") && printed.contains("2 account record(s)"));
        assert!(!printed.contains("dave") && !printed.contains("alice"));
        let new_file = std::fs::read(&config.secrets_file).unwrap();

        // The old file is refused at startup; the new one starts.
        std::fs::write(&config.secrets_file, &old_file).unwrap();
        match open_services(&config).await {
            Err(ServeError::SecretsMismatch(StartupCheckError::RetiredSetupLoaded {
                setup_id: 1,
            })) => {}
            Err(e) => panic!("{e}"),
            Ok(_) => panic!("a retired setup was loaded"),
        }
        std::fs::write(&config.secrets_file, &new_file).unwrap();
        let server = Server::open(dir, &config, |_| {}).await;
        // The login started under #1 cannot finish: its state was deleted with step 1.
        let reply = post(&server, "/api/v1/login/finish", &pending_finish, Auth::None).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let rows = setup_rows(&server).await;
        assert!(rows[0].1.is_some() && rows[1].1.is_none());

        // dave and alice, still on #1: login/start answers like an unknown name, login/finish
        // with the one `unauthorized`.
        let real = login_start_shape(&server, &mut rng, "dave", &dave_sk).await;
        let unknown = login_start_shape(&server, &mut rng, "nobody", &dave_sk).await;
        assert_eq!(real, unknown);
        assert_eq!(
            try_login(&server, &mut rng, "dave", &dave_sk, PASSWORD).await,
            None
        );
        assert_eq!(
            try_login(&server, &mut rng, "carol", &carol_sk, PASSWORD).await,
            Some(false)
        );
        // dave recovers through his enrolled device: device authentication still works, and
        // the device session re-registers the typed password under #2 (ADR 0031 point 7).
        dave.session = device_session(&server, &dave.state, &dave.unlocked)
            .await
            .unwrap();
        assert!(dave.session.reregister());
        reregister_device(&server, &mut rng, &mut dave).await;
        assert_eq!(
            try_login(&server, &mut rng, "dave", &dave_sk, PASSWORD).await,
            Some(false)
        );
        // alice recovers with her recovery code, which registers under the current setup.
        assert_eq!(
            try_login(&server, &mut rng, NAME, &alice_sk, PASSWORD).await,
            None
        );
        let (_done, new_sk, _code) =
            recover(&server, &mut rng, alice_code.as_deref().unwrap(), false).await;
        assert_eq!(
            try_login(&server, &mut rng, NAME, &new_sk, NEW_PASSWORD).await,
            Some(false)
        );
        assert_eq!(record_setups(&server).await, vec![2, 2, 2]);
        drop(server.stop().await);
    });
}

#[test]
fn a_crash_between_the_steps_fails_closed_and_a_rerun_finishes() {
    block_on(async {
        let dir = TempDir::new();
        let config = instance(&dir);
        let server = Server::open(dir, &config, |_| {}).await;
        let mut rng = ChaCha20Rng::seed_from_u64(3102);
        let _ = signup(&server, &mut rng, false).await;
        let dir = server.stop().await;
        admin::secrets_rotate(&config, Rotate::Setup).await.unwrap();
        let server = Server::open(dir, &config, |_| {}).await;
        let db = server.services.db.clone();

        // Step 1 of `--grace-days 0` alone: the process died before it wrote the file.
        let first = now_ms();
        let loaded = rizzy_server::secrets_file::load(&config.secrets_file).unwrap();
        let plan = loaded.plan_retirement(&db, first, 0).await.unwrap();
        assert_eq!(plan.iter().map(|s| s.setup_id).collect::<Vec<_>>(), vec![1]);
        rizzy_domain_auth::ServerSecrets::retire_in_database(&db, &[1], first)
            .await
            .unwrap();
        drop(db);
        let dir = server.stop().await;
        match open_services(&config).await {
            Err(ServeError::SecretsMismatch(StartupCheckError::RetiredSetupLoaded {
                setup_id: 1,
            })) => {}
            Err(e) => panic!("{e}"),
            Ok(_) => panic!("a retired setup was loaded"),
        }
        // The re-run with the default 90 days: nothing new is selected, the setup is dropped
        // from the file, and the first retirement time stays.
        let report = admin::secrets_retire_setups(&config, 90).await.unwrap();
        assert!(report.selected.is_empty());
        assert_eq!(report.removed, vec![1]);
        let server = Server::open(dir, &config, |_| {}).await;
        assert_eq!(
            setup_rows(&server).await,
            vec![(1, Some(i64::try_from(first).unwrap())), (2, None)]
        );
        // And once more: nothing to do, the file unchanged.
        let dir = server.stop().await;
        let before = std::fs::read(&config.secrets_file).unwrap();
        let report = admin::secrets_retire_setups(&config, 0).await.unwrap();
        assert!(report.selected.is_empty() && report.removed.is_empty());
        assert_eq!(std::fs::read(&config.secrets_file).unwrap(), before);
        // A grace period out of range is refused before anything runs.
        assert!(admin::secrets_retire_setups(&config, 3651).await.is_err());
        drop(dir);
    });
}

/// A credential change of `client` (account `name`, Secret Key `sk`) built over a fresh
/// re-authentication and confirmed, as `rv` persists it before the commit leaves: the bearer
/// token, the commit body, the pending record, and the new kit's Secret Key if any.
async fn stored_change(
    server: &Server,
    rng: &mut ChaCha20Rng,
    client: &mut Client,
    name: &str,
    sk: &str,
    input: &CredentialChangeInput<'_>,
) -> (
    rizzy_domain_auth::types::SessionToken,
    Vec<u8>,
    DeviceRecord,
    Option<String>,
) {
    let reauth = login_named(
        server,
        rng,
        name,
        sk,
        Some((&mut client.session, &client.unlocked)),
    )
    .await;
    let token = copy_token(reauth.bearer_token());
    let (started, request) =
        start_credential_change(rng, reauth, &client.state, &client.unlocked, input).unwrap();
    let reply = post(
        server,
        "/api/v1/account/reregister/start",
        &request,
        Auth::Bearer(&token),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let mut pending = started
        .finish(rng, &reply.json(), &client.state, &client.unlocked, &[])
        .unwrap();
    let new_sk = pending.emergency_kit().map(|k| k.secret_key().to_owned());
    if let Some(new_sk) = &new_sk {
        pending
            .confirm_kit(new_sk.rsplit('-').next().unwrap())
            .unwrap();
    }
    let record = client.state.record(Stage::Committed).unwrap().with_pending(
        pending
            .pending_record(rng, &client.state, &client.unlocked)
            .unwrap(),
    );
    let body = serde_json::to_vec(pending.commit_request().unwrap()).unwrap();
    (token, body, record, new_sk)
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "two pending changes, each across a stop, an admin command and a restart"
)]
fn pending_changes_cross_a_rotation_and_a_retirement() {
    block_on(async {
        let dir = TempDir::new();
        let config = instance(&dir);
        let server = Server::open(dir, &config, |_| {}).await;
        let mut rng = ChaCha20Rng::seed_from_u64(3103);
        let (alice_up, alice_sk, _) = signup(&server, &mut rng, false).await;
        let (bob_up, bob_sk, _) = signup_named(&server, &mut rng, "bob", false).await;
        let mut alice = Client::signed_up(&server, alice_up).await;
        let mut bob = Client::signed_up(&server, bob_up).await;

        // 1. alice's password change, started under #1, stored and not sent.
        let password_change = CredentialChangeInput {
            login_name: NAME,
            new_password: "a second password",
            new_secret_key: false,
            rotate: false,
            full_rotation: false,
            recovery_code: None,
            now_ms: now_ms(),
        };
        let (token, body, _, _) = stored_change(
            &server,
            &mut rng,
            &mut alice,
            NAME,
            &alice_sk,
            &password_change,
        )
        .await;
        // `secrets rotate` and a restart: the stored body is accepted byte for byte (the
        // commit ends the OPAQUE sessions, so it is sent once).
        let dir = server.stop().await;
        admin::secrets_rotate(&config, Rotate::Setup).await.unwrap();
        let server = Server::open(dir, &config, |_| {}).await;
        let reply = server
            .post_raw("/api/v1/account/commit", body.clone(), Some(&token))
            .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT, "{}", reply.error());
        // Labelled with the setup its registration started under: #1, not the current #2.
        assert_eq!(
            try_login(&server, &mut rng, NAME, &alice_sk, "a second password").await,
            Some(true)
        );

        // 2. bob's Secret Key change, started under #2, stored with its pending record.
        let sk_change = CredentialChangeInput {
            login_name: "bob",
            new_password: PASSWORD,
            new_secret_key: true,
            rotate: false,
            full_rotation: false,
            recovery_code: None,
            now_ms: now_ms(),
        };
        let (token, body, record, new_sk) =
            stored_change(&server, &mut rng, &mut bob, "bob", &bob_sk, &sk_change).await;
        let new_sk = new_sk.unwrap();
        let before = bob.refresh(&server).await;
        // `secrets rotate` (#3), a start that records it, then `retire-setups --grace-days 0`
        // (#1 and #2) and a restart.
        let dir = server.stop().await;
        admin::secrets_rotate(&config, Rotate::Setup).await.unwrap();
        let dir = Server::open(dir, &config, |_| {}).await.stop().await;
        let report = admin::secrets_retire_setups(&config, 0).await.unwrap();
        assert_eq!(report.removed, vec![1, 2]);
        let server = Server::open(dir, &config, |_| {}).await;
        // The resend is refused with its own code (not `state_conflict`).
        let reply = server
            .post_raw("/api/v1/account/commit", body.clone(), Some(&token))
            .await;
        assert_eq!(reply.status, StatusCode::CONFLICT);
        assert_eq!(reply.error(), "setup_retired");
        // The restart of ADR 0031 point 8 from the stored request, as `rv` runs it.
        let promoted = DeviceRecord::parse(&record.encode().unwrap())
            .unwrap()
            .promote_pending();
        let pending_unlocked = record.unlock_pending(PASSWORD).unwrap();
        let restart = promoted.registration_restart(&mut rng, PASSWORD).unwrap();
        let reply = post(
            &server,
            "/api/v1/account/reregister/start",
            &restart.reregister_request(),
            Auth::Bearer(&token),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let mut request: CommitChangeRequest = serde_json::from_slice(&body).unwrap();
        let original = request.clone();
        restart
            .rebuild_commit(&mut rng, &reply.json(), &pending_unlocked, &mut request)
            .unwrap();
        assert_eq!(request.setup_id, Some(3));
        assert_eq!(request.account_state, original.account_state);
        assert_ne!(request.registration_upload, original.registration_upload);
        post_empty(
            &server,
            "/api/v1/account/commit",
            &request,
            Auth::Bearer(&token),
        )
        .await;
        // The pending Secret Key logs in under #3; the old one does not; the account key did
        // not change.
        assert_eq!(
            try_login(&server, &mut rng, "bob", &new_sk, PASSWORD).await,
            Some(false)
        );
        assert_eq!(
            try_login(&server, &mut rng, "bob", &bob_sk, PASSWORD).await,
            None
        );
        let after = login_named(&server, &mut rng, "bob", &new_sk, None).await;
        assert_eq!(
            after.account().state().account_key_id,
            before.state().account_key_id
        );
        assert_eq!(
            after.account().state().account_key_epoch,
            before.state().account_key_epoch
        );
        assert_eq!(
            promoted.secret_key_text().as_str(),
            new_sk.as_str(),
            "the pending record's Secret Key is the kit's"
        );
        drop(server.stop().await);
    });
}
