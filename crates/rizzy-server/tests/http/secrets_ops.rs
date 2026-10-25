// SPDX-License-Identifier: AGPL-3.0-only

//! The OPAQUE secrets operator commands end to end ([ADR 0047]): `rizzy-client` against the
//! router and the admin commands, over a real `SQLite` database and secrets file.
//!
//! - [`a_restored_secrets_file_brings_the_logins_back`]: the file is lost, the server refuses
//!   to start; `secrets restore` refuses another instance's backup and a wrong passphrase,
//!   writing nothing; the right backup comes back byte for byte (its ADR 0071 backup key too),
//!   and every account logs in again. Restoring an older backup over the file after a setup
//!   rotation reports the account on the setup it lacks, without blocking.
//! - [`invalidate_after_a_setup_only_loss`]: a file whose setup no longer matches; the
//!   diagnosis without `--confirm`; with it, every setup retired, the keys and the TOTP row
//!   kept, and every account back through its enrolled device or its recovery code.
//! - [`invalidate_after_a_whole_loss`]: the file is gone; every TOTP row deleted, no
//!   bootstrap token, fresh keys, and the account back through its enrolled device.
//! - [`a_crash_before_the_file_is_written_resumes_from_the_marker`]: step 4 done, the file
//!   never written, for both cases; the re-run follows the marker (where diagnosing the file
//!   alone would refuse it) and mints a fresh setup; a crash after the file was written only
//!   clears the marker.
//!
//! [ADR 0047]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0047-opaque-secrets-operator-commands.md

use axum::http::StatusCode;
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_domain_auth::invalidation::{
    InvalidationCost, LossCase, PendingInvalidation, invalidate_in_database, pending_invalidation,
};
use rizzy_domain_auth::types::{EnumKey, ServerDataKey, ServerSetup};
use rizzy_domain_auth::{ServerSecrets, StartupCheckError};
use rizzy_server::admin::{
    self, AdminError, InvalidateDiagnosis, Rotate, SecretsInvalidated, SecretsRestored,
};
use rizzy_server::config::Config;
use rizzy_server::secrets_backup::BackupError;
use rizzy_server::server::{ServeError, open_services};
use rizzy_server::{cli, secrets_file};
use zeroize::Zeroizing;

use crate::common::{Server, TempDir, block_on};
use crate::recovery::{NEW_PASSWORD, recover};
use crate::rotation::{
    Auth, Client, NAME, PASSWORD, call, copy_token, device_session, login_named, signup,
    signup_named,
};
use crate::setups::{instance, record_setups, reregister_device, setup_rows, try_login};

/// The operator's passphrase file, written next to the instance.
fn passphrase_file(config: &Config) -> std::path::PathBuf {
    let path = config.secrets_file.with_file_name("passphrase");
    std::fs::write(&path, "an operator passphrase for the drill\n").unwrap();
    path
}

/// The number of TOTP rows.
async fn totp_rows(server: &Server) -> usize {
    let dump = server.services.db.dump().await.unwrap();
    dump.tables
        .iter()
        .find(|t| t.table == "auth_totp_credentials")
        .unwrap()
        .rows
        .len()
}

/// Starts a TOTP enrolment for the account `sk` belongs to: the server stores the row, sealed
/// under the current data key.
async fn totp_row_for(server: &Server, rng: &mut ChaCha20Rng, name: &str, sk: &str) {
    let logged_in = login_named(server, rng, name, sk, None).await;
    let token = copy_token(logged_in.bearer_token());
    let reply = call(
        server,
        "POST",
        "/api/v1/totp/enrol/start",
        Vec::new(),
        Auth::Bearer(&token),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
}

/// The start refusal of `config`'s instance.
async fn start_refusal(config: &Config) -> ServeError {
    match open_services(config).await {
        Err(e) => e,
        Ok(_) => panic!("the server started"),
    }
}

#[test]
fn a_restored_secrets_file_brings_the_logins_back() {
    block_on(async {
        let dir = TempDir::new();
        let config = instance(&dir);
        let server = Server::open(dir, &config, |_| {}).await;
        let mut rng = ChaCha20Rng::seed_from_u64(4711);
        let (_carol, carol_sk, _) = signup_named(&server, &mut rng, "carol", false).await;
        let (_dave, dave_sk, _) = signup_named(&server, &mut rng, "dave", false).await;
        let dir = server.stop().await;
        // A backup key (ADR 0071), then the secrets backup.
        assert_eq!(
            admin::secrets_rotate(&config, Rotate::BackupKey)
                .await
                .unwrap()
                .id,
            1
        );
        let original = std::fs::read(&config.secrets_file).unwrap();
        let passphrase = passphrase_file(&config);
        let backup = config.secrets_file.with_file_name("secrets-backup.json");
        admin::backup_secrets(&config, &backup, &passphrase).unwrap();
        // Another instance's backup, under the same passphrase.
        let other_dir = TempDir::new();
        let other = instance(&other_dir);
        let other_backup = config.secrets_file.with_file_name("other-backup.json");
        admin::backup_secrets(&other, &other_backup, &passphrase).unwrap();

        // The file is lost: the server refuses to start.
        std::fs::remove_file(&config.secrets_file).unwrap();
        assert!(matches!(
            start_refusal(&config).await,
            ServeError::Secrets(_)
        ));
        // Another instance's backup: refused, nothing written.
        match admin::secrets_restore(&config, &other_backup, &passphrase).await {
            Err(AdminError::SecretsBackupMismatch(StartupCheckError::SetupMismatch {
                setup_id: 1,
            })) => {}
            other => panic!("{other:?}"),
        }
        assert!(!config.secrets_file.exists());
        // A wrong passphrase: refused, nothing written.
        let wrong = config.secrets_file.with_file_name("wrong");
        std::fs::write(&wrong, "not the passphrase").unwrap();
        assert!(matches!(
            admin::secrets_restore(&config, &backup, &wrong).await,
            Err(AdminError::Backup(BackupError::Decrypt))
        ));
        assert!(!config.secrets_file.exists());

        // The right backup: the file comes back byte for byte, backup key included.
        let restored = admin::secrets_restore(&config, &backup, &passphrase)
            .await
            .unwrap();
        assert_eq!(
            restored,
            SecretsRestored {
                created: true,
                database_empty: false,
                missing_setups: Vec::new()
            }
        );
        assert_eq!(std::fs::read(&config.secrets_file).unwrap(), original);
        assert_eq!(
            secrets_file::load(&config.secrets_file)
                .unwrap()
                .current_backup_key_id(),
            Some(1)
        );
        let server = Server::open(dir, &config, |_| {}).await;
        for (name, sk) in [("carol", &carol_sk), ("dave", &dave_sk)] {
            assert_eq!(
                try_login(&server, &mut rng, name, sk, PASSWORD).await,
                Some(false),
                "{name}"
            );
        }

        // A setup rotation, and an account on the new setup; then the older backup over the
        // file: it still fits the database, and the account on setup 2 is reported.
        let dir = server.stop().await;
        admin::secrets_rotate(&config, Rotate::Setup).await.unwrap();
        let server = Server::open(dir, &config, |_| {}).await;
        let (_erin, erin_sk, _) = signup_named(&server, &mut rng, "erin", false).await;
        assert_eq!(record_setups(&server).await, [1, 1, 2]);
        let dir = server.stop().await;
        let restored = admin::secrets_restore(&config, &backup, &passphrase)
            .await
            .unwrap();
        assert!(!restored.created);
        assert_eq!(restored.missing_setups, [(2, 1)]);
        let printed = cli::secrets_restore_message(&restored);
        assert!(
            printed.contains("(replaced)")
                && printed.contains("OPAQUE setup 2 is not in this backup: 1 account record(s)"),
            "{printed}"
        );
        assert_eq!(std::fs::read(&config.secrets_file).unwrap(), original);
        let server = Server::open(dir, &config, |_| {}).await;
        assert_eq!(
            try_login(&server, &mut rng, "erin", &erin_sk, PASSWORD).await,
            None,
            "erin's setup is not in the file: the missing-setup path"
        );
        assert_eq!(
            try_login(&server, &mut rng, "carol", &carol_sk, PASSWORD).await,
            Some(false)
        );
        drop(server.stop().await);
        drop(other_dir);
    });
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one instance's life: the loss, the diagnosis, the command, every account back"
)]
fn invalidate_after_a_setup_only_loss() {
    block_on(async {
        let dir = TempDir::new();
        let config = instance(&dir);
        let server = Server::open(dir, &config, |_| {}).await;
        let mut rng = ChaCha20Rng::seed_from_u64(4712);
        let (alice_up, alice_sk, alice_code) = signup(&server, &mut rng, true).await;
        let (carol_up, carol_sk, _) = signup_named(&server, &mut rng, "carol", false).await;
        totp_row_for(&server, &mut rng, "carol", &carol_sk).await;
        assert_eq!(totp_rows(&server).await, 1);
        let mut carol = Client::signed_up(&server, carol_up).await;
        drop(alice_up);
        let dir = server.stop().await;

        // The loss: the same file, but its setup 1 is a different one.
        let old = secrets_file::load(&config.secrets_file).unwrap();
        let (old_enum, old_token) = (
            old.enum_key().expose_secret().to_vec(),
            old.bootstrap_token().map(<[u8]>::to_vec),
        );
        let broken = ServerSecrets::generate_after_loss(
            &mut rng,
            1,
            ServerSetup::generate(&mut ChaCha20Rng::seed_from_u64(1)),
            Some(old),
        );
        let broken = secrets_file::serialize(&broken).unwrap();
        std::fs::write(&config.secrets_file, &broken).unwrap();
        assert!(matches!(
            start_refusal(&config).await,
            ServeError::SecretsMismatch(StartupCheckError::SetupMismatch { setup_id: 1 })
        ));
        // A matching backup does not exist; `restore` would be refused. The diagnosis first.
        let refused = admin::secrets_invalidate(&config, false).await.unwrap_err();
        assert_eq!(
            match &refused {
                AdminError::ConfirmRequired(d) => *d,
                other => panic!("{other}"),
            },
            InvalidateDiagnosis::Loss {
                case: LossCase::SetupOnly,
                resumed: None,
                cost: InvalidationCost {
                    accounts: 2,
                    totp_enrolments: 0
                }
            }
        );
        assert!(refused.is_usage());
        let text = refused.to_string();
        assert!(
            text.contains("needs --confirm") && text.contains("setup-only loss"),
            "{text}"
        );
        assert_eq!(
            std::fs::read(&config.secrets_file).unwrap().as_slice(),
            broken.as_slice()
        );

        let done = admin::secrets_invalidate(&config, true).await.unwrap();
        let SecretsInvalidated::Invalidated { outcome, resumed } = done else {
            panic!("{done:?}")
        };
        assert!(!resumed);
        assert_eq!(
            (
                outcome.case,
                outcome.setup_id,
                outcome.accounts,
                outcome.totp_rows_deleted
            ),
            (LossCase::SetupOnly, 2, 2, 0)
        );
        let printed = cli::secrets_invalidate_message(&done);
        assert!(
            printed.contains("new OPAQUE setup 2")
                && printed.contains("2 account(s) need to re-register")
                && printed.contains("0 TOTP enrollment(s)"),
            "{printed}"
        );
        let renewed = secrets_file::load(&config.secrets_file).unwrap();
        assert_eq!(renewed.setups().map(|(id, _)| id).collect::<Vec<_>>(), [2]);
        assert_eq!(
            renewed.enum_key().expose_secret().as_slice(),
            old_enum.as_slice()
        );
        assert_eq!(renewed.bootstrap_token().map(<[u8]>::to_vec), old_token);
        assert!(renewed.bootstrap_token().is_some());

        // The server starts; nothing was deleted but the setups' acceptance.
        let server = Server::open(dir, &config, |_| {}).await;
        assert_eq!(setup_rows(&server).await.len(), 2);
        assert!(setup_rows(&server).await[0].1.is_some());
        assert_eq!(totp_rows(&server).await, 1, "a setup-only loss keeps TOTP");
        assert_eq!(
            pending_invalidation(&server.services.db).await.unwrap(),
            None
        );
        // Password logins take the missing-setup path until the account re-registers.
        assert_eq!(
            try_login(&server, &mut rng, "carol", &carol_sk, PASSWORD).await,
            None
        );
        assert_eq!(
            try_login(&server, &mut rng, NAME, &alice_sk, PASSWORD).await,
            None
        );
        // carol through her enrolled device: the device session re-registers her password.
        carol.session = device_session(&server, &carol.state, &carol.unlocked)
            .await
            .unwrap();
        assert!(carol.session.reregister());
        reregister_device(&server, &mut rng, &mut carol).await;
        // alice with her recovery code.
        let (_done, new_sk, _code) =
            recover(&server, &mut rng, alice_code.as_deref().unwrap(), false).await;
        assert_eq!(
            try_login(&server, &mut rng, NAME, &new_sk, NEW_PASSWORD).await,
            Some(false)
        );
        assert_eq!(record_setups(&server).await, [2, 2]);
        // And the running server keeps a refused second run out.
        assert!(matches!(
            admin::secrets_invalidate(&config, true).await,
            Err(AdminError::Lock(_))
        ));
        drop(server.stop().await);
    });
}

#[test]
fn invalidate_after_a_whole_loss() {
    block_on(async {
        let dir = TempDir::new();
        let config = instance(&dir);
        let server = Server::open(dir, &config, |_| {}).await;
        let mut rng = ChaCha20Rng::seed_from_u64(4713);
        let (carol_up, carol_sk, _) = signup_named(&server, &mut rng, "carol", false).await;
        totp_row_for(&server, &mut rng, "carol", &carol_sk).await;
        let mut carol = Client::signed_up(&server, carol_up).await;
        let dir = server.stop().await;
        let old = secrets_file::load(&config.secrets_file).unwrap();
        let old_enum = old.enum_key().expose_secret().to_vec();

        std::fs::remove_file(&config.secrets_file).unwrap();
        match admin::secrets_invalidate(&config, false).await {
            Err(AdminError::ConfirmRequired(InvalidateDiagnosis::Loss {
                case: LossCase::Whole,
                resumed: None,
                cost:
                    InvalidationCost {
                        accounts: 1,
                        totp_enrolments: 1,
                    },
            })) => {}
            other => panic!("{other:?}"),
        }
        assert!(
            !config.secrets_file.exists(),
            "nothing written without --confirm"
        );
        let done = admin::secrets_invalidate(&config, true).await.unwrap();
        let SecretsInvalidated::Invalidated { outcome, .. } = done else {
            panic!("{done:?}")
        };
        assert_eq!(
            (outcome.case, outcome.setup_id, outcome.totp_rows_deleted),
            (LossCase::Whole, 2, 1)
        );
        assert!(cli::secrets_invalidate_message(&done).contains("no bootstrap token was made"));
        let renewed = secrets_file::load(&config.secrets_file).unwrap();
        assert!(renewed.bootstrap_token().is_none(), "INV-69");
        assert_ne!(
            renewed.enum_key().expose_secret().as_slice(),
            old_enum.as_slice()
        );
        assert_eq!(renewed.current_backup_key_id(), None);

        let server = Server::open(dir, &config, |_| {}).await;
        assert_eq!(
            totp_rows(&server).await,
            0,
            "a whole loss deletes every TOTP row"
        );
        assert_eq!(
            try_login(&server, &mut rng, "carol", &carol_sk, PASSWORD).await,
            None
        );
        carol.session = device_session(&server, &carol.state, &carol.unlocked)
            .await
            .unwrap();
        assert!(carol.session.reregister());
        reregister_device(&server, &mut rng, &mut carol).await;
        assert_eq!(
            try_login(&server, &mut rng, "carol", &carol_sk, PASSWORD).await,
            Some(false)
        );
        drop(server.stop().await);
    });
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "both cases' crash and re-run, and the crash after the file write"
)]
fn a_crash_before_the_file_is_written_resumes_from_the_marker() {
    block_on(async {
        // A setup-only loss whose first run died after step 4: setup 2 (rotated in and
        // recorded) is damaged in the file, setup 1 still matches.
        let dir = TempDir::new();
        let config = instance(&dir);
        let server = Server::open(dir, &config, |_| {}).await;
        let mut rng = ChaCha20Rng::seed_from_u64(4714);
        let (carol_up, carol_sk, _) = signup_named(&server, &mut rng, "carol", false).await;
        let mut carol = Client::signed_up(&server, carol_up).await;
        let dir = server.stop().await;
        admin::secrets_rotate(&config, Rotate::Setup).await.unwrap();
        let server = Server::open(dir, &config, |_| {}).await;
        let db = server.services.db.clone();
        let old = secrets_file::load(&config.secrets_file).unwrap();
        let old_enum = old.enum_key().expose_secret().to_vec();
        let (_, setup_1) = old.setups().next().unwrap();
        let broken = ServerSecrets::from_parts(
            1,
            vec![
                (
                    1,
                    ServerSetup::from_bytes(setup_1.to_bytes().expose_secret()).unwrap(),
                ),
                (2, ServerSetup::generate(&mut ChaCha20Rng::seed_from_u64(2))),
            ],
            EnumKey::from_slice(&old_enum).unwrap(),
            old.data_keys()
                .map(|k| ServerDataKey::from_slice(k.expose_secret(), k.data_key_id()).unwrap())
                .collect(),
            old.current_data_key_id(),
            old.bootstrap_token().map(|t| Zeroizing::new(t.to_vec())),
        )
        .unwrap();
        assert_eq!(
            broken.check_database_dry_run(&db).await.unwrap(),
            Err(StartupCheckError::SetupMismatch { setup_id: 2 })
        );
        let lost = ServerSetup::generate(&mut rng);
        invalidate_in_database(
            &db,
            LossCase::SetupOnly,
            &lost.public_key_hash(),
            10,
            10,
            |_| {},
        )
        .await
        .unwrap();
        // Diagnosing the unchanged file alone would now refuse it.
        assert_eq!(
            broken.check_database_dry_run(&db).await.unwrap(),
            Err(StartupCheckError::RetiredSetupLoaded { setup_id: 1 })
        );
        drop(db);
        let dir = server.stop().await;
        std::fs::write(
            &config.secrets_file,
            secrets_file::serialize(&broken).unwrap(),
        )
        .unwrap();
        match admin::secrets_invalidate(&config, false).await {
            Err(AdminError::ConfirmRequired(InvalidateDiagnosis::Loss {
                case: LossCase::SetupOnly,
                resumed:
                    Some(PendingInvalidation {
                        case: LossCase::SetupOnly,
                        setup_id: 3,
                        diagnosed_at_ms: 10,
                    }),
                ..
            })) => {}
            other => panic!("{other:?}"),
        }
        let done = admin::secrets_invalidate(&config, true).await.unwrap();
        let SecretsInvalidated::Invalidated { outcome, resumed } = done else {
            panic!("{done:?}")
        };
        assert!(resumed);
        assert_eq!((outcome.case, outcome.setup_id), (LossCase::SetupOnly, 4));
        assert!(cli::secrets_invalidate_message(&done).starts_with("resumed"));
        let renewed = secrets_file::load(&config.secrets_file).unwrap();
        assert_eq!(
            renewed.enum_key().expose_secret().as_slice(),
            old_enum.as_slice()
        );
        let server = Server::open(dir, &config, |_| {}).await;
        assert_eq!(setup_rows(&server).await, {
            let rows = setup_rows(&server).await;
            assert_eq!(rows.iter().map(|r| r.0).collect::<Vec<_>>(), [1, 2, 3, 4]);
            assert!(rows[..3].iter().all(|r| r.1.is_some()) && rows[3].1.is_none());
            rows
        });
        carol.session = device_session(&server, &carol.state, &carol.unlocked)
            .await
            .unwrap();
        reregister_device(&server, &mut rng, &mut carol).await;
        assert_eq!(
            try_login(&server, &mut rng, "carol", &carol_sk, PASSWORD).await,
            Some(false)
        );

        // A whole loss whose first run died after step 4, the file still absent: the re-run
        // resumes it and mints setup 6.
        let db = server.services.db.clone();
        invalidate_in_database(
            &db,
            LossCase::Whole,
            &ServerSetup::generate(&mut rng).public_key_hash(),
            20,
            20,
            |_| {},
        )
        .await
        .unwrap();
        drop(db);
        let dir = server.stop().await;
        std::fs::remove_file(&config.secrets_file).unwrap();
        let done = admin::secrets_invalidate(&config, true).await.unwrap();
        assert!(matches!(
            done,
            SecretsInvalidated::Invalidated {
                outcome: rizzy_domain_auth::invalidation::Invalidated {
                    case: LossCase::Whole,
                    setup_id: 6,
                    ..
                },
                resumed: true
            }
        ));

        // A crash after the file was written, before the marker was cleared: only the marker
        // goes. Step 4 by hand with a setup this test keeps, and its file.
        let server = Server::open(dir, &config, |_| {}).await;
        let db = server.services.db.clone();
        let setup = ServerSetup::generate(&mut rng);
        let marked = invalidate_in_database(
            &db,
            LossCase::Whole,
            &setup.public_key_hash(),
            30,
            30,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(marked.setup_id, 7);
        drop(db);
        let dir = server.stop().await;
        let written = ServerSecrets::generate_after_loss(&mut rng, 7, setup, None);
        let written = secrets_file::serialize(&written).unwrap();
        std::fs::write(&config.secrets_file, &written).unwrap();
        assert!(matches!(
            admin::secrets_invalidate(&config, false).await,
            Err(AdminError::ConfirmRequired(InvalidateDiagnosis::Finished {
                setup_id: 7
            }))
        ));
        assert_eq!(
            admin::secrets_invalidate(&config, true).await.unwrap(),
            SecretsInvalidated::MarkerCleared { setup_id: 7 }
        );
        assert_eq!(
            std::fs::read(&config.secrets_file).unwrap().as_slice(),
            written.as_slice()
        );
        let server = Server::open(dir, &config, |_| {}).await;
        assert_eq!(
            pending_invalidation(&server.services.db).await.unwrap(),
            None
        );
        // Now nothing is broken: a further run is refused.
        let dir = server.stop().await;
        assert!(matches!(
            admin::secrets_invalidate(&config, true).await,
            Err(AdminError::InvalidateRefused(None))
        ));
        drop(dir);
    });
}
