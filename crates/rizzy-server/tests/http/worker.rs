//! The worker on `SQLite` (ADR 0010 §2): the writer lock the database holds makes this process
//! the only writer, so the worker leads at once, stays leading across runs, and runs every step.
//!
//! And the data-key rotation end to end (CRYPTO.md §5.11 "Rotation"), as the operator runs it:
//! `secrets rotate --data-key` with the server stopped, the worker re-sealing the 2FA secrets
//! after the restart, and the old key dropped by the next rotation once no row names it.

use axum::http::StatusCode;
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_server::admin::{self, AdminError, Rotate, Rotated};
use rizzy_server::secrets_file;
use rizzy_server::worker::{RunReport, run_once};
use rizzy_storage::{Database, Engine, Value};

use crate::common::{Server, TempDir, block_on, config_in};
use crate::rotation::{Auth, call, copy_token, login, signup};

#[test]
fn sqlite_worker_leads_and_runs() {
    block_on(async {
        let server = Server::start().await;
        let db = &server.services.db;
        let mut leader = db.try_lead_worker().await.unwrap().unwrap();
        assert_eq!(leader.engine(), Engine::Sqlite);
        for _ in 0..2 {
            let report = run_once(&server.services.api, db, None, &mut leader).await;
            assert_eq!(
                report,
                RunReport::default(),
                "an empty database: nothing to do"
            );
            assert!(!report.leadership_lost);
        }
        assert!(leader.is_held().await.unwrap());
        leader.release().await.unwrap();
    });
}

/// The `data_key_id` of every TOTP row, in the backup's row order.
async fn totp_data_keys(db: &Database) -> Vec<i64> {
    let dump = db.dump().await.unwrap();
    let table = dump
        .tables
        .iter()
        .find(|t| t.table == "auth_totp_credentials")
        .unwrap();
    table
        .rows
        .iter()
        .map(|row| match row.get(2) {
            Some(Value::Integer(id)) => *id,
            other => panic!("data_key_id is an integer, not {other:?}"),
        })
        .collect()
}

/// The ids of the data keys in the secrets file at `path`, and the current one.
fn file_data_keys(path: &std::path::Path) -> (Vec<u32>, u32) {
    let secrets = secrets_file::load(path).unwrap();
    (
        secrets
            .data_keys()
            .map(rizzy_domain_auth::types::ServerDataKey::data_key_id)
            .collect(),
        secrets.current_data_key_id(),
    )
}

/// One worker run on `server`, as the leader.
async fn worker_run(server: &Server) -> RunReport {
    let db = &server.services.db;
    let mut leader = db.try_lead_worker().await.unwrap().unwrap();
    let report = run_once(&server.services.api, db, None, &mut leader).await;
    leader.release().await.unwrap();
    report
}

#[test]
fn a_rotated_data_key_reseals_in_the_worker_and_drops_the_old_key() {
    block_on(async {
        let dir = TempDir::new();
        let config = config_in(&dir, &[]);
        admin::secrets_init(&config).unwrap();
        let server = Server::open(dir, &config, |_| {}).await;

        // An account with a TOTP enrolment, sealed by the server under data key 1.
        let mut rng = ChaCha20Rng::seed_from_u64(61);
        let (_signed_up, sk, _code) = signup(&server, &mut rng, false).await;
        let logged_in = login(&server, &mut rng, &sk, None).await;
        let token = copy_token(logged_in.bearer_token());
        let reply = call(
            &server,
            "POST",
            "/api/v1/totp/enrol/start",
            Vec::new(),
            Auth::Bearer(&token),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(totp_data_keys(&server.services.db).await, vec![1]);
        let run = worker_run(&server).await;
        assert_eq!((run.totp_rows_resealed, run.totp_reseal_failures), (0, 0));

        // The rotation needs the server stopped (ADR 0010 §2), and leaves the file alone
        // otherwise.
        let before = std::fs::read(&config.secrets_file).unwrap();
        assert!(matches!(
            admin::secrets_rotate(&config, Rotate::DataKey).await,
            Err(AdminError::Lock(_))
        ));
        assert_eq!(std::fs::read(&config.secrets_file).unwrap(), before);
        let dir = server.stop().await;
        assert_eq!(
            admin::secrets_rotate(&config, Rotate::DataKey)
                .await
                .unwrap(),
            Rotated {
                id: 2,
                dropped_data_keys: Vec::new()
            },
            "key 1 stays: the TOTP row names it"
        );
        assert_eq!(file_data_keys(&config.secrets_file), (vec![1, 2], 2));

        // The restarted server's worker re-seals the row under key 2, once.
        let server = Server::open(dir, &config, |_| {}).await;
        let run = worker_run(&server).await;
        assert_eq!((run.totp_rows_resealed, run.totp_reseal_failures), (1, 0));
        assert_eq!(totp_data_keys(&server.services.db).await, vec![2]);
        let run = worker_run(&server).await;
        assert_eq!((run.totp_rows_resealed, run.totp_reseal_failures), (0, 0));
        let dir = server.stop().await;

        // No row names key 1 any more: the next rotation drops it, and keeps key 2.
        assert_eq!(
            admin::secrets_rotate(&config, Rotate::DataKey)
                .await
                .unwrap(),
            Rotated {
                id: 3,
                dropped_data_keys: vec![1]
            }
        );
        assert_eq!(file_data_keys(&config.secrets_file), (vec![2, 3], 3));
        // A setup rotation drops nothing.
        assert_eq!(
            admin::secrets_rotate(&config, Rotate::Setup).await.unwrap(),
            Rotated {
                id: 2,
                dropped_data_keys: Vec::new()
            }
        );
        assert_eq!(file_data_keys(&config.secrets_file), (vec![2, 3], 3));

        // The server starts with that file (its startup check finds every named key) and
        // moves the row on.
        let server = Server::open(dir, &config, |_| {}).await;
        let run = worker_run(&server).await;
        assert_eq!((run.totp_rows_resealed, run.totp_reseal_failures), (1, 0));
        assert_eq!(totp_data_keys(&server.services.db).await, vec![3]);
        drop(server.stop().await);
    });
}

/// `RIZZY_RECOVERY_WAIT_HOURS` reaches the auth domain (ADR 0008 decision 5): 72 h by default,
/// and the operator's value otherwise. (`recovery.rs` runs whole recoveries with 0.)
#[test]
fn the_recovery_wait_setting_reaches_the_auth_domain() {
    block_on(async {
        let server = Server::start().await;
        assert_eq!(
            server.services.api.auth.config().recovery_wait_ms,
            72 * 3_600_000
        );
        drop(server.stop().await);
        for (hours, ms) in [("0", 0), ("1", 3_600_000), ("720", 720 * 3_600_000)] {
            let server =
                Server::start_with(&[(rizzy_server::config::RECOVERY_WAIT_HOURS, hours)]).await;
            assert_eq!(server.services.api.auth.config().recovery_wait_ms, ms);
            drop(server.stop().await);
        }
    });
}
