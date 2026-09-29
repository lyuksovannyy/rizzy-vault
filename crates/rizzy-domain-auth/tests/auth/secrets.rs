//! The server secrets' startup checks (CRYPTO.md §5.8, §5.11) and what the database never
//! holds (INV-8, INV-50).

use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_core::opaque::{EnumKey, ServerSetup};
use rizzy_core::server_seal::ServerDataKey;
use rizzy_domain_auth::{ServerSecrets, StartupCheckError};
use rizzy_storage::Value;
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;

use crate::common::{Env, block_on};

/// Whether `needle` occurs in `hay`.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// A fresh secrets file next to a database that has records is refused; so is a file that
/// lacks a data key a sealed row names.
#[test]
fn startup_checks() {
    block_on(async {
        let mut env = Env::new(70).await;
        let client = env.signup("max", "pw").await;
        env.login(&client).await;

        let other = ServerSecrets::generate(&mut ChaCha20Rng::seed_from_u64(99));
        assert_eq!(
            other.check_database(&env.db, env.now).await.unwrap(),
            Err(StartupCheckError::SetupMismatch { setup_id: 1 })
        );

        // The same setup and enum key, but only a new data key 2: a pending login state is
        // sealed under key 1, so this file is refused.
        let (_, setup) = env.secrets.setups().next().unwrap();
        let setup = ServerSetup::from_bytes(setup.to_bytes().expose_secret()).unwrap();
        let enum_key = EnumKey::from_slice(env.secrets.enum_key().expose_secret()).unwrap();
        let key2 = ServerDataKey::generate(&mut ChaCha20Rng::seed_from_u64(5), 2);
        let _pending = env.login_as_start_only(&client.name).await;
        let missing =
            ServerSecrets::from_parts(1, vec![(1, setup)], enum_key, vec![key2], 2, None).unwrap();
        assert_eq!(
            missing.check_database(&env.db, env.now).await.unwrap(),
            Err(StartupCheckError::MissingDataKey { data_key_id: 1 })
        );
        // Another format is refused outright.
        let setup = ServerSetup::generate(&mut ChaCha20Rng::seed_from_u64(6));
        let enum_key = EnumKey::generate(&mut ChaCha20Rng::seed_from_u64(7));
        let key = ServerDataKey::generate(&mut ChaCha20Rng::seed_from_u64(8), 1);
        assert!(
            ServerSecrets::from_parts(2, vec![(1, setup)], enum_key, vec![key], 1, None).is_err()
        );
        // Debug never prints a secret.
        let debug = format!("{:?}", env.secrets);
        assert!(!debug.contains(&format!("{:?}", env.secrets.bootstrap_token())));
    });
}

/// The same checks on a logical backup, before `rizzy-vault restore` loads it (ADR 0023 §5
/// step 4).
#[test]
fn dump_checks() {
    block_on(async {
        let mut env = Env::new(72).await;
        let client = env.signup("olga", "pw").await;
        env.login(&client).await;
        let dump = env.db.dump().await.unwrap();
        assert_eq!(env.secrets.check_dump(&dump), Ok(()));

        // Another instance's secrets: setup 1 differs.
        let other = ServerSecrets::generate(&mut ChaCha20Rng::seed_from_u64(99));
        assert_eq!(
            other.check_dump(&dump),
            Err(StartupCheckError::SetupMismatch { setup_id: 1 })
        );
        // A file whose only setup the backup does not record, next to OPAQUE records.
        let setup = ServerSetup::generate(&mut ChaCha20Rng::seed_from_u64(10));
        let enum_key = EnumKey::generate(&mut ChaCha20Rng::seed_from_u64(11));
        let key = ServerDataKey::generate(&mut ChaCha20Rng::seed_from_u64(12), 1);
        let fresh =
            ServerSecrets::from_parts(1, vec![(2, setup)], enum_key, vec![key], 1, None).unwrap();
        assert_eq!(
            fresh.check_dump(&dump),
            Err(StartupCheckError::NoRecordedSetup)
        );

        // A TOTP row sealed under a data key the file lacks.
        let mut sealed = dump.clone();
        let totp = sealed
            .tables
            .iter_mut()
            .find(|t| t.table == "auth_totp_credentials")
            .unwrap();
        totp.rows.push(vec![
            Value::Blob(vec![1; 16]),
            Value::Integer(1),
            Value::Integer(7),
            Value::Blob(vec![2; 60]),
            Value::Null,
            Value::Integer(0),
        ]);
        assert_eq!(
            env.secrets.check_dump(&sealed),
            Err(StartupCheckError::MissingDataKey { data_key_id: 7 })
        );
        let totp = sealed
            .tables
            .iter_mut()
            .find(|t| t.table == "auth_totp_credentials")
            .unwrap();
        totp.rows.last_mut().unwrap()[2] = Value::Integer(-1);
        assert_eq!(
            env.secrets.check_dump(&sealed),
            Err(StartupCheckError::DumpShape)
        );

        // A dump without the tables the check reads.
        let mut partial = dump;
        partial.tables.retain(|t| t.table != "auth_credentials");
        assert_eq!(
            env.secrets.check_dump(&partial),
            Err(StartupCheckError::DumpShape)
        );
    });
}

/// The database holds session tokens as SHA-256 only, TOTP secrets and login states sealed,
/// and no server secret (INV-8, INV-50).
#[test]
fn database_holds_no_secret() {
    block_on(async {
        let mut env = Env::new(71).await;
        let client = env.signup("ned", "pw").await;
        let login = env.login(&client).await;
        let token = *login.response.session_token.expose_secret();
        let fresh = env.bearer(&login.response.session_token).await;
        let enrolment = env
            .svc
            .totp_enrol_start(&mut env.rng, &fresh, env.now)
            .await
            .unwrap();
        env.login_as_start_only(&client.name).await;

        let rizzy_storage::Database::Sqlite(_) = &env.db else {
            panic!("the tests run on SQLite")
        };
        let mut blobs: Vec<Vec<u8>> = Vec::new();
        let mut tx = env.db.begin_read().await.unwrap();
        let rizzy_storage::Conn::Sqlite(c) = tx.conn() else {
            panic!("SQLite")
        };
        let hashes: Vec<Vec<u8>> = sqlx::query("SELECT token_hash FROM auth_sessions")
            .fetch_all(&mut *c)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.get::<Vec<u8>, _>(0))
            .collect();
        assert!(hashes.contains(&Sha256::digest(token).to_vec()));
        for query in [
            "SELECT token_hash FROM auth_sessions",
            "SELECT session_id FROM auth_sessions",
            "SELECT sealed_secret FROM auth_totp_credentials",
            "SELECT sealed_state FROM auth_login_states",
        ] {
            for row in sqlx::query(query).fetch_all(&mut *c).await.unwrap() {
                blobs.push(row.get::<Vec<u8>, _>(0));
            }
        }
        drop(tx);
        for table in env.db.dump().await.unwrap().tables {
            for row in table.rows {
                for value in row {
                    match value {
                        Value::Blob(b) => blobs.push(b),
                        Value::Text(t) => blobs.push(t.into_bytes()),
                        Value::Null | Value::Integer(_) => {}
                    }
                }
            }
        }
        let (_, setup) = env.secrets.setups().next().unwrap();
        let secrets: Vec<Vec<u8>> = vec![
            token.to_vec(),
            enrolment.secret.expose_secret().to_vec(),
            setup.to_bytes().expose_secret().to_vec(),
            env.secrets.enum_key().expose_secret().to_vec(),
            env.secrets
                .data_keys()
                .next()
                .unwrap()
                .expose_secret()
                .to_vec(),
            client.recovery_token().to_vec(),
        ];
        for blob in &blobs {
            for secret in &secrets {
                assert!(!contains(blob, secret), "a secret reached the database");
            }
        }
    });
}

impl Env {
    /// A `login_start` for `name`, leaving a sealed login state behind.
    pub(crate) async fn login_as_start_only(&mut self, name: &str) {
        let sk = rizzy_core::secret_key::SecretKey::generate(&mut self.rng);
        let pw_in = rizzy_core::opaque::PasswordInput::derive("x", &sk).unwrap();
        let (_, ke1) = rizzy_core::opaque::client_login_start(&mut self.rng, &pw_in).unwrap();
        let req = rizzy_proto::auth::LoginStartRequest {
            login_name: rizzy_proto::wire::Text::new(name.to_owned()).unwrap(),
            ke1: crate::common::bytes(ke1),
        };
        self.svc
            .login_start(&mut self.rng, &req, &self.source, None, self.now)
            .await
            .unwrap();
    }
}
