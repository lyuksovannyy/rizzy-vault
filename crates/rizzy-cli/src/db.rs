//! The `SQLite` executor of the local cache ([ADR 0026] §3–§5; ADR 0019 §5: "sqlx sits in …
//! `rizzy-cli` from M1"; owner decision on ADR 0026 open question 1: the sqlx code lives in the
//! leaf for M1).
//!
//! `rizzy-client`'s `store` module owns the schema, the row model and every decision about
//! what is written. This module only runs them:
//!
//! - [`Db::create`] makes the file (mode 0600, never over an existing one), runs the schema
//!   statements and the first changeset in **one** transaction, so a crash leaves either no
//!   cache or a complete one.
//! - [`Db::write`] runs one changeset as one `BEGIN IMMEDIATE` transaction (ADR 0026 §4: "a
//!   crash leaves the file before or after a step, never inside one"). The caller has passed
//!   the changeset through the store's floors first; the SQL checks the rules it can check a
//!   second time (a counter that would go down, another statement at a held dot, an `own`
//!   that would go back) and fails the whole transaction instead of writing.
//! - [`Db::read`] reads every table back into the store's row model, which then verifies every
//!   row ([`rizzy_client::store::load`]). Before any blob is read its length is checked in SQL
//!   against the `rizzy-proto` limit of its column, so a hostile file cannot make `rv`
//!   allocate in proportion to a length the file chooses.
//!
//! Connection settings are ADR 0026 §3's: `journal_mode=DELETE`, `synchronous=FULL`,
//! `secure_delete=ON` (best-effort hygiene only), `foreign_keys=ON`, `busy_timeout` 5 s.
//! Statements are constant SQL text with bound parameters; nothing is ever formatted into SQL
//! (threat model INV-53).
//!
//! The `vaults.self_grant` blob is the served JSON object of the grant, written and parsed
//! through the `rizzy-proto` type (see `rizzy_client::store::rows`, "Encodings").
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md

use std::path::Path;
use std::time::Duration;

use rizzy_client::ClientError;
use rizzy_client::rizzy_proto::limits::{
    MAX_ACCOUNT_STATEMENT_LEN, MAX_ENVELOPE_LEN, MAX_KEY_ENVELOPE_LEN, MAX_OP_STATEMENT_LEN,
    MAX_SNAPSHOT_STATEMENT_LEN, MAX_UPLOAD_BODY_LEN,
};
use rizzy_client::rizzy_proto::objects::VaultSelfGrant;
use rizzy_client::store::record::MAX_DEVICE_STATE_LEN;
use rizzy_client::store::rows::limits::{MAX_KEY_COLUMN_LEN, MAX_SELF_GRANT_JSON_LEN};
use rizzy_client::store::rows::{
    CacheRows, Changeset, ObjectRow, OpRow, PRAGMAS, SCHEMA, SnapshotRow, VaultRow, WrapRow, Write,
    kind, meta, own,
};
use sqlx_client as sqlx;
use sqlx_client::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqliteSynchronous,
};
use sqlx_client::{Connection as _, Row as _};
use zeroize::Zeroizing;

use crate::error::CliError;
use crate::paths::create_private_file;

/// `busy_timeout` (ADR 0026 §3): how long `BEGIN IMMEDIATE` waits for the write lock.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The start of every write transaction (ADR 0026 §3).
const BEGIN_IMMEDIATE: &str = "BEGIN IMMEDIATE";

/// Sets a counter of `cache_meta`; refuses a value below the stored one (8-byte big-endian
/// blobs compare as the numbers they hold).
const META_COUNTER: &str = "INSERT INTO cache_meta(k, v) VALUES(?1, ?2) \
     ON CONFLICT(k) DO UPDATE SET v = excluded.v WHERE cache_meta.v <= excluded.v";
/// Sets a set-once row of `cache_meta`; refuses another value.
const META_FIXED: &str = "INSERT INTO cache_meta(k, v) VALUES(?1, ?2) \
     ON CONFLICT(k) DO UPDATE SET v = excluded.v WHERE cache_meta.v = excluded.v";
/// Replaces the device-state record.
const PUT_DEVICE_STATE: &str = "INSERT INTO device_state(id, record) VALUES(1, ?1) \
     ON CONFLICT(id) DO UPDATE SET record = excluded.record";
/// Stores the pending commit.
const PUT_PENDING_COMMIT: &str = "INSERT INTO pending_commit(id, request) VALUES(1, ?1) \
     ON CONFLICT(id) DO UPDATE SET request = excluded.request";
/// Removes the pending commit.
const DELETE_PENDING_COMMIT: &str = "DELETE FROM pending_commit";
/// Inserts or replaces an account object.
const PUT_OBJECT: &str = "INSERT INTO account_objects(kind, key, bytes) VALUES(?1, ?2, ?3) \
     ON CONFLICT(kind, key) DO UPDATE SET bytes = excluded.bytes";
/// Inserts an account object that never changes; refuses other bytes at a held key.
const PUT_OBJECT_ONCE: &str = "INSERT INTO account_objects(kind, key, bytes) VALUES(?1, ?2, ?3) \
     ON CONFLICT(kind, key) DO UPDATE SET bytes = excluded.bytes \
     WHERE account_objects.bytes = excluded.bytes";
/// Removes one alarm row (the floors admit this for the identity-change alarm only).
const DELETE_ALARM: &str = "DELETE FROM account_objects WHERE kind = ?1 AND key = ?2";
/// Removes every certificate and revocation row.
const DELETE_DEVICE_SET: &str = "DELETE FROM account_objects WHERE kind IN (4, 5)";
/// Inserts a vault or replaces its self-grant.
const PUT_VAULT_GRANT: &str = "INSERT INTO vaults(vault_id, self_grant) VALUES(?1, ?2) \
     ON CONFLICT(vault_id) DO UPDATE SET self_grant = excluded.self_grant";
/// Sets a vault's restore generation.
const SET_VAULT_GENERATION: &str = "UPDATE vaults SET restore_generation = ?2 WHERE vault_id = ?1";
/// Removes a vault's wrap rows below an epoch.
const DELETE_OLD_WRAPS: &str = "DELETE FROM wraps WHERE vault_id = ?1 AND vault_key_epoch < ?2";
/// Inserts or replaces a wrap row.
const PUT_WRAP: &str = "INSERT INTO wraps(vault_id, item_id, item_key_id, vault_key_epoch, envelope) \
     VALUES(?1, ?2, ?3, ?4, ?5) ON CONFLICT(vault_id, item_id, item_key_id) DO UPDATE SET \
     vault_key_epoch = excluded.vault_key_epoch, envelope = excluded.envelope";
/// Inserts an op row, or fills a missing body or wrap of the same statement.
const PUT_OP: &str = "INSERT INTO ops(vault_id, device_id, device_seq, item_id, statement, body, \
     key_wrap, own, sent_generation) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL) \
     ON CONFLICT(vault_id, device_id, device_seq) DO UPDATE SET \
     body = COALESCE(ops.body, excluded.body), \
     key_wrap = COALESCE(ops.key_wrap, excluded.key_wrap) \
     WHERE ops.statement = excluded.statement";
/// Replaces an unsent own op by its re-issue (ADR 0026 §4 step 6).
const REISSUE_OP: &str = "UPDATE ops SET statement = ?4, body = ?5, key_wrap = ?6, own = 1, \
     sent_generation = NULL WHERE vault_id = ?1 AND device_id = ?2 AND device_seq = ?3 \
     AND (own = 1 OR (own = 3 AND sent_generation IS ?7))";
/// Marks an own op sent; the first send's generation stays.
const OP_SENT: &str = "UPDATE ops SET own = 3, sent_generation = COALESCE(sent_generation, ?4) \
     WHERE vault_id = ?1 AND device_id = ?2 AND device_seq = ?3 AND own IN (1, 3)";
/// Marks an own op acknowledged.
const OP_ACKNOWLEDGED: &str = "UPDATE ops SET own = 2 \
     WHERE vault_id = ?1 AND device_id = ?2 AND device_seq = ?3 AND own IN (3, 2)";
/// Inserts a snapshot row; a held one stays.
const PUT_SNAPSHOT: &str = "INSERT INTO snapshots(vault_id, snapshot_id, item_id, statement, \
     envelope, key_wrap, own, sent_generation) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL) \
     ON CONFLICT(vault_id, snapshot_id) DO NOTHING";
/// Marks an own snapshot sent.
const SNAPSHOT_SENT: &str = "UPDATE snapshots SET own = 3, sent_generation = COALESCE(sent_generation, ?3) \
     WHERE vault_id = ?1 AND snapshot_id = ?2 AND own IN (1, 3)";
/// Marks an own snapshot acknowledged.
const SNAPSHOT_ACKNOWLEDGED: &str = "UPDATE snapshots SET own = 2 \
     WHERE vault_id = ?1 AND snapshot_id = ?2 AND own IN (3, 2)";
/// Drops the body of a served op row (ADR 0026 §4 step 2); an own row keeps its body.
const PRUNE_OP_BODY: &str = "UPDATE ops SET body = NULL \
     WHERE vault_id = ?1 AND device_id = ?2 AND device_seq = ?3 AND own = 0";
/// Deletes an own snapshot the server never acknowledged.
const DELETE_SNAPSHOT: &str =
    "DELETE FROM snapshots WHERE vault_id = ?1 AND snapshot_id = ?2 AND own IN (1, 3)";

/// The rows of `cache_meta`, bounded.
// The caps here must equal `MAX_CACHE_META_KEY_LEN`/`MAX_CACHE_META_VALUE_LEN` (checked by
// `cache_meta_caps_match_the_sql_literal` below): a `const` cap cannot be interpolated into a
// `const` SQL string without a build-time format macro this build does not add for two
// numbers.
const SELECT_META: &str = "SELECT k, v FROM cache_meta WHERE length(k) <= 64 AND length(v) <= 1024";
/// How many `cache_meta` rows there are.
const COUNT_META: &str = "SELECT COUNT(*) FROM cache_meta";
/// The device-state record, if its length is within the cap.
const SELECT_DEVICE_STATE: &str = "SELECT record FROM device_state WHERE length(record) <= ?1";
/// How many device-state rows there are.
const COUNT_DEVICE_STATE: &str = "SELECT COUNT(*) FROM device_state";
/// The pending commit, if its length is within the cap.
const SELECT_PENDING_COMMIT: &str =
    "SELECT request FROM pending_commit WHERE length(request) <= ?1";
/// How many pending-commit rows there are.
const COUNT_PENDING_COMMIT: &str = "SELECT COUNT(*) FROM pending_commit";
/// The account objects over a column cap.
const OVERSIZE_OBJECTS: &str =
    "SELECT COUNT(*) FROM account_objects WHERE length(key) > ?1 OR length(bytes) > ?2";
/// The first two bytes of each alarm row's key (`?1` is the alarm kind): enough to tell a
/// one-byte alarm kind from anything else, whatever length the file claims.
const SELECT_ALARM_KEYS: &str =
    "SELECT CAST(substr(key, 1, 2) AS BLOB) FROM account_objects WHERE kind = ?1 ORDER BY key";
/// Every account object.
const SELECT_OBJECTS: &str = "SELECT kind, key, bytes FROM account_objects ORDER BY kind, key";
/// The vault rows over a column cap.
const OVERSIZE_VAULTS: &str = "SELECT COUNT(*) FROM vaults WHERE length(vault_id) > ?1 \
     OR length(self_grant) > ?2 OR length(restore_generation) > ?1";
/// Every vault.
const SELECT_VAULTS: &str = "SELECT vault_id, self_grant, wraps_after_epoch, restore_generation FROM vaults \
     ORDER BY vault_id";
/// The wrap rows over a column cap.
const OVERSIZE_WRAPS: &str = "SELECT COUNT(*) FROM wraps WHERE length(vault_id) > ?1 \
     OR length(item_id) > ?1 OR length(item_key_id) > ?1 OR length(envelope) > ?2";
/// Every wrap row.
const SELECT_WRAPS: &str = "SELECT vault_id, item_id, item_key_id, vault_key_epoch, envelope \
     FROM wraps ORDER BY vault_id, item_id, item_key_id";
/// The op rows over a column cap.
const OVERSIZE_OPS: &str = "SELECT COUNT(*) FROM ops WHERE length(vault_id) > ?1 \
     OR length(device_id) > ?1 OR length(device_seq) > ?1 OR length(item_id) > ?1 \
     OR length(sent_generation) > ?1 OR length(statement) > ?2 OR length(body) > ?3 \
     OR length(key_wrap) > ?4";
/// Every op row.
const SELECT_OPS: &str = "SELECT vault_id, device_id, device_seq, item_id, statement, body, \
     key_wrap, own, sent_generation FROM ops ORDER BY vault_id, device_id, device_seq";
/// The snapshot rows over a column cap.
const OVERSIZE_SNAPSHOTS: &str = "SELECT COUNT(*) FROM snapshots WHERE length(vault_id) > ?1 \
     OR length(snapshot_id) > ?1 OR length(item_id) > ?1 OR length(sent_generation) > ?1 \
     OR length(statement) > ?2 OR length(envelope) > ?3 OR length(key_wrap) > ?4";
/// Every snapshot row.
const SELECT_SNAPSHOTS: &str = "SELECT vault_id, snapshot_id, item_id, statement, envelope, \
     key_wrap, own, sent_generation FROM snapshots ORDER BY vault_id, snapshot_id";

/// A length as a bound `SQLite` integer.
fn cap(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}

/// A refused write: the SQL guard of a floor did not match exactly one row.
fn one_row(changed: u64) -> Result<(), sqlx::Error> {
    if changed == 1 {
        Ok(())
    } else {
        Err(sqlx::Error::RowNotFound)
    }
}

/// An open cache file. One connection, used by one task.
pub struct Db {
    /// The connection.
    conn: SqliteConnection,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db").finish_non_exhaustive()
    }
}

/// Maps an sqlx error of a write or an open: a busy database is "in use", everything else a
/// database failure. No detail of the error is kept (it could quote a statement).
fn db_error(e: &sqlx::Error) -> CliError {
    let busy = e
        .as_database_error()
        .and_then(|d| d.code().map(|c| c.as_ref() == "5" || c.as_ref() == "6"))
        .unwrap_or(false);
    if busy {
        CliError::InUse
    } else {
        CliError::Database
    }
}

/// The connect options of ADR 0026 §3.
fn options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .journal_mode(SqliteJournalMode::Delete)
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        .busy_timeout(BUSY_TIMEOUT)
        .pragma("secure_delete", "ON")
}

impl Db {
    /// Connects to an existing file and applies the settings.
    async fn connect(path: &Path) -> Result<Self, CliError> {
        let mut conn = SqliteConnection::connect_with(&options(path))
            .await
            .map_err(|e| db_error(&e))?;
        // The settings as the store's text states them, whatever the driver's defaults are.
        for pragma in PRAGMAS {
            sqlx::query(*pragma)
                .fetch_all(&mut conn)
                .await
                .map_err(|e| db_error(&e))?;
        }
        Ok(Self { conn })
    }

    /// Creates the cache of a new enrolment at `path` with its first changeset (module docs).
    ///
    /// # Errors
    /// [`CliError::AlreadyEnrolled`] if a file exists at `path`; [`CliError::Io`];
    /// [`CliError::Database`], after which the empty file is removed again.
    pub async fn create(path: &Path, first: &Changeset) -> Result<Self, CliError> {
        drop(create_private_file(path).map_err(|e| match e {
            CliError::FileExists => CliError::AlreadyEnrolled,
            other => other,
        })?);
        let created = async {
            let mut db = Self::connect(path).await?;
            let mut tx = db
                .conn
                .begin_with(BEGIN_IMMEDIATE)
                .await
                .map_err(|e| db_error(&e))?;
            for statement in SCHEMA {
                sqlx::query(*statement)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| db_error(&e))?;
            }
            for write in first.writes() {
                apply(&mut tx, write).await.map_err(|e| db_error(&e))?;
            }
            tx.commit().await.map_err(|e| db_error(&e))?;
            Ok(db)
        }
        .await;
        if created.is_err() {
            // Nothing was committed: the file holds no enrolment, and leaving it would make the
            // next signup or login fail as "already enrolled".
            let _ = std::fs::remove_file(path);
        }
        created
    }

    /// Opens an existing cache.
    ///
    /// # Errors
    /// [`CliError::NotEnrolled`] if there is no file; [`CliError::InUse`];
    /// [`CliError::Database`].
    pub async fn open(path: &Path) -> Result<Self, CliError> {
        if !path.is_file() {
            return Err(CliError::NotEnrolled);
        }
        Self::connect(path).await
    }

    /// Runs `changeset` as one `BEGIN IMMEDIATE` transaction. An empty changeset does nothing.
    ///
    /// # Errors
    /// [`CliError::InUse`] if the write lock could not be had in time; [`CliError::Database`]
    /// for any other failure, a refused guard included. Nothing is written then.
    pub async fn write(&mut self, changeset: &Changeset) -> Result<(), CliError> {
        self.write_until(changeset, usize::MAX).await
    }

    /// As [`Db::write`], but fails after `limit` writes without committing: the crash a test
    /// injects inside a step (ADR 0026 §6).
    async fn write_until(&mut self, changeset: &Changeset, limit: usize) -> Result<(), CliError> {
        if changeset.is_empty() {
            return Ok(());
        }
        let mut tx = self
            .conn
            .begin_with(BEGIN_IMMEDIATE)
            .await
            .map_err(|e| db_error(&e))?;
        for (index, write) in changeset.writes().iter().enumerate() {
            if index >= limit {
                // Dropping the transaction rolls it back.
                return Err(CliError::Database);
            }
            apply(&mut tx, write).await.map_err(|e| db_error(&e))?;
        }
        tx.commit().await.map_err(|e| db_error(&e))
    }

    /// Reads every table into the store's row model (module docs).
    ///
    /// # Errors
    /// [`ClientError::CacheCorrupt`] (as [`CliError::Client`]) for a file that is not a cache:
    /// a missing table, a column of the wrong type, a blob over its cap, a self-grant that is
    /// not the grant's JSON (ADR 0026 §5 (a)).
    pub async fn read(&mut self) -> Result<CacheRows, CliError> {
        read_rows(&mut self.conn)
            .await
            .map_err(|_| CliError::Client(ClientError::CacheCorrupt))
    }

    /// The keys of the alarm rows (`account_objects` kind 7), each cut to its first two bytes:
    /// one byte is an alarm kind, anything else is an alarm this build does not know.
    ///
    /// Alarm rows are cleartext (ADR 0026 §3 "What is cleartext on disk"), so this needs no
    /// key and no unlock, and it reads this one table only: a cache whose other rows are
    /// damaged, or whose password is not at hand, still says which alarms it holds. `rv
    /// device forget` asks it before removing a file that does not open (ADR 0026 §5: "While
    /// an alarm is active the app refuses removal").
    ///
    /// # Errors
    /// [`CliError::Database`] for a file with no such table: it is not a cache (§5 (a)).
    pub async fn alarm_keys(&mut self) -> Result<Vec<Vec<u8>>, CliError> {
        let rows = sqlx::query(SELECT_ALARM_KEYS)
            .bind(kind::ALARM)
            .fetch_all(&mut self.conn)
            .await
            .map_err(|e| db_error(&e))?;
        rows.iter()
            .map(|row| row.try_get(0).map_err(|e| db_error(&e)))
            .collect()
    }

    /// Closes the connection.
    pub async fn close(self) {
        // A failed close loses nothing: every write was committed in its own transaction.
        let _ = self.conn.close().await;
    }
}

/// A row count from a `COUNT(*)` query with caps bound in order.
async fn count(
    conn: &mut SqliteConnection,
    sql: &'static str,
    caps: &[i64],
) -> Result<i64, sqlx::Error> {
    let mut query = sqlx::query_scalar::<_, i64>(sql);
    for cap in caps {
        query = query.bind(*cap);
    }
    query.fetch_one(&mut *conn).await
}

/// Fails if `sql` counts a row over a cap.
async fn no_oversize(
    conn: &mut SqliteConnection,
    sql: &'static str,
    caps: &[i64],
) -> Result<(), sqlx::Error> {
    if count(conn, sql, caps).await? == 0 {
        Ok(())
    } else {
        Err(sqlx::Error::RowNotFound)
    }
}

/// Reads every table. Any error means "not a cache".
#[expect(
    clippy::too_many_lines,
    reason = "one block per table, each the same three steps: cap check, select, map"
)]
async fn read_rows(conn: &mut SqliteConnection) -> Result<CacheRows, sqlx::Error> {
    let bad = || sqlx::Error::RowNotFound;
    let key_cap = cap(MAX_KEY_COLUMN_LEN);
    let mut rows = CacheRows::default();

    // `cache_meta`: a row the bounded select leaves out is a row over its cap.
    let meta_rows = sqlx::query(SELECT_META).fetch_all(&mut *conn).await?;
    if count(conn, COUNT_META, &[]).await? != cap(meta_rows.len())
        || meta_rows.len() > meta::ALL.len() * 2
    {
        return Err(bad());
    }
    for row in meta_rows {
        rows.meta
            .insert(row.try_get::<String, _>(0)?, row.try_get(1)?);
    }

    let record = sqlx::query(SELECT_DEVICE_STATE)
        .bind(cap(MAX_DEVICE_STATE_LEN))
        .fetch_optional(&mut *conn)
        .await?;
    if count(conn, COUNT_DEVICE_STATE, &[]).await? != i64::from(record.is_some()) {
        return Err(bad());
    }
    rows.device_state = match record {
        Some(row) => Some(Zeroizing::new(row.try_get::<Vec<u8>, _>(0)?)),
        None => None,
    };

    let pending = sqlx::query(SELECT_PENDING_COMMIT)
        .bind(cap(MAX_UPLOAD_BODY_LEN))
        .fetch_optional(&mut *conn)
        .await?;
    if count(conn, COUNT_PENDING_COMMIT, &[]).await? != i64::from(pending.is_some()) {
        return Err(bad());
    }
    rows.pending_commit = match pending {
        Some(row) => Some(row.try_get(0)?),
        None => None,
    };

    // Account objects: the largest blob of any kind is an `ACCOUNT_SETTINGS` envelope.
    no_oversize(conn, OVERSIZE_OBJECTS, &[key_cap, cap(MAX_ENVELOPE_LEN)]).await?;
    for row in sqlx::query(SELECT_OBJECTS).fetch_all(&mut *conn).await? {
        let object = ObjectRow {
            kind: row.try_get(0)?,
            key: row.try_get(1)?,
            bytes: row.try_get(2)?,
        };
        // The signed statements have their own, smaller limit.
        if object.kind != kind::SETTINGS && object.bytes.len() > MAX_ACCOUNT_STATEMENT_LEN {
            return Err(bad());
        }
        rows.objects.push(object);
    }

    no_oversize(
        conn,
        OVERSIZE_VAULTS,
        &[key_cap, cap(MAX_SELF_GRANT_JSON_LEN)],
    )
    .await?;
    for row in sqlx::query(SELECT_VAULTS).fetch_all(&mut *conn).await? {
        let json: Vec<u8> = row.try_get(1)?;
        let self_grant: VaultSelfGrant = serde_json::from_slice(&json).map_err(|_| bad())?;
        rows.vaults.push(VaultRow {
            vault_id: row.try_get(0)?,
            self_grant,
            wraps_after_epoch: row.try_get(2)?,
            restore_generation: row.try_get(3)?,
        });
    }

    no_oversize(conn, OVERSIZE_WRAPS, &[key_cap, cap(MAX_KEY_ENVELOPE_LEN)]).await?;
    for row in sqlx::query(SELECT_WRAPS).fetch_all(&mut *conn).await? {
        rows.wraps.push(WrapRow {
            vault_id: row.try_get(0)?,
            item_id: row.try_get(1)?,
            item_key_id: row.try_get(2)?,
            vault_key_epoch: row.try_get(3)?,
            envelope: row.try_get(4)?,
        });
    }

    no_oversize(
        conn,
        OVERSIZE_OPS,
        &[
            key_cap,
            cap(MAX_OP_STATEMENT_LEN),
            cap(MAX_ENVELOPE_LEN),
            cap(MAX_KEY_ENVELOPE_LEN),
        ],
    )
    .await?;
    for row in sqlx::query(SELECT_OPS).fetch_all(&mut *conn).await? {
        rows.ops.push(OpRow {
            vault_id: row.try_get(0)?,
            device_id: row.try_get(1)?,
            device_seq: row.try_get(2)?,
            item_id: row.try_get(3)?,
            statement: row.try_get(4)?,
            body: row.try_get(5)?,
            key_wrap: row.try_get(6)?,
            own: row.try_get(7)?,
            sent_generation: row.try_get(8)?,
        });
    }

    no_oversize(
        conn,
        OVERSIZE_SNAPSHOTS,
        &[
            key_cap,
            cap(MAX_SNAPSHOT_STATEMENT_LEN),
            cap(MAX_ENVELOPE_LEN),
            cap(MAX_KEY_ENVELOPE_LEN),
        ],
    )
    .await?;
    for row in sqlx::query(SELECT_SNAPSHOTS).fetch_all(&mut *conn).await? {
        rows.snapshots.push(SnapshotRow {
            vault_id: row.try_get(0)?,
            snapshot_id: row.try_get(1)?,
            item_id: row.try_get(2)?,
            statement: row.try_get(3)?,
            envelope: row.try_get(4)?,
            key_wrap: row.try_get(5)?,
            own: row.try_get(6)?,
            sent_generation: row.try_get(7)?,
        });
    }
    Ok(rows)
}

/// Runs one write inside the step's transaction (`rizzy_client::store::rows::CacheRows::apply`
/// is the reference for what each one means).
#[expect(
    clippy::too_many_lines,
    reason = "one arm per write kind, each one statement with its bound parameters"
)]
async fn apply(conn: &mut SqliteConnection, write: &Write) -> Result<(), sqlx::Error> {
    match write {
        Write::Meta { key, value } => {
            let sql = if matches!(*key, meta::NEXT_DEVICE_SEQ | meta::HLC) {
                META_COUNTER
            } else {
                META_FIXED
            };
            let done = sqlx::query(sql)
                .bind(*key)
                .bind(value.as_slice())
                .execute(&mut *conn)
                .await?;
            one_row(done.rows_affected())
        }
        Write::DeviceState(record) => {
            sqlx::query(PUT_DEVICE_STATE)
                .bind(record.as_slice())
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
        Write::PendingCommit(Some(request)) => {
            sqlx::query(PUT_PENDING_COMMIT)
                .bind(request.as_slice())
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
        Write::PendingCommit(None) => {
            sqlx::query(DELETE_PENDING_COMMIT)
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
        Write::AccountState { wire, .. } => {
            sqlx::query(PUT_OBJECT)
                .bind(kind::ACCOUNT_STATE)
                .bind(&[][..])
                .bind(wire.as_slice())
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
        Write::PutObject(row) => {
            let once = matches!(row.kind, kind::BUNDLE | kind::SETTINGS);
            let done = sqlx::query(if once { PUT_OBJECT_ONCE } else { PUT_OBJECT })
                .bind(row.kind)
                .bind(row.key.as_slice())
                .bind(row.bytes.as_slice())
                .execute(&mut *conn)
                .await?;
            one_row(done.rows_affected())
        }
        Write::ClearAlarm(alarm) => {
            sqlx::query(DELETE_ALARM)
                .bind(kind::ALARM)
                .bind([alarm.to_u8()].as_slice())
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
        Write::DeviceSet {
            certificates,
            revocations,
        } => {
            sqlx::query(DELETE_DEVICE_SET).execute(&mut *conn).await?;
            for (kind, set) in [
                (kind::CERTIFICATE, certificates),
                (kind::REVOCATION, revocations),
            ] {
                for (device_id, wire) in set {
                    sqlx::query(PUT_OBJECT)
                        .bind(kind)
                        .bind(device_id.as_slice())
                        .bind(wire.as_slice())
                        .execute(&mut *conn)
                        .await?;
                }
            }
            Ok(())
        }
        Write::VaultGrant { grant, .. } => {
            let json = serde_json::to_vec(grant).map_err(|_| sqlx::Error::RowNotFound)?;
            sqlx::query(PUT_VAULT_GRANT)
                .bind(grant.vault_id.as_bytes().as_slice())
                .bind(json)
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
        Write::VaultGeneration {
            vault_id,
            generation,
        } => {
            let done = sqlx::query(SET_VAULT_GENERATION)
                .bind(vault_id.as_slice())
                .bind(generation.as_slice())
                .execute(&mut *conn)
                .await?;
            one_row(done.rows_affected())
        }
        Write::Wraps {
            vault_id,
            epoch,
            wraps,
        } => {
            sqlx::query(DELETE_OLD_WRAPS)
                .bind(vault_id.as_slice())
                .bind(i64::from(*epoch))
                .execute(&mut *conn)
                .await?;
            for wrap in wraps {
                sqlx::query(PUT_WRAP)
                    .bind(wrap.vault_id.as_slice())
                    .bind(wrap.item_id.as_slice())
                    .bind(wrap.item_key_id.as_slice())
                    .bind(wrap.vault_key_epoch)
                    .bind(wrap.envelope.as_slice())
                    .execute(&mut *conn)
                    .await?;
            }
            Ok(())
        }
        Write::PutOp(row) => {
            let done = sqlx::query(PUT_OP)
                .bind(row.vault_id.as_slice())
                .bind(row.device_id.as_slice())
                .bind(row.device_seq.as_slice())
                .bind(row.item_id.as_slice())
                .bind(row.statement.as_slice())
                .bind(row.body.as_deref())
                .bind(row.key_wrap.as_deref())
                .bind(row.own)
                .execute(&mut *conn)
                .await?;
            one_row(done.rows_affected())
        }
        Write::ReissueOp {
            row,
            stale_generation,
        } => {
            let done = sqlx::query(REISSUE_OP)
                .bind(row.vault_id.as_slice())
                .bind(row.device_id.as_slice())
                .bind(row.device_seq.as_slice())
                .bind(row.statement.as_slice())
                .bind(row.body.as_deref())
                .bind(row.key_wrap.as_deref())
                .bind(stale_generation.as_ref().map(<[u8; 16]>::as_slice))
                .execute(&mut *conn)
                .await?;
            one_row(done.rows_affected())
        }
        Write::OpOwn {
            vault_id,
            device_id,
            device_seq,
            own: to,
            sent_generation,
        } => {
            let seq = device_seq.to_be_bytes();
            let query = match *to {
                own::SENT => sqlx::query(OP_SENT)
                    .bind(vault_id.as_slice())
                    .bind(device_id.as_slice())
                    .bind(seq.as_slice())
                    .bind(sent_generation.as_ref().map(<[u8; 16]>::as_slice)),
                own::ACKNOWLEDGED => sqlx::query(OP_ACKNOWLEDGED)
                    .bind(vault_id.as_slice())
                    .bind(device_id.as_slice())
                    .bind(seq.as_slice()),
                _ => return Err(sqlx::Error::RowNotFound),
            };
            one_row(query.execute(&mut *conn).await?.rows_affected())
        }
        Write::PutSnapshot(row) => {
            sqlx::query(PUT_SNAPSHOT)
                .bind(row.vault_id.as_slice())
                .bind(row.snapshot_id.as_slice())
                .bind(row.item_id.as_slice())
                .bind(row.statement.as_slice())
                .bind(row.envelope.as_slice())
                .bind(row.key_wrap.as_deref())
                .bind(row.own)
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
        Write::SnapshotOwn {
            vault_id,
            snapshot_id,
            own: to,
            sent_generation,
        } => {
            let query = match *to {
                own::SENT => sqlx::query(SNAPSHOT_SENT)
                    .bind(vault_id.as_slice())
                    .bind(snapshot_id.as_slice())
                    .bind(sent_generation.as_ref().map(<[u8; 16]>::as_slice)),
                own::ACKNOWLEDGED => sqlx::query(SNAPSHOT_ACKNOWLEDGED)
                    .bind(vault_id.as_slice())
                    .bind(snapshot_id.as_slice()),
                _ => return Err(sqlx::Error::RowNotFound),
            };
            one_row(query.execute(&mut *conn).await?.rows_affected())
        }
        Write::PruneOpBody {
            vault_id,
            device_id,
            device_seq,
        } => {
            let seq = device_seq.to_be_bytes();
            let done = sqlx::query(PRUNE_OP_BODY)
                .bind(vault_id.as_slice())
                .bind(device_id.as_slice())
                .bind(seq.as_slice())
                .execute(&mut *conn)
                .await?;
            one_row(done.rows_affected())
        }
        Write::DeleteSnapshot {
            vault_id,
            snapshot_id,
        } => {
            sqlx::query(DELETE_SNAPSHOT)
                .bind(vault_id.as_slice())
                .bind(snapshot_id.as_slice())
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    //! The executor against the reference executor of `rizzy_client::store::rows`, a crash
    //! inside a step, and the SQL guards. The rows are synthetic: the executor checks no
    //! signature (the load does).

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use rizzy_client::rizzy_proto::wire::{Bytes, Id};
    use rizzy_client::store::rows::limits::{MAX_CACHE_META_KEY_LEN, MAX_CACHE_META_VALUE_LEN};
    use rizzy_client::store::rows::{Alarm, CACHE_FORMAT};

    use super::*;

    const VAULT: [u8; 16] = [0x0a; 16];
    const DEVICE: [u8; 16] = [0x0d; 16];
    const OTHER: [u8; 16] = [0x0e; 16];

    /// `SELECT_META`'s literal caps must equal the shared constants (module docs on
    /// `SELECT_META`): nothing re-derives the SQL text from the `const`s, so a change to one
    /// without the other would silently reopen the gap this cap closes.
    #[test]
    fn cache_meta_caps_match_the_sql_literal() {
        assert_eq!(MAX_CACHE_META_KEY_LEN, 64);
        assert_eq!(MAX_CACHE_META_VALUE_LEN, 1024);
        assert!(SELECT_META.contains(&format!("length(k) <= {MAX_CACHE_META_KEY_LEN}")));
        assert!(SELECT_META.contains(&format!("length(v) <= {MAX_CACHE_META_VALUE_LEN}")));
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn temp_file(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rv-db-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("cache.sqlite3")
    }

    fn grant(epoch: u32) -> VaultSelfGrant {
        VaultSelfGrant {
            vault_id: Id::from_bytes(VAULT),
            account_key_epoch: epoch,
            vault_key_epoch: epoch,
            envelope: Bytes::from_slice(&[0x11; 90]).unwrap(),
        }
    }

    fn op(device: [u8; 16], seq: u64, own: i64) -> OpRow {
        OpRow {
            vault_id: VAULT.to_vec(),
            device_id: device.to_vec(),
            device_seq: seq.to_be_bytes().to_vec(),
            item_id: vec![0x33; 16],
            statement: vec![u8::try_from(seq).unwrap(); 100],
            body: Some(vec![0x44; 120]),
            key_wrap: None,
            own,
            sent_generation: None,
        }
    }

    fn snapshot(id: u8, own: i64) -> SnapshotRow {
        SnapshotRow {
            vault_id: VAULT.to_vec(),
            snapshot_id: vec![id; 16],
            item_id: vec![0x33; 16],
            statement: vec![id; 80],
            envelope: vec![0x55; 140],
            key_wrap: Some(vec![0x66; 90]),
            own,
            sent_generation: None,
        }
    }

    fn wrap(item: u8, epoch: i64) -> WrapRow {
        WrapRow {
            vault_id: VAULT.to_vec(),
            item_id: vec![item; 16],
            item_key_id: vec![0x77; 16],
            vault_key_epoch: epoch,
            envelope: vec![item; 90],
        }
    }

    fn counter(key: &'static str, value: u64) -> Write {
        Write::Meta {
            key,
            value: value.to_be_bytes().to_vec(),
        }
    }

    /// The first changeset of a cache: what `store::create_writes` gives, by hand.
    fn first() -> Changeset {
        [
            Write::Meta {
                key: meta::FORMAT,
                value: CACHE_FORMAT.to_be_bytes().to_vec(),
            },
            Write::Meta {
                key: meta::SERVER_ORIGIN,
                value: b"https://vault.example.com".to_vec(),
            },
            Write::Meta {
                key: meta::ACCOUNT_ID,
                value: vec![0xa1; 16],
            },
            Write::Meta {
                key: meta::DEVICE_ID,
                value: DEVICE.to_vec(),
            },
            counter(meta::NEXT_DEVICE_SEQ, 1),
            counter(meta::HLC, 0),
            Write::DeviceState(Zeroizing::new(vec![1, 2, 3])),
        ]
        .into_iter()
        .collect()
    }

    /// Steps that use every kind of write.
    #[expect(clippy::too_many_lines, reason = "one step per kind of write")]
    fn steps() -> Vec<Changeset> {
        let object = |kind: i64, key: Vec<u8>, bytes: &[u8]| {
            Write::PutObject(ObjectRow {
                kind,
                key,
                bytes: bytes.to_vec(),
            })
        };
        let own_op = |seq: u64, own: i64, generation: Option<[u8; 16]>| Write::OpOwn {
            vault_id: VAULT,
            device_id: DEVICE,
            device_seq: seq,
            own,
            sent_generation: generation,
        };
        let sets: Vec<Vec<Write>> = vec![
            vec![
                Write::PendingCommit(Some(b"{\"a\":1}".to_vec())),
                object(kind::BUNDLE, 1u64.to_be_bytes().to_vec(), b"bundle"),
                Write::AccountState {
                    wire: b"state-1".to_vec(),
                    state_seq: 1,
                    settings_seq: 0,
                },
                Write::DeviceSet {
                    certificates: vec![(DEVICE, b"cert".to_vec())],
                    revocations: Vec::new(),
                },
                object(kind::IDENTITY_KEYS, 0u32.to_be_bytes().to_vec(), b"e_id"),
                Write::VaultGrant {
                    grant: grant(0),
                    vault_key_id: [9; 16],
                },
            ],
            vec![
                Write::DeviceState(Zeroizing::new(vec![4, 5, 6, 7])),
                Write::PendingCommit(None),
            ],
            vec![
                Write::VaultGeneration {
                    vault_id: VAULT,
                    generation: [0x61; 16],
                },
                Write::Wraps {
                    vault_id: VAULT,
                    epoch: 0,
                    wraps: vec![wrap(1, 0), wrap(2, 0)],
                },
                Write::PutOp(op(OTHER, 1, own::SERVED)),
                Write::PutSnapshot(snapshot(0x21, own::SERVED)),
                counter(meta::HLC, 77),
            ],
            vec![
                counter(meta::NEXT_DEVICE_SEQ, 3),
                Write::PutOp(op(DEVICE, 1, own::UNSENT)),
                Write::PutOp(op(DEVICE, 2, own::UNSENT)),
                Write::PutSnapshot(snapshot(0x22, own::UNSENT)),
                Write::PutSnapshot(snapshot(0x23, own::UNSENT)),
            ],
            vec![
                own_op(1, own::SENT, Some([0x61; 16])),
                own_op(2, own::SENT, Some([0x61; 16])),
                Write::SnapshotOwn {
                    vault_id: VAULT,
                    snapshot_id: [0x22; 16],
                    own: own::SENT,
                    sent_generation: Some([0x61; 16]),
                },
            ],
            vec![
                own_op(1, own::ACKNOWLEDGED, None),
                // A resend keeps the first generation.
                own_op(2, own::SENT, Some([0x62; 16])),
                Write::SnapshotOwn {
                    vault_id: VAULT,
                    snapshot_id: [0x22; 16],
                    own: own::ACKNOWLEDGED,
                    sent_generation: None,
                },
                Write::DeleteSnapshot {
                    vault_id: VAULT,
                    snapshot_id: [0x23; 16],
                },
            ],
            vec![
                // A stale answer under the first generation, then the re-issue.
                Write::ReissueOp {
                    row: OpRow {
                        statement: vec![0xee; 90],
                        body: Some(vec![0xef; 100]),
                        key_wrap: Some(vec![0xf0; 90]),
                        ..op(DEVICE, 2, own::UNSENT)
                    },
                    stale_generation: Some([0x61; 16]),
                },
                // The same served op again, now with the wrap it lacked.
                Write::PutOp(OpRow {
                    key_wrap: Some(vec![0x99; 90]),
                    body: None,
                    ..op(OTHER, 1, own::SERVED)
                }),
            ],
            vec![
                // A rotation: the new record and state, the new grant and wrap set.
                Write::AccountState {
                    wire: b"state-2".to_vec(),
                    state_seq: 2,
                    settings_seq: 1,
                },
                object(kind::SETTINGS, 1u64.to_be_bytes().to_vec(), b"settings"),
                object(kind::IDENTITY_KEYS, 0u32.to_be_bytes().to_vec(), b"e_id-2"),
                Write::DeviceSet {
                    certificates: vec![(DEVICE, b"cert-2".to_vec()), (OTHER, b"cert-o".to_vec())],
                    revocations: vec![(OTHER, b"revoked".to_vec())],
                },
                Write::VaultGrant {
                    grant: grant(1),
                    vault_key_id: [8; 16],
                },
                Write::Wraps {
                    vault_id: VAULT,
                    epoch: 1,
                    wraps: vec![wrap(1, 1)],
                },
                object(
                    kind::ALARM,
                    vec![Alarm::UnconfirmedIdentityChange.to_u8()],
                    b"ev",
                ),
                object(kind::ALARM, vec![Alarm::Fork.to_u8()], b"ev2"),
            ],
            vec![Write::ClearAlarm(Alarm::UnconfirmedIdentityChange)],
            // The pruning of a served body (ADR 0026 §4 step 2).
            vec![Write::PruneOpBody {
                vault_id: VAULT,
                device_id: OTHER,
                device_seq: 1,
            }],
        ];
        sets.into_iter()
            .map(|writes| writes.into_iter().collect())
            .collect()
    }

    /// The rows as comparable parts.
    fn parts(mut rows: CacheRows) -> impl PartialEq + std::fmt::Debug {
        rows.sort();
        (
            rows.meta,
            rows.device_state.map(|r| r.to_vec()),
            rows.pending_commit,
            rows.objects,
            rows.vaults,
            rows.wraps,
            (rows.ops, rows.snapshots),
        )
    }

    #[test]
    fn the_sql_does_what_the_reference_executor_does() {
        block_on(async {
            let path = temp_file("same");
            let mut reference = CacheRows::default();
            let mut db = Db::create(&path, &first()).await.unwrap();
            reference.apply(&first());
            assert_eq!(parts(db.read().await.unwrap()), parts(copy(&reference)));
            for step in steps() {
                db.write(&step).await.unwrap();
                reference.apply(&step);
                assert_eq!(parts(db.read().await.unwrap()), parts(copy(&reference)));
            }
            // What the story leaves: the re-issued own op, the dropped old-epoch wraps, the
            // alarm that stays.
            let rows = db.read().await.unwrap();
            assert_eq!(rows.ops.len(), 3);
            assert!(
                rows.ops
                    .iter()
                    .any(|o| o.own == own::UNSENT && o.statement == [0xee; 90])
            );
            assert_eq!(rows.wraps.len(), 1);
            assert_eq!(rows.snapshots.len(), 2);
            assert_eq!(
                rows.objects
                    .iter()
                    .filter(|o| o.kind == kind::ALARM)
                    .count(),
                1
            );
            // The file survives a close and an open, byte for byte of content.
            db.close().await;
            let mut db = Db::open(&path).await.unwrap();
            assert_eq!(parts(db.read().await.unwrap()), parts(copy(&reference)));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
        });
    }

    fn copy(rows: &CacheRows) -> CacheRows {
        CacheRows {
            meta: rows.meta.clone(),
            device_state: rows.device_state.clone(),
            pending_commit: rows.pending_commit.clone(),
            objects: rows.objects.clone(),
            vaults: rows.vaults.clone(),
            wraps: rows.wraps.clone(),
            ops: rows.ops.clone(),
            snapshots: rows.snapshots.clone(),
        }
    }

    /// ADR 0026 §4, §6: a crash after any write of a step leaves the file as it was before the
    /// step, never inside it.
    #[test]
    fn a_crash_inside_a_step_writes_nothing() {
        block_on(async {
            let path = temp_file("crash");
            let mut db = Db::create(&path, &first()).await.unwrap();
            for step in steps() {
                let before = parts(db.read().await.unwrap());
                for crash_after in 0..step.writes().len() {
                    assert!(db.write_until(&step, crash_after).await.is_err());
                    assert_eq!(parts(db.read().await.unwrap()), before);
                }
                db.write(&step).await.unwrap();
            }
        });
    }

    /// The SQL refuses, a second time after the floors, what must never be written; the whole
    /// step is rolled back.
    #[test]
    fn the_sql_guards_refuse_and_roll_back() {
        block_on(async {
            let path = temp_file("guards");
            let mut db = Db::create(&path, &first()).await.unwrap();
            for step in steps() {
                db.write(&step).await.unwrap();
            }
            let before = parts(db.read().await.unwrap());
            let refused: Vec<Write> = vec![
                counter(meta::NEXT_DEVICE_SEQ, 2),
                counter(meta::HLC, 76),
                Write::Meta {
                    key: meta::DEVICE_ID,
                    value: OTHER.to_vec(),
                },
                // Another statement at a held dot.
                Write::PutOp(OpRow {
                    statement: vec![0xab; 50],
                    ..op(OTHER, 1, own::SERVED)
                }),
                // `own` never goes back, and an acknowledged row is never re-issued.
                Write::OpOwn {
                    vault_id: VAULT,
                    device_id: DEVICE,
                    device_seq: 1,
                    own: own::SENT,
                    sent_generation: Some([1; 16]),
                },
                Write::ReissueOp {
                    row: op(DEVICE, 1, own::UNSENT),
                    stale_generation: None,
                },
                // Other bytes at a held bundle; a generation for a vault that is not there.
                Write::PutObject(ObjectRow {
                    kind: kind::BUNDLE,
                    key: 1u64.to_be_bytes().to_vec(),
                    bytes: b"other".to_vec(),
                }),
                Write::VaultGeneration {
                    vault_id: [0x42; 16],
                    generation: [0; 16],
                },
                // An own row keeps its body.
                Write::PruneOpBody {
                    vault_id: VAULT,
                    device_id: DEVICE,
                    device_seq: 1,
                },
            ];
            for write in refused {
                // A good write first: the refusal must roll it back too.
                let step: Changeset = [counter(meta::HLC, 99), write].into_iter().collect();
                assert!(matches!(db.write(&step).await, Err(CliError::Database)));
                assert_eq!(parts(db.read().await.unwrap()), before);
            }
            // An acknowledged snapshot is not deleted (the statement matches no row).
            let step: Changeset = [Write::DeleteSnapshot {
                vault_id: VAULT,
                snapshot_id: [0x22; 16],
            }]
            .into_iter()
            .collect();
            db.write(&step).await.unwrap();
            assert_eq!(parts(db.read().await.unwrap()), before);
        });
    }

    /// The alarm keys are read without a key, and from a cache whose other rows do not read
    /// (ADR 0026 §5: removal is refused while an alarm is active, whatever else is damaged).
    #[test]
    fn alarm_keys_are_read_from_a_cache_that_does_not_load() {
        block_on(async {
            let path = temp_file("alarms");
            let mut db = Db::create(&path, &first()).await.unwrap();
            assert!(db.alarm_keys().await.unwrap().is_empty());
            let step: Changeset = [Write::PutObject(ObjectRow {
                kind: kind::ALARM,
                key: vec![Alarm::Fork.to_u8()],
                bytes: b"ev".to_vec(),
            })]
            .into_iter()
            .collect();
            db.write(&step).await.unwrap();
            // A row a newer or a hostile writer left: its key is cut, never read whole.
            sqlx::query("INSERT INTO account_objects(kind, key, bytes) VALUES(7, ?1, x'')")
                .bind([9u8; 64].as_slice())
                .execute(&mut db.conn)
                .await
                .unwrap();
            // The rest of the file stops reading.
            sqlx::query("INSERT INTO vaults(vault_id, self_grant) VALUES(?1, ?2)")
                .bind([0x77u8; 16].as_slice())
                .bind(b"{not json".as_slice())
                .execute(&mut db.conn)
                .await
                .unwrap();
            assert!(db.read().await.is_err());
            assert_eq!(
                db.alarm_keys().await.unwrap(),
                vec![vec![Alarm::Fork.to_u8()], vec![9, 9]]
            );
            db.close().await;
            // A file that is no cache has no alarm table to read.
            let garbage = path.with_file_name("alarm-garbage.sqlite3");
            std::fs::write(&garbage, b"this is not a database, not even nearly one").unwrap();
            if let Ok(mut db) = Db::open(&garbage).await {
                assert!(db.alarm_keys().await.is_err());
            }
        });
    }

    /// A file is created once, opened only if it is there, and read only if it is a cache
    /// whose blobs are within their caps.
    #[test]
    fn files_that_are_not_a_cache_are_refused() {
        block_on(async {
            let path = temp_file("refuse");
            let db = Db::create(&path, &first()).await.unwrap();
            db.close().await;
            assert!(matches!(
                Db::create(&path, &first()).await,
                Err(CliError::AlreadyEnrolled)
            ));
            let missing = path.with_file_name("missing.sqlite3");
            assert!(matches!(
                Db::open(&missing).await,
                Err(CliError::NotEnrolled)
            ));
            // A first changeset the SQL refuses leaves no file behind.
            let bad: Changeset = [
                counter(meta::HLC, 1),
                Write::VaultGeneration {
                    vault_id: VAULT,
                    generation: [0; 16],
                },
            ]
            .into_iter()
            .collect();
            let other = path.with_file_name("bad.sqlite3");
            assert!(Db::create(&other, &bad).await.is_err());
            assert!(!other.exists());
            // Not SQLite at all.
            let garbage = path.with_file_name("garbage.sqlite3");
            std::fs::write(&garbage, b"this is not a database, not even nearly one").unwrap();
            match Db::open(&garbage).await {
                Ok(mut db) => assert!(matches!(
                    db.read().await,
                    Err(CliError::Client(ClientError::CacheCorrupt))
                )),
                Err(e) => assert!(matches!(e, CliError::Database)),
            }
            // A device-state record over its cap is not read into memory.
            let mut db = Db::open(&path).await.unwrap();
            let step: Changeset = [Write::DeviceState(Zeroizing::new(vec![
                0;
                MAX_DEVICE_STATE_LEN
                    + 1
            ]))]
            .into_iter()
            .collect();
            db.write(&step).await.unwrap();
            assert!(matches!(
                db.read().await,
                Err(CliError::Client(ClientError::CacheCorrupt))
            ));
            // A self-grant that is not the grant's JSON.
            let path = temp_file("grant");
            let mut db = Db::create(&path, &first()).await.unwrap();
            sqlx::query("INSERT INTO vaults(vault_id, self_grant) VALUES(?1, ?2)")
                .bind(VAULT.as_slice())
                .bind(b"{not json".as_slice())
                .execute(&mut db.conn)
                .await
                .unwrap();
            assert!(matches!(
                db.read().await,
                Err(CliError::Client(ClientError::CacheCorrupt))
            ));
        });
    }
}
