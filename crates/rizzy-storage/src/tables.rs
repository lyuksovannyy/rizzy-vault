//! The tables a logical backup carries, with their columns, in restore order (ADR 0011
//! "Backups").
//!
//! [`TABLES`] lists every `auth_` and `vault_` table except the short-lived session state, in
//! foreign-key order: a table comes after every table it references, so `restore` inserts
//! rows with foreign keys on. Each table has two shared query files under
//! `queries/backup/`, one `SELECT` of every column in primary-key order and one `INSERT` of one
//! row with `$1 … $n`; both list the columns in the order of [`TableSpec::columns`].
//!
//! **Not backed up** (the conservative reading of "every table as rows"; see the crate docs):
//! - `auth_sessions`, `auth_login_states` and `auth_device_challenges`: a restore must not
//!   revive sessions that were ended after the backup (for example those of a device revoked
//!   since, INV-59), and 60 s login state and challenges mean nothing after a restore. Every
//!   user signs in again.
//! - `storage_meta` and `storage_reconciliation`: `restore` writes both itself, with a new
//!   restore generation (ADR 0021 §2) and a reconciliation epoch for every account (INV-59).
//!
//! The tests check this list against the schema the migrations create: every column of every
//! backed-up table, with its kind and nullability, and every other table named above.

/// The storage class of a column, the same on both engines (ADR 0011 point 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `INTEGER` / `BIGINT`: an `i64`.
    Integer,
    /// `TEXT`: a UTF-8 string.
    Text,
    /// `BLOB` / `BYTEA`: bytes.
    Blob,
}

/// One column of a backed-up table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Column {
    /// The column name.
    pub name: &'static str,
    /// Its storage class.
    pub kind: Kind,
    /// Whether it may be NULL.
    pub nullable: bool,
}

/// One backed-up table.
#[derive(Clone, Copy, Debug)]
pub struct TableSpec {
    /// The table name.
    pub name: &'static str,
    /// `SELECT` of every column, in primary-key order.
    pub(crate) select: &'static str,
    /// `INSERT` of one row, `$1 … $n` in column order.
    pub(crate) insert: &'static str,
    /// The columns, in the order both queries list them.
    pub columns: &'static [Column],
}

/// A [`Column`], for the table below.
const fn col(name: &'static str, kind: Kind, nullable: bool) -> Column {
    Column {
        name,
        kind,
        nullable,
    }
}

/// The tables not in [`TABLES`], which a logical backup leaves out on purpose (module docs).
pub const NOT_BACKED_UP: &[&str] = &[
    "auth_sessions",
    "auth_login_states",
    "auth_device_challenges",
    "storage_meta",
    "storage_reconciliation",
];

/// The backed-up tables, in restore (foreign-key) order.
pub const TABLES: &[TableSpec] = &[
    TableSpec {
        name: "auth_accounts",
        select: include_str!("../queries/backup/auth_accounts.select.sql"),
        insert: include_str!("../queries/backup/auth_accounts.insert.sql"),
        columns: &[
            col("id", Kind::Blob, false),
            col("login_name", Kind::Text, false),
            col("created_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_opaque_setups",
        select: include_str!("../queries/backup/auth_opaque_setups.select.sql"),
        insert: include_str!("../queries/backup/auth_opaque_setups.insert.sql"),
        columns: &[
            col("setup_id", Kind::Integer, false),
            col("ake_public_key_hash", Kind::Blob, false),
            col("created_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_credentials",
        select: include_str!("../queries/backup/auth_credentials.select.sql"),
        insert: include_str!("../queries/backup/auth_credentials.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("setup_id", Kind::Integer, false),
            col("opaque_record", Kind::Blob, false),
            col("kdf_id", Kind::Integer, false),
            col("password_epoch", Kind::Integer, false),
            col("e_srv", Kind::Blob, false),
            col("updated_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_identity_keys",
        select: include_str!("../queries/backup/auth_identity_keys.select.sql"),
        insert: include_str!("../queries/backup/auth_identity_keys.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("identity_epoch", Kind::Integer, false),
            col("e_id", Kind::Blob, false),
            col("updated_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_recovery",
        select: include_str!("../queries/backup/auth_recovery.select.sql"),
        insert: include_str!("../queries/backup/auth_recovery.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("recovery_epoch", Kind::Integer, false),
            col("e_rec", Kind::Blob, false),
            col("h_rec", Kind::Blob, false),
            col("updated_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_bundles",
        select: include_str!("../queries/backup/auth_bundles.select.sql"),
        insert: include_str!("../queries/backup/auth_bundles.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("bundle_seq", Kind::Integer, false),
            col("bundle", Kind::Blob, false),
            col("stored_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_account_states",
        select: include_str!("../queries/backup/auth_account_states.select.sql"),
        insert: include_str!("../queries/backup/auth_account_states.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("state_seq", Kind::Integer, false),
            col("statement", Kind::Blob, false),
            col("updated_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_account_settings",
        select: include_str!("../queries/backup/auth_account_settings.select.sql"),
        insert: include_str!("../queries/backup/auth_account_settings.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("settings_seq", Kind::Integer, false),
            col("envelope", Kind::Blob, false),
            col("updated_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_retired_secret_keys",
        select: include_str!("../queries/backup/auth_retired_secret_keys.select.sql"),
        insert: include_str!("../queries/backup/auth_retired_secret_keys.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("retired_key_id", Kind::Blob, false),
            col("envelope", Kind::Blob, false),
            col("stored_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_device_certificates",
        select: include_str!("../queries/backup/auth_device_certificates.select.sql"),
        insert: include_str!("../queries/backup/auth_device_certificates.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("device_id", Kind::Blob, false),
            col("identity_epoch", Kind::Integer, false),
            col("device_kind", Kind::Integer, false),
            col("expires_at_ms", Kind::Integer, false),
            col("certificate", Kind::Blob, false),
            col("suspended_at_ms", Kind::Integer, true),
            col("stored_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_device_revocations",
        select: include_str!("../queries/backup/auth_device_revocations.select.sql"),
        insert: include_str!("../queries/backup/auth_device_revocations.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("device_id", Kind::Blob, false),
            col("last_accepted_device_seq", Kind::Integer, false),
            col("revocation", Kind::Blob, false),
            col("stored_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_key_grants",
        select: include_str!("../queries/backup/auth_key_grants.select.sql"),
        insert: include_str!("../queries/backup/auth_key_grants.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("recipient_device_id", Kind::Blob, false),
            col("account_key_epoch", Kind::Integer, false),
            col("sender_device_id", Kind::Blob, false),
            col("grant_record", Kind::Blob, false),
            col("stored_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_totp_credentials",
        select: include_str!("../queries/backup/auth_totp_credentials.select.sql"),
        insert: include_str!("../queries/backup/auth_totp_credentials.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("totp_credential_seq", Kind::Integer, false),
            col("data_key_id", Kind::Integer, false),
            col("sealed_secret", Kind::Blob, false),
            col("last_accepted_step", Kind::Integer, true),
            col("created_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_rate_limits",
        select: include_str!("../queries/backup/auth_rate_limits.select.sql"),
        insert: include_str!("../queries/backup/auth_rate_limits.insert.sql"),
        columns: &[
            col("bucket", Kind::Blob, false),
            col("attempts", Kind::Integer, false),
            col("window_started_at_ms", Kind::Integer, false),
            col("blocked_until_ms", Kind::Integer, false),
            col("expires_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "auth_pending_recoveries",
        select: include_str!("../queries/backup/auth_pending_recoveries.select.sql"),
        insert: include_str!("../queries/backup/auth_pending_recoveries.insert.sql"),
        columns: &[
            col("account_id", Kind::Blob, false),
            col("recovery_epoch", Kind::Integer, false),
            col("opened_at_ms", Kind::Integer, false),
            col("available_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "vault_vaults",
        select: include_str!("../queries/backup/vault_vaults.select.sql"),
        insert: include_str!("../queries/backup/vault_vaults.insert.sql"),
        columns: &[
            col("id", Kind::Blob, false),
            col("account_id", Kind::Blob, false),
            col("vault_key_epoch", Kind::Integer, false),
            col("next_store_seq", Kind::Integer, false),
            col("created_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "vault_self_grants",
        select: include_str!("../queries/backup/vault_self_grants.select.sql"),
        insert: include_str!("../queries/backup/vault_self_grants.insert.sql"),
        columns: &[
            col("vault_id", Kind::Blob, false),
            col("account_key_epoch", Kind::Integer, false),
            col("vault_key_epoch", Kind::Integer, false),
            col("envelope", Kind::Blob, false),
            col("updated_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "vault_item_key_wraps",
        select: include_str!("../queries/backup/vault_item_key_wraps.select.sql"),
        insert: include_str!("../queries/backup/vault_item_key_wraps.insert.sql"),
        columns: &[
            col("vault_id", Kind::Blob, false),
            col("item_id", Kind::Blob, false),
            col("item_key_id", Kind::Blob, false),
            col("vault_key_epoch", Kind::Integer, false),
            col("envelope", Kind::Blob, false),
            col("updated_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "vault_ops",
        select: include_str!("../queries/backup/vault_ops.select.sql"),
        insert: include_str!("../queries/backup/vault_ops.insert.sql"),
        columns: &[
            col("vault_id", Kind::Blob, false),
            col("device_id", Kind::Blob, false),
            col("device_seq", Kind::Integer, false),
            col("item_id", Kind::Blob, false),
            col("op_id", Kind::Blob, false),
            col("vault_prev_seq", Kind::Integer, false),
            col("hlc", Kind::Integer, false),
            col("item_schema_version", Kind::Integer, false),
            col("vault_key_epoch", Kind::Integer, false),
            col("header", Kind::Blob, false),
            col("body_hash", Kind::Blob, false),
            col("wrap_hash", Kind::Blob, false),
            col("signature", Kind::Blob, false),
            col("body", Kind::Blob, true),
            col("key_wrap", Kind::Blob, true),
            col("stored_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "vault_snapshots",
        select: include_str!("../queries/backup/vault_snapshots.select.sql"),
        insert: include_str!("../queries/backup/vault_snapshots.insert.sql"),
        columns: &[
            col("vault_id", Kind::Blob, false),
            col("snapshot_id", Kind::Blob, false),
            col("item_id", Kind::Blob, false),
            col("author_device_id", Kind::Blob, false),
            col("item_schema_version", Kind::Integer, false),
            col("vault_key_epoch", Kind::Integer, false),
            col("header", Kind::Blob, false),
            col("envelope", Kind::Blob, false),
            col("wrap_hash", Kind::Blob, false),
            col("signature", Kind::Blob, false),
            col("key_wrap", Kind::Blob, true),
            col("clamped_vv", Kind::Blob, false),
            col("store_seq", Kind::Integer, false),
            col("stored_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "vault_compaction_queue",
        select: include_str!("../queries/backup/vault_compaction_queue.select.sql"),
        insert: include_str!("../queries/backup/vault_compaction_queue.insert.sql"),
        columns: &[
            col("vault_id", Kind::Blob, false),
            col("item_id", Kind::Blob, false),
            col("queued_at_ms", Kind::Integer, false),
        ],
    },
    TableSpec {
        name: "vault_device_cursors",
        select: include_str!("../queries/backup/vault_device_cursors.select.sql"),
        insert: include_str!("../queries/backup/vault_device_cursors.insert.sql"),
        columns: &[
            col("vault_id", Kind::Blob, false),
            col("device_id", Kind::Blob, false),
            col("cursor", Kind::Blob, false),
            col("updated_at_ms", Kind::Integer, false),
        ],
    },
];
