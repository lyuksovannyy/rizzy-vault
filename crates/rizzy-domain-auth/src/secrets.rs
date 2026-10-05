//! The server secrets (CRYPTO.md §5.8, §5.11; ADR 0010 §4; threat model INV-50, INV-69).
//!
//! CRYPTO.md §5.11 is "the single normative list" of the secrets file's contents, in a
//! versioned format, `format = 1`:
//! - `server_setup` per `setup_id` (§5.8);
//! - `enum_key` (§5.9);
//! - `server_data_key` per `data_key_id`, 32 random bytes each, one marked current;
//! - the first-run bootstrap token (INV-69).
//!
//! [`ServerSecrets`] holds exactly that list in memory, with the generation primitive
//! ([`ServerSecrets::generate`], `rizzy-vault secrets init`), the rotation primitives
//! (§5.8 "Rotating `server_setup`", §5.11 "Rotation", with
//! [`ServerSecrets::drop_unused_data_keys`] for "the old key is dropped once no row names it")
//! and the startup checks against the
//! database ([`ServerSecrets::check_database`]) and, before `rizzy-vault restore` loads it,
//! against a logical backup ([`ServerSecrets::check_dump`], ADR 0023 §5 step 4).
//!
//! **What is not here, and why.** No Accepted ADR fixes the file's byte or text layout, only
//! its version (`format = 1`) and its contents. This crate therefore defines no encoding: it
//! takes and gives the parts ([`ServerSecrets::from_parts`], the accessors), and the reader and
//! writer of the file belong to `rizzy-server` once the layout is decided. Also the server's
//! job, because they are file-system facts (ADR 0010 §4): refusing a secrets path inside the
//! data directory, never writing the file at run time, and mode 0600.
//!
//! **Secrets never reach the database** (INV-50): the database stores only
//! `SHA-256(server AKE public key)` per `setup_id` and the `data_key_id` of every sealed row.
//! Every secret type here wipes itself on drop and redacts its `Debug`.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::opaque::{EnumKey, ServerSetup};
use rizzy_core::rng::CryptoRng;
use rizzy_core::server_seal::ServerDataKey;
use rizzy_storage::tables::TABLES;
use rizzy_storage::{Database, Dump, Value};
use zeroize::Zeroizing;

use crate::error::AuthError;
use crate::sql::{self, exec, fetch_all, fetch_opt};

/// The only secrets-file format this build knows (CRYPTO.md §5.11: "A versioned format
/// (`format = 1`)"). Any other value is refused, never guessed.
pub const SECRETS_FORMAT: u32 = 1;

/// Length of a generated first-run bootstrap token (INV-69). No Accepted ADR fixes it; 32
/// random bytes, like a session token (CRYPTO.md §5.10).
pub const BOOTSTRAP_TOKEN_LEN: usize = 32;

/// Why a set of secrets was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretsError {
    /// The format is not [`SECRETS_FORMAT`].
    UnsupportedFormat,
    /// There is no `server_setup`.
    NoSetup,
    /// There is no `server_data_key`, or none with the id marked current.
    NoCurrentDataKey,
    /// Two entries share one id.
    DuplicateId,
    /// An id is exhausted (a rotation past `u32::MAX`).
    IdOverflow,
}

impl fmt::Display for SecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedFormat => "unsupported secrets format",
            Self::NoSetup => "no OPAQUE server setup",
            Self::NoCurrentDataKey => "no current server data key",
            Self::DuplicateId => "duplicate setup or data key id",
            Self::IdOverflow => "setup or data key id overflow",
        })
    }
}

impl std::error::Error for SecretsError {}

/// Why the loaded secrets do not fit the database (the startup refusals of CRYPTO.md §5.8 and
/// §5.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupCheckError {
    /// The database records an OPAQUE setup under this `setup_id` whose public-key hash differs
    /// from the loaded setup's (§5.8: "The server refuses to start if the database has OPAQUE
    /// records and the loaded setup does not match").
    SetupMismatch {
        /// The `setup_id`.
        setup_id: u32,
    },
    /// OPAQUE records exist, yet none of the loaded setups is recorded in the database: a
    /// fresh secrets file next to a restored database (§5.8: "This keeps a restore from
    /// silently generating a fresh seed").
    NoRecordedSetup,
    /// A sealed row names a `data_key_id` the secrets file lacks (§5.11: "the server refuses to
    /// start if a row names an id the file lacks").
    MissingDataKey {
        /// The `data_key_id`.
        data_key_id: u32,
    },
    /// The secrets file holds a setup the database marks retired (ADR 0031 point 6): a crash
    /// between the two steps of `rizzy-vault secrets retire-setups`, or an old secrets backup
    /// that would bring the setup back. Running `secrets retire-setups` again removes it.
    RetiredSetupLoaded {
        /// The `setup_id`.
        setup_id: u32,
    },
    /// A logical backup checked by [`ServerSecrets::check_dump`] lacks one of the tables the
    /// check reads, or holds a value of the wrong kind or range there (an id outside `u32`).
    DumpShape,
}

impl fmt::Display for StartupCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetupMismatch { setup_id } => {
                write!(f, "OPAQUE setup {setup_id} does not match the database")
            }
            Self::NoRecordedSetup => {
                f.write_str("the database has OPAQUE records but none of the loaded setups")
            }
            Self::MissingDataKey { data_key_id } => {
                write!(
                    f,
                    "a sealed row names data key {data_key_id}, which the secrets lack"
                )
            }
            Self::RetiredSetupLoaded { setup_id } => write!(
                f,
                "the secrets file holds OPAQUE setup {setup_id}, which the database marks \
                 retired; run `rizzy-vault secrets retire-setups` again"
            ),
            Self::DumpShape => f.write_str(
                "the backup's OPAQUE setup, credential or TOTP rows do not have the expected shape",
            ),
        }
    }
}

impl std::error::Error for StartupCheckError {}

/// The server secrets of CRYPTO.md §5.11, in memory.
///
/// Not `Clone`: share it behind an `Arc`. `Debug` prints the ids only.
pub struct ServerSecrets {
    /// `server_setup` per `setup_id`. The highest id is the one new registrations use (§5.8
    /// "Rotating `server_setup`", step 2).
    setups: BTreeMap<u32, ServerSetup>,
    /// `enum_key` (§5.9).
    enum_key: EnumKey,
    /// `server_data_key` per `data_key_id`.
    data_keys: BTreeMap<u32, ServerDataKey>,
    /// The `data_key_id` marked current: new rows are sealed under it.
    current_data_key_id: u32,
    /// The first-run bootstrap token (INV-69), if the file still carries one.
    bootstrap_token: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for ServerSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSecrets")
            .field("format", &SECRETS_FORMAT)
            .field("setup_ids", &self.setups.keys().collect::<Vec<_>>())
            .field("data_key_ids", &self.data_keys.keys().collect::<Vec<_>>())
            .field("current_data_key_id", &self.current_data_key_id)
            .field(
                "bootstrap_token",
                &self.bootstrap_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish_non_exhaustive()
    }
}

impl ServerSecrets {
    /// New secrets for `rizzy-vault secrets init` (ADR 0010 §4): setup 1, a fresh `enum_key`,
    /// data key 1 marked current, and a fresh bootstrap token, all from the injected CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut setups = BTreeMap::new();
        setups.insert(1, ServerSetup::generate(rng));
        let enum_key = EnumKey::generate(rng);
        let mut data_keys = BTreeMap::new();
        data_keys.insert(1, ServerDataKey::generate(rng, 1));
        let mut token = Zeroizing::new(vec![0u8; BOOTSTRAP_TOKEN_LEN]);
        rng.fill_bytes(token.as_mut_slice());
        Self {
            setups,
            enum_key,
            data_keys,
            current_data_key_id: 1,
            bootstrap_token: Some(token),
        }
    }

    /// Assembles secrets read from the file by the server's reader.
    ///
    /// # Errors
    /// [`SecretsError`]: another format, no setup, no data key with the id marked current, or
    /// two setups or two data keys with one id.
    pub fn from_parts(
        format: u32,
        setups: Vec<(u32, ServerSetup)>,
        enum_key: EnumKey,
        data_keys: Vec<ServerDataKey>,
        current_data_key_id: u32,
        bootstrap_token: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Self, SecretsError> {
        if format != SECRETS_FORMAT {
            return Err(SecretsError::UnsupportedFormat);
        }
        let mut setup_map = BTreeMap::new();
        for (id, setup) in setups {
            if setup_map.insert(id, setup).is_some() {
                return Err(SecretsError::DuplicateId);
            }
        }
        if setup_map.is_empty() {
            return Err(SecretsError::NoSetup);
        }
        let mut key_map = BTreeMap::new();
        for key in data_keys {
            if key_map.insert(key.data_key_id(), key).is_some() {
                return Err(SecretsError::DuplicateId);
            }
        }
        if !key_map.contains_key(&current_data_key_id) {
            return Err(SecretsError::NoCurrentDataKey);
        }
        Ok(Self {
            setups: setup_map,
            enum_key,
            data_keys: key_map,
            current_data_key_id,
            bootstrap_token,
        })
    }

    /// Adds a new `server_setup` under the next `setup_id`, which new registrations then use
    /// (`rizzy-vault secrets rotate`, CRYPTO.md §5.8 steps 1–2). Returns the new id.
    ///
    /// # Errors
    /// [`SecretsError::IdOverflow`].
    pub fn rotate_setup<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<u32, SecretsError> {
        let id = self
            .setups
            .keys()
            .next_back()
            .map_or(Some(1), |last| last.checked_add(1))
            .ok_or(SecretsError::IdOverflow)?;
        self.setups.insert(id, ServerSetup::generate(rng));
        Ok(id)
    }

    /// Adds a new `server_data_key` under the next `data_key_id` and marks it current
    /// (`rizzy-vault secrets rotate --data-key`, CRYPTO.md §5.11 "Rotation"). Returns the new
    /// id. The old key stays until no row names it: `worker` re-seals the TOTP rows under the
    /// new key ([`crate::AuthService::reseal_totp_secrets`]), and
    /// [`ServerSecrets::drop_unused_data_keys`] then drops it.
    ///
    /// # Errors
    /// [`SecretsError::IdOverflow`].
    pub fn rotate_data_key<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<u32, SecretsError> {
        let id = self
            .data_keys
            .keys()
            .next_back()
            .map_or(Some(1), |last| last.checked_add(1))
            .ok_or(SecretsError::IdOverflow)?;
        self.data_keys.insert(id, ServerDataKey::generate(rng, id));
        self.current_data_key_id = id;
        Ok(id)
    }

    /// Drops every `server_data_key` that is not current and that no sealed row names any more
    /// (CRYPTO.md §5.11 "Rotation": "the old key is dropped once no row names it"). Returns the
    /// dropped ids, ascending; the caller writes the file.
    ///
    /// In one transaction it first deletes the login states expired at `now_ms`, as `worker`
    /// does (they can never be opened again, and the server is stopped, so nothing else would
    /// remove them), then reads every `data_key_id` a TOTP row or a login state names. A key
    /// a row still names is kept, so the startup check (§5.11: "the server refuses to start if
    /// a row names an id the file lacks") keeps passing; the current key is always kept.
    ///
    /// **Who calls it.** The server never writes the secrets file (ADR 0010 §4), so dropping is
    /// not `worker`'s: `worker` re-seals ([`crate::AuthService::reseal_totp_secrets`]), and
    /// `rizzy-vault secrets rotate --data-key`, which runs with the secrets mount writable and
    /// every server process excluded, calls this. No Accepted ADR names the actor; this reading
    /// is reported to the owner. The database must be at this release's schema.
    ///
    /// A logical backup taken before the rows were re-sealed still names the dropped key:
    /// restoring it needs a secrets backup from before the drop
    /// ([`ServerSecrets::check_dump`] refuses it otherwise).
    ///
    /// # Errors
    /// Storage errors; nothing is dropped then.
    pub async fn drop_unused_data_keys(
        &mut self,
        db: &Database,
        now_ms: u64,
    ) -> Result<Vec<u32>, AuthError> {
        let now = sql::u64_sql(now_ms, "now_ms")?;
        let mut tx = db.begin_write().await?;
        exec!(tx.conn(), sql::LOGIN_STATES_DELETE_EXPIRED, now)?;
        let mut named = BTreeSet::new();
        for query in [sql::TOTP_DATA_KEY_IDS, sql::LOGIN_STATE_DATA_KEY_IDS] {
            let ids: Vec<(i64,)> = fetch_all!(tx.conn(), (i64,), query)?;
            for (id,) in ids {
                named.insert(sql::sql_u32(id, "data_key_id")?);
            }
        }
        tx.commit().await?;
        let unused: Vec<u32> = self
            .data_keys
            .keys()
            .copied()
            .filter(|id| *id != self.current_data_key_id && !named.contains(id))
            .collect();
        for id in &unused {
            // Dropping the key wipes it (`ServerDataKey` zeroizes on drop).
            self.data_keys.remove(id);
        }
        Ok(unused)
    }

    /// The setups, by `setup_id`, for the server's writer.
    pub fn setups(&self) -> impl Iterator<Item = (u32, &ServerSetup)> {
        self.setups.iter().map(|(id, s)| (*id, s))
    }

    /// The setup new registrations use: the highest `setup_id` (§5.8 step 2).
    ///
    /// # Errors
    /// [`AuthError::Internal`] if there is none (unreachable: construction requires one).
    pub(crate) fn current_setup(&self) -> Result<(u32, &ServerSetup), AuthError> {
        self.setups
            .iter()
            .next_back()
            .map(|(id, s)| (*id, s))
            .ok_or(AuthError::Internal("no OPAQUE setup"))
    }

    /// The setup with `setup_id`, if the file still has it (§5.8 step 4: `secrets
    /// retire-setups` removes retired ones, ADR 0031 point 5).
    pub(crate) fn setup(&self, setup_id: u32) -> Option<&ServerSetup> {
        self.setups.get(&setup_id)
    }

    /// The `setup_id` new registrations use: the highest one (§5.8 step 2). Construction
    /// requires a setup, so there always is one; `0` is never returned for a constructed value.
    #[must_use]
    pub fn current_setup_id(&self) -> u32 {
        self.setups.keys().next_back().copied().unwrap_or(0)
    }

    /// Removes the setup `setup_id` from the file's contents (ADR 0031 point 5 step 2), unless
    /// it is the current one, which is never removed. Returns whether it was removed; dropping
    /// the setup wipes its OPRF seed and private key (opaque-ke's types wipe themselves).
    pub(crate) fn remove_setup(&mut self, setup_id: u32) -> bool {
        setup_id != self.current_setup_id() && self.setups.remove(&setup_id).is_some()
    }

    /// `enum_key`, for the server's writer and the fake `kdf_id` selector.
    #[must_use]
    pub const fn enum_key(&self) -> &EnumKey {
        &self.enum_key
    }

    /// The data keys, for the server's writer.
    pub fn data_keys(&self) -> impl Iterator<Item = &ServerDataKey> {
        self.data_keys.values()
    }

    /// The `data_key_id` marked current.
    #[must_use]
    pub const fn current_data_key_id(&self) -> u32 {
        self.current_data_key_id
    }

    /// The current data key, which seals every new row.
    ///
    /// # Errors
    /// [`AuthError::Internal`] (unreachable: construction checks it).
    pub(crate) fn current_data_key(&self) -> Result<&ServerDataKey, AuthError> {
        self.data_keys
            .get(&self.current_data_key_id)
            .ok_or(AuthError::Internal("no current data key"))
    }

    /// The data key a stored row names.
    ///
    /// # Errors
    /// [`AuthError::Internal`] when the file lacks it; the startup check refuses such a
    /// database, so this is reached only if a row changed underneath the running server.
    pub(crate) fn data_key(&self, data_key_id: u32) -> Result<&ServerDataKey, AuthError> {
        self.data_keys.get(&data_key_id).ok_or(AuthError::Internal(
            "a sealed row names an unknown data key",
        ))
    }

    /// The first-run bootstrap token (INV-69), for the admin API (M3) and the server's writer.
    /// Shown once, never logged.
    #[must_use]
    pub fn bootstrap_token(&self) -> Option<&[u8]> {
        self.bootstrap_token.as_deref().map(Vec::as_slice)
    }

    /// The startup checks of CRYPTO.md §5.8 and §5.11, run after migrating and before serving
    /// (ADR 0010 §4 "refuses to start"):
    ///
    /// 1. For every loaded setup whose `setup_id` the database records, the recorded
    ///    `SHA-256(AKE public key)` must equal the loaded setup's, and the database must not
    ///    mark it retired (ADR 0031 point 6: a crash between the two steps of
    ///    `secrets retire-setups` fails closed, and an old secrets backup cannot revive it).
    /// 2. If the database holds OPAQUE records, at least one loaded setup must be recorded
    ///    there already, so a fresh secrets file next to a restored database is refused rather
    ///    than silently answering with a new seed.
    /// 3. Every `data_key_id` a sealed row names (TOTP secrets, login states) must be loaded.
    /// 4. Then every loaded setup the database does not record yet is recorded, with `now_ms`.
    ///
    /// Records naming a `setup_id` the file no longer has are allowed: `secrets retire-setups`
    /// removes a retired setup from the file (CRYPTO.md §5.8 step 4, ADR 0031 point 5), and
    /// those accounts take the fake-record path at login and the device or recovery path
    /// (point 7). So is a database restored from before a retirement next to a file without
    /// the setup (point 6).
    ///
    /// # Errors
    /// `Ok(Err(StartupCheckError))` when the server must refuse to start; `Err(AuthError)` when
    /// the database could not be read or written.
    pub async fn check_database(
        &self,
        db: &Database,
        now_ms: u64,
    ) -> Result<Result<(), StartupCheckError>, AuthError> {
        let now = sql::u64_sql(now_ms, "now_ms")?;
        let mut tx = db.begin_write().await?;
        let mut recorded_any = false;
        let mut unrecorded = Vec::new();
        for (id, setup) in &self.setups {
            let stored: Option<(Vec<u8>, Option<i64>)> = fetch_opt!(
                tx.conn(),
                (Vec<u8>, Option<i64>),
                sql::SETUP_GET,
                i64::from(*id)
            )?;
            match stored {
                Some((hash, retired_at_ms)) => {
                    if hash.as_slice() != setup.public_key_hash().as_slice() {
                        return Ok(Err(StartupCheckError::SetupMismatch { setup_id: *id }));
                    }
                    if retired_at_ms.is_some() {
                        return Ok(Err(StartupCheckError::RetiredSetupLoaded { setup_id: *id }));
                    }
                    recorded_any = true;
                }
                None => unrecorded.push((*id, setup.public_key_hash())),
            }
        }
        let record_setups: Vec<(i64,)> = fetch_all!(tx.conn(), (i64,), sql::CREDENTIAL_SETUP_IDS)?;
        if !record_setups.is_empty() && !recorded_any {
            return Ok(Err(StartupCheckError::NoRecordedSetup));
        }
        for query in [sql::TOTP_DATA_KEY_IDS, sql::LOGIN_STATE_DATA_KEY_IDS] {
            let ids: Vec<(i64,)> = fetch_all!(tx.conn(), (i64,), query)?;
            for (id,) in ids {
                let id = sql::sql_u32(id, "data_key_id")?;
                if !self.data_keys.contains_key(&id) {
                    return Ok(Err(StartupCheckError::MissingDataKey { data_key_id: id }));
                }
            }
        }
        for (id, hash) in unrecorded {
            exec!(tx.conn(), sql::SETUP_INSERT, i64::from(id), &hash[..], now)?;
        }
        tx.commit().await?;
        Ok(Ok(()))
    }

    /// The checks 1–3 of [`ServerSecrets::check_database`], on a logical backup before
    /// `rizzy-vault restore` loads it (ADR 0023 §5 step 4: "require the dump's
    /// `auth_opaque_setups` to match it, as the startup check does"). Pure: it reads the dump's
    /// `auth_opaque_setups`, `auth_credentials` and `auth_totp_credentials` rows and writes
    /// nothing. Login states, the other sealed rows of check 3, are not in a backup
    /// (`rizzy_storage::tables::NOT_BACKED_UP`).
    ///
    /// # Errors
    ///
    /// [`StartupCheckError`] when the restore must be refused: a setup mismatch, a loaded setup
    /// the dump marks retired (ADR 0031 point 6: an old secrets backup must not revive it), OPAQUE records
    /// with none of the loaded setups recorded (a fresh secrets file next to an old backup), a
    /// TOTP row naming a data key the file lacks, or [`StartupCheckError::DumpShape`] when one
    /// of those tables is missing or a value there is not the integer or blob it must be.
    pub fn check_dump(&self, dump: &Dump) -> Result<(), StartupCheckError> {
        /// The rows of table `name`, and the index of each named column.
        fn table<'d, const N: usize>(
            dump: &'d Dump,
            name: &str,
            columns: [&str; N],
        ) -> Result<(&'d [Vec<Value>], [usize; N]), StartupCheckError> {
            let spec = TABLES
                .iter()
                .find(|s| s.name == name)
                .ok_or(StartupCheckError::DumpShape)?;
            let mut indexes = [0usize; N];
            for (slot, column) in indexes.iter_mut().zip(columns) {
                *slot = spec
                    .columns
                    .iter()
                    .position(|c| c.name == column)
                    .ok_or(StartupCheckError::DumpShape)?;
            }
            let rows = dump
                .tables
                .iter()
                .find(|t| t.table == name)
                .ok_or(StartupCheckError::DumpShape)?;
            Ok((rows.rows.as_slice(), indexes))
        }
        /// The integer at `index` of `row`.
        fn int(row: &[Value], index: usize) -> Result<i64, StartupCheckError> {
            match row.get(index) {
                Some(Value::Integer(v)) => Ok(*v),
                _ => Err(StartupCheckError::DumpShape),
            }
        }

        // 1. Every loaded setup the dump records must match; 2. OPAQUE records need one.
        let (setups, [id_col, hash_col, retired_col]) = table(
            dump,
            "auth_opaque_setups",
            ["setup_id", "ake_public_key_hash", "retired_at_ms"],
        )?;
        let mut recorded_any = false;
        for row in setups {
            let id = int(row, id_col)?;
            let Some(Value::Blob(hash)) = row.get(hash_col) else {
                return Err(StartupCheckError::DumpShape);
            };
            let retired = match row.get(retired_col) {
                Some(Value::Null) => false,
                Some(Value::Integer(_)) => true,
                _ => return Err(StartupCheckError::DumpShape),
            };
            let loaded = u32::try_from(id)
                .ok()
                .and_then(|id| Some((id, self.setup(id)?)));
            if let Some((setup_id, setup)) = loaded {
                if hash.as_slice() != setup.public_key_hash().as_slice() {
                    return Err(StartupCheckError::SetupMismatch { setup_id });
                }
                if retired {
                    return Err(StartupCheckError::RetiredSetupLoaded { setup_id });
                }
                recorded_any = true;
            }
        }
        let (credentials, _) = table(dump, "auth_credentials", ["setup_id"])?;
        if !credentials.is_empty() && !recorded_any {
            return Err(StartupCheckError::NoRecordedSetup);
        }
        // 3. Every data key a sealed TOTP row names must be loaded.
        let (totp, [key_col]) = table(dump, "auth_totp_credentials", ["data_key_id"])?;
        for row in totp {
            let id = int(row, key_col)?;
            let data_key_id = u32::try_from(id).map_err(|_| StartupCheckError::DumpShape)?;
            if !self.data_keys.contains_key(&data_key_id) {
                return Err(StartupCheckError::MissingDataKey { data_key_id });
            }
        }
        Ok(())
    }
}
