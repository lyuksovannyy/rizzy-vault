//! The byte-blob codec of the encrypted local cache ([ADR 0026] §3, §4) for a host that stores
//! raw bytes only (`IndexedDB`), as opposed to the typed `SQLite` columns `rv` writes.
//!
//! # The split (written before this module's code, as CLAUDE.md requires)
//!
//! [`rizzy_client::store`] already is the host-agnostic model (ADR 0026 §4: "`rizzy-client`
//! owns all of this … the leaves run it"): [`rizzy_client::store::rows::CacheRows`] is the
//! in-memory row set and the reference executor for a [`rizzy_client::store::rows::Changeset`]
//! (what each write means), and [`rizzy_client::store::load`] verifies it back into a
//! [`rizzy_client::store::load::Loaded`] device. None of that moved: `rv`'s own `db.rs` is
//! already thin `sqlx` glue over the same model (checked while designing this module), so
//! there was nothing to extract into `rizzy-client` that was not already there.
//!
//! What was missing is purely a marshaling concern, and lives here, in the binding crate, not
//! in `rizzy-client` (ADR 0016 R1 is about *decisions*, and `rizzy-client` already makes every
//! one; this module makes none): **a canonical byte encoding of each cache-format-1 row**, so
//! that a store keyed and valued in raw bytes (an `IndexedDB` object store, or any other
//! byte-blob key-value store) can hold exactly [ADR 0026] §3's eight logical tables — "the same
//! logical stores, keyed identically, with the same blobs" (§3) — without ever parsing a
//! `rizzy-proto` type itself. [`STORE_NAMES`] are those eight tables' names, verbatim, so a
//! host's `IDBDatabase.createObjectStore` calls map 1:1 onto them (one call per name, run once,
//! mirroring [ADR 0026] §3's `SCHEMA`/`PRAGMAS` being run once for `rv`).
//!
//! # What crosses this boundary
//!
//! [`KvRow`] is one row: `store` (one of [`STORE_NAMES`]), `key` and `value`, every one opaque
//! bytes. `encode_rows` (crate-private: JavaScript only ever receives a [`KvRow`], never calls
//! this) turns a [`CacheRows`] into every [`KvRow`] it holds, used right after a flow applies a
//! changeset, to know what to persist; `decode_rows` is its inverse, used before
//! [`rizzy_client::store::load::open`]/[`rizzy_client::store::load::load`] read a dump back.
//! Never a delta: this build always round-trips the *whole* cache (reported, §
//! "Not attempted"), so correctness rests on one property, checked by this module's tests:
//! `decode_rows(encode_rows(rows)) == rows` after [`CacheRows::sort`]. A host writes every
//! [`KvRow`] of one call inside one `IndexedDB` transaction across the named stores, exactly as
//! `rv` runs one changeset as one `BEGIN IMMEDIATE` ([ADR 0026] §4: "a crash leaves the file
//! before or after a step, never inside one").
//!
//! The columns `rv`'s `SQLite` schema types (`INTEGER`, `BLOB`, composite primary keys) have no
//! `IndexedDB` equivalent one call can express as one blob, so this module's one new decision is
//! the byte layout of a composite key or a multi-column row. It reuses the project's own
//! canonical framing (`rizzy_core::encoding`: fixed-width big-endian integers, `bytes(x) =
//! u32(len(x)) ‖ x`) rather than inventing another one, and keeps every fixed-width field in
//! the order [ADR 0026] §3's column list gives it, so a composite key's bytewise order is still
//! its numeric/lexicographic order (as the ADR already requires of a `u64` `BLOB` column). This
//! layout is this module's own and not frozen by any ADR (reported, as `rows.rs` already notes
//! for `vaults.self_grant`'s JSON blob, which this module keeps: the served grant is held as
//! the same JSON object cache format 1 already chose for `SQLite`, for one format across both
//! hosts).
//!
//! # Not attempted here
//!
//! - **Delta writes.** Every call re-encodes the whole [`CacheRows`]; an incremental changeset
//!   → `KvRow` diff (write only the rows a step actually touched) is a documented follow-up,
//!   not a correctness requirement ([`CacheRows::apply`] is still the only place a write's
//!   meaning is decided; this module never reimplements it).
//! - **Migration.** Cache format 1 is the only format `rizzy-client` itself knows yet (its own
//!   module docs, "Not in this build"); this module inherits that.
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md

use rizzy_client::ClientError;
use rizzy_client::rizzy_core::encoding::{Reader, put_bytes, put_u8, put_u64};
use rizzy_client::rizzy_proto::limits::{
    MAX_ACCOUNT_STATEMENT_LEN, MAX_ENVELOPE_LEN, MAX_KEY_ENVELOPE_LEN, MAX_OP_STATEMENT_LEN,
    MAX_SNAPSHOT_STATEMENT_LEN, MAX_UPLOAD_BODY_LEN,
};
use rizzy_client::store::record::MAX_DEVICE_STATE_LEN;
use rizzy_client::store::rows::limits::{
    MAX_CACHE_META_VALUE_LEN, MAX_KEY_COLUMN_LEN, MAX_SELF_GRANT_JSON_LEN,
};
use rizzy_client::store::rows::{
    CacheRows, ObjectRow, OpRow, SnapshotRow, VaultRow, WrapRow, kind, meta, own,
};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::error::CoreError;

/// `bytes` if it is within `max`, else `cache_corrupt`: every blob is checked against its
/// `rizzy-proto`/cache-format limit before anything parses it (ADR 0026 §3, "Each blob is
/// length-checked against its rizzy-proto limit before it is parsed"; `rv`'s `db.rs` runs the
/// same check in `SQLite` before a row's bytes ever reach Rust — `crates/rizzy-cli/src/db.rs`'s
/// `OVERSIZE_*` queries and this function's call sites use the identical caps,
/// `rizzy_client::store::rows::limits` and `rizzy_proto::limits`, so the two hosts can never
/// drift onto different ones).
fn capped(bytes: &[u8], max: usize) -> Result<&[u8], ClientError> {
    if bytes.len() > max {
        Err(ClientError::CacheCorrupt)
    } else {
        Ok(bytes)
    }
}

/// [`capped`] for an optional field.
fn capped_opt(bytes: Option<&[u8]>, max: usize) -> Result<Option<&[u8]>, ClientError> {
    bytes.map(|b| capped(b, max)).transpose()
}

/// [ADR 0026] §3's eight logical stores, verbatim, in schema order. A host creates exactly
/// these `IndexedDB` object stores, once, the way `rv` runs `SCHEMA` once.
///
/// [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md
pub const STORE_NAMES: [&str; 8] = [
    "cache_meta",
    "device_state",
    "pending_commit",
    "account_objects",
    "vaults",
    "wraps",
    "ops",
    "snapshots",
];

/// The `IndexedDB` key of the single-row `device_state`/`pending_commit` tables (`SQLite`'s
/// `INTEGER PRIMARY KEY CHECK (id = 1)`).
const SINGLETON_KEY: [u8; 1] = [1];

/// [`STORE_NAMES`], for a host building its `IndexedDB` schema. A plain function, not a
/// constant, because `#[wasm_bindgen]` cannot export a `const` array directly.
#[wasm_bindgen(js_name = cacheStoreNames)]
#[must_use]
pub fn cache_store_names() -> Vec<String> {
    STORE_NAMES.iter().map(|s| (*s).to_owned()).collect()
}

/// One row of a byte-blob cache store: the object store's name ([`STORE_NAMES`]), its key and
/// its value, all opaque bytes (module docs). `Debug` shows the store and key only: a value may
/// hold ciphertext this build does not log.
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq)]
pub struct KvRow {
    /// One of [`STORE_NAMES`].
    store: String,
    /// The row's key within that store.
    key: Vec<u8>,
    /// The row's value.
    value: Vec<u8>,
}

impl core::fmt::Debug for KvRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KvRow")
            .field("store", &self.store)
            .field("key_len", &self.key.len())
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl KvRow {
    /// Wraps a row a host read back from its own byte-blob store (the `IndexedDB` adapter),
    /// so it can be handed to [`crate::device::DeviceSession::unlock`]. `store` need not be
    /// one of [`STORE_NAMES`] here: `decode_rows` is where an unknown name is refused
    /// (`cache_corrupt`), the same as every other untrusted field of a row.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn from_js(store: String, key: Vec<u8>, value: Vec<u8>) -> Self {
        Self { store, key, value }
    }

    /// One of [`STORE_NAMES`].
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn store(&self) -> String {
        self.store.clone()
    }

    /// The key, a copy.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }

    /// The value, a copy.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn value(&self) -> Vec<u8> {
        self.value.clone()
    }
}

impl KvRow {
    /// A row for `store`. `pub(crate)` so other modules of this crate (and their tests) can
    /// build one directly, while JavaScript only ever receives one from [`encode_rows`].
    pub(crate) fn new(store: &'static str, key: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            store: store.to_owned(),
            key,
            value,
        }
    }
}

/// One row's location, with no value: what `CacheDelta::diff` reports removed. `Debug` shows the
/// store only, as [`KvRow`].
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq)]
pub struct CacheKey {
    /// One of [`STORE_NAMES`].
    store: String,
    /// The row's key within that store.
    key: Vec<u8>,
}

impl core::fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CacheKey")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl CacheKey {
    /// One of [`STORE_NAMES`].
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn store(&self) -> String {
        self.store.clone()
    }

    /// The key, a copy.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

/// The minimal write a host's byte-blob cache store needs to catch up with a device session's
/// steps since the last drain (`crate::device::DeviceSession`'s module docs, "Sync and items"):
/// every row to `put` and every key to `delete`, across [`STORE_NAMES`]. A host with a
/// `get`/`put`/`delete`/`list` store (ADR 0026 §3) applies `deletes` and `puts` in the one
/// transaction [`Changeset`](rizzy_client::store::rows::Changeset)'s own module docs call "one
/// `BEGIN IMMEDIATE`" — never one without the other, so a crash leaves the store at the row set
/// before this drain or after it, never between the two.
#[wasm_bindgen]
#[derive(Clone, Debug, Default)]
pub struct CacheDelta {
    /// Rows to write (new or changed).
    puts: Vec<KvRow>,
    /// Rows to remove: present before the drain, absent after.
    deletes: Vec<CacheKey>,
}

#[wasm_bindgen]
impl CacheDelta {
    /// The rows to `put`, a copy.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn puts(&self) -> Vec<KvRow> {
        self.puts.clone()
    }

    /// The keys to `delete`, a copy.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn deletes(&self) -> Vec<CacheKey> {
        self.deletes.clone()
    }

    /// Whether there is nothing to write: a host need not open a transaction for an empty
    /// delta.
    #[wasm_bindgen(getter, js_name = isEmpty)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.puts.is_empty() && self.deletes.is_empty()
    }
}

impl CacheDelta {
    /// The rows of `before` that changed or were added in `after` (`puts`), and the rows of
    /// `before` missing from `after` (`deletes`), by `(store, key)`. Never inspects a value
    /// beyond byte equality: deciding what a row *means* is
    /// [`rizzy_client::store::rows::CacheRows::apply`]'s job, already run by the caller before
    /// `after` was encoded (`crate::device`'s module docs, "The split"); this function only
    /// reports the bytes that differ, so a host's `put`/`delete` calls move it from `before`'s
    /// row set to `after`'s, never further.
    pub(crate) fn diff(before: &[KvRow], after: &[KvRow]) -> Self {
        let mut before_map: std::collections::BTreeMap<(&str, &[u8]), &[u8]> =
            std::collections::BTreeMap::new();
        for row in before {
            before_map.insert(
                (row.store.as_str(), row.key.as_slice()),
                row.value.as_slice(),
            );
        }
        let mut puts = Vec::new();
        let mut seen: std::collections::BTreeSet<(&str, &[u8])> = std::collections::BTreeSet::new();
        for row in after {
            let id = (row.store.as_str(), row.key.as_slice());
            seen.insert(id);
            if before_map.get(&id) != Some(&row.value.as_slice()) {
                puts.push(row.clone());
            }
        }
        let deletes = before
            .iter()
            .filter(|row| !seen.contains(&(row.store.as_str(), row.key.as_slice())))
            .map(|row| CacheKey {
                store: row.store.clone(),
                key: row.key.clone(),
            })
            .collect();
        Self { puts, deletes }
    }
}

/// `put_u8(1)` then `put_bytes(b)`, or `put_u8(0)` for `None`: an optional byte string that
/// still decodes unambiguously.
fn put_opt_bytes(out: &mut Vec<u8>, b: Option<&[u8]>) -> Result<(), CoreError> {
    if let Some(b) = b {
        put_u8(out, 1);
        put_bytes(out, b).map_err(|_| CoreError::from(ClientError::Internal))
    } else {
        put_u8(out, 0);
        Ok(())
    }
}

/// The inverse of [`put_opt_bytes`].
fn get_opt_bytes<'a>(r: &mut Reader<'a>) -> Result<Option<&'a [u8]>, ClientError> {
    let corrupt = ClientError::CacheCorrupt;
    match r.u8().map_err(|_| corrupt)? {
        0 => Ok(None),
        1 => Ok(Some(r.bytes().map_err(|_| corrupt)?)),
        _ => Err(corrupt),
    }
}

/// Every [`KvRow`] of `rows` (module docs; this is the whole cache, not a delta).
///
/// # Errors
/// [`ClientError::Internal`] if a vault's self-grant does not serialise to JSON ([`vault_row`]).
/// A host must never persist a partial encoding on this error: dropping even one row would
/// make the next load miss a vault or a cache row that was supposedly already written.
pub(crate) fn encode_rows(rows: &CacheRows) -> Result<Vec<KvRow>, ClientError> {
    let mut out = Vec::new();
    for (key, value) in &rows.meta {
        out.push(KvRow::new(
            "cache_meta",
            key.as_bytes().to_vec(),
            value.clone(),
        ));
    }
    if let Some(record) = &rows.device_state {
        out.push(KvRow::new(
            "device_state",
            SINGLETON_KEY.to_vec(),
            record.as_slice().to_vec(),
        ));
    }
    if let Some(request) = &rows.pending_commit {
        out.push(KvRow::new(
            "pending_commit",
            SINGLETON_KEY.to_vec(),
            request.clone(),
        ));
    }
    for row in &rows.objects {
        out.push(object_row(row));
    }
    for row in &rows.vaults {
        out.push(vault_row(row)?);
    }
    for row in &rows.wraps {
        out.push(wrap_row(row));
    }
    for row in &rows.ops {
        out.push(op_row(row));
    }
    for row in &rows.snapshots {
        out.push(snapshot_row(row));
    }
    Ok(out)
}

/// `account_objects`: key `u64(kind) ‖ key`, so two rows of different kinds never collide and
/// the bytewise order of same-kind keys matches the ADR's numeric order.
fn object_row(row: &ObjectRow) -> KvRow {
    let mut key = Vec::with_capacity(8 + row.key.len());
    #[expect(
        clippy::cast_sign_loss,
        reason = "account_objects.kind is one of the 7 small non-negative constants in `kind`"
    )]
    put_u64(&mut key, row.kind as u64);
    key.extend_from_slice(&row.key);
    KvRow::new("account_objects", key, row.bytes.clone())
}

/// `vaults`: key `vault_id`; value the served grant as JSON (the convention `rows.rs` already
/// chose for `SQLite`), then `wraps_after_epoch` and `restore_generation` as optional fields.
///
/// # Errors
/// [`ClientError::Internal`] if the grant does not serialise (it always does: it round-tripped
/// through `rizzy-proto`'s own JSON codec to reach this row).
fn vault_row(row: &VaultRow) -> Result<KvRow, ClientError> {
    let grant_json = serde_json::to_vec(&row.self_grant).map_err(|_| ClientError::Internal)?;
    let mut value = Vec::new();
    put_bytes(&mut value, &grant_json).map_err(|_| ClientError::Internal)?;
    match row.wraps_after_epoch {
        Some(epoch) => {
            put_u8(&mut value, 1);
            #[expect(
                clippy::cast_sign_loss,
                reason = "an epoch is never negative; the column is INTEGER only for SQLite's NULL"
            )]
            put_u64(&mut value, epoch as u64);
        }
        None => put_u8(&mut value, 0),
    }
    put_opt_bytes(&mut value, row.restore_generation.as_deref())
        .map_err(|_| ClientError::Internal)?;
    Ok(KvRow::new("vaults", row.vault_id.clone(), value))
}

/// `wraps`: key `vault_id ‖ item_id ‖ item_key_id` (each a fixed 16 bytes); value
/// `u64(vault_key_epoch) ‖ bytes(envelope)`.
fn wrap_row(row: &WrapRow) -> KvRow {
    let mut key = Vec::with_capacity(48);
    key.extend_from_slice(&row.vault_id);
    key.extend_from_slice(&row.item_id);
    key.extend_from_slice(&row.item_key_id);
    let mut value = Vec::new();
    #[expect(clippy::cast_sign_loss, reason = "an epoch is never negative")]
    put_u64(&mut value, row.vault_key_epoch as u64);
    // `put_bytes` only fails above `u32::MAX` bytes, far above any envelope this build parses;
    // an oversized envelope was already refused before it became a row.
    let _ = put_bytes(&mut value, &row.envelope);
    KvRow::new("wraps", key, value)
}

/// `ops`: key `vault_id ‖ device_id ‖ device_seq` (`device_seq` already the 8-byte big-endian
/// form `rizzy-client` stores it in); value every other column, in schema order.
fn op_row(row: &OpRow) -> KvRow {
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(&row.vault_id);
    key.extend_from_slice(&row.device_id);
    key.extend_from_slice(&row.device_seq);
    let mut value = Vec::new();
    let _ = put_bytes(&mut value, &row.item_id);
    let _ = put_bytes(&mut value, &row.statement);
    let _ = put_opt_bytes(&mut value, row.body.as_deref());
    let _ = put_opt_bytes(&mut value, row.key_wrap.as_deref());
    #[expect(
        clippy::cast_sign_loss,
        reason = "`own` is one of the 3 small non-negative values"
    )]
    put_u64(&mut value, row.own as u64);
    let _ = put_opt_bytes(&mut value, row.sent_generation.as_deref());
    KvRow::new("ops", key, value)
}

/// `snapshots`: key `vault_id ‖ snapshot_id`; value every other column, in schema order.
fn snapshot_row(row: &SnapshotRow) -> KvRow {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(&row.vault_id);
    key.extend_from_slice(&row.snapshot_id);
    let mut value = Vec::new();
    let _ = put_bytes(&mut value, &row.item_id);
    let _ = put_bytes(&mut value, &row.statement);
    let _ = put_bytes(&mut value, &row.envelope);
    let _ = put_opt_bytes(&mut value, row.key_wrap.as_deref());
    #[expect(
        clippy::cast_sign_loss,
        reason = "`own` is one of the 3 small non-negative values"
    )]
    put_u64(&mut value, row.own as u64);
    let _ = put_opt_bytes(&mut value, row.sent_generation.as_deref());
    KvRow::new("snapshots", key, value)
}

/// The inverse of [`encode_rows`]: every row of `dump`, which may be given in any order and
/// come from any subset of [`STORE_NAMES`] (an empty dump, for a fresh cache, decodes to an
/// empty [`CacheRows`]).
///
/// # Errors
/// [`ClientError::CacheCorrupt`] for a row whose store name is not one of [`STORE_NAMES`], a
/// key or value of the wrong shape for its store, or a duplicate singleton row. Nothing here
/// verifies a signature or a wrap: that is [`rizzy_client::store::load::open`]/`load`'s job,
/// run on the [`CacheRows`] this function returns, exactly as for `rv`'s `SQLite` rows (module
/// docs, "columns are indexes, never facts").
pub(crate) fn decode_rows(dump: &[KvRow]) -> Result<CacheRows, ClientError> {
    let corrupt = ClientError::CacheCorrupt;
    let mut rows = CacheRows::default();
    for row in dump {
        match row.store.as_str() {
            "cache_meta" => {
                let key = core::str::from_utf8(&row.key).map_err(|_| corrupt)?;
                if !meta::ALL.contains(&key) || rows.meta.contains_key(key) {
                    return Err(corrupt);
                }
                let value = capped(&row.value, MAX_CACHE_META_VALUE_LEN)?;
                rows.meta.insert(key.to_owned(), value.to_vec());
            }
            "device_state" => {
                if row.key != SINGLETON_KEY || rows.device_state.is_some() {
                    return Err(corrupt);
                }
                let value = capped(&row.value, MAX_DEVICE_STATE_LEN)?;
                rows.device_state = Some(zeroize::Zeroizing::new(value.to_vec()));
            }
            "pending_commit" => {
                if row.key != SINGLETON_KEY || rows.pending_commit.is_some() {
                    return Err(corrupt);
                }
                let value = capped(&row.value, MAX_UPLOAD_BODY_LEN)?;
                rows.pending_commit = Some(value.to_vec());
            }
            "account_objects" => rows.objects.push(decode_object_row(row)?),
            "vaults" => rows.vaults.push(decode_vault_row(row)?),
            "wraps" => rows.wraps.push(decode_wrap_row(row)?),
            "ops" => rows.ops.push(decode_op_row(row)?),
            "snapshots" => rows.snapshots.push(decode_snapshot_row(row)?),
            _ => return Err(corrupt),
        }
    }
    // A cache_meta row set that disagrees with cache format 1 (a wrong count, a missing or
    // extra key) is not refused here: `store::load::open` is the single place that checks
    // `cache_meta` as a whole, the same way it would for `rv`'s SQLite rows, so this function
    // never duplicates that check.
    Ok(rows)
}

/// The inverse of [`object_row`]: decodes one `account_objects` row. The value cap is
/// [`MAX_ENVELOPE_LEN`], the loosest of any kind (`SETTINGS`' own envelope); every other kind
/// is a signed statement under the tighter [`MAX_ACCOUNT_STATEMENT_LEN`] (as
/// `crates/rizzy-cli/src/db.rs`'s `read_rows` checks the same two caps in the same order).
fn decode_object_row(row: &KvRow) -> Result<ObjectRow, ClientError> {
    let corrupt = ClientError::CacheCorrupt;
    if row.key.len() < 8 || row.key.len() > MAX_KEY_COLUMN_LEN {
        return Err(corrupt);
    }
    let bytes = capped(&row.value, MAX_ENVELOPE_LEN)?;
    let mut r = Reader::new(&row.key);
    let kind_u64 = r.u64().map_err(|_| corrupt)?;
    let kind = i64::try_from(kind_u64).map_err(|_| corrupt)?;
    if !(kind::BUNDLE..=kind::ALARM).contains(&kind) {
        return Err(corrupt);
    }
    if kind != kind::SETTINGS && bytes.len() > MAX_ACCOUNT_STATEMENT_LEN {
        return Err(corrupt);
    }
    let rest = r.rest().to_vec();
    Ok(ObjectRow {
        kind,
        key: rest,
        bytes: bytes.to_vec(),
    })
}

/// The inverse of [`vault_row`]: decodes one `vaults` row.
fn decode_vault_row(row: &KvRow) -> Result<VaultRow, ClientError> {
    let corrupt = ClientError::CacheCorrupt;
    if row.key.len() != 16 {
        return Err(corrupt);
    }
    let mut r = Reader::new(&row.value);
    let grant_json = r.bytes().map_err(|_| corrupt)?;
    let grant_json = capped(grant_json, MAX_SELF_GRANT_JSON_LEN)?;
    let self_grant = serde_json::from_slice(grant_json).map_err(|_| corrupt)?;
    let has_epoch = r.u8().map_err(|_| corrupt)?;
    let wraps_after_epoch = match has_epoch {
        0 => None,
        1 => {
            let value = r.u64().map_err(|_| corrupt)?;
            Some(i64::try_from(value).map_err(|_| corrupt)?)
        }
        _ => return Err(corrupt),
    };
    let restore_generation = get_opt_bytes(&mut r)?.map(<[u8]>::to_vec);
    r.finish().map_err(|_| corrupt)?;
    Ok(VaultRow {
        vault_id: row.key.clone(),
        self_grant,
        wraps_after_epoch,
        restore_generation,
    })
}

/// The inverse of [`wrap_row`]: decodes one `wraps` row.
fn decode_wrap_row(row: &KvRow) -> Result<WrapRow, ClientError> {
    let corrupt = ClientError::CacheCorrupt;
    if row.key.len() != 48 {
        return Err(corrupt);
    }
    let mut r = Reader::new(&row.value);
    let epoch = r.u64().map_err(|_| corrupt)?;
    let envelope = capped(r.bytes().map_err(|_| corrupt)?, MAX_KEY_ENVELOPE_LEN)?.to_vec();
    r.finish().map_err(|_| corrupt)?;
    Ok(WrapRow {
        vault_id: row.key.get(0..16).ok_or(corrupt)?.to_vec(),
        item_id: row.key.get(16..32).ok_or(corrupt)?.to_vec(),
        item_key_id: row.key.get(32..48).ok_or(corrupt)?.to_vec(),
        vault_key_epoch: i64::try_from(epoch).map_err(|_| corrupt)?,
        envelope,
    })
}

/// The inverse of [`op_row`]: decodes one `ops` row.
fn decode_op_row(row: &KvRow) -> Result<OpRow, ClientError> {
    let corrupt = ClientError::CacheCorrupt;
    if row.key.len() != 40 {
        return Err(corrupt);
    }
    let mut r = Reader::new(&row.value);
    let item_id = capped(r.bytes().map_err(|_| corrupt)?, MAX_KEY_COLUMN_LEN)?.to_vec();
    let statement = capped(r.bytes().map_err(|_| corrupt)?, MAX_OP_STATEMENT_LEN)?.to_vec();
    let body = capped_opt(get_opt_bytes(&mut r)?, MAX_ENVELOPE_LEN)?.map(<[u8]>::to_vec);
    let key_wrap = capped_opt(get_opt_bytes(&mut r)?, MAX_KEY_ENVELOPE_LEN)?.map(<[u8]>::to_vec);
    let own_value = r.u64().map_err(|_| corrupt)?;
    let own_value = i64::try_from(own_value).map_err(|_| corrupt)?;
    if !matches!(
        own_value,
        own::SERVED | own::UNSENT | own::ACKNOWLEDGED | own::SENT
    ) {
        return Err(corrupt);
    }
    let sent_generation =
        capped_opt(get_opt_bytes(&mut r)?, MAX_KEY_COLUMN_LEN)?.map(<[u8]>::to_vec);
    r.finish().map_err(|_| corrupt)?;
    Ok(OpRow {
        vault_id: row.key.get(0..16).ok_or(corrupt)?.to_vec(),
        device_id: row.key.get(16..32).ok_or(corrupt)?.to_vec(),
        device_seq: row.key.get(32..40).ok_or(corrupt)?.to_vec(),
        item_id,
        statement,
        body,
        key_wrap,
        own: own_value,
        sent_generation,
    })
}

/// The inverse of [`snapshot_row`]: decodes one `snapshots` row.
fn decode_snapshot_row(row: &KvRow) -> Result<SnapshotRow, ClientError> {
    let corrupt = ClientError::CacheCorrupt;
    if row.key.len() != 32 {
        return Err(corrupt);
    }
    let mut r = Reader::new(&row.value);
    let item_id = capped(r.bytes().map_err(|_| corrupt)?, MAX_KEY_COLUMN_LEN)?.to_vec();
    let statement = capped(r.bytes().map_err(|_| corrupt)?, MAX_SNAPSHOT_STATEMENT_LEN)?.to_vec();
    let envelope = capped(r.bytes().map_err(|_| corrupt)?, MAX_ENVELOPE_LEN)?.to_vec();
    let key_wrap = capped_opt(get_opt_bytes(&mut r)?, MAX_KEY_ENVELOPE_LEN)?.map(<[u8]>::to_vec);
    let own_value = r.u64().map_err(|_| corrupt)?;
    let own_value = i64::try_from(own_value).map_err(|_| corrupt)?;
    if !matches!(
        own_value,
        own::SERVED | own::UNSENT | own::ACKNOWLEDGED | own::SENT
    ) {
        return Err(corrupt);
    }
    let sent_generation =
        capped_opt(get_opt_bytes(&mut r)?, MAX_KEY_COLUMN_LEN)?.map(<[u8]>::to_vec);
    r.finish().map_err(|_| corrupt)?;
    Ok(SnapshotRow {
        vault_id: row.key.get(0..16).ok_or(corrupt)?.to_vec(),
        snapshot_id: row.key.get(16..32).ok_or(corrupt)?.to_vec(),
        item_id,
        statement,
        envelope,
        key_wrap,
        own: own_value,
        sent_generation,
    })
}

#[cfg(test)]
mod tests {
    use rizzy_client::store::rows::{CACHE_FORMAT, Write};

    use super::*;

    /// A `CacheRows` round-trips through [`encode_rows`]/[`decode_rows`] when it holds only the
    /// stores every cache has from its first write: meta, the device-state record and one
    /// account object.
    #[test]
    fn meta_and_device_state_round_trip() {
        let mut changeset = rizzy_client::store::rows::Changeset::new();
        changeset.push(Write::Meta {
            key: meta::FORMAT,
            value: CACHE_FORMAT.to_be_bytes().to_vec(),
        });
        changeset.push(Write::Meta {
            key: meta::SERVER_ORIGIN,
            value: b"https://vault.example.com".to_vec(),
        });
        changeset.push(Write::DeviceState(zeroize::Zeroizing::new(vec![1, 2, 3])));
        changeset.push(Write::PutObject(ObjectRow {
            kind: kind::ACCOUNT_STATE,
            key: Vec::new(),
            bytes: vec![9, 9, 9],
        }));
        let mut rows = CacheRows::default();
        rows.apply(&changeset);

        let dump = encode_rows(&rows).unwrap();
        let mut decoded = decode_rows(&dump).unwrap();
        decoded.sort();
        let mut expected = rows;
        expected.sort();
        assert_eq!(expected.objects, decoded.objects);
        assert_eq!(expected.meta, decoded.meta);
        assert_eq!(
            expected.device_state.map(|d| d.to_vec()),
            decoded.device_state.map(|d| d.to_vec())
        );
    }

    #[test]
    fn wrap_and_op_and_snapshot_rows_round_trip() {
        let mut rows = CacheRows::default();
        rows.wraps.push(WrapRow {
            vault_id: vec![1; 16],
            item_id: vec![2; 16],
            item_key_id: vec![3; 16],
            vault_key_epoch: 7,
            envelope: vec![4, 5, 6],
        });
        rows.ops.push(OpRow {
            vault_id: vec![1; 16],
            device_id: vec![2; 16],
            device_seq: 1u64.to_be_bytes().to_vec(),
            item_id: vec![3; 16],
            statement: vec![7, 8],
            body: Some(vec![9]),
            key_wrap: None,
            own: own::UNSENT,
            sent_generation: None,
        });
        rows.snapshots.push(SnapshotRow {
            vault_id: vec![1; 16],
            snapshot_id: vec![4; 16],
            item_id: vec![3; 16],
            statement: vec![10],
            envelope: vec![11, 12],
            key_wrap: Some(vec![13]),
            own: own::SENT,
            sent_generation: Some(vec![9; 16]),
        });
        rows.sort();

        let dump = encode_rows(&rows).unwrap();
        let mut decoded = decode_rows(&dump).unwrap();
        decoded.sort();
        assert_eq!(rows.wraps, decoded.wraps);
        assert_eq!(rows.ops, decoded.ops);
        assert_eq!(rows.snapshots, decoded.snapshots);
    }

    /// A `vaults` row round-trips, including the `wraps_after_epoch`/`restore_generation`
    /// optional fields: the one encode path with a fallible step ([`vault_row`]'s JSON grant),
    /// otherwise uncovered by the two tests above.
    #[test]
    fn vault_row_round_trips_with_and_without_optional_fields() {
        use rizzy_client::rizzy_proto::objects::VaultSelfGrant;
        use rizzy_client::rizzy_proto::wire::{Bytes, Id};

        let grant = VaultSelfGrant {
            vault_id: Id::from_bytes([5; 16]),
            account_key_epoch: 1,
            vault_key_epoch: 2,
            envelope: Bytes::from_slice(&[7, 8, 9]).unwrap(),
        };
        let mut rows = CacheRows::default();
        rows.vaults.push(VaultRow {
            vault_id: vec![5; 16],
            self_grant: grant.clone(),
            wraps_after_epoch: Some(3),
            restore_generation: Some(vec![6; 16]),
        });
        rows.vaults.push(VaultRow {
            vault_id: vec![9; 16],
            self_grant: VaultSelfGrant {
                vault_id: Id::from_bytes([9; 16]),
                ..grant
            },
            wraps_after_epoch: None,
            restore_generation: None,
        });
        rows.sort();

        let dump = encode_rows(&rows).unwrap();
        let mut decoded = decode_rows(&dump).unwrap();
        decoded.sort();
        assert_eq!(rows.vaults, decoded.vaults);
    }

    #[test]
    fn an_unknown_store_name_is_cache_corrupt() {
        let bad = KvRow::new("not_a_real_store", vec![], vec![]);
        assert_eq!(decode_rows(&[bad]).unwrap_err(), ClientError::CacheCorrupt);
    }

    #[test]
    fn a_duplicate_singleton_row_is_cache_corrupt() {
        let a = KvRow::new("device_state", SINGLETON_KEY.to_vec(), vec![1]);
        let b = KvRow::new("device_state", SINGLETON_KEY.to_vec(), vec![2]);
        assert_eq!(decode_rows(&[a, b]).unwrap_err(), ClientError::CacheCorrupt);
    }

    #[test]
    fn an_empty_dump_decodes_to_an_empty_cache() {
        let rows = decode_rows(&[]).unwrap();
        assert!(rows.meta.is_empty());
        assert!(rows.device_state.is_none());
        assert!(rows.objects.is_empty());
    }

    #[test]
    fn store_names_match_the_adr() {
        assert_eq!(cache_store_names(), STORE_NAMES.map(str::to_owned).to_vec());
    }

    // Every oversize test below builds a row whose blob is one byte over its cap and nothing
    // else about its shape valid (a `self_grant` that is not JSON, a `statement` that is not a
    // signed statement): `CacheCorrupt` must come from the length check, before any parse that
    // would otherwise be the first thing to notice the bytes are garbage (ADR 0026 §3; module
    // docs, `capped`).

    #[test]
    fn an_oversize_cache_meta_value_is_cache_corrupt_before_any_parse() {
        let row = KvRow::new(
            meta::FORMAT,
            meta::FORMAT.as_bytes().to_vec(),
            vec![0; MAX_CACHE_META_VALUE_LEN + 1],
        );
        assert_eq!(decode_rows(&[row]).unwrap_err(), ClientError::CacheCorrupt);
    }

    #[test]
    fn an_oversize_device_state_record_is_cache_corrupt() {
        let row = KvRow::new(
            "device_state",
            SINGLETON_KEY.to_vec(),
            vec![0; MAX_DEVICE_STATE_LEN + 1],
        );
        assert_eq!(decode_rows(&[row]).unwrap_err(), ClientError::CacheCorrupt);
    }

    #[test]
    fn an_oversize_pending_commit_request_is_cache_corrupt() {
        let row = KvRow::new(
            "pending_commit",
            SINGLETON_KEY.to_vec(),
            vec![0; MAX_UPLOAD_BODY_LEN + 1],
        );
        assert_eq!(decode_rows(&[row]).unwrap_err(), ClientError::CacheCorrupt);
    }

    #[test]
    fn an_oversize_account_objects_key_is_cache_corrupt() {
        let mut key = Vec::new();
        put_u64(&mut key, kind::ACCOUNT_STATE as u64);
        key.extend(std::iter::repeat_n(0u8, MAX_KEY_COLUMN_LEN));
        let row = KvRow::new("account_objects", key, vec![1, 2, 3]);
        assert_eq!(decode_rows(&[row]).unwrap_err(), ClientError::CacheCorrupt);
    }

    #[test]
    fn an_oversize_account_statement_is_cache_corrupt_even_under_the_envelope_cap() {
        // A non-`SETTINGS` kind's tighter cap (`MAX_ACCOUNT_STATEMENT_LEN`), exceeded while
        // still well inside the looser `MAX_ENVELOPE_LEN` the `SELECT`-level check alone would
        // have let through.
        let mut key = Vec::new();
        put_u64(&mut key, kind::BUNDLE as u64);
        let row = KvRow::new(
            "account_objects",
            key,
            vec![0; MAX_ACCOUNT_STATEMENT_LEN + 1],
        );
        assert_eq!(decode_rows(&[row]).unwrap_err(), ClientError::CacheCorrupt);
    }

    #[test]
    fn an_oversize_self_grant_is_cache_corrupt_before_any_json_parse() {
        let mut value = Vec::new();
        let _ = put_bytes(&mut value, &vec![0; MAX_SELF_GRANT_JSON_LEN + 1]);
        put_u8(&mut value, 0); // no `wraps_after_epoch`
        put_u8(&mut value, 0); // no `restore_generation`
        let row = KvRow::new("vaults", vec![5; 16], value);
        assert_eq!(decode_rows(&[row]).unwrap_err(), ClientError::CacheCorrupt);
    }

    #[test]
    fn an_oversize_wrap_envelope_is_cache_corrupt() {
        let mut value = Vec::new();
        put_u64(&mut value, 7);
        let _ = put_bytes(&mut value, &vec![0; MAX_KEY_ENVELOPE_LEN + 1]);
        let row = KvRow::new("wraps", vec![1; 48], value);
        assert_eq!(decode_rows(&[row]).unwrap_err(), ClientError::CacheCorrupt);
    }

    #[test]
    fn an_oversize_op_statement_is_cache_corrupt() {
        let mut value = Vec::new();
        let _ = put_bytes(&mut value, &[3; 16]); // item_id
        let _ = put_bytes(&mut value, &vec![0; MAX_OP_STATEMENT_LEN + 1]); // statement
        put_u8(&mut value, 0); // no body
        put_u8(&mut value, 0); // no key_wrap
        put_u64(&mut value, own::UNSENT.try_into().unwrap());
        put_u8(&mut value, 0); // no sent_generation
        let row = KvRow::new("ops", vec![1; 40], value);
        assert_eq!(decode_rows(&[row]).unwrap_err(), ClientError::CacheCorrupt);
    }

    #[test]
    fn an_oversize_snapshot_statement_is_cache_corrupt() {
        let mut value = Vec::new();
        let _ = put_bytes(&mut value, &[3; 16]); // item_id
        let _ = put_bytes(&mut value, &vec![0; MAX_SNAPSHOT_STATEMENT_LEN + 1]); // statement
        let _ = put_bytes(&mut value, &[9, 9, 9]); // envelope
        put_u8(&mut value, 0); // no key_wrap
        put_u64(&mut value, own::UNSENT.try_into().unwrap());
        put_u8(&mut value, 0); // no sent_generation
        let row = KvRow::new("snapshots", vec![1; 32], value);
        assert_eq!(decode_rows(&[row]).unwrap_err(), ClientError::CacheCorrupt);
    }

    #[test]
    fn diff_reports_additions_changes_and_removals_only() {
        let unchanged = KvRow::new("cache_meta", b"format".to_vec(), vec![1]);
        let changed_before = KvRow::new("cache_meta", b"hlc".to_vec(), vec![0]);
        let changed_after = KvRow::new("cache_meta", b"hlc".to_vec(), vec![1]);
        let removed = KvRow::new("cache_meta", b"gone".to_vec(), vec![9]);
        let added = KvRow::new("cache_meta", b"new".to_vec(), vec![7]);

        let before = vec![unchanged.clone(), changed_before, removed.clone()];
        let after = vec![unchanged, changed_after.clone(), added.clone()];

        let delta = CacheDelta::diff(&before, &after);
        assert_eq!(delta.puts(), vec![changed_after, added]);
        assert_eq!(
            delta.deletes(),
            vec![CacheKey {
                store: removed.store,
                key: removed.key,
            }]
        );
        assert!(!delta.is_empty());
    }

    #[test]
    fn diff_of_identical_rows_is_empty() {
        let row = KvRow::new("cache_meta", b"format".to_vec(), vec![1]);
        let delta = CacheDelta::diff(std::slice::from_ref(&row), std::slice::from_ref(&row));
        assert!(delta.is_empty());
    }

    #[test]
    fn diff_of_two_empty_sets_is_empty() {
        assert!(CacheDelta::diff(&[], &[]).is_empty());
    }
}
