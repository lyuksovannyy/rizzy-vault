//! The encrypted export's payload: its encoding, its reader, and the import of our own export
//! ([ADR 0027] §1–§2; CRYPTO.md §11.14 for the file around it).
//!
//! # Layout (payload version 1, ADR 0027 §1)
//!
//! The plaintext of the `EXPORT_FILE` envelope, in CRYPTO.md §2 notation:
//!
//! ```text
//! payload = u16(payload_version = 1) ‖ u32(n) ‖ entry{n}
//! entry   = item_id (16) ‖ u16(item_schema_version = 1) ‖ covered_vv ‖ bytes(data)
//! covered_vv = u16(c) ‖ c × ( device_id (16) ‖ u64(seq) )      canonical VV of ADR 0012 §3
//! data    = ADR 0018 §3 live snapshot data (record kind 0x02) of the item's merged state
//! ```
//!
//! - **What is exported.** Every item of the vault whose state is live (Active or Trashed),
//!   with its registers and history exactly as the merge holds them, unknown keys and
//!   unsupported values included. Not exported: tombstones, the vault-settings item
//!   (`0xF001`), parked records (they are not part of an item's state).
//! - **Canonical.** Entries strictly ascending by `item_id`; `data` is the ADR 0018 §4
//!   canonical encoding (`rizzy_sync::record::encode_snapshot`). One vault state gives one
//!   payload.
//! - **Oversize items** cannot be encoded within ADR 0018 §10: the writer refuses the export
//!   ([`ClientError::ExportOversizeItems`]) and [`VaultSync::export_blockers`] names them. An
//!   item whose state breaks another ADR 0018 §5 rule (only a cycle of verified contexts can
//!   cause it) cannot be encoded either and is named the same way. Items with an unresolved
//!   disagreement are exported as merged and reported ([`EncryptedExport::unresolved`]).
//! - **Too large.** A payload over 16 MiB ([`MAX_PAYLOAD_LEN`]) is refused
//!   ([`ClientError::ExportTooLarge`]) before any key derivation. More than 1,048,576 entries
//!   are always over 16 MiB (an entry is at least 24 bytes), so the writer answers them the
//!   same way: the entry bound is a reader rule (§2 step 2), not a writer error.
//! - **Never plaintext to the host.** The payload is every item of the vault in plaintext.
//!   The only public call that builds it from a vault is [`VaultSync::export_encrypted`],
//!   which seals it in the same call; the step that builds it is private to this crate. A
//!   host gets plaintext out of a vault only through [`plaintext`](super::plaintext), which
//!   takes the typed acknowledgement of ADR 0027 §5 ("no flag, setting or environment
//!   variable skips this"). [`encode_payload`] is public for the fuzz target: it encodes
//!   bytes its caller already holds.
//! - **Versions.** The file's `version` stays 1; the reader requires `payload_version` 1 and
//!   refuses any other as "update required" ([`ClientError::ExportUpdateRequired`]). The
//!   payload version is inside the envelope because the file's `version` is not in the
//!   `EXPORT_FILE` context.
//!
//! # Reading (ADR 0027 §2 step 2)
//!
//! [`parse_payload`] checks, before any allocation: `len ≤ 16 MiB`; `n ≤ 1,048,576` and
//! `n × 24 ≤ remaining`; ascending `item_id`; `item_schema_version` = 1; `c × 24 ≤ remaining`
//! (`c` is a `u16`, so `c ≤ 65,535`); `bytes(data)` ≤ 12 MiB; then the record layer's
//! `parse_snapshot(covered_vv, data)` with every ADR 0018 §5 rule, accepting live snapshot
//! data only; no trailing bytes. **Any failure refuses the whole file**
//! ([`ClientError::InvalidExportFile`]); nothing is imported from a malformed payload. The
//! fuzz target `client_export_payload` runs it on arbitrary bytes.
//!
//! # Import (ADR 0027 §2 steps 3–5)
//!
//! Each entry becomes a **new item** through the one import path
//! ([`VaultSync::import_item_writes`]): a new item id and item key, and ops of the importing
//! device. Dots, HLCs and device ids of the exporting account are read only to pick what
//! displays; none is written.
//!
//! - each register's **displayed** value (ADR 0018 §6), unknown keys included, byte for byte,
//!   as a carried write; element ids kept; a register that displays Cleared writes nothing;
//! - `import.created_ms` = the ADR 0018 §9 "Created" time of the exported state;
//! - the history of `login.password`, newest first, as `pwhist/<id>/value` and `/ms`
//!   (`hlc >> 16`) with fresh element ids, at most 50;
//! - a Trashed item is created, then trashed in a second op;
//! - writes beyond one op's limits are split into consecutive ops.
//!
//! **Per-item refusals do not refuse the file**: the item is skipped and counted
//! ([`PayloadImport`]). The report names no value (INV-48).
//!
//! # Readings (conservative, where ADR 0027 §2 leaves a detail open)
//!
//! - **A write the new item may not make.** `check_carried` refuses a known key of another
//!   item type and the keys an M1 client never writes (`uri/<id>/match`,
//!   `share/<id>/secret`). Such a register is left out and counted
//!   ([`PayloadImport::fields_not_carried`]); the item is still imported. `rizzy-core` treats
//!   those keys the same way in a restore or duplicate as a new item.
//! - **Which items are skipped.** An item without a valid `item.type`, of a type this client
//!   does not support, or of the vault-settings type (which a writer never exports, and which
//!   is never imported as an item), and an item the import path refuses because it would be
//!   oversize as a new item.
//! - **Which history is carried.** Only history entries that are a non-empty Text, since
//!   `pwhist/<id>/value` is a Text; a cleared or unsupported entry counts as not carried, as
//!   do entries past the fiftieth and, on an item that is not a Login, all of them.
//! - **A tombstone in a payload** (record kind `0x03`) refuses the file: §1 defines `data` as
//!   live snapshot data.
//!
//! [ADR 0027]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0027-export-payload.md

use core::fmt;

use rizzy_core::encoding::{Reader, put_u16, put_u32};
use rizzy_core::envelope::symmetric::MAX_PLAINTEXT_LEN;
use rizzy_core::ids::{ID_LEN, ItemId};
use rizzy_core::item::ITEM_SCHEMA_VERSION;
use rizzy_core::item::key::{ElementId, FieldKey};
use rizzy_core::item::schema::{
    ATTR_MS, ATTR_VALUE, IMPORT_CREATED_MS, ITEM_TYPE, LIST_PWHIST, WriteError, WriteMode,
    WriteSource, check_carried,
};
use rizzy_core::item::types::{ItemType, SupportedType};
use rizzy_core::item::value::{Value, ValueRef};
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret::SecretBytes;
use rizzy_sync::merge::{ItemLifecycle, ItemMerge};
use rizzy_sync::record::{
    LiveSnapshot, MAX_SNAPSHOT_DATA_LEN, SnapshotData, encode_snapshot, parse_snapshot,
};
use rizzy_sync::vv::VersionVector;
use zeroize::Zeroizing;

use super::state;
use super::{read_export, write_export};
use crate::device::UnlockedDevice;
use crate::error::ClientError;
use crate::items::{ImportWrite, check_import};
use crate::sync::VaultSync;

/// The payload version this client writes and reads (ADR 0027 §1).
pub const PAYLOAD_VERSION: u16 = 1;

/// The largest payload: the 16 MiB an `EXPORT_FILE` envelope holds (CRYPTO.md §9.1;
/// ADR 0027 §1 "Too large").
pub const MAX_PAYLOAD_LEN: usize = MAX_PLAINTEXT_LEN;

/// Most entries a reader accepts (ADR 0027 §2 step 2).
pub const MAX_PAYLOAD_ENTRIES: usize = 1_048_576;

/// The fixed part of an entry: `item_id` (16), `item_schema_version` (2), the covered VV's
/// count (2) and the length of `data` (4) (ADR 0027 §2 step 2: "24 = the fixed part of an
/// entry").
const ENTRY_FIXED_LEN: usize = 24;

/// Most password-history entries carried into a new item (ADR 0027 §2 step 3; the merge keeps
/// at most 50 history entries per field, ADR 0018 §10).
pub const MAX_HISTORY: usize = rizzy_import::limits::MAX_HISTORY;

/// One item for [`encode_payload`]: its id, the covered VV of its merged state and the
/// ADR 0018 §3 live snapshot data of that state. `Debug` prints the id only.
#[derive(Clone, Copy)]
pub struct PayloadItem<'a> {
    /// The item's id.
    pub item_id: ItemId,
    /// The covered VV of the state (the item VV).
    pub covered: &'a VersionVector,
    /// The canonical live snapshot data of the state.
    pub data: &'a [u8],
}

impl fmt::Debug for PayloadItem<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PayloadItem")
            .field("item_id", &self.item_id)
            .finish_non_exhaustive()
    }
}

/// One entry of a parsed payload: an item's id, the covered VV of its exported state, and
/// that state as parsed live snapshot data, borrowing from the payload. `Debug` prints the id
/// only.
pub struct PayloadEntry<'a> {
    /// The item's id in the exporting vault.
    item_id: ItemId,
    /// The covered VV of the exported state.
    covered: VersionVector,
    /// The exported state.
    snapshot: LiveSnapshot<'a>,
}

impl fmt::Debug for PayloadEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PayloadEntry")
            .field("item_id", &self.item_id)
            .finish_non_exhaustive()
    }
}

impl<'a> PayloadEntry<'a> {
    /// The item's id in the exporting vault. An import never reuses it.
    #[must_use]
    pub const fn item_id(&self) -> ItemId {
        self.item_id
    }

    /// The covered VV of the exported state.
    #[must_use]
    pub const fn covered(&self) -> &VersionVector {
        &self.covered
    }

    /// The exported state: registers and history as the exporting merge held them.
    #[must_use]
    pub const fn snapshot(&self) -> &LiveSnapshot<'a> {
        &self.snapshot
    }
}

/// Encodes a payload (module docs, "Layout") into a zeroizing buffer allocated once at its
/// final size, then reads it back with [`parse_payload`], so a writer never emits what the
/// reader refuses.
///
/// # Errors
/// [`ClientError::ExportTooLarge`] for a payload over [`MAX_PAYLOAD_LEN`] or of more than
/// [`MAX_PAYLOAD_ENTRIES`] items (which is always over [`MAX_PAYLOAD_LEN`]: an entry is at
/// least 24 bytes), before anything is allocated (ADR 0027 §1 "Too large");
/// [`ClientError::InvalidInput`] for items that are not strictly ascending by id, or data
/// that is not live snapshot data of its covered VV.
pub fn encode_payload(items: &[PayloadItem<'_>]) -> Result<SecretBytes, ClientError> {
    // The entry bound is a reader rule (ADR 0027 §2 step 2). A writer over it is over 16 MiB
    // too, so it gets the "too large" refusal of §1, not an input error.
    let count = u32::try_from(items.len())
        .ok()
        .filter(|_| items.len() <= MAX_PAYLOAD_ENTRIES)
        .ok_or(ClientError::ExportTooLarge)?;
    let mut len = 6usize;
    for item in items {
        // `covered.encoded_len()` holds the VV's own `u16` count.
        len = len
            .saturating_add(ENTRY_FIXED_LEN - 2)
            .saturating_add(item.covered.encoded_len())
            .saturating_add(item.data.len());
    }
    if len > MAX_PAYLOAD_LEN {
        return Err(ClientError::ExportTooLarge);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    put_u16(&mut out, PAYLOAD_VERSION);
    put_u32(&mut out, count);
    for item in items {
        let data_len = u32::try_from(item.data.len()).map_err(|_| ClientError::InvalidInput)?;
        out.extend_from_slice(&item.item_id.to_bytes());
        put_u16(&mut out, ITEM_SCHEMA_VERSION);
        item.covered
            .encode(&mut out)
            .map_err(|_| ClientError::InvalidInput)?;
        put_u32(&mut out, data_len);
        out.extend_from_slice(item.data);
    }
    if out.len() != len || parse_payload(&out).is_err() {
        return Err(ClientError::InvalidInput);
    }
    Ok(SecretBytes::from_zeroizing(out))
}

/// Parses a payload (module docs, "Reading"). Every check runs before the allocation it
/// bounds; any failure refuses the whole payload. Never panics.
///
/// # Errors
/// [`ClientError::ExportUpdateRequired`] for a payload of another version;
/// [`ClientError::InvalidExportFile`] for every other failure.
pub fn parse_payload(payload: &[u8]) -> Result<Vec<PayloadEntry<'_>>, ClientError> {
    const BAD: ClientError = ClientError::InvalidExportFile;
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(BAD);
    }
    let mut reader = Reader::new(payload);
    if reader.u16().map_err(|_| BAD)? != PAYLOAD_VERSION {
        return Err(ClientError::ExportUpdateRequired);
    }
    let count = usize::try_from(reader.u32().map_err(|_| BAD)?).map_err(|_| BAD)?;
    if count > MAX_PAYLOAD_ENTRIES
        || count
            .checked_mul(ENTRY_FIXED_LEN)
            .is_none_or(|needed| needed > reader.remaining())
    {
        return Err(BAD);
    }
    // No capacity is reserved from `count`: each entry pushed has been read from the input.
    let mut entries = Vec::new();
    let mut previous: Option<[u8; ID_LEN]> = None;
    for _ in 0..count {
        let id = *reader.array::<ID_LEN>().map_err(|_| BAD)?;
        if previous.is_some_and(|p| id <= p) {
            return Err(BAD);
        }
        previous = Some(id);
        if reader.u16().map_err(|_| BAD)? != ITEM_SCHEMA_VERSION {
            return Err(BAD);
        }
        // Reads the `u16` count, checks `c × 24 ≤ remaining`, then the canonical entries.
        let covered = VersionVector::read(&mut reader).map_err(|_| BAD)?;
        let data = reader.bytes_max(MAX_SNAPSHOT_DATA_LEN).map_err(|_| BAD)?;
        let Ok(SnapshotData::Live(snapshot)) = parse_snapshot(&covered, data) else {
            return Err(BAD);
        };
        entries.push(PayloadEntry {
            item_id: ItemId::from_bytes(id),
            covered,
            snapshot,
        });
    }
    reader.finish().map_err(|_| BAD)?;
    Ok(entries)
}

/// A payload ready for the envelope, with what the writer reports (ADR 0027 §1). `Debug`
/// prints no byte of the payload.
///
/// Private to the crate: the payload is the whole vault in plaintext, and ADR 0027 §5 lets
/// plaintext leave `rizzy-client` only through the call that takes the typed acknowledgement.
/// [`VaultSync::export_encrypted`] seals it before anything reaches the host.
#[derive(Debug)]
pub(crate) struct PayloadExport {
    /// The payload.
    payload: SecretBytes,
    /// How many items it holds.
    pub(crate) items: usize,
    /// The items exported as merged while a disagreement about them is unresolved
    /// (ADR 0018 §3 "Snapshots are claims"; "exported as merged and reported", ADR 0027 §1).
    pub(crate) unresolved: Vec<ItemId>,
}

impl PayloadExport {
    /// The payload bytes: every item of the vault in plaintext. For
    /// [`write_export`] only; never logged or written as it is.
    #[must_use]
    pub(crate) fn expose_secret(&self) -> &[u8] {
        self.payload.expose_secret()
    }
}

/// An encrypted export file with what the writer reports (ADR 0027 §1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedExport {
    /// The file: the JSON document of CRYPTO.md §11.14.
    pub file: Vec<u8>,
    /// How many items it holds.
    pub items: usize,
    /// The items exported as merged while a disagreement about them is unresolved.
    pub unresolved: Vec<ItemId>,
}

/// What importing an export of our own did (ADR 0027 §2 step 4). Ids and counts only: "The
/// report names no value" (INV-48).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadImport {
    /// The new items, in the order of the payload.
    pub imported: Vec<ItemId>,
    /// Items skipped (module docs, "Which items are skipped").
    pub skipped_items: usize,
    /// Fields of imported items whose concurrent values collapsed to the displayed one.
    pub collapsed_fields: usize,
    /// History entries of imported items that were not carried: histories of other fields,
    /// and what of `login.password`'s was not carried (module docs).
    pub history_not_carried: usize,
    /// Registers of imported items left out because the new item may not write them (module
    /// docs, "A write the new item may not make").
    pub fields_not_carried: usize,
}

/// The encoded live snapshot of a merge's state, or `None` when the state cannot be encoded
/// within ADR 0018 §5 and §10 (an oversize item) or is not live.
fn encoded_state(merge: &ItemMerge) -> Option<SecretBytes> {
    let Ok(Some(data @ SnapshotData::Live(_))) = merge.snapshot_data() else {
        return None;
    };
    encode_snapshot(merge.covered(), &data).ok()
}

/// One new item built from a payload entry: what [`VaultSync::import_item_writes`] takes, and
/// what was lost on the way.
struct NewItem {
    /// The item's type.
    item_type: ItemType,
    /// The writes: where each comes from, its key and its value.
    writes: Vec<(WriteSource, FieldKey, Value)>,
    /// Whether the exported item displayed Trashed.
    trashed: bool,
    /// Fields whose concurrent values collapsed to the displayed one.
    collapsed: usize,
    /// History entries not carried.
    history_lost: usize,
    /// Registers the new item may not write.
    fields_lost: usize,
}

/// Builds the new item of one payload entry (module docs, "Import"); `None` skips the entry.
fn new_item<R: CryptoRng + ?Sized>(entry: &PayloadEntry<'_>, rng: &mut R) -> Option<NewItem> {
    let live = entry.snapshot();
    let item_type = state::item_type(live)?;
    let kind = item_type.supported().filter(|t| t.is_user_item())?;
    let mut item = NewItem {
        item_type,
        writes: Vec::new(),
        trashed: state::trashed(live)?,
        collapsed: 0,
        history_lost: state::other_history(live),
        fields_lost: 0,
    };
    item.writes.push((
        WriteSource::Entered,
        FieldKey::parse(ITEM_TYPE.as_bytes()).ok()?,
        Value::enumeration(item_type.id()),
    ));
    if let Some(ms) = state::created(live) {
        item.writes.push((
            WriteSource::Entered,
            FieldKey::parse(IMPORT_CREATED_MS.as_bytes()).ok()?,
            Value::u64(ms),
        ));
    }
    for register in state::fields(live) {
        let key = register.key().expose_secret();
        let shown = state::displayed(register)?;
        if shown.conflict {
            item.collapsed = item.collapsed.saturating_add(1);
        }
        if shown.value.is_empty() || key == ITEM_TYPE || key == IMPORT_CREATED_MS {
            continue;
        }
        match check_carried(item_type, WriteMode::Import, key.as_bytes(), shown.value) {
            Ok(()) => item.writes.push((
                WriteSource::Carried,
                FieldKey::parse(key.as_bytes()).ok()?,
                Value::copy_from_encoded(shown.value).ok()?,
            )),
            Err(WriteError::NotWritable | WriteError::WrongItemType) => {
                item.fields_lost = item.fields_lost.saturating_add(1);
            }
            Err(_) => return None,
        }
    }
    let mut carried = 0usize;
    for (value, ms) in state::password_history(live) {
        let is_password = matches!(ValueRef::decode(value), Ok(ValueRef::Text(t)) if !t.is_empty());
        if kind != SupportedType::Login || !is_password || carried >= MAX_HISTORY {
            item.history_lost = item.history_lost.saturating_add(1);
            continue;
        }
        carried += 1;
        let id = ElementId::generate(rng);
        item.writes.push((
            WriteSource::Entered,
            id.key(LIST_PWHIST, ATTR_VALUE).ok()?,
            Value::copy_from_encoded(value).ok()?,
        ));
        item.writes.push((
            WriteSource::Entered,
            id.key(LIST_PWHIST, ATTR_MS).ok()?,
            Value::u64(ms),
        ));
    }
    Some(item)
}

/// The new item of `entry`, if the import path takes it: [`new_item`], then the checks every
/// imported item passes before its first op ([`check_import`]). `None` skips the entry.
fn importable_item<R: CryptoRng + ?Sized>(
    entry: &PayloadEntry<'_>,
    rng: &mut R,
) -> Option<NewItem> {
    let item = new_item(entry, rng)?;
    let mut writes: Vec<(WriteSource, &str, &[u8])> = item
        .writes
        .iter()
        .map(|(source, key, value)| (*source, key.as_str(), value.expose_secret()))
        .collect();
    check_import(item.item_type, &mut writes).ok()?;
    Some(item)
}

/// What importing a payload would do, without a vault: the counts of [`PayloadImport`] for a
/// host to show before the user confirms, and the entry point of the fuzz target
/// `client_export_payload` into the import mapping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PayloadPreview {
    /// Items that would be imported.
    pub importable: usize,
    /// Items that would be skipped.
    pub skipped_items: usize,
    /// As [`PayloadImport::collapsed_fields`].
    pub collapsed_fields: usize,
    /// As [`PayloadImport::history_not_carried`].
    pub history_not_carried: usize,
    /// As [`PayloadImport::fields_not_carried`].
    pub fields_not_carried: usize,
}

/// Parses `payload` and runs the import mapping and its checks on every entry, writing
/// nothing (module docs, "Reading" and "Import"). `rng` supplies the element ids the mapping
/// draws for password history, as in the import itself.
///
/// # Errors
/// As [`parse_payload`].
pub fn preview_payload<R: CryptoRng + ?Sized>(
    payload: &[u8],
    rng: &mut R,
) -> Result<PayloadPreview, ClientError> {
    let mut preview = PayloadPreview::default();
    for entry in &parse_payload(payload)? {
        match importable_item(entry, rng) {
            Some(item) => {
                preview.importable = preview.importable.saturating_add(1);
                preview.collapsed_fields = preview.collapsed_fields.saturating_add(item.collapsed);
                preview.history_not_carried = preview
                    .history_not_carried
                    .saturating_add(item.history_lost);
                preview.fields_not_carried =
                    preview.fields_not_carried.saturating_add(item.fields_lost);
            }
            None => preview.skipped_items = preview.skipped_items.saturating_add(1),
        }
    }
    Ok(preview)
}

impl VaultSync {
    /// The merges an export holds (ADR 0027 §1 "What is exported"): every item whose state is
    /// live, Active or Trashed, ascending by id, without the vault-settings item.
    pub(crate) fn exported_merges(&self) -> impl Iterator<Item = (ItemId, &ItemMerge)> + '_ {
        self.merges().filter(|(id, merge)| {
            matches!(
                merge.lifecycle(),
                ItemLifecycle::Active | ItemLifecycle::Trashed
            ) && self.item_type(*id) != Some(ItemType::VAULT_SETTINGS)
        })
    }

    /// The items that stop an export: those that cannot be encoded within the ADR 0018 §10
    /// limits ("The writer refuses the export and names the items; the user runs 'duplicate
    /// as a new item' first", ADR 0027 §1). Empty when an export can be written. Item ids are
    /// not secret; the host shows each item's name from its own view of the vault.
    #[must_use]
    pub fn export_blockers(&self) -> Vec<ItemId> {
        self.exported_merges()
            .filter(|(_, merge)| encoded_state(merge).is_none())
            .map(|(id, _)| id)
            .collect()
    }

    /// The export payload of this vault (module docs, "Layout"), in a zeroizing buffer.
    ///
    /// Private to the crate (module docs, "Never plaintext to the host"): it returns every
    /// item in plaintext, so the host reaches it only sealed, through
    /// [`VaultSync::export_encrypted`].
    ///
    /// # Errors
    /// [`ClientError::ExportOversizeItems`] while [`VaultSync::export_blockers`] is not
    /// empty; [`ClientError::ExportTooLarge`] over 16 MiB; [`ClientError::Internal`].
    pub(crate) fn export_payload(&self) -> Result<PayloadExport, ClientError> {
        let mut states = Vec::new();
        let mut unresolved = Vec::new();
        for (id, merge) in self.exported_merges() {
            let data = encoded_state(merge).ok_or(ClientError::ExportOversizeItems)?;
            if merge.unresolved().next().is_some() {
                unresolved.push(id);
            }
            states.push((id, merge.covered(), data));
        }
        let items: Vec<PayloadItem<'_>> = states
            .iter()
            .map(|(id, covered, data)| PayloadItem {
                item_id: *id,
                covered,
                data: data.expose_secret(),
            })
            .collect();
        let payload = encode_payload(&items).map_err(|e| match e {
            ClientError::ExportTooLarge => e,
            _ => ClientError::Internal,
        })?;
        Ok(PayloadExport {
            payload,
            items: items.len(),
            unresolved,
        })
    }

    /// Writes an encrypted export of this vault under `export_password` (CRYPTO.md §11.14;
    /// ADR 0027 §1): the payload, then one Argon2id run and the `EXPORT_FILE` envelope. Every
    /// refusal of the payload comes before the key derivation.
    ///
    /// # Errors
    /// [`ClientError::ExportOversizeItems`] while [`VaultSync::export_blockers`] is not
    /// empty; [`ClientError::ExportTooLarge`] for a payload over 16 MiB;
    /// [`ClientError::InvalidInput`] for an empty export password or one with an unassigned
    /// code point; [`ClientError::Internal`].
    pub fn export_encrypted<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        export_password: &str,
        now_ms: u64,
    ) -> Result<EncryptedExport, ClientError> {
        let payload = self.export_payload()?;
        let file = write_export(rng, export_password, payload.expose_secret(), now_ms)?;
        Ok(EncryptedExport {
            file,
            items: payload.items,
            unresolved: payload.unresolved,
        })
    }

    /// Imports a payload into this vault (module docs, "Import"): the whole payload is parsed
    /// and checked first, then each entry becomes a new item.
    ///
    /// # Errors
    /// Before anything is written: [`ClientError::ReadOnly`]; [`ClientError::InvalidInput`] if
    /// `unlocked` is another device's; [`ClientError::ExportUpdateRequired`] or
    /// [`ClientError::InvalidExportFile`] for the payload. [`ClientError::Internal`], after
    /// which the items written so far stay.
    pub fn import_payload<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<PayloadImport, ClientError> {
        self.check_writable(unlocked)?;
        let entries = parse_payload(payload)?;
        let mut report = PayloadImport::default();
        for entry in &entries {
            let Some(item) = importable_item(entry, rng) else {
                report.skipped_items = report.skipped_items.saturating_add(1);
                continue;
            };
            let writes: Vec<ImportWrite<'_>> = item
                .writes
                .iter()
                .map(|(source, key, value)| ImportWrite {
                    source: *source,
                    key,
                    value,
                })
                .collect();
            match self.import_item_writes(
                rng,
                unlocked,
                item.item_type,
                &writes,
                item.trashed,
                now_ms,
            ) {
                Ok(id) => {
                    report.imported.push(id);
                    report.collapsed_fields =
                        report.collapsed_fields.saturating_add(item.collapsed);
                    report.history_not_carried =
                        report.history_not_carried.saturating_add(item.history_lost);
                    report.fields_not_carried =
                        report.fields_not_carried.saturating_add(item.fields_lost);
                }
                Err(ClientError::InvalidEdit) => {
                    report.skipped_items = report.skipped_items.saturating_add(1);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(report)
    }

    /// Imports an encrypted export file into this vault: [`read_export`] (the size cap, the
    /// strict JSON, the header checks, one Argon2id run, the envelope), then
    /// [`VaultSync::import_payload`] on the plaintext, which stays in its zeroizing buffer.
    ///
    /// # Errors
    /// As [`read_export`] and [`VaultSync::import_payload`]. The vault's own refusals
    /// ([`ClientError::ReadOnly`], [`ClientError::InvalidInput`]) come before the key
    /// derivation.
    pub fn import_encrypted<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        file: &[u8],
        export_password: &str,
        now_ms: u64,
    ) -> Result<PayloadImport, ClientError> {
        self.check_writable(unlocked)?;
        let payload = read_export(file, export_password)?;
        self.import_payload(rng, unlocked, payload.expose_secret(), now_ms)
    }
}
