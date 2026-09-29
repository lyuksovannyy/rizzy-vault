//! Fetch from a cursor (ADR 0012 §7 "Fetch" as ADR 0021 §4 supersedes its bodiless-header
//! sentence).
//!
//! **One consistent read.** Every part of a response (heads, headers, bodies, wraps, covers and
//! the restore generation) comes from one read transaction: the SQLite reader in WAL mode, a
//! `REPEATABLE READ READ ONLY` transaction on PostgreSQL (`rizzy_storage::Database::begin_read`,
//! ADR 0021 §4). A compaction that commits during the Fetch is either wholly visible to it or
//! not at all, so a response never holds a bodiless header whose cover the same compaction
//! dropped.
//!
//! **What a page holds.**
//! - `heads`: every head h(V, d) (ADR 0021 §2), so the client can evaluate "Server behind".
//! - `ops`: every op header after the cursor, per device in chain order, each with its body when
//!   held and with its carried wrap while that wrap is still the current wrap-set row (CRYPTO.md
//!   §4.2: after a rotation "the server serves that record without its wrap"). Devices are taken
//!   in ascending id order, each from its cursor entry, and a page stops inside one device's
//!   chain only; the devices after it are untouched, so the client's advanced cursor (the
//!   highest `device_seq` it received per device) is exact.
//! - `covers`: for each item with a bodiless header in the page,
//!   `rizzy_sync::compaction::select_covers` over the item's retained snapshots, each served as
//!   its full record (ADR 0021 §4 "Each page of a paged response carries its own covers").
//! - `item_key_wraps`: every wrap-set row with a `vault_key_epoch` above the request's
//!   `wraps_after_epoch` (all on a first fetch), on every page.
//! - `complete`: `false` when the page stopped early; the client fetches again from its
//!   advanced cursor. A `false` page can be followed by an empty `complete` one.
//!
//! **Page bounds** (this crate's choice; `rizzy-proto` bounds each list at
//! [`MAX_RECORDS`]): at most [`PAGE_MAX_OPS`] ops, so that the covers, at most two per bodiless
//! header (each cover added raises some header's number of covering authors, up to two), fit
//! [`MAX_RECORDS`]; and at most [`PAGE_BYTES`] bytes (by default; `rizzy-server` may set
//! another budget with [`VaultDomain::with_page_bytes`]) of ops **and covers together**: an op's
//! statement, body and wrap, and every full cover snapshot its item's bodiless headers need.
//! An op joins the page only together with the covers it adds, so a bodiless header is never
//! split from its covers (ADR 0021 §4 "Each page of a paged response carries its own covers").
//! The first op always joins, however large, so a page always makes progress: its worst case is
//! one op of at most 16 MiB with two covers of at most 16 MiB each (CRYPTO.md §9.1; ADR 0021
//! "One snapshot | Plaintext ≤ 16 MiB").
//!
//! **Integrity errors** (ADR 0021 §4): "A bodiless header without a retained cover means a bug
//! or a damaged database. The server serves the header alone and logs an integrity error naming
//! the vault, item and dot, never content." This crate has no logging dependency, so it returns
//! each one as an [`IntegrityError`] with the response, and `rizzy-server` logs it.

use core::fmt;
use std::collections::BTreeMap;

use rizzy_core::ids::{AccountId, ItemId, VaultId};
use rizzy_proto::limits::{MAX_ITEM_KEY_WRAPS, MAX_RECORDS};
use rizzy_proto::objects::{Envelope, ItemKeyWrap, KeyEnvelope, OpStatement, SnapshotStatement};
use rizzy_proto::vault::{
    FetchRequest, FetchResponse, OpRecord, RecordKeyWrap, SeqEntry, SeqVector, SnapshotRecord,
};
use rizzy_proto::wire::{Id, List};
use rizzy_storage::ReadTx;
use rizzy_sync::compaction::{CoverSelection, RetainedSnapshot, select_covers};
use rizzy_sync::dot::Dot;

use crate::authors::DeviceDirectory;
use crate::error::VaultError;
use crate::repo::{self, FetchedOp, StoredRecord};
use crate::{VaultDomain, restore_generation};

/// The most ops in one page: half of [`MAX_RECORDS`], so that the page's covers fit the other
/// list's [`MAX_RECORDS`] (module docs).
pub const PAGE_MAX_OPS: usize = MAX_RECORDS / 2;

/// The default byte budget of one page, ops and covers together (module docs): 32 MiB. A page
/// holds at least one op and its covers, however large.
pub const PAGE_BYTES: usize = 32 * 1024 * 1024;

/// How many ops one query reads at a time.
const BATCH: usize = 256;

/// A bodiless header served without a retained cover (ADR 0021 §4): a bug or a damaged
/// database. Names the vault, item and dot, never content. `Display` gives the log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntegrityError {
    /// The vault.
    pub vault_id: VaultId,
    /// The item.
    pub item_id: ItemId,
    /// The op's dot.
    pub dot: Dot,
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "integrity error: bodiless header without a retained cover: vault {:?}, item {:?}, \
             device {:?}, seq {}",
            self.vault_id,
            self.item_id,
            self.dot.device_id(),
            self.dot.seq()
        )
    }
}

/// A Fetch page and the integrity errors found while building it.
#[derive(Clone, Debug)]
pub struct FetchOutcome {
    /// The page to send.
    pub response: FetchResponse,
    /// Bodiless headers of the page without a retained cover, for `rizzy-server` to log; empty
    /// on an honest, undamaged server (ADR 0021 §8 property 1).
    pub integrity_errors: Vec<IntegrityError>,
}

/// A proto value from stored bytes; a length a stored row cannot have is corruption.
fn wire_value<T, E>(value: Result<T, E>, what: &'static str) -> Result<T, VaultError> {
    value.map_err(|_| VaultError::Corrupt { what })
}

/// The carried wrap of a stored record, if it is still the current wrap-set row.
async fn served_wrap(
    tx: &mut ReadTx,
    vault_id: VaultId,
    item_id: ItemId,
    stored: Option<&[u8]>,
) -> Result<Option<RecordKeyWrap>, VaultError> {
    let Some(envelope) = stored else {
        return Ok(None);
    };
    let Some(item_key_id) = repo::wrap_by_envelope(tx.conn(), vault_id, item_id, envelope).await?
    else {
        return Ok(None);
    };
    Ok(Some(RecordKeyWrap {
        item_key_id: Id::from_bytes(item_key_id),
        envelope: wire_value(
            KeyEnvelope::from_slice(envelope),
            "a stored key wrap's length",
        )?,
    }))
}

/// An op record as served.
async fn op_record(
    tx: &mut ReadTx,
    vault_id: VaultId,
    op: &FetchedOp,
) -> Result<OpRecord, VaultError> {
    let wire = op.record.signed.wire().map_err(|_| VaultError::Corrupt {
        what: "a stored op statement does not encode",
    })?;
    Ok(OpRecord {
        statement: wire_value(OpStatement::new(wire), "a stored op statement's length")?,
        body: op
            .record
            .body
            .as_deref()
            .map(|b| wire_value(Envelope::from_slice(b), "a stored op body's length"))
            .transpose()?,
        key_wrap: served_wrap(tx, vault_id, op.item_id, op.record.key_wrap.as_deref()).await?,
    })
}

/// A snapshot record as served.
async fn snapshot_record(
    tx: &mut ReadTx,
    vault_id: VaultId,
    item_id: ItemId,
    stored: &StoredRecord,
) -> Result<SnapshotRecord, VaultError> {
    let wire = stored.signed.wire().map_err(|_| VaultError::Corrupt {
        what: "a stored snapshot statement does not encode",
    })?;
    let envelope = stored.body.as_deref().ok_or(VaultError::Corrupt {
        what: "vault_snapshots.envelope",
    })?;
    Ok(SnapshotRecord {
        statement: wire_value(
            SnapshotStatement::new(wire),
            "a stored snapshot statement's length",
        )?,
        envelope: wire_value(Envelope::from_slice(envelope), "a stored snapshot's length")?,
        key_wrap: served_wrap(tx, vault_id, item_id, stored.key_wrap.as_deref()).await?,
    })
}

/// The framing a served statement adds to its header and signature container: the statement
/// length, version and header length prefixes and the two signed hashes (CRYPTO.md §9.6).
const STATEMENT_FRAME: usize = 4 + 2 + 4 + 64;

/// The bytes an op adds to a page.
fn op_size(op: &FetchedOp) -> usize {
    let r = &op.record;
    (STATEMENT_FRAME + r.signed.header.len() + r.signed.container.len())
        .saturating_add(r.body.as_ref().map_or(0, Vec::len))
        .saturating_add(r.key_wrap.as_ref().map_or(0, Vec::len))
}

/// The covers of one item with bodiless headers in a page, as the page is being built.
struct ItemCovers {
    /// The item's retained snapshots.
    retained: Vec<RetainedSnapshot>,
    /// Each retained snapshot's size as served, by store sequence.
    sizes: BTreeMap<u64, usize>,
    /// The item's bodiless headers in the page so far.
    dots: Vec<Dot>,
    /// `select_covers` over `retained` and `dots`.
    selection: CoverSelection,
    /// The bytes of the selected covers.
    bytes: usize,
}

impl ItemCovers {
    /// The item's retained snapshots and their sizes, with no header yet.
    async fn load(tx: &mut ReadTx, vault_id: VaultId, item_id: ItemId) -> Result<Self, VaultError> {
        Ok(Self {
            retained: repo::item_snapshots(tx.conn(), vault_id, item_id).await?,
            sizes: repo::item_snapshot_sizes(tx.conn(), vault_id, item_id).await?,
            dots: Vec::new(),
            selection: CoverSelection::default(),
            bytes: 0,
        })
    }

    /// The covers once bodiless header `dot` joins the page: the new selection and its bytes.
    fn with(&self, dot: Dot) -> Result<(Vec<Dot>, CoverSelection, usize), VaultError> {
        let mut dots = self.dots.clone();
        dots.push(dot);
        let selection = select_covers(&self.retained, &dots).map_err(|_| VaultError::Corrupt {
            what: "vault_snapshots.store_seq repeats within an item",
        })?;
        let mut bytes = 0usize;
        for store_seq in &selection.covers {
            let size = self.sizes.get(store_seq).ok_or(VaultError::Corrupt {
                what: "a retained snapshot without a size inside one read transaction",
            })?;
            bytes = bytes.saturating_add(STATEMENT_FRAME.saturating_add(*size));
        }
        Ok((dots, selection, bytes))
    }
}

/// One page's ops and the covers of their bodiless headers.
struct Page {
    /// The ops, in the order the module docs give.
    ops: Vec<FetchedOp>,
    /// Whether nothing remains after them.
    complete: bool,
    /// The covers per item with a bodiless header in `ops`.
    covers: BTreeMap<ItemId, ItemCovers>,
}

/// The ops of one page, in the order the module docs give, with their covers, within
/// `budget` bytes (ops and covers together) and [`PAGE_MAX_OPS`] ops. An op joins the page only
/// with the covers it needs, so a bodiless header is never split from its covers; the first
/// op always joins, however large, so a page always makes progress.
async fn page_ops(
    tx: &mut ReadTx,
    vault_id: VaultId,
    heads: &rizzy_sync::vv::VersionVector,
    request: &FetchRequest,
    budget: usize,
) -> Result<Page, VaultError> {
    let mut page = Page {
        ops: Vec::new(),
        complete: false,
        covers: BTreeMap::new(),
    };
    // Bytes of the page's ops plus the bytes of every item's current covers.
    let mut bytes = 0usize;
    for head in heads.entries() {
        let device = head.device_id();
        let mut after = request.cursor.get(&Id::from_bytes(device.to_bytes()));
        while after < head.seq() {
            let room = PAGE_MAX_OPS.saturating_sub(page.ops.len());
            if room == 0 {
                return Ok(page);
            }
            let batch =
                repo::ops_after(tx.conn(), vault_id, device, after, room.min(BATCH)).await?;
            if batch.is_empty() {
                break;
            }
            for op in batch {
                let mut total = bytes.saturating_add(op_size(&op));
                let mut joined = None;
                if op.record.body.is_none() {
                    let item = match page.covers.remove(&op.item_id) {
                        Some(item) => item,
                        None => ItemCovers::load(tx, vault_id, op.item_id).await?,
                    };
                    let (dots, selection, cover_bytes) = item.with(op.dot)?;
                    total = total.saturating_sub(item.bytes).saturating_add(cover_bytes);
                    joined = Some((item, dots, selection, cover_bytes));
                }
                if !page.ops.is_empty() && total > budget {
                    // Put back an item this op would have changed, unchanged.
                    if let Some((item, ..)) = joined
                        && !item.dots.is_empty()
                    {
                        page.covers.insert(op.item_id, item);
                    }
                    return Ok(page);
                }
                if let Some((mut item, dots, selection, cover_bytes)) = joined {
                    item.dots = dots;
                    item.selection = selection;
                    item.bytes = cover_bytes;
                    page.covers.insert(op.item_id, item);
                }
                bytes = total;
                after = op.dot.seq();
                page.ops.push(op);
            }
        }
    }
    page.complete = true;
    Ok(page)
}

impl<D: DeviceDirectory> VaultDomain<D> {
    /// One Fetch page for the session's account, from one consistent read (module docs).
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for a vault that does not exist or belongs to another account;
    /// [`VaultError::WrapSetTooLarge`] when the wrap set to return exceeds one response;
    /// [`VaultError::Storage`], [`VaultError::NoRestoreGeneration`] or [`VaultError::Corrupt`]
    /// otherwise.
    pub async fn fetch(
        &self,
        account_id: AccountId,
        request: &FetchRequest,
    ) -> Result<FetchOutcome, VaultError> {
        let vault_id = VaultId::from_bytes(request.vault_id.to_bytes());
        let mut tx = self.database().begin_read().await?;
        repo::vault(tx.conn(), vault_id)
            .await?
            .filter(|v| v.account_id == account_id)
            .ok_or(VaultError::NotFound)?;
        let generation = restore_generation(tx.conn()).await?;
        let heads = repo::heads(tx.conn(), vault_id).await?;
        let wraps = repo::wraps_after(
            tx.conn(),
            vault_id,
            request.wraps_after_epoch,
            MAX_ITEM_KEY_WRAPS.saturating_add(1),
        )
        .await?;
        if wraps.len() > MAX_ITEM_KEY_WRAPS {
            return Err(VaultError::WrapSetTooLarge);
        }
        let page = page_ops(&mut tx, vault_id, &heads, request, self.page_bytes()).await?;
        let complete = page.complete;

        let mut records = Vec::with_capacity(page.ops.len());
        for op in &page.ops {
            records.push(op_record(&mut tx, vault_id, op).await?);
        }

        let mut covers = Vec::new();
        let mut integrity_errors = Vec::new();
        for (item_id, item) in page.covers {
            for store_seq in item.selection.covers {
                let stored = repo::snapshot_record(tx.conn(), vault_id, item_id, store_seq)
                    .await?
                    .ok_or(VaultError::Corrupt {
                        what: "a retained snapshot vanished inside one read transaction",
                    })?;
                covers.push(snapshot_record(&mut tx, vault_id, item_id, &stored).await?);
            }
            integrity_errors.extend(item.selection.uncovered.into_iter().map(|dot| {
                IntegrityError {
                    vault_id,
                    item_id,
                    dot,
                }
            }));
        }

        let item_key_wraps = wraps
            .into_iter()
            .map(|w| {
                Ok(ItemKeyWrap {
                    item_id: Id::from_bytes(w.item_id.to_bytes()),
                    item_key_id: Id::from_bytes(w.item_key_id),
                    vault_key_epoch: w.vault_key_epoch,
                    envelope: wire_value(KeyEnvelope::new(w.envelope), "a stored wrap's length")?,
                })
            })
            .collect::<Result<Vec<_>, VaultError>>()?;
        let heads = heads
            .entries()
            .map(|d| SeqEntry {
                device_id: Id::from_bytes(d.device_id().to_bytes()),
                seq: d.seq(),
            })
            .collect();
        tx.finish().await?;

        Ok(FetchOutcome {
            response: FetchResponse {
                restore_generation: generation,
                heads: wire_value(SeqVector::new(heads), "the heads")?,
                ops: wire_value(List::new(records), "a page's ops")?,
                covers: wire_value(List::new(covers), "a page's covers")?,
                item_key_wraps: wire_value(List::new(item_key_wraps), "a page's wraps")?,
                complete,
            },
            integrity_errors,
        })
    }
}
