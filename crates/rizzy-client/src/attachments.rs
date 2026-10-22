// SPDX-License-Identifier: AGPL-3.0-only

//! Encrypted attachments, the client half ([ADR 0054]; `rizzy_proto::attachments`).
//!
//! ```text
//! upload:   VaultSync::add_attachment ── item op with attachment/<id>/… written (queued) first
//!             ──► AttachmentUpload: create_request ──► host (attachments/create)
//!                                   chunk_request(i), i in 0..chunk_count ──► host (upload-chunk)
//! download: VaultSync::begin_download ── layout from the item's attachment/<id>/size
//!             ──► AttachmentDownload: get_request ──► host (attachments/get) ──► accept_key
//!                 chunk_request(i) ──► host (download-chunk) ──► accept_chunk(i) … ──► finish
//! delete:   delete_request ──► host (attachments/delete), then VaultSync::remove_attachment
//! ```
//!
//! - **Nothing the server says enters an AAD** (ADR 0054 §1). The chunk count comes from the
//!   size this client wrote into the item (upload) or reads from it (download), and the
//!   `total_plaintext_len` declared at `create` is that same size (§4). The server's
//!   `attachments/get` answer is the wrap alone.
//! - **The item op goes first** (ADR 0054 §7). [`VaultSync::add_attachment`] writes the op that
//!   adds the `attachment/<id>/name`, `/mime`, `/size` and `/order` fields into the outbox before
//!   it returns the first request, so an interrupted upload leaves a dangling reference (every
//!   device sees it; its download answers `not_found`) and never a complete blob no item names.
//!   The op is also the writer rule's place: a stale item key is replaced there, and the
//!   attachment key is wrapped under the item's current key (§3).
//! - **Completeness** (INV-79). [`Assembly`] holds each opened chunk at its index and assembles
//!   only when exactly `chunk_count` chunks, indices `0..chunk_count`, each opened and of its
//!   exact length, are in: a short or long set, a repeat, or a chunk that fails to open is
//!   [`ClientError::AttachmentIncomplete`], and the partial plaintext is wiped.
//! - **Deleting** sends `attachments/delete` first and clears the fields after (a `not_found`
//!   answer counts as deleted), so a failed delete leaves a dangling reference, which
//!   self-heals, rather than an orphaned blob that keeps counting against the quota.
//! - **Secrets.** The attachment key stays in `rizzy-core`'s zeroizing type; opened chunks and
//!   the assembled file are `Zeroizing` buffers; names and media types are item data, so every
//!   type here redacts `Debug`.
//!
//! [ADR 0054]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0054-attachments-envelope-and-api.md

use core::fmt;

use rizzy_core::attachment::{AttachmentKey, AttachmentLayout, AttachmentRef};
use rizzy_core::envelope::parse::{EnvelopeRef, parse as parse_envelope};
use rizzy_core::ids::{AttachmentId, ItemId, SymmetricKeyId};
use rizzy_core::item::key::{ElementId, FieldKey};
use rizzy_core::item::schema::{ATTR_MIME, ATTR_NAME, ATTR_SIZE, LIST_ATTACHMENT};
use rizzy_core::item::value::{Value, ValueRef};
use rizzy_core::keys::ItemKey;
use rizzy_core::rng::CryptoRng;
use rizzy_proto::attachments::{
    AttachmentRequest, CreateAttachmentRequest, DownloadChunkRequest, DownloadChunkResponse,
    GetAttachmentResponse, UploadChunkRequest,
};
use rizzy_proto::limits::ATTACHMENT_KEY_WRAP_LEN;
use rizzy_proto::wire::{Bytes, Fixed, Id};
use zeroize::Zeroizing;

use crate::device::UnlockedDevice;
use crate::error::ClientError;
use crate::items::FieldEdit;
use crate::sync::VaultSync;

/// The media type a host declares when it knows none (ADR 0054 §4: declared, never sniffed).
pub const DEFAULT_MIME: &str = "application/octet-stream";

/// The most bytes a file name or a media type may hold, so one attachment's fields stay small
/// next to ADR 0018 §10's per-op limits.
pub const MAX_ATTACHMENT_TEXT_LEN: usize = 255;

/// One attachment an item lists (ADR 0054 §4), as read from its fields. Item data: `Debug`
/// prints the size only.
pub struct AttachmentInfo {
    /// The attachment's id, which also names its fields and its server row.
    pub attachment_id: AttachmentId,
    /// The file name, as entered.
    pub name: Zeroizing<String>,
    /// The declared media type.
    pub mime: Zeroizing<String>,
    /// The plaintext size in bytes.
    pub size: u64,
}

impl fmt::Debug for AttachmentInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentInfo")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// The `attachment/<id>/<attribute>` key.
fn key(attachment_id: AttachmentId, attribute: &str) -> Result<FieldKey, ClientError> {
    ElementId::from_bytes(attachment_id.to_bytes())
        .key(LIST_ATTACHMENT, attribute)
        .map_err(|_| ClientError::Internal)
}

/// The lowercase hex of an attachment id: its element id in the item's keys.
fn element_hex(attachment_id: AttachmentId) -> Zeroizing<String> {
    use core::fmt::Write as _;
    let mut out = Zeroizing::new(String::with_capacity(32));
    for b in attachment_id.to_bytes() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The wire id of an attachment.
const fn wire_id(attachment_id: AttachmentId) -> Id {
    Id::from_bytes(attachment_id.to_bytes())
}

/// A file name or media type as an item value: 1 to [`MAX_ATTACHMENT_TEXT_LEN`] bytes.
fn text_value(text: &str) -> Result<Value, ClientError> {
    if text.is_empty() || text.len() > MAX_ATTACHMENT_TEXT_LEN {
        return Err(ClientError::InvalidInput);
    }
    Value::text(text).map_err(|_| ClientError::InvalidInput)
}

impl VaultSync {
    /// The text of a displayed Text field, if it is one.
    fn text_field(&self, item: ItemId, key: &FieldKey) -> Option<Zeroizing<String>> {
        let value = self.field_value(item, key.as_str())?;
        match value.decode().ok()? {
            ValueRef::Text(text) => Some(Zeroizing::new(text.to_owned())),
            _ => None,
        }
    }

    /// The attachment `attachment_id` of `item`, if the item lists it with a name and a size.
    #[must_use]
    pub fn attachment(&self, item: ItemId, attachment_id: AttachmentId) -> Option<AttachmentInfo> {
        let name = self.text_field(item, &key(attachment_id, ATTR_NAME).ok()?)?;
        let mime = self
            .text_field(item, &key(attachment_id, ATTR_MIME).ok()?)
            .unwrap_or_else(|| Zeroizing::new(DEFAULT_MIME.to_owned()));
        let size_key = key(attachment_id, ATTR_SIZE).ok()?;
        let ValueRef::U64(size) = self.field_value(item, size_key.as_str())?.decode().ok()? else {
            return None;
        };
        Some(AttachmentInfo {
            attachment_id,
            name,
            mime,
            size,
        })
    }

    /// The attachments `item` lists, in list order (ADR 0018 §6). An element without a usable
    /// name and size (written by a newer client, say) is left out.
    #[must_use]
    pub fn attachments(&self, item: ItemId) -> Vec<AttachmentInfo> {
        self.list_elements(item, LIST_ATTACHMENT)
            .iter()
            .filter_map(|e| {
                let mut bytes = [0u8; 16];
                if e.element.len() != 32 {
                    return None;
                }
                for (slot, pair) in bytes.iter_mut().zip(e.element.as_bytes().chunks_exact(2)) {
                    let pair = core::str::from_utf8(pair).ok()?;
                    *slot = u8::from_str_radix(pair, 16).ok()?;
                }
                self.attachment(item, AttachmentId::from_bytes(bytes))
            })
            .collect()
    }

    /// Adds `data` to `item` as an encrypted attachment (ADR 0054 §1–§4, §7).
    ///
    /// Writes the item op with the attachment's fields first (module docs), then wraps a fresh
    /// attachment key under the item's current key and seals every chunk. The returned
    /// [`AttachmentUpload`] holds ciphertext only; the host sends its requests.
    ///
    /// # Errors
    /// [`ClientError::AttachmentTooLarge`] over 25 MiB; [`ClientError::InvalidInput`] for an
    /// empty or overlong name or media type; the errors of [`VaultSync::edit_item`]
    /// (an inactive item, read-only); [`ClientError::Internal`] if a seal fails.
    #[expect(
        clippy::too_many_arguments,
        reason = "the edit's inputs (rng, unlocked device, item, time) plus the file's three parts"
    )]
    pub fn add_attachment<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
        name: &str,
        mime: &str,
        data: &[u8],
        now_ms: u64,
    ) -> Result<AttachmentUpload, ClientError> {
        let size = u64::try_from(data.len()).map_err(|_| ClientError::AttachmentTooLarge)?;
        let layout = AttachmentLayout::new(size).map_err(|_| ClientError::AttachmentTooLarge)?;
        let name = text_value(name)?;
        let mime = text_value(mime)?;
        let attachment_id = AttachmentId::generate(rng);
        let order = self
            .append_orders(Some(item), LIST_ATTACHMENT, 1)?
            .into_iter()
            .next()
            .ok_or(ClientError::Internal)?;
        let writes = Self::element_writes(
            ElementId::from_bytes(attachment_id.to_bytes()),
            LIST_ATTACHMENT,
            vec![
                (ATTR_NAME, name),
                (ATTR_MIME, mime),
                (ATTR_SIZE, Value::u64(size)),
            ],
            Some(&order),
        )?;
        let edits: Vec<FieldEdit<'_>> = writes
            .iter()
            .map(|(key, value)| FieldEdit { key, value })
            .collect();
        self.edit_item(rng, unlocked, item, &edits, now_ms)?;

        let at = AttachmentRef {
            vault_id: self.vault_id(),
            item_id: item,
            attachment_id,
        };
        let item_key = self.writer_key(item).ok_or(ClientError::Internal)?;
        let attachment_key = AttachmentKey::generate(rng);
        let wrap = item_key
            .wrap_attachment_key(rng, &at.key_wrap_ctx(), &attachment_key)
            .map_err(|_| ClientError::Internal)?;
        let wrap = <[u8; ATTACHMENT_KEY_WRAP_LEN]>::try_from(wrap.as_slice())
            .map_err(|_| ClientError::Internal)?;
        let mut chunks = Vec::with_capacity(usize::try_from(layout.chunk_count()).unwrap_or(0));
        for index in 0..layout.chunk_count() {
            let range = chunk_range(layout, index)?;
            let plaintext = data.get(range).ok_or(ClientError::Internal)?;
            let envelope = attachment_key
                .seal_chunk(rng, &at, layout, index, plaintext)
                .map_err(|_| ClientError::Internal)?;
            chunks.push(envelope);
        }
        Ok(AttachmentUpload {
            at,
            layout,
            wrap,
            chunks,
        })
    }

    /// Starts downloading attachment `attachment_id` of `item`: the layout comes from the
    /// item's own `size` field, never from the server (ADR 0054 §1).
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] if the item does not list it; [`ClientError::AttachmentTooLarge`]
    /// for a recorded size over the cap (a damaged or hostile record).
    pub fn begin_download(
        &self,
        item: ItemId,
        attachment_id: AttachmentId,
    ) -> Result<AttachmentDownload, ClientError> {
        let info = self
            .attachment(item, attachment_id)
            .ok_or(ClientError::UnknownItem)?;
        AttachmentDownload::new(
            AttachmentRef {
                vault_id: self.vault_id(),
                item_id: item,
                attachment_id,
            },
            info.size,
        )
    }

    /// Opens the `attachments/get` answer for `download` with the item key its header names,
    /// current or old (CRYPTO.md §11.6 reader rule).
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] when no held key opens it.
    pub fn accept_attachment_key(
        &self,
        download: &mut AttachmentDownload,
        response: &GetAttachmentResponse,
    ) -> Result<(), ClientError> {
        let wrap = response.attachment_key_wrap.as_bytes();
        let Ok(EnvelopeRef::Symmetric(parsed)) = parse_envelope(wrap) else {
            return Err(ClientError::InvalidServerResponse);
        };
        let key_id = SymmetricKeyId::from_bytes(*parsed.key_id());
        let item_key = self
            .item_key_by_id(download.at.item_id, &key_id)
            .ok_or(ClientError::InvalidServerResponse)?;
        download.accept_key(item_key, wrap)
    }

    /// The writes that remove attachment `attachment_id` from `item` (ADR 0018 §6: Cleared to
    /// every attribute it holds), written as one edit. Send [`delete_request`] first (module
    /// docs).
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] if the item does not list it; the errors of
    /// [`VaultSync::edit_item`].
    pub fn remove_attachment<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
        attachment_id: AttachmentId,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        let hex = element_hex(attachment_id);
        let writes = self.element_removal_writes(item, LIST_ATTACHMENT, hex.as_str())?;
        if writes.is_empty() {
            return Err(ClientError::UnknownItem);
        }
        let edits: Vec<FieldEdit<'_>> = writes
            .iter()
            .map(|(key, value)| FieldEdit { key, value })
            .collect();
        self.edit_item(rng, unlocked, item, &edits, now_ms)
    }
}

/// The plaintext range of chunk `index`.
fn chunk_range(
    layout: AttachmentLayout,
    index: u32,
) -> Result<core::ops::Range<usize>, ClientError> {
    let offset = layout
        .chunk_offset(index)
        .and_then(|o| usize::try_from(o).ok())
        .ok_or(ClientError::Internal)?;
    let len = layout.chunk_len(index).ok_or(ClientError::Internal)?;
    Ok(offset..offset.saturating_add(len))
}

/// The `attachments/delete` request for `attachment_id`. A `not_found` answer means it is gone
/// already; either way, the host then calls [`VaultSync::remove_attachment`].
#[must_use]
pub const fn delete_request(attachment_id: AttachmentId) -> AttachmentRequest {
    AttachmentRequest {
        attachment_id: wire_id(attachment_id),
    }
}

/// An attachment sealed and ready to send: the declaration and every chunk envelope. Holds
/// ciphertext only.
pub struct AttachmentUpload {
    /// Where the attachment belongs.
    at: AttachmentRef,
    /// The layout of its plaintext size.
    layout: AttachmentLayout,
    /// The `ATTACHMENT_KEY_WRAP`.
    wrap: [u8; ATTACHMENT_KEY_WRAP_LEN],
    /// The chunk envelopes, in index order.
    chunks: Vec<Vec<u8>>,
}

impl fmt::Debug for AttachmentUpload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentUpload")
            .field("chunk_count", &self.layout.chunk_count())
            .finish_non_exhaustive()
    }
}

impl AttachmentUpload {
    /// The new attachment's id.
    #[must_use]
    pub const fn attachment_id(&self) -> AttachmentId {
        self.at.attachment_id
    }

    /// How many `upload-chunk` requests follow the declaration.
    #[must_use]
    pub const fn chunk_count(&self) -> u32 {
        self.layout.chunk_count()
    }

    /// The `attachments/create` request: ids, wrap and the declared size (equal to the item's
    /// `size` field, ADR 0054 §4).
    #[must_use]
    pub fn create_request(&self) -> CreateAttachmentRequest {
        CreateAttachmentRequest {
            attachment_id: wire_id(self.at.attachment_id),
            vault_id: Id::from_bytes(self.at.vault_id.to_bytes()),
            item_id: Id::from_bytes(self.at.item_id.to_bytes()),
            attachment_key_wrap: Fixed::from_bytes(self.wrap),
            total_plaintext_len: self.layout.size(),
        }
    }

    /// The `attachments/upload-chunk` request for chunk `index`.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] past the last chunk.
    pub fn chunk_request(&self, index: u32) -> Result<UploadChunkRequest, ClientError> {
        let envelope = usize::try_from(index)
            .ok()
            .and_then(|i| self.chunks.get(i))
            .ok_or(ClientError::InvalidInput)?;
        Ok(UploadChunkRequest {
            attachment_id: wire_id(self.at.attachment_id),
            chunk_index: index,
            envelope: Bytes::from_slice(envelope).map_err(|_| ClientError::Internal)?,
        })
    }
}

/// The opened chunks of one attachment, held by index until every one is in (INV-79).
pub struct Assembly {
    /// The layout the chunks must fill.
    layout: AttachmentLayout,
    /// One slot per index.
    chunks: Vec<Option<Zeroizing<Vec<u8>>>>,
}

impl fmt::Debug for Assembly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Assembly")
            .field("chunk_count", &self.layout.chunk_count())
            .field("received", &self.received())
            .finish_non_exhaustive()
    }
}

impl Assembly {
    /// An empty assembly for `layout`.
    #[must_use]
    pub fn new(layout: AttachmentLayout) -> Self {
        let count = usize::try_from(layout.chunk_count()).unwrap_or(0);
        let mut chunks = Vec::with_capacity(count);
        chunks.resize_with(count, || None);
        Self { layout, chunks }
    }

    /// How many chunks are in.
    #[must_use]
    pub fn received(&self) -> usize {
        self.chunks.iter().filter(|c| c.is_some()).count()
    }

    /// Takes the opened chunk `index`.
    ///
    /// # Errors
    /// [`ClientError::AttachmentIncomplete`] for an index past the last chunk (an extra chunk), a
    /// second chunk at a filled index, or a plaintext of another length than the index's.
    pub fn accept(&mut self, index: u32, plaintext: Zeroizing<Vec<u8>>) -> Result<(), ClientError> {
        let expected = self
            .layout
            .chunk_len(index)
            .ok_or(ClientError::AttachmentIncomplete)?;
        let slot = usize::try_from(index)
            .ok()
            .and_then(|i| self.chunks.get_mut(i))
            .ok_or(ClientError::AttachmentIncomplete)?;
        if slot.is_some() || plaintext.len() != expected {
            return Err(ClientError::AttachmentIncomplete);
        }
        *slot = Some(plaintext);
        Ok(())
    }

    /// The assembled plaintext, only when every index `0..chunk_count` is in.
    ///
    /// # Errors
    /// [`ClientError::AttachmentIncomplete`] when a chunk is missing; the chunks held are wiped.
    pub fn finish(self) -> Result<Zeroizing<Vec<u8>>, ClientError> {
        let size =
            usize::try_from(self.layout.size()).map_err(|_| ClientError::AttachmentIncomplete)?;
        let mut out = Zeroizing::new(Vec::with_capacity(size));
        for chunk in self.chunks {
            out.extend_from_slice(&chunk.ok_or(ClientError::AttachmentIncomplete)?);
        }
        if out.len() != size {
            return Err(ClientError::AttachmentIncomplete);
        }
        Ok(out)
    }
}

/// One attachment being downloaded and verified (module docs).
pub struct AttachmentDownload {
    /// Where the attachment belongs.
    at: AttachmentRef,
    /// The layout of the item's recorded size.
    layout: AttachmentLayout,
    /// The unwrapped attachment key, once `attachments/get` answered.
    key: Option<AttachmentKey>,
    /// The chunks opened so far.
    assembly: Assembly,
}

impl fmt::Debug for AttachmentDownload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentDownload")
            .field("chunk_count", &self.layout.chunk_count())
            .field("keyed", &self.key.is_some())
            .finish_non_exhaustive()
    }
}

impl AttachmentDownload {
    /// A download of the attachment `at` whose recorded size is `size`.
    ///
    /// # Errors
    /// [`ClientError::AttachmentTooLarge`] for a size over the cap.
    pub fn new(at: AttachmentRef, size: u64) -> Result<Self, ClientError> {
        let layout = AttachmentLayout::new(size).map_err(|_| ClientError::AttachmentTooLarge)?;
        Ok(Self {
            at,
            layout,
            key: None,
            assembly: Assembly::new(layout),
        })
    }

    /// How many chunks to fetch: `ceil(size / CHUNK_SIZE)` of the item's own size.
    #[must_use]
    pub const fn chunk_count(&self) -> u32 {
        self.layout.chunk_count()
    }

    /// The plaintext size the item records.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.layout.size()
    }

    /// The `attachments/get` request.
    #[must_use]
    pub const fn get_request(&self) -> AttachmentRequest {
        delete_request(self.at.attachment_id)
    }

    /// Unwraps the attachment key from `wrap` with `item_key`.
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] when it does not open (another attachment's wrap,
    /// a tampered one, another item key).
    pub fn accept_key(&mut self, item_key: &ItemKey, wrap: &[u8]) -> Result<(), ClientError> {
        let key = item_key
            .unwrap_attachment_key(&self.at.key_wrap_ctx(), wrap)
            .map_err(|_| ClientError::InvalidServerResponse)?;
        self.key = Some(key);
        Ok(())
    }

    /// The `attachments/download-chunk` request for chunk `index`.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] past the last chunk.
    pub fn chunk_request(&self, index: u32) -> Result<DownloadChunkRequest, ClientError> {
        if index >= self.layout.chunk_count() {
            return Err(ClientError::InvalidInput);
        }
        Ok(DownloadChunkRequest {
            attachment_id: wire_id(self.at.attachment_id),
            chunk_index: index,
        })
    }

    /// Opens the envelope served for chunk `index` against this client's own layout and keeps
    /// its plaintext.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] before the key is in; [`ClientError::AttachmentIncomplete`]
    /// for a chunk that fails to open where it was asked for (moved, from another attachment or
    /// size, tampered), past the last index, or a repeat.
    pub fn accept_chunk(&mut self, index: u32, envelope: &[u8]) -> Result<(), ClientError> {
        let key = self.key.as_ref().ok_or(ClientError::InvalidInput)?;
        let plaintext = key
            .open_chunk(&self.at, self.layout, index, envelope)
            .map_err(|_| ClientError::AttachmentIncomplete)?;
        self.assembly
            .accept(index, Zeroizing::new(plaintext.expose_secret().to_vec()))
    }

    /// [`AttachmentDownload::accept_chunk`] with the `download-chunk` answer.
    ///
    /// # Errors
    /// As [`AttachmentDownload::accept_chunk`].
    pub fn accept_response(
        &mut self,
        index: u32,
        response: &DownloadChunkResponse,
    ) -> Result<(), ClientError> {
        self.accept_chunk(index, response.envelope.as_slice())
    }

    /// The verified file, only once every chunk opened (INV-79).
    ///
    /// # Errors
    /// [`ClientError::AttachmentIncomplete`] when a chunk is missing, or no key came.
    pub fn finish(self) -> Result<Zeroizing<Vec<u8>>, ClientError> {
        if self.key.is_none() {
            return Err(ClientError::AttachmentIncomplete);
        }
        self.assembly.finish()
    }
}
