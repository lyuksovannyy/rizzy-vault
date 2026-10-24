// SPDX-License-Identifier: AGPL-3.0-only

//! Encrypted attachments: the five `attachments` endpoints of [ADR 0054] §6.
//!
//! | Endpoint | Request | Response | Caller |
//! |---|---|---|---|
//! | `attachments/create` | [`CreateAttachmentRequest`] | empty success | OPAQUE or device |
//! | `attachments/get` | [`AttachmentRequest`] | [`GetAttachmentResponse`] | OPAQUE or device |
//! | `attachments/upload-chunk` | [`UploadChunkRequest`] | empty success | OPAQUE or device |
//! | `attachments/download-chunk` | [`DownloadChunkRequest`] | [`DownloadChunkResponse`] | OPAQUE or device |
//! | `attachments/delete` | [`AttachmentRequest`] | empty success | OPAQUE or device |
//!
//! - **Small bodies.** A chunk envelope is at most [`MAX_ATTACHMENT_CHUNK_ENVELOPE_LEN`] bytes,
//!   about 699 KiB as base64url, so every request and response fits ADR 0028 item 7's 1 MiB
//!   default body limit; no endpoint needs a large-body allowance (ADR 0054 §2, §6).
//! - **Ids in the body only** (INV-52), as every other endpoint.
//! - **What the server is told, and trusts.** `total_plaintext_len` is declared in the clear: the
//!   server derives `chunk_count = ceil(total / CHUNK_SIZE)` from it to size the table, check
//!   each chunk's length and charge the ADR 0048 quota. It never enters an AAD: the client
//!   derives its own count from the item's `attachment/<id>/size` field (ADR 0054 §1).
//!   [`GetAttachmentResponse`] therefore carries the wrap only, never the count or the size.
//! - **Not validated here:** the declared size against [`MAX_ATTACHMENT_LEN`]. An over-cap
//!   `create` is the server's `quota_exceeded` refusal (ADR 0054 "Owner answers" 5), not an
//!   `invalid_request`, so the number parses as any `u64`.
//!
//! [ADR 0054]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0054-attachments-envelope-and-api.md

use serde::{Deserialize, Serialize};

#[cfg(doc)]
use crate::limits::MAX_ATTACHMENT_LEN;
use crate::limits::{ATTACHMENT_KEY_WRAP_LEN, MAX_ATTACHMENT_CHUNK_ENVELOPE_LEN};
use crate::wire::{Bytes, Fixed, Id};

/// Body of `attachments/create`: declares a new attachment before any chunk is uploaded.
///
/// A byte-identical repeat is a no-op success; a repeat with the same `attachment_id` and any
/// other field is `record_conflict` (ADR 0054 §6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAttachmentRequest {
    /// The attachment's 16-byte id, drawn by the client (CRYPTO.md §2).
    pub attachment_id: Id,
    /// The vault holding the item; one of the session account's vaults.
    pub vault_id: Id,
    /// The item the attachment belongs to.
    pub item_id: Id,
    /// The `ATTACHMENT_KEY_WRAP` envelope: the attachment key under the item key (CRYPTO.md
    /// §8.4), exactly [`ATTACHMENT_KEY_WRAP_LEN`] bytes. Opaque to the server.
    pub attachment_key_wrap: Fixed<ATTACHMENT_KEY_WRAP_LEN>,
    /// The plaintext byte length, equal to the item's `attachment/<id>/size` (ADR 0054 §4).
    pub total_plaintext_len: u64,
}

/// Body of `attachments/get` and `attachments/delete`: one attachment by id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentRequest {
    /// The attachment.
    pub attachment_id: Id,
}

/// Answer to `attachments/get`: the wrap, and nothing a reader could put into an AAD.
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetAttachmentResponse {
    /// The `ATTACHMENT_KEY_WRAP` stored at `create`. The reader picks the item key by the
    /// envelope header's `key_id` (the wrap is never re-wrapped, ADR 0054 §3).
    pub attachment_key_wrap: Fixed<ATTACHMENT_KEY_WRAP_LEN>,
}

/// Body of `attachments/upload-chunk`: one `ATTACHMENT_CHUNK` envelope.
///
/// The server refuses `chunk_index >= chunk_count` (`not_found`) and an envelope whose length is
/// not exactly what `total_plaintext_len` implies for that index (`invalid_request`). A
/// byte-identical repeat is a no-op success; another envelope at a stored index is
/// `record_conflict`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadChunkRequest {
    /// The attachment.
    pub attachment_id: Id,
    /// Zero-based chunk position.
    pub chunk_index: u32,
    /// The chunk envelope.
    pub envelope: Bytes<MAX_ATTACHMENT_CHUNK_ENVELOPE_LEN>,
}

/// Body of `attachments/download-chunk`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadChunkRequest {
    /// The attachment.
    pub attachment_id: Id,
    /// Zero-based chunk position.
    pub chunk_index: u32,
}

/// Answer to `attachments/download-chunk`: one stored chunk envelope.
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadChunkResponse {
    /// The chunk envelope, as uploaded. The client opens it against its own layout.
    pub envelope: Bytes<MAX_ATTACHMENT_CHUNK_ENVELOPE_LEN>,
}
