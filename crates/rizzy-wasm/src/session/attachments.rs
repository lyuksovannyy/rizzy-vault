// SPDX-License-Identifier: AGPL-3.0-only

//! Encrypted attachments for the web vault ([ADR 0054]; `rizzy_client::attachments`).
//!
//! ```text
//! const id = session.addAttachment(itemId, name, mime, bytes, now)    // the item op is written
//! send(session.attachmentCreateRequest(id))                            // attachments/create
//! for i in 0..session.attachmentChunkCount(id): send(session.attachmentUploadChunkRequest(id, i))
//! session.attachmentUploadDone(id)
//!
//! const n = session.attachmentDownloadStart(itemId, id)                // n from the item's size
//! session.attachmentGetResponse(id, ...send(session.attachmentGetRequest(id)))
//! for i in 0..n: session.attachmentDownloadChunkResponse(id, i, ...send(…ChunkRequest(id, i)))
//! const file = session.attachmentDownloadFinish(id)                    // only if every chunk opened
//!
//! send(session.attachmentDeleteRequest(id)); session.removeAttachment(itemId, id, now)
//! ```
//!
//! Every request is built here and every answer verified here; JavaScript only carries bytes.
//! The finished file crosses to JavaScript as a byte array, the one copy a download needs; like
//! a plaintext export, it cannot be wiped once there (ADR 0013 §4 "Honest limit").
//!
//! [ADR 0054]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0054-attachments-envelope-and-api.md

use rizzy_client::ClientError;
use rizzy_client::attachments::{AttachmentInfo, delete_request};
use rizzy_client::rizzy_core::ids::AttachmentId;
use rizzy_client::rizzy_proto::attachments::{DownloadChunkResponse, GetAttachmentResponse};
use rizzy_client::rizzy_proto::http::paths;
use wasm_bindgen::prelude::wasm_bindgen;

use super::Session;
use crate::error::{CoreError, CoreResult};
use crate::http::{self, HttpRequest};
use crate::items::{self, hex, parse_id};

/// An attachment id from its 32 hex digits.
fn attachment_id(text: &str) -> CoreResult<AttachmentId> {
    Ok(AttachmentId::from_bytes(parse_id(text)?))
}

/// One attachment an item lists: id, name, media type and size. Item data, for display.
#[wasm_bindgen]
pub struct AttachmentView {
    /// The id, 32 hex digits.
    id: String,
    /// The file name.
    name: String,
    /// The declared media type.
    mime: String,
    /// The size in bytes.
    size: u64,
}

impl core::fmt::Debug for AttachmentView {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttachmentView")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl AttachmentView {
    /// The view of a listed attachment.
    fn of(info: &AttachmentInfo) -> Self {
        Self {
            id: hex(&info.attachment_id.to_bytes()),
            name: info.name.as_str().to_owned(),
            mime: info.mime.as_str().to_owned(),
            size: info.size,
        }
    }
}

#[wasm_bindgen]
impl AttachmentView {
    /// The attachment id, 32 hex digits.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// The file name, as entered.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// The declared media type.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn mime(&self) -> String {
        self.mime.clone()
    }

    /// The plaintext size in bytes.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }
}

#[wasm_bindgen]
impl Session {
    /// The attachments of an item, in list order.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for a malformed id.
    pub fn attachments(&self, id: &str) -> Result<Vec<AttachmentView>, CoreError> {
        let item = items::item_id(id)?;
        Ok(self
            .inner()?
            .vault
            .attachments(item)
            .iter()
            .map(AttachmentView::of)
            .collect())
    }

    /// Adds a file to an item: writes the item op naming it (ADR 0054 §7), wraps a fresh
    /// attachment key and seals every chunk. Returns the new attachment's id; its requests follow.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `attachment_too_large` over 25 MiB;
    /// `invalid_input` for an empty or overlong name or media type; `read_only`;
    /// `unknown_item`.
    #[wasm_bindgen(js_name = addAttachment)]
    pub fn add_attachment(
        &mut self,
        id: &str,
        name: &str,
        mime: &str,
        data: &[u8],
        now_ms: u64,
    ) -> Result<String, CoreError> {
        let item = items::item_id(id)?;
        let inner = self.writable()?;
        let upload = inner.vault.add_attachment(
            &mut inner.rng,
            &inner.unlocked,
            item,
            name,
            mime,
            data,
            now_ms,
        )?;
        let attachment = upload.attachment_id();
        inner.uploads.insert(attachment, upload);
        Ok(hex(&attachment.to_bytes()))
    }

    /// The `attachments/create` request of an attachment being uploaded.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an id with no upload in progress.
    #[wasm_bindgen(js_name = attachmentCreateRequest)]
    pub fn attachment_create_request(&self, attachment: &str) -> Result<HttpRequest, CoreError> {
        let inner = self.inner()?;
        let upload = inner
            .uploads
            .get(&attachment_id(attachment)?)
            .ok_or(ClientError::InvalidInput)?;
        HttpRequest::post(
            paths::ATTACHMENTS_CREATE,
            &upload.create_request(),
            Some(&inner.token),
        )
    }

    /// How many chunks an attachment being uploaded or downloaded has.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an id with no transfer in progress.
    #[wasm_bindgen(js_name = attachmentChunkCount)]
    pub fn attachment_chunk_count(&self, attachment: &str) -> Result<u32, CoreError> {
        let inner = self.inner()?;
        let id = attachment_id(attachment)?;
        if let Some(upload) = inner.uploads.get(&id) {
            return Ok(upload.chunk_count());
        }
        Ok(inner
            .downloads
            .get(&id)
            .ok_or(ClientError::InvalidInput)?
            .chunk_count())
    }

    /// The `attachments/upload-chunk` request of chunk `index`.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an id with no upload in progress or an index past the
    /// last chunk.
    #[wasm_bindgen(js_name = attachmentUploadChunkRequest)]
    pub fn attachment_upload_chunk_request(
        &self,
        attachment: &str,
        index: u32,
    ) -> Result<HttpRequest, CoreError> {
        let inner = self.inner()?;
        let upload = inner
            .uploads
            .get(&attachment_id(attachment)?)
            .ok_or(ClientError::InvalidInput)?;
        HttpRequest::post(
            paths::ATTACHMENTS_UPLOAD_CHUNK,
            &upload.chunk_request(index)?,
            Some(&inner.token),
        )
    }

    /// Forgets an upload: its requests were sent, or the host gave up on them (the item then
    /// names an attachment the server lacks; its download answers `not_found`, ADR 0054 §7).
    ///
    /// # Errors
    /// `locked`; `invalid_input` for a malformed id.
    #[wasm_bindgen(js_name = attachmentUploadDone)]
    pub fn attachment_upload_done(&mut self, attachment: &str) -> Result<(), CoreError> {
        let id = attachment_id(attachment)?;
        self.inner_mut()?.uploads.remove(&id);
        Ok(())
    }

    /// Starts downloading an attachment of an item; returns its chunk count, derived from the
    /// size the item records (never from the server).
    ///
    /// # Errors
    /// `locked`; `unknown_item` if the item does not list it; `invalid_input`.
    #[wasm_bindgen(js_name = attachmentDownloadStart)]
    pub fn attachment_download_start(
        &mut self,
        id: &str,
        attachment: &str,
    ) -> Result<u32, CoreError> {
        let item = items::item_id(id)?;
        let attachment = attachment_id(attachment)?;
        let inner = self.inner_mut()?;
        let download = inner.vault.begin_download(item, attachment)?;
        let count = download.chunk_count();
        inner.downloads.insert(attachment, download);
        Ok(count)
    }

    /// The `attachments/get` request of a download.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an id with no download in progress.
    #[wasm_bindgen(js_name = attachmentGetRequest)]
    pub fn attachment_get_request(&self, attachment: &str) -> Result<HttpRequest, CoreError> {
        let inner = self.inner()?;
        let download = inner
            .downloads
            .get(&attachment_id(attachment)?)
            .ok_or(ClientError::InvalidInput)?;
        HttpRequest::post(
            paths::ATTACHMENTS_GET,
            &download.get_request(),
            Some(&inner.token),
        )
    }

    /// Reads the `attachments/get` answer: the wrap, opened with the item key its header names.
    ///
    /// # Errors
    /// `locked`; `invalid_input`; the server's code (`server_not_found` for an attachment the
    /// server does not hold); `invalid_server_response` for a wrap no held key opens.
    #[wasm_bindgen(js_name = attachmentGetResponse)]
    pub fn attachment_get_response(
        &mut self,
        attachment: &str,
        status: u16,
        body: &[u8],
    ) -> Result<(), CoreError> {
        let id = attachment_id(attachment)?;
        let answer: GetAttachmentResponse = http::json(status, body)?;
        let inner = self.inner_mut()?;
        let download = inner
            .downloads
            .get_mut(&id)
            .ok_or(ClientError::InvalidInput)?;
        inner.vault.accept_attachment_key(download, &answer)?;
        Ok(())
    }

    /// The `attachments/download-chunk` request of chunk `index`.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an id with no download or an index past the last chunk.
    #[wasm_bindgen(js_name = attachmentDownloadChunkRequest)]
    pub fn attachment_download_chunk_request(
        &self,
        attachment: &str,
        index: u32,
    ) -> Result<HttpRequest, CoreError> {
        let inner = self.inner()?;
        let download = inner
            .downloads
            .get(&attachment_id(attachment)?)
            .ok_or(ClientError::InvalidInput)?;
        HttpRequest::post(
            paths::ATTACHMENTS_DOWNLOAD_CHUNK,
            &download.chunk_request(index)?,
            Some(&inner.token),
        )
    }

    /// Reads the answer for chunk `index` and opens it against this client's own layout.
    ///
    /// # Errors
    /// `locked`; `invalid_input`; the server's code; `attachment_incomplete` for a chunk that
    /// does not open where it was asked for.
    #[wasm_bindgen(js_name = attachmentDownloadChunkResponse)]
    pub fn attachment_download_chunk_response(
        &mut self,
        attachment: &str,
        index: u32,
        status: u16,
        body: &[u8],
    ) -> Result<(), CoreError> {
        let id = attachment_id(attachment)?;
        let answer: DownloadChunkResponse = http::json(status, body)?;
        let inner = self.inner_mut()?;
        let download = inner
            .downloads
            .get_mut(&id)
            .ok_or(ClientError::InvalidInput)?;
        download.accept_response(index, &answer)?;
        Ok(())
    }

    /// The verified file, only when every chunk opened (INV-79). The download is forgotten
    /// either way.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an id with no download; `attachment_incomplete`.
    #[wasm_bindgen(js_name = attachmentDownloadFinish)]
    pub fn attachment_download_finish(&mut self, attachment: &str) -> Result<Vec<u8>, CoreError> {
        let id = attachment_id(attachment)?;
        let download = self
            .inner_mut()?
            .downloads
            .remove(&id)
            .ok_or(ClientError::InvalidInput)?;
        let file = download.finish()?;
        Ok(file.as_slice().to_vec())
    }

    /// Forgets a download without assembling it.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for a malformed id.
    #[wasm_bindgen(js_name = attachmentDownloadAbort)]
    pub fn attachment_download_abort(&mut self, attachment: &str) -> Result<(), CoreError> {
        let id = attachment_id(attachment)?;
        self.inner_mut()?.downloads.remove(&id);
        Ok(())
    }

    /// The `attachments/delete` request. Send it before [`Session::remove_attachment`]; a
    /// `server_not_found` answer means it is gone already.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for a malformed id.
    #[wasm_bindgen(js_name = attachmentDeleteRequest)]
    pub fn attachment_delete_request(&self, attachment: &str) -> Result<HttpRequest, CoreError> {
        let inner = self.inner()?;
        HttpRequest::post(
            paths::ATTACHMENTS_DELETE,
            &delete_request(attachment_id(attachment)?),
            Some(&inner.token),
        )
    }

    /// Removes an attachment from an item: clears its fields in one edit.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `unknown_item` if the item does not list
    /// it; `read_only`.
    #[wasm_bindgen(js_name = removeAttachment)]
    pub fn remove_attachment(
        &mut self,
        id: &str,
        attachment: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let item = items::item_id(id)?;
        let attachment = attachment_id(attachment)?;
        let inner = self.writable()?;
        inner
            .vault
            .remove_attachment(&mut inner.rng, &inner.unlocked, item, attachment, now_ms)?;
        Ok(())
    }
}
