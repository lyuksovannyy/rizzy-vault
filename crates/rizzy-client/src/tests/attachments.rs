// SPDX-License-Identifier: AGPL-3.0-only

//! Attachments, the client half (ADR 0054; `crate::attachments`): the item op written before
//! any chunk, the requests as the host sends them, a byte-identical download against the
//! client's own layout, every integrity failure a hostile server can cause (a chunk moved,
//! withheld, repeated, extra, from another attachment, a foreign wrap), the 25 MiB cap, removal,
//! and the INV-15 canary over every request body (ADR 0054 §8 (c)). The server side is
//! `rizzy-domain-vault`'s; a map stands in for it here.

use std::collections::BTreeMap;

use proptest::prelude::*;
use rizzy_core::attachment::{AttachmentLayout, CHUNK_SIZE, MAX_ATTACHMENT_LEN};
use rizzy_core::ids::AttachmentId;
use rizzy_proto::attachments::{DownloadChunkResponse, GetAttachmentResponse};

use super::canary::{contains, forms};
use super::lists::one_item;
use super::*;
use crate::attachments::{Assembly, AttachmentDownload, AttachmentUpload, delete_request};

/// `len` bytes, byte `i` = `i mod 251`, with `marker` at offset 1000 when it fits.
fn file(len: usize, marker: &[u8]) -> Vec<u8> {
    let mut data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
    if len >= 1000 + marker.len() {
        data[1000..1000 + marker.len()].copy_from_slice(marker);
    }
    data
}

/// What the server keeps of one upload: the wrap and the chunks by index.
struct Stored {
    wrap: [u8; 122],
    chunks: BTreeMap<u32, Vec<u8>>,
}

/// Sends every request of `upload` to the stand-in server, returning their JSON bodies.
fn upload_all(upload: &AttachmentUpload) -> (Stored, Vec<Vec<u8>>) {
    let create = upload.create_request();
    let mut bodies = vec![serde_json::to_vec(&create).unwrap()];
    let mut chunks = BTreeMap::new();
    for i in 0..upload.chunk_count() {
        let request = upload.chunk_request(i).unwrap();
        bodies.push(serde_json::to_vec(&request).unwrap());
        assert_eq!(request.chunk_index, i);
        chunks.insert(i, request.envelope.as_slice().to_vec());
    }
    assert!(upload.chunk_request(upload.chunk_count()).is_err());
    (
        Stored {
            wrap: *create.attachment_key_wrap.as_bytes(),
            chunks,
        },
        bodies,
    )
}

fn get_response(stored: &Stored) -> GetAttachmentResponse {
    GetAttachmentResponse {
        attachment_key_wrap: Fixed::from_bytes(stored.wrap),
    }
}

fn chunk_response(envelope: &[u8]) -> DownloadChunkResponse {
    DownloadChunkResponse {
        envelope: Bytes::from_slice(envelope).unwrap(),
    }
}

#[test]
fn an_attachment_round_trips_byte_for_byte_and_the_op_goes_first() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(0x54);
    let mut marker = [0u8; 32];
    rng.fill_bytes(&mut marker);
    let data = file(2 * CHUNK_SIZE + 1234, &marker);
    let before = vault.unacknowledged().0;
    let upload = vault
        .add_attachment(
            &mut rng,
            &unlocked,
            item,
            "report.pdf",
            "application/pdf",
            &data,
            T0 + 5,
        )
        .unwrap();
    // ADR 0054 §7: the op naming the attachment is in the outbox before any request.
    assert_eq!(vault.unacknowledged().0, before + 1);
    assert_eq!(upload.chunk_count(), 3);
    let create = upload.create_request();
    assert_eq!(
        create.total_plaintext_len,
        u64::try_from(data.len()).unwrap()
    );
    assert_eq!(create.vault_id.to_bytes(), vault.vault_id().to_bytes());
    assert_eq!(create.item_id.to_bytes(), item.to_bytes());
    let id = upload.attachment_id();
    assert_eq!(create.attachment_id.to_bytes(), id.to_bytes());

    // The item lists it, with the size it declared.
    let listed = vault.attachments(item);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].attachment_id, id);
    assert_eq!(listed[0].name.as_str(), "report.pdf");
    assert_eq!(listed[0].mime.as_str(), "application/pdf");
    assert_eq!(listed[0].size, create.total_plaintext_len);

    let (stored, bodies) = upload_all(&upload);
    // INV-15 (c): no chunk plaintext in any request body, raw, hex or base64.
    for body in &bodies {
        for form in forms(&marker) {
            assert!(!contains(body, &form), "plaintext in a request body");
        }
    }

    let mut download = vault.begin_download(item, id).unwrap();
    assert_eq!(download.chunk_count(), 3);
    assert_eq!(
        download.get_request().attachment_id.to_bytes(),
        id.to_bytes()
    );
    vault
        .accept_attachment_key(&mut download, &get_response(&stored))
        .unwrap();
    for i in 0..download.chunk_count() {
        assert_eq!(download.chunk_request(i).unwrap().chunk_index, i);
        download
            .accept_response(i, &chunk_response(&stored.chunks[&i]))
            .unwrap();
    }
    assert!(download.chunk_request(3).is_err());
    assert_eq!(download.finish().unwrap().as_slice(), data.as_slice());

    // Removal: the delete request names it, and the fields go.
    assert_eq!(delete_request(id).attachment_id.to_bytes(), id.to_bytes());
    vault
        .remove_attachment(&mut rng, &unlocked, item, id, T0 + 6)
        .unwrap();
    assert!(vault.attachments(item).is_empty());
    assert_eq!(
        vault
            .remove_attachment(&mut rng, &unlocked, item, id, T0 + 7)
            .unwrap_err(),
        ClientError::UnknownItem
    );
    assert_eq!(
        vault.begin_download(item, id).unwrap_err(),
        ClientError::UnknownItem
    );
}

#[test]
fn a_hostile_server_cannot_get_a_wrong_file_assembled() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(0x55);
    let data = file(2 * CHUNK_SIZE + 77, &[]);
    let upload = vault
        .add_attachment(
            &mut rng,
            &unlocked,
            item,
            "a.bin",
            "application/octet-stream",
            &data,
            T0,
        )
        .unwrap();
    let (stored, _) = upload_all(&upload);
    let other = vault
        .add_attachment(
            &mut rng,
            &unlocked,
            item,
            "b.bin",
            "application/octet-stream",
            &data,
            T0,
        )
        .unwrap();
    let (other_stored, _) = upload_all(&other);
    let id = upload.attachment_id();
    let keyed = |vault: &VaultSync| {
        let mut d = vault.begin_download(item, id).unwrap();
        vault
            .accept_attachment_key(&mut d, &get_response(&stored))
            .unwrap();
        d
    };

    // Another attachment's wrap does not open.
    let mut d = vault.begin_download(item, id).unwrap();
    assert_eq!(
        vault
            .accept_attachment_key(&mut d, &get_response(&other_stored))
            .unwrap_err(),
        ClientError::InvalidServerResponse
    );
    // A chunk before the key is refused.
    assert_eq!(
        d.accept_chunk(0, &stored.chunks[&0]).unwrap_err(),
        ClientError::InvalidInput
    );

    // Two full chunks swapped (same length, so only the AAD tells them apart).
    let mut d = keyed(&vault);
    assert_eq!(
        d.accept_chunk(0, &stored.chunks[&1]).unwrap_err(),
        ClientError::AttachmentIncomplete
    );
    // The same index of another attachment with the same size.
    assert_eq!(
        d.accept_chunk(0, &other_stored.chunks[&0]).unwrap_err(),
        ClientError::AttachmentIncomplete
    );
    // A flipped bit, and a truncated envelope.
    let mut flipped = stored.chunks[&2].clone();
    flipped[100] ^= 1;
    assert!(d.accept_chunk(2, &flipped).is_err());
    assert!(d.accept_chunk(2, &stored.chunks[&2][..20]).is_err());
    // A repeat of an accepted chunk, and an index past the end.
    d.accept_chunk(0, &stored.chunks[&0]).unwrap();
    assert_eq!(
        d.accept_chunk(0, &stored.chunks[&0]).unwrap_err(),
        ClientError::AttachmentIncomplete
    );
    assert!(d.accept_chunk(3, &stored.chunks[&2]).is_err());
    // A withheld chunk: never assembled.
    d.accept_chunk(1, &stored.chunks[&1]).unwrap();
    assert_eq!(d.finish().unwrap_err(), ClientError::AttachmentIncomplete);

    // No key at all: never assembled, even for an empty file.
    let empty = vault
        .add_attachment(&mut rng, &unlocked, item, "empty", "text/plain", &[], T0)
        .unwrap();
    assert_eq!(empty.chunk_count(), 0);
    let (empty_stored, _) = upload_all(&empty);
    let d = vault.begin_download(item, empty.attachment_id()).unwrap();
    assert_eq!(d.finish().unwrap_err(), ClientError::AttachmentIncomplete);
    let mut d = vault.begin_download(item, empty.attachment_id()).unwrap();
    vault
        .accept_attachment_key(&mut d, &get_response(&empty_stored))
        .unwrap();
    assert!(d.finish().unwrap().is_empty());
}

#[test]
fn the_cap_and_bad_names_write_nothing() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(0x56);
    let before = vault.unacknowledged().0;
    let too_big = vec![0u8; usize::try_from(MAX_ATTACHMENT_LEN).unwrap() + 1];
    assert_eq!(
        vault
            .add_attachment(&mut rng, &unlocked, item, "big", "x/y", &too_big, T0)
            .unwrap_err(),
        ClientError::AttachmentTooLarge
    );
    for (name, mime) in [("", "x/y"), ("n", ""), (&*"n".repeat(256), "x/y")] {
        assert_eq!(
            vault
                .add_attachment(&mut rng, &unlocked, item, name, mime, b"abc", T0)
                .unwrap_err(),
            ClientError::InvalidInput
        );
    }
    assert_eq!(vault.unacknowledged().0, before);
    assert!(vault.attachments(item).is_empty());
    // A recorded size over the cap is refused before any request.
    let at = rizzy_core::attachment::AttachmentRef {
        vault_id: vault.vault_id(),
        item_id: item,
        attachment_id: AttachmentId::from_bytes([1; 16]),
    };
    assert_eq!(
        AttachmentDownload::new(at, MAX_ATTACHMENT_LEN + 1).unwrap_err(),
        ClientError::AttachmentTooLarge
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    /// INV-79: any order of exactly every chunk assembles the file; one fewer never does; an
    /// extra index or a repeat is refused.
    #[test]
    fn assembly_needs_exactly_every_chunk(
        size in prop_oneof![1u64..4096, (2 * CHUNK_SIZE as u64)..(2 * CHUNK_SIZE as u64 + 4096)],
        order in any::<u64>(),
        drop in any::<prop::sample::Index>(),
    ) {
        let layout = AttachmentLayout::new(size).unwrap();
        let data = file(usize::try_from(size).unwrap(), &[]);
        let count = layout.chunk_count();
        let chunk = |i: u32| {
            let off = usize::try_from(layout.chunk_offset(i).unwrap()).unwrap();
            Zeroizing::new(data[off..off + layout.chunk_len(i).unwrap()].to_vec())
        };
        let mut indices: Vec<u32> = (0..count).collect();
        let len = indices.len();
        indices.rotate_left(usize::try_from(order % u64::try_from(len).unwrap()).unwrap());

        let mut full = Assembly::new(layout);
        for &i in &indices {
            full.accept(i, chunk(i)).unwrap();
        }
        prop_assert!(full.accept(indices[0], chunk(indices[0])).is_err());
        prop_assert!(full.accept(count, Zeroizing::new(vec![0; 1])).is_err());
        let assembled = full.finish().unwrap();
        prop_assert_eq!(assembled.as_slice(), data.as_slice());

        let mut short = Assembly::new(layout);
        let skipped = indices[drop.index(len)];
        for &i in indices.iter().filter(|&&i| i != skipped) {
            short.accept(i, chunk(i)).unwrap();
        }
        prop_assert_eq!(short.received(), len - 1);
        prop_assert!(short.finish().is_err());
    }
}
