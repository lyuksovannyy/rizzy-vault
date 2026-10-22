// SPDX-License-Identifier: AGPL-3.0-only

//! Unit and property tests of the attachment layout, chunk envelopes and key wrap (ADR 0054
//! §1–§3, §8). The normative vectors are in `crate::test_vectors::attachments`.

use proptest::prelude::*;

use super::{
    ATTACHMENT_KEY_WRAP_LEN, AttachmentKey, AttachmentLayout, AttachmentRef, CHUNK_OVERHEAD,
    CHUNK_SIZE, MAX_ATTACHMENT_LEN, MAX_CHUNK_COUNT, MAX_CHUNK_ENVELOPE_LEN, TooLarge,
};
use crate::envelope::Purpose;
use crate::error::EncryptError;
use crate::ids::{AttachmentId, ItemId, VaultId};
use crate::keys::ItemKey;
use crate::test_util::seeded_rng;

const CHUNK: u64 = CHUNK_SIZE as u64;

fn at(seed: u8) -> AttachmentRef {
    AttachmentRef {
        vault_id: VaultId::from_bytes([seed; 16]),
        item_id: ItemId::from_bytes([seed.wrapping_add(1); 16]),
        attachment_id: AttachmentId::from_bytes([seed.wrapping_add(2); 16]),
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

/// Seals every chunk of `data`.
fn seal_all(key: &AttachmentKey, at: &AttachmentRef, data: &[u8], seed: u64) -> Vec<Vec<u8>> {
    let layout = AttachmentLayout::new(data.len() as u64).unwrap();
    let mut rng = seeded_rng(seed);
    (0..layout.chunk_count())
        .map(|i| {
            let off = usize::try_from(layout.chunk_offset(i).unwrap()).unwrap();
            let len = layout.chunk_len(i).unwrap();
            key.seal_chunk(&mut rng, at, layout, i, &data[off..off + len])
                .unwrap()
        })
        .collect()
}

#[test]
fn constants_match_adr_0054() {
    assert_eq!(CHUNK_SIZE, 512 * 1024);
    assert_eq!(MAX_ATTACHMENT_LEN, 25 * 1024 * 1024);
    assert_eq!(MAX_CHUNK_COUNT, 50);
    assert_eq!(CHUNK_OVERHEAD, 90);
    assert_eq!(MAX_CHUNK_ENVELOPE_LEN, 524_378);
    assert_eq!(ATTACHMENT_KEY_WRAP_LEN, 122);
    // A chunk envelope under JSON/base64url stays well under ADR 0028 item 7's 1 MiB body.
    assert!(MAX_CHUNK_ENVELOPE_LEN.div_ceil(3) * 4 < 1024 * 1024);
    // ATTACHMENT_CHUNK is an ordinary 0x01 purpose now; 0x03 is undefined.
    assert_eq!(
        Purpose::AttachmentChunk.spec().encrypt,
        crate::envelope::AlgId::XChaCha20Poly1305Committed
    );
    assert_eq!(crate::envelope::AlgId::from_u8(0x03), None);
}

#[test]
fn layout_counts_chunks_from_the_size_alone() {
    let cases: [(u64, u32, Option<usize>); 7] = [
        (0, 0, None),
        (1, 1, Some(1)),
        (CHUNK - 1, 1, Some(CHUNK_SIZE - 1)),
        (CHUNK, 1, Some(CHUNK_SIZE)),
        (CHUNK + 1, 2, Some(1)),
        (2 * CHUNK + 17, 3, Some(17)),
        (MAX_ATTACHMENT_LEN, 50, Some(CHUNK_SIZE)),
    ];
    for (size, count, last) in cases {
        let layout = AttachmentLayout::new(size).unwrap();
        assert_eq!(layout.size(), size);
        assert_eq!(layout.chunk_count(), count, "size {size}");
        let last_index = count.checked_sub(1);
        assert_eq!(last_index.and_then(|i| layout.chunk_len(i)), last);
        for i in 0..count.saturating_sub(1) {
            assert_eq!(layout.chunk_len(i), Some(CHUNK_SIZE));
            assert_eq!(layout.chunk_envelope_len(i), Some(MAX_CHUNK_ENVELOPE_LEN));
        }
        assert_eq!(layout.chunk_len(count), None);
        assert_eq!(layout.chunk_offset(count), None);
        assert_eq!(layout.chunk_envelope_len(count), None);
        let sum: u64 = (0..count)
            .map(|i| layout.chunk_envelope_len(i).unwrap() as u64)
            .sum();
        assert_eq!(layout.envelopes_len(), sum);
    }
    assert_eq!(AttachmentLayout::new(MAX_ATTACHMENT_LEN + 1), Err(TooLarge));
    assert_eq!(AttachmentLayout::new(u64::MAX), Err(TooLarge));
}

#[test]
fn three_chunks_round_trip_and_bind_their_place() {
    let key = AttachmentKey::generate(&mut seeded_rng(1));
    let a = at(1);
    let data = pattern(2 * CHUNK_SIZE + 1000);
    let layout = AttachmentLayout::new(data.len() as u64).unwrap();
    let chunks = seal_all(&key, &a, &data, 2);
    assert_eq!(chunks.len(), 3);
    let mut out = Vec::new();
    for (i, env) in (0u32..).zip(&chunks) {
        assert_eq!(env.len(), layout.chunk_envelope_len(i).unwrap());
        out.extend_from_slice(key.open_chunk(&a, layout, i, env).unwrap().expose_secret());
    }
    assert_eq!(out, data);

    // Another index (two full chunks swapped: same length, so only the AAD differs).
    assert!(key.open_chunk(&a, layout, 1, &chunks[0]).is_err());
    assert!(key.open_chunk(&a, layout, 0, &chunks[1]).is_err());
    // Another attachment, item or vault.
    let mut other = a;
    other.attachment_id = AttachmentId::from_bytes([0xee; 16]);
    assert!(key.open_chunk(&other, layout, 0, &chunks[0]).is_err());
    let mut other = a;
    other.item_id = ItemId::from_bytes([0xee; 16]);
    assert!(key.open_chunk(&other, layout, 0, &chunks[0]).is_err());
    let mut other = a;
    other.vault_id = VaultId::from_bytes([0xee; 16]);
    assert!(key.open_chunk(&other, layout, 0, &chunks[0]).is_err());
    // A chunk count derived from another size (four chunks, same full first chunk length).
    let bigger = AttachmentLayout::new(3 * CHUNK + 1).unwrap();
    assert!(key.open_chunk(&a, bigger, 0, &chunks[0]).is_err());
    // Past the end, and truncated.
    assert!(key.open_chunk(&a, layout, 3, &chunks[2]).is_err());
    assert!(
        key.open_chunk(&a, layout, 2, &chunks[2][..chunks[2].len() - 1])
            .is_err()
    );
    // Another key.
    let other_key = AttachmentKey::generate(&mut seeded_rng(9));
    assert!(other_key.open_chunk(&a, layout, 0, &chunks[0]).is_err());
}

#[test]
fn seal_refuses_a_chunk_outside_the_layout() {
    let key = AttachmentKey::generate(&mut seeded_rng(3));
    let a = at(3);
    let layout = AttachmentLayout::new(CHUNK + 5).unwrap();
    let mut rng = seeded_rng(4);
    assert_eq!(
        key.seal_chunk(&mut rng, &a, layout, 2, &[0; 5]),
        Err(EncryptError::ContextMismatch)
    );
    assert_eq!(
        key.seal_chunk(&mut rng, &a, layout, 1, &[0; 6]),
        Err(EncryptError::InvalidPlaintextLength)
    );
    assert_eq!(
        key.seal_chunk(&mut rng, &a, layout, 0, &[0; 5]),
        Err(EncryptError::InvalidPlaintextLength)
    );
    let empty = AttachmentLayout::new(0).unwrap();
    assert_eq!(
        key.seal_chunk(&mut rng, &a, empty, 0, &[]),
        Err(EncryptError::ContextMismatch)
    );
}

#[test]
fn key_wrap_round_trips_under_the_item_key_and_binds_the_attachment() {
    let mut rng = seeded_rng(5);
    let item_key = ItemKey::generate(&mut rng, 0);
    let key = AttachmentKey::generate(&mut rng);
    let a = at(5);
    let wrap = item_key
        .wrap_attachment_key(&mut rng, &a.key_wrap_ctx(), &key)
        .unwrap();
    assert_eq!(wrap.len(), ATTACHMENT_KEY_WRAP_LEN);
    // The header names the item key.
    assert_eq!(&wrap[2..18], item_key.key_id().unwrap().as_bytes());
    let back = item_key
        .unwrap_attachment_key(&a.key_wrap_ctx(), &wrap)
        .unwrap();
    assert_eq!(back.expose_for_tests(), key.expose_for_tests());
    assert_eq!(back.key_id().unwrap(), key.key_id().unwrap());

    let mut other = a;
    other.attachment_id = AttachmentId::from_bytes([0xaa; 16]);
    assert!(
        item_key
            .unwrap_attachment_key(&other.key_wrap_ctx(), &wrap)
            .is_err()
    );
    let other_item_key = ItemKey::generate(&mut rng, 0);
    assert!(
        other_item_key
            .unwrap_attachment_key(&a.key_wrap_ctx(), &wrap)
            .is_err()
    );
    // An item-key wrap is not an attachment-key wrap, even with the same key bytes in reach.
    assert!(
        item_key
            .unwrap_attachment_key(&a.key_wrap_ctx(), &wrap[..wrap.len() - 1])
            .is_err()
    );
}

#[test]
fn debug_output_is_redacted() {
    let key = AttachmentKey::generate(&mut seeded_rng(6));
    assert_eq!(format!("{key:?}"), "AttachmentKey([REDACTED])");
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// Round trip for any size up to three chunks and a bit, and every misplacement fails:
    /// another index, a truncated envelope, one flipped bit, and a count from another size.
    #[test]
    fn chunks_round_trip_and_reject_every_tamper(
        size in prop_oneof![0u64..2048, (CHUNK - 64)..(CHUNK + 64), (2 * CHUNK)..(3 * CHUNK + 4096)],
        seed in any::<u64>(),
        flip in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let key = AttachmentKey::generate(&mut seeded_rng(seed));
        let a = at(seed.to_le_bytes()[0]);
        let data = pattern(usize::try_from(size).unwrap());
        let layout = AttachmentLayout::new(size).unwrap();
        let chunks = seal_all(&key, &a, &data, seed.wrapping_add(1));
        let mut out = Vec::new();
        for (i, env) in (0u32..).zip(&chunks) {
            out.extend_from_slice(key.open_chunk(&a, layout, i, env).unwrap().expose_secret());
            // Truncated by one byte.
            prop_assert!(key.open_chunk(&a, layout, i, &env[..env.len() - 1]).is_err());
            // One flipped bit anywhere in the envelope.
            let mut bad = env.clone();
            let at_byte = flip.index(bad.len());
            bad[at_byte] ^= 1 << bit;
            prop_assert!(key.open_chunk(&a, layout, i, &bad).is_err());
            // Every other index, whatever its length.
            for j in 0..layout.chunk_count() {
                if j != i {
                    prop_assert!(key.open_chunk(&a, layout, j, env).is_err());
                }
            }
            // A layout one full chunk larger: another chunk_count in the AAD.
            let more = AttachmentLayout::new(size + CHUNK).unwrap();
            prop_assert!(key.open_chunk(&a, more, i, env).is_err());
        }
        prop_assert_eq!(out, data);
    }
}
