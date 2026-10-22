// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the attachment download path of `rizzy-client` ([ADR 0054] §8): the index and count
//! handling over envelopes a hostile server serves, from the wrap to the assembled file.
//!
//! The fixture seals a real attachment (an item key from a counting RNG, its
//! `ATTACHMENT_KEY_WRAP` and every chunk) of a size the input picks: empty, a few bytes, or a
//! full chunk plus a remainder (two chunks). The rest of the input is a script of deliveries:
//! the right chunk at its index, another chunk at an index, a chunk with one byte changed, or
//! arbitrary bytes, at any index including past the last one. Then the download finishes.
//!
//! - Nothing panics, whatever the wrap, the indices or the bytes.
//! - A wrap of arbitrary bytes never yields a key.
//! - [`AttachmentDownload::finish`] succeeds only with exactly every chunk delivered in its
//!   place, and then returns the sealed file byte for byte (INV-78, INV-79).
//!
//! The chunk envelope itself is an ordinary `0x01` envelope, whose parser `envelope_parse`
//! already fuzzes.
//!
//! ```text
//! cargo +nightly fuzz run client_attachment_reassembly
//! ```
//!
//! [ADR 0054]: ../../docs/adr/0054-attachments-envelope-and-api.md
#![no_main]

use std::convert::Infallible;

use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};
use rizzy_client::attachments::AttachmentDownload;
use rizzy_client::rizzy_core::attachment::{
    AttachmentKey, AttachmentLayout, AttachmentRef, CHUNK_SIZE, MAX_CHUNK_ENVELOPE_LEN,
};
use rizzy_client::rizzy_core::ids::{AttachmentId, ItemId, VaultId};
use rizzy_client::rizzy_core::keys::ItemKey;

/// A deterministic RNG: the fixture's keys and nonces, not the fuzzer's input.
struct CountingRng(u8);

impl TryRng for CountingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for b in dst {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

impl TryCryptoRng for CountingRng {}

/// Reads the input front to back; an exhausted input reads zeros and ends the script.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }

    fn take(&mut self, n: usize) -> &[u8] {
        let n = n.min(self.0.len());
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        head
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let size: u64 = match input.byte().unwrap_or(0) % 3 {
        0 => 0,
        1 => u64::from(input.byte().unwrap_or(0)) + 1,
        _ => CHUNK_SIZE as u64 + u64::from(input.byte().unwrap_or(0)) + 1,
    };
    let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let layout = AttachmentLayout::new(size).expect("within the cap");
    let at = AttachmentRef {
        vault_id: VaultId::from_bytes([1; 16]),
        item_id: ItemId::from_bytes([2; 16]),
        attachment_id: AttachmentId::from_bytes([3; 16]),
    };
    let mut rng = CountingRng(7);
    let item_key = ItemKey::generate(&mut rng, 0);
    let key = AttachmentKey::generate(&mut rng);
    let wrap = item_key
        .wrap_attachment_key(&mut rng, &at.key_wrap_ctx(), &key)
        .expect("wrap");
    let chunks: Vec<Vec<u8>> = (0..layout.chunk_count())
        .map(|i| {
            let off = layout.chunk_offset(i).expect("in range") as usize;
            let len = layout.chunk_len(i).expect("in range");
            key.seal_chunk(&mut rng, &at, layout, i, &plaintext[off..off + len])
                .expect("seal")
        })
        .collect();

    let mut download = AttachmentDownload::new(at, size).expect("within the cap");
    // A wrap of arbitrary bytes never opens.
    let junk_len = usize::from(input.byte().unwrap_or(0));
    let junk = input.take(junk_len).to_vec();
    if junk != wrap {
        assert!(download.accept_key(&item_key, &junk).is_err());
    }
    download.accept_key(&item_key, &wrap).expect("the real wrap opens");

    let count = chunks.len();
    let mut placed = vec![false; count];
    while let Some(op) = input.byte() {
        let index = u32::from(input.byte().unwrap_or(0) % 4);
        let delivered: Vec<u8> = match op % 4 {
            0 => match chunks.get(index as usize) {
                Some(c) => c.clone(),
                None => continue,
            },
            1 => {
                let from = usize::from(input.byte().unwrap_or(0));
                match chunks.get(from % count.max(1)) {
                    Some(c) => c.clone(),
                    None => continue,
                }
            }
            2 => match chunks.get(index as usize) {
                Some(c) => {
                    let mut c = c.clone();
                    let at_byte = usize::from(input.byte().unwrap_or(0)) % c.len();
                    c[at_byte] ^= input.byte().unwrap_or(0) | 1;
                    c
                }
                None => continue,
            },
            _ => {
                let len = usize::from(input.byte().unwrap_or(0)) * 8;
                input.take(len.min(MAX_CHUNK_ENVELOPE_LEN + 16)).to_vec()
            }
        };
        let genuine = chunks.get(index as usize) == Some(&delivered);
        let accepted = download.accept_chunk(index, &delivered).is_ok();
        if accepted {
            // Only the genuine chunk opens at an index, and only once.
            assert!(genuine, "a chunk opened where it does not belong");
            let slot = &mut placed[index as usize];
            assert!(!*slot, "a chunk was accepted twice");
            *slot = true;
        } else {
            assert!(
                !(genuine && !placed[index as usize]),
                "the genuine chunk was refused at its own index"
            );
        }
    }
    match download.finish() {
        Ok(file) => {
            assert!(placed.iter().all(|p| *p), "assembled with a chunk missing");
            assert_eq!(file.as_slice(), plaintext.as_slice());
        }
        Err(_) => assert!(placed.iter().any(|p| !*p), "a complete set was refused"),
    }
});
