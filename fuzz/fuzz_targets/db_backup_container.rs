// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes `rizzy-server`'s format version 2 database backup container (`rizzy_server::db_backup`,
//! ADR 0071, CRYPTO.md §9.8): `rizzy-vault restore` reads it from the operator's disk or a pipe,
//! often from off-site storage less protected than the server, so a damaged or hostile file
//! must be refused without a panic, before any allocation its header alone sizes, and an error
//! must never carry a byte of the payload.
//!
//! For each input:
//! 1. the raw bytes, as a file (almost always refused by the magic);
//! 2. the bytes behind the magic and `format_version` 2, so the header and framing checks are
//!    reached;
//! 3. a real file sealed from the input's tail under the fixture key, then mutated by the
//!    input's head (bit flips, a truncation, an appended byte, a rewritten header field). An
//!    unmutated file must open to its payload; a mutated one must be refused.
//!
//! None may panic; every refusal names a rule or a chunk index in under 200 bytes.
//!
//! ```text
//! cargo +nightly fuzz run db_backup_container
//! ```
#![no_main]

use std::convert::Infallible;

use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};
use rizzy_domain_auth::types::ServerDbBackupKey;
use rizzy_server::db_backup::{HEADER_LEN, open, parse_header, seal};
use rizzy_storage::backup::file::MAGIC;

/// The randomness the writer draws (`backup_id`, nonces). It counts upward; nothing here
/// depends on unpredictability, and a crash must reproduce from its input alone. Marked
/// `CryptoRng` only so the API accepts it.
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

/// Opens `bytes` with the fixture key; returns whether it opened.
fn check(key: &ServerDbBackupKey, bytes: &[u8]) -> Option<Vec<u8>> {
    let _ = parse_header(bytes);
    match open(|id| (id == key.backup_key_id()).then_some(key), bytes) {
        Ok(plaintext) => Some(plaintext.to_vec()),
        Err(e) => {
            // Errors name a rule or a chunk index, never a value.
            assert!(e.to_string().len() < 200);
            None
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let key = ServerDbBackupKey::from_slice(&[0x5a; 32], 1).expect("32 bytes");

    // 1. The raw bytes. Without the fixture key's seal no input can open.
    assert!(check(&key, data).is_none(), "an unsealed input opened");

    // 2. Behind the magic and format_version 2.
    let framed = [MAGIC.as_slice(), &[0, 2], data].concat();
    assert!(check(&key, &framed).is_none(), "an unsealed input opened");

    // 3. A real file, mutated by the input's head.
    let Some((&op, rest)) = data.split_first() else {
        return;
    };
    let Some((&arg, payload)) = rest.split_first() else {
        return;
    };
    if payload.is_empty() {
        return;
    }
    let file = seal(&mut CountingRng(arg), &key, payload, u64::from(arg)).expect("seals");
    assert_eq!(
        check(&key, &file).as_deref(),
        Some(payload),
        "a sealed file opens to its payload"
    );
    let mut bad = file.clone();
    let at = usize::from(arg) * 7 % bad.len();
    match op % 5 {
        0 => bad[at] ^= 1 << (op % 8),
        1 => bad.truncate(at),
        2 => bad.push(arg),
        // A header field rewritten, if the byte differs: backup_id, created_at_ms, backup_key_id,
        // plaintext_len, chunk_count (§9.8 offsets).
        3 => {
            let i = HEADER_LEN - 1 - usize::from(arg) % (HEADER_LEN - MAGIC.len() - 2);
            bad[i] = bad[i].wrapping_add(1 + op % 255);
        }
        _ => {
            let j = (at + 1 + usize::from(op)) % bad.len();
            bad.swap(at, j);
        }
    }
    if bad != file {
        assert!(check(&key, &bad).is_none(), "a mutated file opened");
    }
});
