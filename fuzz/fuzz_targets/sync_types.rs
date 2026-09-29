//! Fuzzes the decoders of `rizzy-sync`'s core types, which read server-supplied op and snapshot
//! headers and decrypted item records: the canonical version vector (ADR 0012 §3), the dot
//! (ADR 0018 §3) and the HLC (ADR 0012 §2). None may panic or allocate in proportion to a
//! count, and each accepts only canonical bytes.
//!
//! What runs on each input:
//!
//! - [`VersionVector::parse`] on the whole input. When it accepts, re-encoding must give back
//!   exactly the input: one encoding per vector, no byte dropped or invented.
//! - The input read as consecutive fields, the way a header parser reads them: a dot, an HLC and
//!   two version vectors, each with [`Reader`]. A successful read must consume exactly its
//!   encoding and re-encode to it; a failed one must leave the reader where it was.
//! - When both vectors decode: join commutes, the meet is below both, the join above both, and
//!   `compare` is antisymmetric.
//! - The HLC rules ([`Hlc::tick`], [`Hlc::receive`]) on the first 24 bytes as clock, remote and
//!   wall clock: they return an error or a clock that moved forward, never a panic or a wrap.
//!   The skew guard fires exactly when the remote is more than [`SKEW_GUARD_MS`] ahead of the
//!   wall clock, whatever the local clock (ADR 0012 §2), and leaves the clock unchanged then;
//!   an adopted receipt moves the clock at most one millisecond past the larger of the clock
//!   and the wall clock plus 24 h, so no receipt can ratchet it further.
//!
//! Part of CRYPTO.md §15 item 7, "sync-engine decoders: the canonical version vector, dot and
//! HLC" (ADR 0012 §2–§3).
//!
//! ```text
//! cargo +nightly fuzz run sync_types
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::encoding::Reader;
use rizzy_sync::dot::Dot;
use rizzy_sync::hlc::{Hlc, SKEW_GUARD_MS};
use rizzy_sync::vv::{VersionVector, VvOrdering};

/// Reads one vector from `reader` and checks the read against its re-encoding.
fn read_vv(reader: &mut Reader<'_>) -> Option<VersionVector> {
    let before = reader.remaining();
    match VersionVector::read(reader) {
        Ok(vv) => {
            let bytes = vv.to_vec().expect("a decoded vector fits its u16 count");
            assert_eq!(before - reader.remaining(), bytes.len());
            assert_eq!(vv.encoded_len(), bytes.len());
            assert_eq!(VersionVector::parse(&bytes).as_ref(), Ok(&vv));
            Some(vv)
        }
        Err(_) => {
            assert_eq!(reader.remaining(), before);
            None
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(vv) = VersionVector::parse(data) {
        assert_eq!(vv.to_vec().as_deref(), Ok(data));
    }

    let mut reader = Reader::new(data);
    let before = reader.remaining();
    match Dot::read(&mut reader) {
        Ok(dot) => {
            let mut bytes = Vec::new();
            dot.encode(&mut bytes);
            assert_eq!(Some(bytes.as_slice()), data.get(..Dot::ENCODED_LEN));
            assert!(dot.seq() >= 1);
        }
        Err(_) => assert_eq!(reader.remaining(), before),
    }
    let before = reader.remaining();
    match Hlc::read(&mut reader) {
        Ok(_) => assert_eq!(before - reader.remaining(), Hlc::ENCODED_LEN),
        Err(_) => assert_eq!(reader.remaining(), before),
    }
    if let (Some(a), Some(b)) = (read_vv(&mut reader), read_vv(&mut reader)) {
        let mut ab = a.clone();
        ab.join(&b);
        let mut ba = b.clone();
        ba.join(&a);
        assert_eq!(ab, ba);
        let mut meet = a.clone();
        meet.meet(&b);
        assert!(meet <= a && meet <= b && a <= ab && b <= ab);
        let expected = match a.compare(&b) {
            VvOrdering::Less => VvOrdering::Greater,
            VvOrdering::Greater => VvOrdering::Less,
            other => other,
        };
        assert_eq!(b.compare(&a), expected);
    }

    let word = |i: usize| {
        data.get(i * 8..i * 8 + 8)
            .and_then(|w| <[u8; 8]>::try_from(w).ok())
            .map(u64::from_be_bytes)
    };
    if let (Some(clock), Some(remote), Some(now)) = (word(0), word(1), word(2)) {
        let (clock, remote) = (Hlc::from_u64(clock), Hlc::from_u64(remote));
        if let Ok(next) = clock.tick(now) {
            assert!(next > clock);
        }
        if let Ok(receipt) = clock.receive(remote, now) {
            let ahead = remote.millis() > now.saturating_add(SKEW_GUARD_MS);
            assert_eq!(receipt.remote_ahead, ahead);
            if ahead {
                assert_eq!(receipt.clock, clock);
            } else {
                assert!(receipt.clock > clock && receipt.clock > remote);
                let limit = clock
                    .millis()
                    .max(now.saturating_add(SKEW_GUARD_MS))
                    .saturating_add(1);
                assert!(receipt.clock.millis() <= limit);
            }
        }
    }
});
