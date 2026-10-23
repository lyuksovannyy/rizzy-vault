// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the `icons` role's decode path (ADR 0052 point 4; INV-76): fetched bytes are
//! attacker-chosen (any site, any redirect target), so `rizzy_icon_proxy::decode::reencode`
//! must never panic, hang or allocate past its limits, whatever the header claims.
//!
//! On arbitrary bytes: `reencode` returns an error or a PNG that starts with the signature,
//! is at most `MAX_ICON_PNG_LEN` bytes, and decodes back to at most 128×128 pixels. A second
//! pass over the output (a PNG of ours) succeeds and keeps the size: re-encoding is stable.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_icon_proxy::decode::{ICON_SIZE, MAX_IMAGE_BYTES, reencode};
use rizzy_proto::icons::PNG_SIGNATURE;
use rizzy_proto::limits::MAX_ICON_PNG_LEN;

fuzz_target!(|data: &[u8]| {
    let Ok(png) = reencode(data) else {
        return;
    };
    assert!(data.len() <= MAX_IMAGE_BYTES);
    assert!(png.starts_with(&PNG_SIGNATURE));
    assert!(png.len() <= MAX_ICON_PNG_LEN);
    let again = reencode(&png).expect("our own PNG re-encodes");
    let (a, b) = (dimensions(&png), dimensions(&again));
    assert_eq!(a, b);
    assert!(a.0 >= 1 && a.1 >= 1 && a.0 <= ICON_SIZE && a.1 <= ICON_SIZE);
});

/// The width and height in a PNG's IHDR chunk (bytes 16..24).
fn dimensions(png: &[u8]) -> (u32, u32) {
    let w = png.get(16..20).and_then(|s| s.try_into().ok()).map(u32::from_be_bytes);
    let h = png.get(20..24).and_then(|s| s.try_into().ok()).map(u32::from_be_bytes);
    (w.expect("IHDR width"), h.expect("IHDR height"))
}
