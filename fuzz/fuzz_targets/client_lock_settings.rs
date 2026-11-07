// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the vault lock settings record parser (ADR 0110 §3; INV-127): `rizzy-client`'s
//! [`LockSettings::parse`]. The record sits in plain `localStorage`, `storage.local` or app
//! preferences, which anything with access to that store can rewrite, so it is untrusted input.
//!
//! For each input:
//!
//! - the parser never panics, and a record it refuses ([`LockSettings::parse_strict`] `None`)
//!   reads as exactly the defaults (locking on, 5 minutes, restart on, sleep on);
//! - a record over 256 bytes is always refused;
//! - whatever it reads has an `idle_minutes` in ADR 0110 §1's list and restart on;
//! - the settings it reads encode to the canonical text, which is at most 256 bytes and parses
//!   back to the same settings; a canonical text encodes to itself, byte for byte;
//! - the lock timer driven by the input's bytes as clock readings never panics, and never locks
//!   while automatic locking is off.
//!
//! ```text
//! cargo +nightly fuzz run client_lock_settings
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_client::lock_settings::{
    ClockReading, IDLE_MINUTES, LockSettings, LockTimer, MAX_LOCK_SETTINGS_LEN,
};

fuzz_target!(|data: &[u8]| {
    let strict = LockSettings::parse_strict(data);
    let read = LockSettings::parse(data);
    match strict {
        None => assert_eq!(read, LockSettings::DEFAULT, "a broken record is the defaults"),
        Some(s) => {
            assert_eq!(read, s);
            assert!(data.len() <= MAX_LOCK_SETTINGS_LEN);
        }
    }
    if data.len() > MAX_LOCK_SETTINGS_LEN {
        assert!(strict.is_none());
    }
    assert!(IDLE_MINUTES.contains(&read.idle_minutes()));
    assert!(read.lock_on_restart());

    let encoded = read.encode();
    assert!(encoded.len() <= MAX_LOCK_SETTINGS_LEN);
    assert_eq!(LockSettings::parse_strict(encoded.as_bytes()), Some(read));
    assert_eq!(
        LockSettings::parse(encoded.as_bytes()).encode(),
        encoded,
        "the canonical text is its own encoding"
    );

    // The timer, with the input's bytes as a stream of clock readings.
    let reading = |chunk: &[u8]| {
        let mut word = [0_u8; 8];
        for (to, from) in word.iter_mut().zip(chunk) {
            *to = *from;
        }
        let v = u64::from_le_bytes(word);
        ClockReading {
            monotonic_ms: v >> 20,
            wall_ms: (v & 0xf_ffff) * 1_000,
        }
    };
    let mut timer = LockTimer::new(read, reading(&[]));
    let off = read.with_auto_lock(false);
    let mut off_timer = LockTimer::new(off, reading(&[]));
    for (i, chunk) in data.chunks(8).enumerate() {
        let now = reading(chunk);
        match i % 3 {
            0 => {
                let _ = timer.tick(now);
            }
            1 => timer.input(now),
            _ => {
                let _ = timer.set_settings(read, now);
            }
        }
        assert_eq!(off_timer.tick(now), None, "locking off never locks");
        assert_eq!(off_timer.set_settings(off, now), None);
    }
});
