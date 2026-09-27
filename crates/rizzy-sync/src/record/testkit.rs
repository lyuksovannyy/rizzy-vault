//! Helpers shared by the record tests: ids, dots, HLCs and version vectors from single bytes,
//! hex, and [`Spec`], an independent writer of the ADR 0018 §3 layouts.
//!
//! [`Spec`] writes whatever it is told, field by field as the ADR spells the layouts, with no
//! check and no sorting. Tests compare the encoder's output with it, and feed it deliberately
//! broken structures (reordered, duplicated, over the limits) that the encoder would refuse to
//! write, to check that the parser rejects them.

use rizzy_core::ids::DeviceId;

use super::{FieldKey, LIFECYCLE_KEY};
use crate::dot::Dot;
use crate::hlc::Hlc;
use crate::vv::VersionVector;

/// A device id whose 16 bytes are all `b`.
pub(super) fn device(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

/// The dot `(device(b), seq)`.
pub(super) fn dot(b: u8, seq: u64) -> Dot {
    Dot::new(device(b), seq).unwrap()
}

/// 2026-05-28T20:26:40Z, the vectors' base time in Unix milliseconds.
pub(super) const T0: u64 = 1_780_000_000_000;

/// The HLC `T0 + ms` milliseconds with logical counter `counter`.
pub(super) fn hlc(ms: u64, counter: u16) -> Hlc {
    Hlc::from_parts(T0 + ms, counter).unwrap()
}

/// The version vector with the entries `(device(b), seq)`.
pub(super) fn vv(entries: &[(u8, u64)]) -> VersionVector {
    entries.iter().map(|&(b, seq)| dot(b, seq)).collect()
}

/// A field key: `@lifecycle`, or a key [`FieldKey::new`] accepts.
pub(super) fn key(text: &str) -> FieldKey<'_> {
    if text == LIFECYCLE_KEY {
        FieldKey::LIFECYCLE
    } else {
        FieldKey::new(text).unwrap()
    }
}

/// A key of `len` bytes, 133 to 164, that matches the §7 grammar: four 32-byte names and a
/// fifth of `len − 132` bytes, joined by dots.
pub(super) fn key_of_len(len: usize) -> String {
    let mut k = ["a", "b", "c", "d"].map(|c| c.repeat(32)).join(".");
    k.push('.');
    k.push_str(&"e".repeat(len - k.len()));
    k
}

/// Decodes lowercase hex, ignoring whitespace.
pub(super) fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            other => panic!("not a lowercase hex digit: {other:#04x}"),
        })
        .collect();
    assert!(digits.len().is_multiple_of(2), "odd number of hex digits");
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

/// Encodes bytes as lowercase hex.
pub(super) fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// One entry for [`Spec::register`]: `(device byte, seq, hlc, value)`.
pub(super) type SpecEntry<'a> = (u8, u64, Hlc, &'a [u8]);

/// An independent writer of the ADR 0018 §3 layouts, field by field. No checks, no sorting.
#[derive(Clone, Debug, Default)]
pub(super) struct Spec(pub(super) Vec<u8>);

impl Spec {
    /// An empty buffer.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// `u8`.
    pub(super) fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }

    /// `u16`, big-endian.
    pub(super) fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// `u64`, big-endian.
    pub(super) fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Raw bytes, no length.
    pub(super) fn raw(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }

    /// `bytes(b) = u32(len) ‖ b`.
    pub(super) fn bytes(mut self, b: &[u8]) -> Self {
        self.0
            .extend_from_slice(&u32::try_from(b.len()).unwrap().to_be_bytes());
        self.raw(b)
    }

    /// `str(s) = bytes(UTF-8(s))`.
    pub(super) fn str(self, s: &str) -> Self {
        self.bytes(s.as_bytes())
    }

    /// `dot = device_id (16) ‖ u64 seq`, with `device_id` all `b`.
    pub(super) fn dot(self, b: u8, seq: u64) -> Self {
        self.raw(&[b; 16]).u64(seq)
    }

    /// A canonical VV `u16 n ‖ n × (device_id ‖ u64 seq)`, entries as given.
    pub(super) fn vv(self, entries: &[(u8, u64)]) -> Self {
        let n = u16::try_from(entries.len()).unwrap();
        entries
            .iter()
            .fold(self.u16(n), |s, &(b, seq)| s.dot(b, seq))
    }

    /// One op write: `str(key) ‖ bytes(value)`.
    pub(super) fn write(self, key: &str, value: &[u8]) -> Self {
        self.str(key).bytes(value)
    }

    /// `register = str(key) ‖ u16 m ‖ m × (dot ‖ u64 hlc ‖ bytes(value))`.
    pub(super) fn register(self, key: &str, entries: &[SpecEntry<'_>]) -> Self {
        let m = u16::try_from(entries.len()).unwrap();
        entries
            .iter()
            .fold(self.str(key).u16(m), |s, &(b, seq, h, v)| {
                s.dot(b, seq).u64(h.to_u64()).bytes(v)
            })
    }

    /// The bytes.
    pub(super) fn done(self) -> Vec<u8> {
        self.0
    }
}
