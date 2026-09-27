//! Dots: the identity of an op (ADR 0012 §2 "Dot").
//!
//! A dot is `(device_id, device_seq)`. `device_id` is the author's
//! [`DeviceId`], a 16-byte random id (CRYPTO.md §2). `device_seq` is a `u64` that starts at 1 and
//! increases by exactly 1 for every op the device writes, in any vault, so it is gap-free per
//! device (INV-27). A [`Dot`] therefore never has `seq` 0: its constructor and its decoder
//! refuse it (ADR 0018 §3 `dot`, "`seq` ≥ 1"; §5 rule 6).
//!
//! # Encoding
//!
//! `device_id (16) ‖ u64 seq` (ADR 0018 §3 `dot`). The same 24 bytes are a version-vector
//! entry (ADR 0012 §3) and the `device_id ‖ u64 device_seq` pair of the op header.
//!
//! # Order
//!
//! `Dot` orders by `device_id` bytewise, then by `seq` numerically: the dot order within a
//! register or history group (ADR 0018 §4 "Order"). A tuple `(Hlc, Dot)` therefore orders by
//! `(hlc, device_id, seq)`, the order of history pruning (ADR 0012 §5), the recorded purge
//! (ADR 0018 §3) and display (ADR 0018 §6).
//!
//! Causality is not a property of a dot alone: op A happened before op B when B's causal
//! context covers A's dot ([`VersionVector::covers`](crate::vv::VersionVector::covers),
//! ADR 0012 §2).

use core::num::NonZeroU64;

use rizzy_core::encoding::{Reader, put_u64};
use rizzy_core::ids::{DeviceId, ID_LEN};

use crate::error::{DecodeError, DecodeErrorKind};

/// The identity of one op: `(device_id, device_seq)` with `device_seq` ≥ 1 (ADR 0012 §2).
///
/// Also the identity of every register value and history entry an op wrote (ADR 0018 §3), and
/// of the recorded purge of a tombstone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dot {
    /// The authoring device. Compared first, bytewise.
    device_id: DeviceId,
    /// The author's `device_seq` of the op, never 0. Compared second, numerically.
    seq: NonZeroU64,
}

impl Dot {
    /// Length of the encoding: a 16-byte `device_id` and a `u64` seq.
    pub const ENCODED_LEN: usize = ID_LEN + 8;

    /// The dot `(device_id, seq)`. `None` when `seq` is 0, which no op has.
    #[must_use]
    pub const fn new(device_id: DeviceId, seq: u64) -> Option<Self> {
        match NonZeroU64::new(seq) {
            Some(seq) => Some(Self { device_id, seq }),
            None => None,
        }
    }

    /// The dot `(device_id, seq)` from a sequence number already known to be non-zero.
    pub(crate) const fn from_nonzero(device_id: DeviceId, seq: NonZeroU64) -> Self {
        Self { device_id, seq }
    }

    /// The authoring device.
    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// The author's `device_seq`, at least 1.
    #[must_use]
    pub const fn seq(self) -> u64 {
        self.seq.get()
    }

    /// The sequence number as a [`NonZeroU64`].
    pub(crate) const fn seq_nonzero(self) -> NonZeroU64 {
        self.seq
    }

    /// Appends the canonical encoding `device_id ‖ u64 seq` to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.device_id.as_bytes());
        put_u64(out, self.seq.get());
    }

    /// Reads a dot from `reader`, for a header or record parser.
    ///
    /// # Errors
    /// [`DecodeErrorKind::Truncated`] at offset 0 or 16 if the input ends early, and
    /// [`DecodeErrorKind::ZeroSeq`] at offset 16 if `seq` is 0. The reader is unchanged on
    /// error.
    pub fn read(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let mut probe = reader.clone();
        let device_id = probe
            .array::<ID_LEN>()
            .map(|bytes| DeviceId::from_bytes(*bytes))
            .map_err(|_| DecodeError::new(DecodeErrorKind::Truncated, 0))?;
        let seq = probe
            .u64()
            .map_err(|_| DecodeError::new(DecodeErrorKind::Truncated, ID_LEN))?;
        let seq = NonZeroU64::new(seq).ok_or(DecodeError::new(DecodeErrorKind::ZeroSeq, ID_LEN))?;
        *reader = probe;
        Ok(Self { device_id, seq })
    }
}

#[cfg(test)]
mod tests {
    //! The known-answer encoding, the zero-seq refusal on both paths, truncation at every
    //! length, and the order ADR 0018 §4 prescribes: first-byte-most-significant on the device
    //! id, checked on known answers and, as a property, against the bytewise order of the
    //! encoding.

    use proptest::prelude::*;

    use super::*;
    use crate::hlc::Hlc;

    fn device(first: u8) -> DeviceId {
        let mut bytes = [0u8; ID_LEN];
        bytes.iter_mut().zip(first..).for_each(|(b, v)| *b = v);
        DeviceId::from_bytes(bytes)
    }

    #[test]
    fn encoding_known_answer_and_read() {
        let dot = Dot::new(device(0x00), 0x0102).unwrap();
        let mut out = Vec::new();
        dot.encode(&mut out);
        assert_eq!(
            out,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
            ]
        );
        assert_eq!(out.len(), Dot::ENCODED_LEN);
        out.push(0xff);
        let mut r = Reader::new(&out);
        assert_eq!(Dot::read(&mut r), Ok(dot));
        assert_eq!(r.remaining(), 1);
        assert_eq!(dot.device_id(), device(0x00));
        assert_eq!(dot.seq(), 0x0102);
    }

    #[test]
    fn seq_zero_is_refused() {
        assert_eq!(Dot::new(device(1), 0), None);
        let mut bytes = device(1).to_bytes().to_vec();
        bytes.extend_from_slice(&[0; 8]);
        let mut r = Reader::new(&bytes);
        let e = Dot::read(&mut r).unwrap_err();
        assert_eq!((e.kind(), e.offset()), (DecodeErrorKind::ZeroSeq, 16));
        assert_eq!(r.remaining(), Dot::ENCODED_LEN);
    }

    #[test]
    fn truncation_at_every_length_is_refused() {
        let mut bytes = Vec::new();
        Dot::new(device(7), u64::MAX).unwrap().encode(&mut bytes);
        for len in 0..Dot::ENCODED_LEN {
            let mut r = Reader::new(bytes.get(..len).unwrap());
            let e = Dot::read(&mut r).unwrap_err();
            assert_eq!(e.kind(), DecodeErrorKind::Truncated, "{len}");
            assert_eq!(e.offset(), if len < 16 { 0 } else { 16 }, "{len}");
            assert_eq!(r.remaining(), len);
        }
    }

    #[test]
    fn order_is_device_bytewise_then_seq() {
        // Equal but for the last byte.
        let low =
            DeviceId::from_bytes(0x0101_0101_0101_0101_0101_0101_0101_0101_u128.to_be_bytes());
        let high =
            DeviceId::from_bytes(0x0101_0101_0101_0101_0101_0101_0101_0102_u128.to_be_bytes());
        let mut dots = vec![
            Dot::new(high, 1).unwrap(),
            Dot::new(low, 10).unwrap(),
            Dot::new(low, 2).unwrap(),
        ];
        dots.sort();
        assert_eq!(
            dots,
            [
                Dot::new(low, 2).unwrap(),
                Dot::new(low, 10).unwrap(),
                Dot::new(high, 1).unwrap(),
            ]
        );
        // (hlc, device_id, seq): the HLC decides first.
        let a = (Hlc::from_u64(5), Dot::new(high, 1).unwrap());
        let b = (Hlc::from_u64(6), Dot::new(low, 1).unwrap());
        let c = (Hlc::from_u64(6), Dot::new(low, 2).unwrap());
        assert!(a < b && b < c);
    }

    /// "Bytewise" is lexicographic from the first byte: ids whose first and last bytes
    /// disagree tell it apart from any order over reversed or permuted bytes (for example a
    /// little-endian integer key), which the ids above cannot.
    #[test]
    fn device_order_is_first_byte_most_significant() {
        let a = 0x00ff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_u128.to_be_bytes();
        let b = 0x0100_0000_0000_0000_0000_0000_0000_0000_u128.to_be_bytes();
        assert_eq!(a.first().zip(a.last()), Some((&0x00, &0xff)));
        assert_eq!(b.first().zip(b.last()), Some((&0x01, &0x00)));
        let (a, b) = (DeviceId::from_bytes(a), DeviceId::from_bytes(b));
        assert!(Dot::new(a, 1).unwrap() < Dot::new(b, 1).unwrap());
        assert!(Dot::new(a, u64::MAX).unwrap() < Dot::new(b, 1).unwrap());
    }

    fn config() -> ProptestConfig {
        ProptestConfig {
            cases: 1_000,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(config())]

        /// The dot order is the bytewise order of the encoding `device_id ‖ u64 seq` (a
        /// fixed-width big-endian seq sorts like its number): an oracle independent of
        /// `DeviceId`'s `Ord`. The ids share a random-length prefix so that every byte
        /// position gets to decide.
        #[test]
        fn order_is_the_order_of_the_encoding(
            a in any::<[u8; ID_LEN]>(), mut b in any::<[u8; ID_LEN]>(), shared in 0..=ID_LEN,
            sa in 1..=u64::MAX, sb in 1..=u64::MAX
        ) {
            b.iter_mut().zip(a).take(shared).for_each(|(dst, src)| *dst = src);
            let x = Dot::new(DeviceId::from_bytes(a), sa).unwrap();
            let y = Dot::new(DeviceId::from_bytes(b), sb).unwrap();
            let (mut ex, mut ey) = (Vec::new(), Vec::new());
            x.encode(&mut ex);
            y.encode(&mut ey);
            prop_assert_eq!(x.cmp(&y), ex.cmp(&ey));
            prop_assert_eq!(x.cmp(&y), a.as_slice().cmp(b.as_slice()).then(sa.cmp(&sb)));
        }
    }
}
