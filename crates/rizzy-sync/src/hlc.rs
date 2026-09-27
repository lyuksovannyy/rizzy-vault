//! Hybrid logical clocks (ADR 0012 §2 "HLC" and "Skew guard").
//!
//! An [`Hlc`] is a `u64`: the top 48 bits are Unix milliseconds, the low 16 bits a logical
//! counter (Kulkarni, Demirbas et al. 2014). It orders history and breaks ties between
//! concurrent writes: display, pruning and the recorded purge rank values by
//! `(hlc, device_id, seq)` (ADR 0012 §5, ADR 0018 §3 and §6). **It never decides causality**;
//! the version vectors of [`vv`](crate::vv) do.
//!
//! # Encoding
//!
//! `u64 hlc`, big-endian (CRYPTO.md §2), in the op header (ADR 0012 §3), the `ITEM_OP` AAD
//! context (CRYPTO.md §8.4) and every register entry and `purge_hlc` of the item record
//! (ADR 0018 §3). Every `u64` is a valid HLC, so decoding rejects only truncated input.
//!
//! # Reading the time
//!
//! [`Hlc::millis`] is `hlc >> 16`, the Unix milliseconds that CRYPTO.md §10.2 rule (c) compares
//! with a certificate's `expires_at_ms` ("the op's HLC, read as milliseconds (its top 48
//! bits)") and that ADR 0018 §9 derives the created, modified and trashed times from.
//!
//! # Update rules
//!
//! The host injects the wall clock (ADR 0012 §2, ADR 0016 R1): both rules take `now_ms`, Unix
//! milliseconds, and nothing here reads a clock. With `pt = now_ms << 16`:
//!
//! - **Local or send event** ([`Hlc::tick`]), for every op a device writes:
//!   `hlc' = max(hlc + 1, pt)`.
//! - **Receive event** ([`Hlc::receive`]), for every applied op of another device (the
//!   spike applies it to no own op fetched back) and, under ADR 0018 §3 "Absorbing a
//!   snapshot", for the highest HLC an absorbed snapshot carries:
//!   `hlc' = max(pt, max(hlc, remote) + 1)`.
//!
//! These are the standard rules on the pair `(l, c)` evaluated on the packed `u64`, as the
//! merge spike does (`spikes/merge-model`, `replica.rs` `tick_local` and `tick_recv`). They
//! give the textbook result whenever the counter stays below `0xFFFF`; a counter that would
//! pass `0xFFFF` carries into the milliseconds instead, so the clock stays strictly increasing
//! and runs at most one millisecond ahead per 65,536 events within one millisecond.
//!
//! The rules move only the local clock, and so only the HLCs of the ops this device writes.
//! A receiver takes a received HLC as signed and never recomputes it, so replicas agree on
//! every applied value whatever clock each author ran.
//!
//! **Skew guard.** A received HLC whose milliseconds are more than [`SKEW_GUARD_MS`] (24 h)
//! ahead of `now_ms` is still applied by the caller, because every replica must apply the same
//! ops, but the local clock does not adopt it: [`Hlc::receive`] leaves the clock unchanged, as
//! the spike's `tick_recv` does, and sets [`Receipt::remote_ahead`] so that the caller reports
//! "Device X's clock is ahead". The guard measures from the injected wall clock `now_ms`, the
//! "local wall clock" of ADR 0012 §2, never from the local HLC, even when that HLC is ahead of
//! the wall clock.
//!
//! The guard therefore bounds the clock. A receipt adopts only an HLC of at most
//! `M = hlc(now_ms + 24 h, 0xFFFF)` and moves the clock to at most one past the larger of the
//! clock and `M`. From a clock no more than 24 h ahead of `now_ms`, 65,536 receipts at one
//! wall-clock reading leave its milliseconds at most `now_ms + 24 h + 1`; each further 65,536
//! add one millisecond. So a hostile peer can push the clock about a day ahead of the wall
//! clock at most, and cannot exhaust it. The tests pin this bound, including with the local
//! clock ahead of the wall clock.
//!
//! # Errors
//!
//! Both rules fail rather than wrap: [`HlcError::WallClockOutOfRange`] when `now_ms` does not
//! fit 48 bits (after the year 10889), and [`HlcError::Exhausted`] when the clock cannot
//! advance past `u64::MAX`. With an honest wall clock neither is reachable, the second not even
//! through a hostile peer (skew guard).

use core::fmt;

use rizzy_core::encoding::{Reader, put_u64};

use crate::error::{DecodeError, DecodeErrorKind};

/// Width of the logical counter in the low bits of an HLC (ADR 0012 §2).
pub const COUNTER_BITS: u32 = 16;

/// The largest Unix-milliseconds value the top 48 bits of an HLC can hold: 2^48 − 1, in the
/// year 10889.
pub const MAX_MILLIS: u64 = u64::MAX >> COUNTER_BITS;

/// The skew guard of ADR 0012 §2: 24 hours, in milliseconds. A received HLC more than this far
/// ahead of the local wall clock is not adopted.
pub const SKEW_GUARD_MS: u64 = 24 * 60 * 60 * 1000;

/// A hybrid logical clock value (ADR 0012 §2).
///
/// Ordered numerically, which is the order ADR 0018 §3 and §6 use ("`hlc` numerically"). A
/// device keeps one as its clock and advances it with [`Hlc::tick`] and [`Hlc::receive`]; ops,
/// register entries and purges carry the value the author's clock had when it wrote them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hlc(u64);

/// The outcome of [`Hlc::receive`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct Receipt {
    /// The local clock after the receipt. Unchanged when [`Receipt::remote_ahead`] is set.
    pub clock: Hlc,
    /// The skew guard fired: the received HLC is more than [`SKEW_GUARD_MS`] ahead of the local
    /// wall clock, so the clock did not adopt it. The op or snapshot is still applied; the
    /// caller reports that the author's clock is ahead (ADR 0012 §2).
    pub remote_ahead: bool,
}

/// Why a clock update failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HlcError {
    /// The injected wall clock is above [`MAX_MILLIS`] and does not fit the 48-bit
    /// milliseconds field.
    WallClockOutOfRange,
    /// The clock is at `u64::MAX` and cannot advance.
    Exhausted,
}

impl fmt::Display for HlcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WallClockOutOfRange => "wall clock out of the 48-bit millisecond range",
            Self::Exhausted => "hybrid logical clock exhausted",
        })
    }
}

impl core::error::Error for HlcError {}

impl Hlc {
    /// The zero clock: 0 ms, counter 0. The initial value of a device's clock.
    pub const ZERO: Self = Self(0);

    /// Length of the encoding: one `u64`.
    pub const ENCODED_LEN: usize = 8;

    /// Wraps a raw `u64` HLC, as it appears in a header or record.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// The raw `u64`.
    #[must_use]
    pub const fn to_u64(self) -> u64 {
        self.0
    }

    /// Builds an HLC from its two parts. `None` when `millis` is above [`MAX_MILLIS`].
    #[must_use]
    pub fn from_parts(millis: u64, counter: u16) -> Option<Self> {
        (millis <= MAX_MILLIS).then(|| Self((millis << COUNTER_BITS) | u64::from(counter)))
    }

    /// The Unix milliseconds in the top 48 bits: `hlc >> 16` (CRYPTO.md §10.2 rule (c),
    /// ADR 0018 §9).
    #[must_use]
    pub const fn millis(self) -> u64 {
        self.0 >> COUNTER_BITS
    }

    /// The logical counter in the low 16 bits.
    #[must_use]
    pub const fn counter(self) -> u16 {
        let [.., high, low] = self.0.to_be_bytes();
        u16::from_be_bytes([high, low])
    }

    /// The canonical encoding: `u64` big-endian.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::ENCODED_LEN] {
        self.0.to_be_bytes()
    }

    /// Decodes the canonical encoding. Every 8-byte string is a valid HLC.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::ENCODED_LEN]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }

    /// Appends the canonical encoding to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        put_u64(out, self.0);
    }

    /// Reads an HLC from `reader`, for a header or record parser.
    ///
    /// # Errors
    /// [`DecodeErrorKind::Truncated`] at offset 0 if fewer than 8 bytes remain; the reader is
    /// unchanged then.
    pub fn read(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        reader
            .u64()
            .map(Self)
            .map_err(|_| DecodeError::new(DecodeErrorKind::Truncated, 0))
    }

    /// The local or send event rule: `max(hlc + 1, now_ms << 16)`. The result is the new
    /// clock and the HLC of the op being written.
    ///
    /// # Errors
    /// [`HlcError::WallClockOutOfRange`] if `now_ms` is above [`MAX_MILLIS`];
    /// [`HlcError::Exhausted`] if the clock is at `u64::MAX`.
    pub fn tick(self, now_ms: u64) -> Result<Self, HlcError> {
        let physical = physical(now_ms)?;
        let next = self.0.checked_add(1).ok_or(HlcError::Exhausted)?;
        Ok(Self(next.max(physical)))
    }

    /// The receive event rule with the skew guard, for the HLC of an applied op of another
    /// device, or the highest HLC of an absorbed snapshot (ADR 0018 §3).
    ///
    /// If `remote`'s milliseconds are more than [`SKEW_GUARD_MS`] ahead of `now_ms`, the clock
    /// is returned unchanged with [`Receipt::remote_ahead`] set. Otherwise the new clock is
    /// `max(now_ms << 16, max(hlc, remote) + 1)`.
    ///
    /// # Errors
    /// [`HlcError::WallClockOutOfRange`] if `now_ms` is above [`MAX_MILLIS`];
    /// [`HlcError::Exhausted`] if the larger of the clock and `remote` is `u64::MAX`.
    pub fn receive(self, remote: Self, now_ms: u64) -> Result<Receipt, HlcError> {
        let physical = physical(now_ms)?;
        if remote.millis() > now_ms.saturating_add(SKEW_GUARD_MS) {
            return Ok(Receipt {
                clock: self,
                remote_ahead: true,
            });
        }
        let next = self
            .0
            .max(remote.0)
            .checked_add(1)
            .ok_or(HlcError::Exhausted)?;
        Ok(Receipt {
            clock: Self(next.max(physical)),
            remote_ahead: false,
        })
    }
}

/// `now_ms << 16`, the wall clock as an HLC with counter 0.
///
/// # Errors
/// [`HlcError::WallClockOutOfRange`] if `now_ms` is above [`MAX_MILLIS`].
fn physical(now_ms: u64) -> Result<u64, HlcError> {
    if now_ms > MAX_MILLIS {
        return Err(HlcError::WallClockOutOfRange);
    }
    Ok(now_ms << COUNTER_BITS)
}

#[cfg(test)]
mod tests {
    //! Known answers for the encoding and the two parts, the update rules on hand-checked
    //! cases (wall clock ahead, behind and equal; counter carry; skew guard at and past 24 h,
    //! measured from the wall clock also when the local clock is ahead of it; a hostile peer's
    //! ratchet; the error bounds), and property tests: both rules strictly advance the clock,
    //! never fall behind the wall clock, and agree with the textbook `(l, c)` rules of Kulkarni
    //! et al. whenever the counter does not overflow; the guard fires exactly when the remote
    //! is more than 24 h ahead of the wall clock; and receipts at a fixed wall clock keep the
    //! clock within `now_ms + 24 h + 1`.

    use proptest::prelude::*;

    use super::*;

    /// 2026-09-27T00:00:00Z in Unix milliseconds.
    const NOW: u64 = 1_790_467_200_000;

    fn hlc(millis: u64, counter: u16) -> Hlc {
        Hlc::from_parts(millis, counter).unwrap()
    }

    #[test]
    fn encoding_and_parts_known_answer() {
        let h = hlc(NOW, 7);
        // 1_790_467_200_000 = 0x01A0_E029_5400; << 16, then | 7.
        assert_eq!(h.to_u64(), 0x01A0_E029_5400_0007);
        assert_eq!(
            h.to_bytes(),
            [0x01, 0xa0, 0xe0, 0x29, 0x54, 0x00, 0x00, 0x07]
        );
        let mut out = vec![0xee];
        h.encode(&mut out);
        assert_eq!(out, [0xee, 0x01, 0xa0, 0xe0, 0x29, 0x54, 0x00, 0x00, 0x07]);
        assert_eq!(Hlc::from_bytes(h.to_bytes()), h);
        assert_eq!(h.millis(), NOW);
        assert_eq!(h.counter(), 7);
        assert_eq!(Hlc::from_u64(u64::MAX).millis(), MAX_MILLIS);
        assert_eq!(Hlc::from_u64(u64::MAX).counter(), u16::MAX);
        assert_eq!(
            Hlc::from_parts(MAX_MILLIS, u16::MAX),
            Some(Hlc::from_u64(u64::MAX))
        );
        assert_eq!(Hlc::from_parts(MAX_MILLIS + 1, 0), None);
        assert_eq!(Hlc::ZERO, Hlc::default());
        assert_eq!(MAX_MILLIS, (1 << 48) - 1);
        assert_eq!(SKEW_GUARD_MS, 86_400_000);
    }

    #[test]
    fn read_takes_eight_bytes_and_leaves_the_rest() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut r = Reader::new(&bytes);
        assert_eq!(Hlc::read(&mut r).unwrap().to_u64(), 0x0102_0304_0506_0708);
        assert_eq!(r.remaining(), 1);
        let short = [1, 2, 3, 4, 5, 6, 7];
        let mut r = Reader::new(&short);
        let e = Hlc::read(&mut r).unwrap_err();
        assert_eq!((e.kind(), e.offset()), (DecodeErrorKind::Truncated, 0));
        assert_eq!(r.remaining(), 7);
    }

    #[test]
    fn tick_follows_the_wall_clock_or_counts() {
        // Wall clock ahead of the clock: jump to it, counter 0.
        assert_eq!(hlc(NOW - 5, 3).tick(NOW), Ok(hlc(NOW, 0)));
        assert_eq!(Hlc::ZERO.tick(NOW), Ok(hlc(NOW, 0)));
        // Same millisecond, or wall clock behind: count.
        assert_eq!(hlc(NOW, 0).tick(NOW), Ok(hlc(NOW, 1)));
        assert_eq!(hlc(NOW + 9, 4).tick(NOW), Ok(hlc(NOW + 9, 5)));
        // A full counter carries into the milliseconds.
        assert_eq!(hlc(NOW, u16::MAX).tick(NOW), Ok(hlc(NOW + 1, 0)));
        // Bounds.
        assert_eq!(Hlc::ZERO.tick(MAX_MILLIS), Ok(hlc(MAX_MILLIS, 0)));
        assert_eq!(
            Hlc::ZERO.tick(MAX_MILLIS + 1),
            Err(HlcError::WallClockOutOfRange)
        );
        assert_eq!(Hlc::from_u64(u64::MAX).tick(NOW), Err(HlcError::Exhausted));
    }

    #[test]
    fn receive_takes_the_maximum_and_counts() {
        let advanced = |clock: Hlc| Receipt {
            clock,
            remote_ahead: false,
        };
        // Wall clock ahead of both.
        assert_eq!(
            hlc(NOW - 2, 9).receive(hlc(NOW - 1, 4), NOW),
            Ok(advanced(hlc(NOW, 0)))
        );
        // Remote ahead of the clock and the wall clock (within the guard).
        assert_eq!(
            hlc(NOW, 2).receive(hlc(NOW + 60_000, 5), NOW),
            Ok(advanced(hlc(NOW + 60_000, 6)))
        );
        // Clock ahead of the remote: count on the clock.
        assert_eq!(
            hlc(NOW + 3, 1).receive(hlc(NOW, 8), NOW),
            Ok(advanced(hlc(NOW + 3, 2)))
        );
        // Same milliseconds: one past the larger counter.
        assert_eq!(
            hlc(NOW, 2).receive(hlc(NOW, 7), NOW),
            Ok(advanced(hlc(NOW, 8)))
        );
        // Carry.
        assert_eq!(
            hlc(NOW, 1).receive(hlc(NOW, u16::MAX), NOW),
            Ok(advanced(hlc(NOW + 1, 0)))
        );
    }

    #[test]
    fn skew_guard_at_and_past_24_hours() {
        let clock = hlc(NOW, 3);
        // Exactly 24 h ahead is adopted ("more than 24 h" is the guard).
        let at = hlc(NOW + SKEW_GUARD_MS, u16::MAX);
        assert_eq!(
            clock.receive(at, NOW),
            Ok(Receipt {
                clock: hlc(NOW + SKEW_GUARD_MS + 1, 0),
                remote_ahead: false,
            })
        );
        // One millisecond more is applied by the caller but not adopted.
        let past = hlc(NOW + SKEW_GUARD_MS + 1, 0);
        assert_eq!(
            clock.receive(past, NOW),
            Ok(Receipt {
                clock,
                remote_ahead: true,
            })
        );
        assert_eq!(
            clock.receive(Hlc::from_u64(u64::MAX), NOW),
            Ok(Receipt {
                clock,
                remote_ahead: true,
            })
        );
    }

    /// ADR 0012 §2 measures the guard from the local *wall* clock. With the local HLC 20 h
    /// ahead of the wall clock, a remote 25 h ahead of the wall clock (5 h ahead of the HLC) is
    /// not adopted; a reading "more than 24 h ahead of the local HLC" would adopt it.
    #[test]
    fn skew_guard_measures_from_the_wall_clock_when_the_clock_is_ahead() {
        const HOUR: u64 = 60 * 60 * 1000;
        let clock = hlc(NOW + 20 * HOUR, 0);
        assert_eq!(
            clock.receive(hlc(NOW + 25 * HOUR, 0), NOW),
            Ok(Receipt {
                clock,
                remote_ahead: true,
            })
        );
        // Within 24 h of the wall clock and ahead of the clock: adopted.
        assert_eq!(
            clock.receive(hlc(NOW + 23 * HOUR, 4), NOW),
            Ok(Receipt {
                clock: hlc(NOW + 23 * HOUR, 5),
                remote_ahead: false,
            })
        );
        // Behind the clock: the clock counts.
        assert_eq!(
            clock.receive(hlc(NOW + 10 * HOUR, 9), NOW),
            Ok(Receipt {
                clock: hlc(NOW + 20 * HOUR, 1),
                remote_ahead: false,
            })
        );
    }

    /// A hostile peer that sends, again and again, an HLC exactly 24 h ahead of the receiver's
    /// current clock moves it once, to 24 h + 1 ms past the wall clock, and no further.
    #[test]
    fn a_hostile_peer_cannot_ratchet_the_clock() {
        let bound = NOW + SKEW_GUARD_MS + 1;
        let mut clock = hlc(NOW, 3);
        for round in 0..8 {
            let remote = hlc(clock.millis() + SKEW_GUARD_MS, u16::MAX);
            let r = clock.receive(remote, NOW).unwrap();
            assert_eq!(r.remote_ahead, round > 0, "round {round}");
            clock = r.clock;
            assert_eq!(clock, hlc(bound, 0), "round {round}");
        }
        // The largest adoptable HLC, twice: the clock only counts.
        let top = hlc(NOW + SKEW_GUARD_MS, u16::MAX);
        let r = clock.receive(top, NOW).unwrap();
        assert_eq!((r.clock, r.remote_ahead), (hlc(bound, 1), false));
        let r = r.clock.receive(top, NOW).unwrap();
        assert_eq!((r.clock, r.remote_ahead), (hlc(bound, 2), false));
    }

    #[test]
    fn receive_bounds() {
        assert_eq!(
            Hlc::ZERO.receive(Hlc::ZERO, MAX_MILLIS + 1),
            Err(HlcError::WallClockOutOfRange)
        );
        // Only reachable with a wall clock within 24 h of the end of the range.
        assert_eq!(
            Hlc::ZERO.receive(Hlc::from_u64(u64::MAX), MAX_MILLIS),
            Err(HlcError::Exhausted)
        );
        assert_eq!(
            Hlc::from_u64(u64::MAX).receive(Hlc::ZERO, NOW),
            Err(HlcError::Exhausted)
        );
        assert_eq!(
            HlcError::WallClockOutOfRange.to_string(),
            "wall clock out of the 48-bit millisecond range"
        );
        assert_eq!(
            HlcError::Exhausted.to_string(),
            "hybrid logical clock exhausted"
        );
    }

    /// The textbook send rule on `(l, c)` (Kulkarni et al. 2014, Figure 5).
    fn textbook_send((l, c): (u64, u64), pt: u64) -> (u64, u64) {
        let l2 = l.max(pt);
        if l2 == l { (l2, c + 1) } else { (l2, 0) }
    }

    /// The textbook receive rule on `(l, c)` for a message `(lm, cm)`.
    fn textbook_receive((l, c): (u64, u64), (lm, cm): (u64, u64), pt: u64) -> (u64, u64) {
        let l2 = l.max(lm).max(pt);
        if l2 == l && l2 == lm {
            (l2, c.max(cm) + 1)
        } else if l2 == l {
            (l2, c + 1)
        } else if l2 == lm {
            (l2, cm + 1)
        } else {
            (l2, 0)
        }
    }

    fn parts(h: Hlc) -> (u64, u64) {
        (h.millis(), u64::from(h.counter()))
    }

    /// Milliseconds around `NOW`, so that clock, remote and wall clock often coincide.
    fn near_now() -> impl Strategy<Value = u64> {
        prop_oneof![NOW - 3..=NOW + 3, NOW - 100_000..=NOW + 100_000]
    }

    /// Counters, often small or at the top.
    fn counter() -> impl Strategy<Value = u16> {
        prop_oneof![0u16..4, u16::MAX - 3..=u16::MAX, any::<u16>()]
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

        #[test]
        fn tick_advances_and_matches_the_textbook(
            l in near_now(), c in counter(), now in near_now()
        ) {
            let clock = hlc(l, c);
            let next = clock.tick(now).unwrap();
            prop_assert!(next > clock);
            prop_assert!(next.millis() >= now);
            if c < u16::MAX {
                prop_assert_eq!(parts(next), textbook_send(parts(clock), now));
            }
        }

        #[test]
        fn receive_advances_and_matches_the_textbook(
            l in near_now(), c in counter(), lm in near_now(), cm in counter(), now in near_now()
        ) {
            let (clock, remote) = (hlc(l, c), hlc(lm, cm));
            let r = clock.receive(remote, now).unwrap();
            prop_assert!(!r.remote_ahead);
            prop_assert!(r.clock > clock && r.clock > remote);
            prop_assert!(r.clock.millis() >= now);
            if c < u16::MAX && cm < u16::MAX {
                prop_assert_eq!(
                    parts(r.clock),
                    textbook_receive(parts(clock), parts(remote), now)
                );
            }
        }

        #[test]
        fn skew_guard_is_exactly_more_than_24_hours(
            c in counter(), ahead in 0..3 * SKEW_GUARD_MS, cm in counter()
        ) {
            let clock = hlc(NOW, c);
            let r = clock.receive(hlc(NOW + ahead, cm), NOW).unwrap();
            prop_assert_eq!(r.remote_ahead, ahead > SKEW_GUARD_MS);
            if r.remote_ahead {
                prop_assert_eq!(r.clock, clock);
            }
        }

        /// The guard with the local clock ahead of or behind the wall clock by up to 2 days: it
        /// fires exactly when the remote is more than 24 h ahead of the wall clock.
        #[test]
        fn skew_guard_ignores_the_local_clock(
            behind in any::<bool>(), skew in 0..2 * SKEW_GUARD_MS, c in counter(),
            ahead in 0..3 * SKEW_GUARD_MS, cm in counter()
        ) {
            let l = if behind { NOW - skew } else { NOW + skew };
            let clock = hlc(l, c);
            let r = clock.receive(hlc(NOW + ahead, cm), NOW).unwrap();
            prop_assert_eq!(r.remote_ahead, ahead > SKEW_GUARD_MS);
            if r.remote_ahead {
                prop_assert_eq!(r.clock, clock);
            }
        }

        /// Any sequence of fewer than 65,536 receipts at one wall-clock reading, from a clock
        /// not ahead of it, keeps the clock within `now + 24 h + 1` ms. Remotes are placed
        /// either relative to the wall clock or relative to the receiver's current clock, the
        /// second being how a hostile peer would try to ratchet it.
        #[test]
        fn receipts_at_one_wall_clock_stay_within_a_day(
            now in near_now(), back in 0u64..100_000, c in counter(),
            remotes in prop::collection::vec(
                (any::<bool>(), 0..2 * SKEW_GUARD_MS + 2, counter()), 1..64
            )
        ) {
            let bound = now + SKEW_GUARD_MS + 1;
            let mut clock = hlc(now - back, c);
            for (relative, offset, cm) in remotes {
                let base = if relative { clock.millis() } else { now };
                let remote = hlc(base + offset, cm);
                let r = clock.receive(remote, now).unwrap();
                prop_assert_eq!(r.remote_ahead, remote.millis() > now + SKEW_GUARD_MS);
                if r.remote_ahead {
                    prop_assert_eq!(r.clock, clock);
                }
                clock = r.clock;
                prop_assert!(clock.millis() <= bound);
            }
        }

        #[test]
        fn any_inputs_give_a_result_never_a_panic(
            raw in any::<u64>(), remote in any::<u64>(), now in any::<u64>()
        ) {
            let clock = Hlc::from_u64(raw);
            if let Ok(next) = clock.tick(now) {
                prop_assert!(next > clock);
            }
            let remote_hlc = Hlc::from_u64(remote);
            if let Ok(r) = clock.receive(remote_hlc, now) {
                // The guard measures from the wall clock only (ADR 0012 §2).
                let ahead = remote_hlc.millis() > now.saturating_add(SKEW_GUARD_MS);
                prop_assert_eq!(r.remote_ahead, ahead);
                if ahead {
                    prop_assert_eq!(r.clock, clock);
                } else {
                    prop_assert!(r.clock > clock && r.clock > remote_hlc);
                    // At most one past the larger of the clock and the adoptable maximum.
                    let limit = clock.millis().max(now + SKEW_GUARD_MS) + 1;
                    prop_assert!(r.clock.millis() <= limit);
                }
            }
            let h = Hlc::from_u64(raw);
            prop_assert_eq!(Hlc::from_parts(h.millis(), h.counter()), Some(h));
            prop_assert_eq!(Hlc::from_bytes(h.to_bytes()), h);
        }
    }
}
