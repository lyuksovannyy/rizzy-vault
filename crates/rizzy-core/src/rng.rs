//! Randomness (CRYPTO.md §5.1, §12.1; ADR 0009 "RNG rules").
//!
//! `rizzy-core` never reaches a randomness source itself. Every function that needs
//! randomness takes `&mut impl CryptoRng` (`rand_core` 0.10), supplied by a leaf crate: in
//! practice `rand_core::UnwrapErr(getrandom::SysRng)`, and in tests a seeded `ChaCha20Rng`
//! from the `chacha20` dev-dependency. `rand_core` 0.10's `CryptoRng` is
//! `TryCryptoRng<Error = Infallible>`: there is no error channel, and an OS RNG failure
//! aborts the process in the leaf crate (§12.1).
//!
//! opaque-ke 4.0.1 still takes a `rand_core` **0.6** RNG. [`OpaqueRng`] adapts the injected
//! 0.10 RNG to the 0.6 traits, written only against `opaque_ke::rand` (opaque-ke's re-export
//! of rand 0.8, which re-exports `rand_core` 0.6), so there is no separate `rand_core` 0.6 or
//! rand dependency. The adapter contains no cryptography: it forwards every call. No other
//! `rand_core` 0.6 use is allowed (§12.1).

use core::fmt;

pub use rand_core::CryptoRng;

/// Adapter from the injected `rand_core` 0.10 [`CryptoRng`] to the `rand_core` 0.6
/// `RngCore + CryptoRng` that opaque-ke 4.0.1 requires (CRYPTO.md §5.1).
///
/// It borrows the injected RNG for the duration of one opaque-ke call and forwards every
/// request unchanged, so opaque-ke draws exactly the bytes the injected RNG produces.
pub struct OpaqueRng<'a, R: CryptoRng + ?Sized> {
    inner: &'a mut R,
}

impl<'a, R: CryptoRng + ?Sized> OpaqueRng<'a, R> {
    /// Wraps the injected RNG.
    pub fn new(inner: &'a mut R) -> Self {
        Self { inner }
    }
}

impl<R: CryptoRng + ?Sized> fmt::Debug for OpaqueRng<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueRng")
    }
}

impl<R: CryptoRng + ?Sized> opaque_ke::rand::RngCore for OpaqueRng<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), opaque_ke::rand::Error> {
        // rand_core 0.10's `CryptoRng` is infallible (`Error = Infallible`), so this never
        // reports an error; a failing OS source aborts in the leaf crate instead.
        self.inner.fill_bytes(dest);
        Ok(())
    }
}

/// The injected RNG is a CSPRNG (`CryptoRng` in `rand_core` 0.10), so the adapter is one too.
impl<R: CryptoRng + ?Sized> opaque_ke::rand::CryptoRng for OpaqueRng<'_, R> {}

#[cfg(test)]
mod tests {
    use opaque_ke::rand::RngCore as RngCore06;
    use rand_core::Rng as _;

    use super::*;
    use crate::test_util::seeded_rng;

    fn assert_opaque_rng<T: opaque_ke::rand::RngCore + opaque_ke::rand::CryptoRng>(_: &T) {}

    #[test]
    fn adapter_forwards_the_injected_stream_unchanged() {
        let mut direct = seeded_rng(42);
        let mut expected = [0u8; 100];
        direct.fill_bytes(&mut expected[..37]);
        direct.fill_bytes(&mut expected[37..]);

        let mut injected = seeded_rng(42);
        let mut adapter = OpaqueRng::new(&mut injected);
        assert_opaque_rng(&adapter);
        let mut got = [0u8; 100];
        RngCore06::fill_bytes(&mut adapter, &mut got[..37]);
        adapter.try_fill_bytes(&mut got[37..]).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn adapter_forwards_integers() {
        let mut direct = seeded_rng(7);
        let (a, b) = (direct.next_u32(), direct.next_u64());
        let mut injected = seeded_rng(7);
        let mut adapter = OpaqueRng::new(&mut injected);
        assert_eq!(RngCore06::next_u32(&mut adapter), a);
        assert_eq!(RngCore06::next_u64(&mut adapter), b);
        assert_eq!(format!("{adapter:?}"), "OpaqueRng");
    }
}
