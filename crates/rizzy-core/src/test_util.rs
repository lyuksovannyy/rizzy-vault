//! Test helpers. Compiled only for `cfg(test)`.
//!
//! - [`seeded_rng`]: the deterministic RNG of CRYPTO.md §12.1 and §15 item 1, so every test
//!   and vector that draws randomness is reproducible from a seed. It is `chacha20`'s
//!   `ChaCha20Rng`, a dev-dependency only (ADR 0009); no release build contains it.
//! - [`FixedRng`]: an RNG that replays given bytes, for pinning the random input of an
//!   operation or simulating a broken RNG. Release code has no API that accepts a nonce
//!   (threat model INV-12); a test pins the nonce only by controlling the injected RNG.
//! - [`hex`]: hex decoding for fixtures.
//!
//! None of this is for release code: these RNGs are predictable by design.

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;

/// The deterministic test RNG named in ADR 0009: `chacha20`'s seeded `ChaCha20Rng`.
pub(crate) fn seeded_rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// A test RNG that returns the given bytes in order, cycling when they run out. Used to pin
/// the nonce of known-answer envelope vectors without any nonce-taking API (INV-12), and to
/// stand in for a broken RNG (a constant stream) in the generator's exhaustion test.
///
/// Unlike the vector generator's `ExactRng`, it does not check how many bytes were drawn.
/// `next_u32` and `next_u64` read the next bytes little-endian.
#[derive(Debug)]
pub(crate) struct FixedRng {
    /// The bytes to replay; never empty.
    bytes: Vec<u8>,
    /// How many bytes have been drawn so far; the next one is `bytes[pos % bytes.len()]`.
    pos: usize,
}

impl FixedRng {
    /// An RNG that replays `bytes`. Panics if `bytes` is empty.
    pub(crate) fn new(bytes: &[u8]) -> Self {
        assert!(!bytes.is_empty());
        Self {
            bytes: bytes.to_vec(),
            pos: 0,
        }
    }
}

// rand_core 0.10: implementing the fallible `TryRng` with an `Infallible` error, plus the
// `TryCryptoRng` marker, makes this usable wherever the crate takes `&mut impl CryptoRng`.
impl rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for d in dst {
            *d = self.bytes[self.pos % self.bytes.len()];
            self.pos += 1;
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FixedRng {}

/// Decodes a hex string, ignoring ASCII whitespace. Test vectors only.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => u8::MAX,
        })
        .collect();
    assert!(digits.len().is_multiple_of(2), "odd hex length");
    assert!(digits.iter().all(|d| *d < 16), "invalid hex digit");
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}
