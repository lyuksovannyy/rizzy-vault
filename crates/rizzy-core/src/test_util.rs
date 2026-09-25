//! Test helpers. Compiled only for `cfg(test)`.

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;

/// The deterministic test RNG named in ADR 0009: `chacha20`'s seeded `ChaCha20Rng`.
pub(crate) fn seeded_rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// A test RNG that returns the given bytes in order, cycling when they run out. Used to pin
/// the nonce of known-answer envelope vectors without any nonce-taking API (INV-12).
#[derive(Debug)]
pub(crate) struct FixedRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl FixedRng {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        assert!(!bytes.is_empty());
        Self {
            bytes: bytes.to_vec(),
            pos: 0,
        }
    }
}

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
