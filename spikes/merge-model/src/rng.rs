//! Deterministic xorshift64 RNG for the seeded explorer (ADR 0012 §12 "a deterministic scheduler
//! and a seeded RNG drive everything").

#[derive(Clone, Debug)]
pub struct XorShift(u64);

impl XorShift {
    pub fn new(seed: u64) -> Self {
        // Mix the seed so that small consecutive seeds give unrelated streams; never zero.
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03;
        if s == 0 {
            s = 1;
        }
        let mut r = XorShift(s);
        for _ in 0..4 {
            r.next_u64();
        }
        r
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform-ish in `0..n` (n > 0).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % (n as u64)) as usize
    }

    pub fn chance(&mut self, percent: u64) -> bool {
        self.next_u64() % 100 < percent
    }

    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i + 1);
            v.swap(i, j);
        }
    }
}
