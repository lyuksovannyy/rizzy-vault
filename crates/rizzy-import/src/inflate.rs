//! A DEFLATE decoder (RFC 1951) and the CRC-32 of zip (ISO 3309, as in APPNOTE.TXT §4.4.7),
//! for the `export.data` member of a 1PUX archive. Neither is cryptography: DEFLATE is a
//! compression format and CRC-32 an error-detecting code, and nothing here protects a secret
//! or decides trust.
//!
//! **Why here.** A crates.io inflater (`miniz_oxide`) would add external crates to this no-I/O
//! crate's allow-list (ADR 0016 R1) and would grow its output buffer as it goes, leaving copies
//! of the decompressed passwords in freed memory. This decoder writes into one zeroizing buffer
//! allocated at the size the archive declares and never grows it (CRYPTO.md §12.2).
//!
//! **The decoder** follows the structure of Mark Adler's `puff.c`, the reference decoder
//! distributed with zlib: canonical Huffman codes rebuilt from code lengths, decoded one bit
//! at a time. It is slow next to a table-driven inflater, and simple enough to review.
//!
//! **Bounds** (threat model A16, "zip bombs"). Output stops with [`ImportError::TooLarge`] as
//! soon as it would pass the expected size, so a stream cannot expand past what the caller
//! allocated. Work is linear in the input: the fixed codes are built once per stream, and a
//! dynamic block costs a bounded amount beyond the bits it reads. The caller bounds the input
//! by the declared output size ([`crate::zip::extract`]), so a stream of empty blocks cannot
//! run long. Every read is bounds-checked; an over-subscribed or incomplete code, a
//! distance before the start of the output, a reserved block type or a truncated stream is
//! [`ImportError::Malformed`]. The decoder never panics.

use zeroize::Zeroizing;

use crate::error::ImportError;

/// Longest Huffman code, in bits.
const MAX_BITS: usize = 15;
/// Literal/length symbols (286 usable, 288 in the fixed code).
const MAX_LCODES: usize = 288;
/// Distance symbols (30 usable, 30 in the fixed code).
const MAX_DCODES: usize = 30;

/// Base length of length symbols 257–285.
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
/// Extra bits of length symbols 257–285.
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// Base distance of distance symbols 0–29.
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
/// Extra bits of distance symbols 0–29.
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// The order in which code-length code lengths are sent (RFC 1951 §3.2.7).
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Decompresses a raw DEFLATE stream whose output must be exactly `expected_len` bytes, into a
/// zeroizing buffer allocated once at that size. Bytes after the final block are ignored.
///
/// # Errors
/// [`ImportError::TooLarge`] if the output would pass `expected_len`, and
/// [`ImportError::Malformed`] for an invalid or truncated stream or a shorter output.
pub fn inflate(input: &[u8], expected_len: usize) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let mut state = State {
        input,
        pos: 0,
        bit_buf: 0,
        bit_count: 0,
        out: Zeroizing::new(Vec::with_capacity(expected_len)),
        limit: expected_len,
        fixed_codes: None,
    };
    loop {
        let last = state.bits(1)?;
        match state.bits(2)? {
            0 => state.stored()?,
            1 => state.fixed()?,
            2 => state.dynamic()?,
            _ => return Err(ImportError::Malformed),
        }
        if last == 1 {
            break;
        }
    }
    if state.out.len() == expected_len {
        Ok(state.out)
    } else {
        Err(ImportError::Malformed)
    }
}

/// A canonical Huffman code: how many codes of each length, and the symbols ordered by code.
struct Huffman {
    /// `count[len]`: the number of codes of length `len` (index 0 unused).
    count: [u16; MAX_BITS + 1],
    /// The symbols, in canonical code order.
    symbol: [u16; MAX_LCODES],
}

impl Huffman {
    /// Builds the code for `lengths`. Returns it and how many codes are left unused: 0 for a
    /// complete code, more for an incomplete one.
    ///
    /// # Errors
    /// [`ImportError::Malformed`] for an over-subscribed code or a length above 15.
    fn new(lengths: &[u8]) -> Result<(Self, i32), ImportError> {
        let mut h = Self {
            count: [0; MAX_BITS + 1],
            symbol: [0; MAX_LCODES],
        };
        for &len in lengths {
            let slot = h
                .count
                .get_mut(usize::from(len))
                .ok_or(ImportError::Malformed)?;
            *slot += 1;
        }
        let n = u16::try_from(lengths.len()).map_err(|_| ImportError::Malformed)?;
        if h.count.first().copied() == Some(n) {
            // No codes at all: complete, and any decode fails.
            return Ok((h, 0));
        }
        let mut left: i32 = 1;
        for len in 1..=MAX_BITS {
            left <<= 1;
            left -= i32::from(h.count.get(len).copied().unwrap_or(0));
            if left < 0 {
                return Err(ImportError::Malformed);
            }
        }
        let mut offs = [0u16; MAX_BITS + 1];
        for len in 1..MAX_BITS {
            let next = offs.get(len).copied().unwrap_or(0) + h.count.get(len).copied().unwrap_or(0);
            if let Some(slot) = offs.get_mut(len + 1) {
                *slot = next;
            }
        }
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let off = offs
                .get_mut(usize::from(len))
                .ok_or(ImportError::Malformed)?;
            let slot = h
                .symbol
                .get_mut(usize::from(*off))
                .ok_or(ImportError::Malformed)?;
            *slot = u16::try_from(symbol).map_err(|_| ImportError::Malformed)?;
            *off += 1;
        }
        Ok((h, left))
    }
}

/// Builds the fixed literal/length and distance codes of RFC 1951 §3.2.6.
fn fixed_codes() -> Result<(Huffman, Huffman), ImportError> {
    let mut lengths = [0u8; MAX_LCODES];
    for (symbol, len) in lengths.iter_mut().enumerate() {
        *len = match symbol {
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let (lencode, _) = Huffman::new(&lengths)?;
    let (distcode, _) = Huffman::new(&[5u8; MAX_DCODES])?;
    Ok((lencode, distcode))
}

/// The decoder's state.
struct State<'a> {
    /// The compressed stream.
    input: &'a [u8],
    /// The next input byte.
    pos: usize,
    /// Bits read but not used, least significant first.
    bit_buf: u32,
    /// How many bits `bit_buf` holds.
    bit_count: u32,
    /// The output, allocated at `limit`.
    out: Zeroizing<Vec<u8>>,
    /// The expected output size, never passed.
    limit: usize,
    /// The fixed codes of RFC 1951 §3.2.6, built at the first fixed block and kept, so a
    /// stream of empty fixed blocks (10 bits each) does not rebuild them at every block.
    fixed_codes: Option<(Huffman, Huffman)>,
}

impl State<'_> {
    /// Reads `need` bits (at most 16), least significant first.
    fn bits(&mut self, need: u32) -> Result<u32, ImportError> {
        while self.bit_count < need {
            let byte = self.input.get(self.pos).ok_or(ImportError::Malformed)?;
            self.pos += 1;
            self.bit_buf |= u32::from(*byte) << self.bit_count;
            self.bit_count += 8;
        }
        let value = self.bit_buf & ((1u32 << need) - 1);
        self.bit_buf >>= need;
        self.bit_count -= need;
        Ok(value)
    }

    /// Appends one output byte, unless the output is full.
    fn put(&mut self, byte: u8) -> Result<(), ImportError> {
        if self.out.len() >= self.limit {
            return Err(ImportError::TooLarge);
        }
        self.out.push(byte);
        Ok(())
    }

    /// A stored block: byte-aligned `LEN`, `NLEN`, then `LEN` bytes.
    fn stored(&mut self) -> Result<(), ImportError> {
        // Drop the rest of the current byte.
        self.bit_buf = 0;
        self.bit_count = 0;
        let header = self
            .input
            .get(self.pos..self.pos.saturating_add(4))
            .ok_or(ImportError::Malformed)?;
        let [a, b, c, d] = <[u8; 4]>::try_from(header).map_err(|_| ImportError::Malformed)?;
        let len = u16::from_le_bytes([a, b]);
        if len != !u16::from_le_bytes([c, d]) {
            return Err(ImportError::Malformed);
        }
        self.pos += 4;
        let len = usize::from(len);
        let body = self
            .input
            .get(self.pos..self.pos.saturating_add(len))
            .ok_or(ImportError::Malformed)?;
        if self.out.len().saturating_add(len) > self.limit {
            return Err(ImportError::TooLarge);
        }
        self.out.extend_from_slice(body);
        self.pos += len;
        Ok(())
    }

    /// Decodes one symbol of `h`, one bit at a time (canonical codes are sent most
    /// significant bit first).
    fn decode(&mut self, h: &Huffman) -> Result<usize, ImportError> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=MAX_BITS {
            code |= i32::try_from(self.bits(1)?).map_err(|_| ImportError::Malformed)?;
            let count = i32::from(h.count.get(len).copied().unwrap_or(0));
            if code - count < first {
                let at =
                    usize::try_from(index + (code - first)).map_err(|_| ImportError::Malformed)?;
                return h
                    .symbol
                    .get(at)
                    .map(|s| usize::from(*s))
                    .ok_or(ImportError::Malformed);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(ImportError::Malformed)
    }

    /// Decodes literals and matches until the end-of-block symbol.
    fn codes(&mut self, lencode: &Huffman, distcode: &Huffman) -> Result<(), ImportError> {
        loop {
            let symbol = self.decode(lencode)?;
            if symbol < 256 {
                self.put(u8::try_from(symbol).map_err(|_| ImportError::Malformed)?)?;
                continue;
            }
            if symbol == 256 {
                return Ok(());
            }
            let index = symbol - 257;
            let base = LENGTH_BASE.get(index).ok_or(ImportError::Malformed)?;
            let extra = LENGTH_EXTRA.get(index).ok_or(ImportError::Malformed)?;
            let len = usize::from(*base)
                + usize::try_from(self.bits(u32::from(*extra))?)
                    .map_err(|_| ImportError::Malformed)?;
            let dsym = self.decode(distcode)?;
            let dbase = DIST_BASE.get(dsym).ok_or(ImportError::Malformed)?;
            let dextra = DIST_EXTRA.get(dsym).ok_or(ImportError::Malformed)?;
            let dist = usize::from(*dbase)
                + usize::try_from(self.bits(u32::from(*dextra))?)
                    .map_err(|_| ImportError::Malformed)?;
            if dist > self.out.len() {
                return Err(ImportError::Malformed);
            }
            if self.out.len().saturating_add(len) > self.limit {
                return Err(ImportError::TooLarge);
            }
            for _ in 0..len {
                let from = self.out.len() - dist;
                let byte = *self.out.get(from).ok_or(ImportError::Malformed)?;
                self.out.push(byte);
            }
        }
    }

    /// A block with the fixed codes of RFC 1951 §3.2.6.
    fn fixed(&mut self) -> Result<(), ImportError> {
        let codes = self.fixed_codes.take().map_or_else(fixed_codes, Ok)?;
        let result = self.codes(&codes.0, &codes.1);
        self.fixed_codes = Some(codes);
        result
    }

    /// A block with dynamic codes (RFC 1951 §3.2.7).
    fn dynamic(&mut self) -> Result<(), ImportError> {
        let nlen = usize::try_from(self.bits(5)?).map_err(|_| ImportError::Malformed)? + 257;
        let ndist = usize::try_from(self.bits(5)?).map_err(|_| ImportError::Malformed)? + 1;
        let ncode = usize::try_from(self.bits(4)?).map_err(|_| ImportError::Malformed)? + 4;
        if nlen > 286 || ndist > MAX_DCODES {
            return Err(ImportError::Malformed);
        }
        let mut clens = [0u8; 19];
        for &at in CLEN_ORDER.iter().take(ncode) {
            let slot = clens.get_mut(at).ok_or(ImportError::Malformed)?;
            *slot = u8::try_from(self.bits(3)?).map_err(|_| ImportError::Malformed)?;
        }
        let (clencode, left) = Huffman::new(&clens)?;
        if left != 0 {
            return Err(ImportError::Malformed);
        }
        let mut lengths = [0u8; MAX_LCODES + MAX_DCODES];
        let total = nlen + ndist;
        let mut index = 0;
        while index < total {
            let symbol = self.decode(&clencode)?;
            let (value, repeat) = match symbol {
                0..=15 => (u8::try_from(symbol).map_err(|_| ImportError::Malformed)?, 1),
                16 => {
                    let prev = index
                        .checked_sub(1)
                        .and_then(|i| lengths.get(i))
                        .copied()
                        .ok_or(ImportError::Malformed)?;
                    (prev, 3 + self.bits(2)?)
                }
                17 => (0, 3 + self.bits(3)?),
                18 => (0, 11 + self.bits(7)?),
                _ => return Err(ImportError::Malformed),
            };
            let repeat = usize::try_from(repeat).map_err(|_| ImportError::Malformed)?;
            if index + repeat > total {
                return Err(ImportError::Malformed);
            }
            for _ in 0..repeat {
                let slot = lengths.get_mut(index).ok_or(ImportError::Malformed)?;
                *slot = value;
                index += 1;
            }
        }
        let lit = lengths.get(..nlen).ok_or(ImportError::Malformed)?;
        // The end-of-block symbol must have a code.
        if lit.get(256).copied().unwrap_or(0) == 0 {
            return Err(ImportError::Malformed);
        }
        let (lencode, left) = Huffman::new(lit)?;
        // An incomplete code is allowed only when it has a single code.
        if left > 0 && nlen - usize::from(lencode.count.first().copied().unwrap_or(0)) != 1 {
            return Err(ImportError::Malformed);
        }
        let dist = lengths.get(nlen..total).ok_or(ImportError::Malformed)?;
        let (distcode, left) = Huffman::new(dist)?;
        if left > 0 && ndist - usize::from(distcode.count.first().copied().unwrap_or(0)) != 1 {
            return Err(ImportError::Malformed);
        }
        self.codes(&lencode, &distcode)
    }
}

/// The CRC-32 table of the reflected polynomial `0xEDB88320`, built at compile time.
#[expect(
    clippy::indexing_slicing,
    reason = "evaluated at compile time with n < 256 as the loop bound; an out-of-range index would fail the build, not panic at run time"
)]
const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        #[expect(clippy::cast_possible_truncation, reason = "n < 256, so it fits a u32")]
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
};

/// The CRC-32 of `data`, as zip stores it.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let index = usize::from(u8::try_from((crc ^ u32::from(b)) & 0xFF).unwrap_or(0));
        crc = CRC_TABLE.get(index).copied().unwrap_or(0) ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Writes bits least significant first, as DEFLATE packs them.
    #[derive(Default)]
    struct BitWriter {
        /// Finished bytes.
        out: Vec<u8>,
        /// Pending bits.
        buf: u64,
        /// How many bits are pending.
        count: u32,
    }

    impl BitWriter {
        /// Appends the `n` low bits of `value`.
        fn bits(&mut self, value: u32, n: u32) {
            self.buf |= u64::from(value) << self.count;
            self.count += n;
            while self.count >= 8 {
                self.out.push(u8::try_from(self.buf & 0xFF).unwrap());
                self.buf >>= 8;
                self.count -= 8;
            }
        }

        /// Appends a Huffman code, most significant bit first.
        fn code(&mut self, code: u32, len: u32) {
            for i in (0..len).rev() {
                self.bits((code >> i) & 1, 1);
            }
        }

        /// Pads to a byte boundary and returns the bytes.
        fn finish(mut self) -> Vec<u8> {
            if self.count > 0 {
                self.bits(0, 8 - self.count);
            }
            self.out
        }
    }

    /// Canonical codes for `lengths` (RFC 1951 §3.2.2).
    fn canonical(lengths: &[u8]) -> Vec<u32> {
        let mut bl_count = [0u32; 16];
        for &l in lengths {
            if l > 0 {
                bl_count[usize::from(l)] += 1;
            }
        }
        let mut next = [0u32; 16];
        let mut code = 0;
        for bits in 1..16 {
            code = (code + bl_count[bits - 1]) << 1;
            next[bits] = code;
        }
        lengths
            .iter()
            .map(|&l| {
                if l == 0 {
                    0
                } else {
                    let c = next[usize::from(l)];
                    next[usize::from(l)] += 1;
                    c
                }
            })
            .collect()
    }

    /// The fixed literal/length code lengths.
    fn fixed_lengths() -> Vec<u8> {
        (0..288)
            .map(|s| match s {
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            })
            .collect()
    }

    /// A test-only compressor: a fixed-code block (`dynamic` false) or a dynamic block whose
    /// complete codes are sent explicitly, with greedy matches of up to 258 bytes found by a
    /// naive search, so both code paths and back-references are exercised.
    pub(crate) fn deflate(data: &[u8], dynamic: bool) -> Vec<u8> {
        let mut w = BitWriter::default();
        w.bits(1, 1);
        let (lit_lengths, dist_lengths): (Vec<u8>, Vec<u8>) = if dynamic {
            w.bits(2, 2);
            // Literals 9 bits, symbols 256-257 5 bits, 258-285 6 bits: a complete code.
            let lit: Vec<u8> = (0..286)
                .map(|s| match s {
                    0..=255 => 9,
                    256 | 257 => 5,
                    _ => 6,
                })
                .collect();
            // Distances 0-1 4 bits, 2-29 5 bits: complete.
            let dist: Vec<u8> = (0..30).map(|s| if s < 2 { 4 } else { 5 }).collect();
            w.bits(286 - 257, 5);
            w.bits(30 - 1, 5);
            // Code-length code: lengths 4, 5, 6, 9 each 2 bits; HCLEN covers up to symbol 4
            // in CLEN_ORDER (index 11).
            let mut clens = [0u8; 19];
            for s in [4usize, 5, 6, 9] {
                clens[s] = 2;
            }
            w.bits(12 - 4, 4);
            for &at in CLEN_ORDER.iter().take(12) {
                w.bits(u32::from(clens[at]), 3);
            }
            let clcodes = canonical(&clens);
            for &l in lit.iter().chain(dist.iter()) {
                w.code(clcodes[usize::from(l)], 2);
            }
            (lit, dist)
        } else {
            w.bits(1, 2);
            (fixed_lengths(), vec![5; 30])
        };
        let lit_codes = canonical(&lit_lengths);
        let dist_codes = canonical(&dist_lengths);
        let mut i = 0;
        while i < data.len() {
            // Longest match within 32 KiB, at least 3 bytes.
            let mut best = (0, 0);
            let start = i.saturating_sub(32_768);
            for j in (start..i).rev() {
                let mut l = 0;
                while l < 258 && i + l < data.len() && data[j + l] == data[i + l] {
                    l += 1;
                }
                if l > best.0 {
                    best = (l, i - j);
                }
                if best.0 == 258 {
                    break;
                }
            }
            if best.0 >= 3 {
                let (len, dist) = best;
                let li = LENGTH_BASE
                    .iter()
                    .rposition(|&b| usize::from(b) <= len)
                    .unwrap();
                let sym = 257 + li;
                w.code(lit_codes[sym], u32::from(lit_lengths[sym]));
                w.bits(
                    u32::try_from(len - usize::from(LENGTH_BASE[li])).unwrap(),
                    u32::from(LENGTH_EXTRA[li]),
                );
                let di = DIST_BASE
                    .iter()
                    .rposition(|&b| usize::from(b) <= dist)
                    .unwrap();
                w.code(dist_codes[di], u32::from(dist_lengths[di]));
                w.bits(
                    u32::try_from(dist - usize::from(DIST_BASE[di])).unwrap(),
                    u32::from(DIST_EXTRA[di]),
                );
                i += len;
            } else {
                let sym = usize::from(data[i]);
                w.code(lit_codes[sym], u32::from(lit_lengths[sym]));
                i += 1;
            }
        }
        w.code(lit_codes[256], u32::from(lit_lengths[256]));
        w.finish()
    }

    /// One stored block holding `data` (at most 65,535 bytes).
    pub(crate) fn stored(data: &[u8]) -> Vec<u8> {
        let len = u16::try_from(data.len()).unwrap();
        let mut out = vec![1];
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn known_fixed_stream() {
        // "a", fixed codes, derived by hand from RFC 1951 §3.2.6.
        assert_eq!(inflate(&[0x4b, 0x04, 0x00], 1).unwrap().as_slice(), b"a");
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn stored_and_sizes() {
        let data = b"hello, stored world";
        assert_eq!(inflate(&stored(data), data.len()).unwrap().as_slice(), data);
        assert_eq!(
            inflate(&stored(data), data.len() - 1).unwrap_err(),
            ImportError::TooLarge
        );
        assert_eq!(
            inflate(&stored(data), data.len() + 1).unwrap_err(),
            ImportError::Malformed
        );
        let mut bad = stored(data);
        bad[3] ^= 1;
        assert_eq!(
            inflate(&bad, data.len()).unwrap_err(),
            ImportError::Malformed
        );
        assert_eq!(
            inflate(&stored(data)[..10], data.len()).unwrap_err(),
            ImportError::Malformed
        );
    }

    #[test]
    fn rejects() {
        // Reserved block type 3.
        assert_eq!(inflate(&[0x07], 0).unwrap_err(), ImportError::Malformed);
        assert_eq!(inflate(&[], 0).unwrap_err(), ImportError::Malformed);
        // A match before the start of the output: fixed block, length symbol 257, distance 0.
        let mut w = BitWriter::default();
        w.bits(1, 1);
        w.bits(1, 2);
        let codes = canonical(&fixed_lengths());
        w.code(codes[257], 7);
        w.code(0, 5);
        w.code(codes[256], 7);
        assert_eq!(inflate(&w.finish(), 3).unwrap_err(), ImportError::Malformed);
    }

    #[test]
    fn bomb_is_capped() {
        let data = vec![0u8; 100_000];
        let packed = deflate(&data, false);
        assert!(packed.len() < 2_000);
        assert_eq!(inflate(&packed, 1_000).unwrap_err(), ImportError::TooLarge);
        assert_eq!(
            inflate(&packed, data.len()).unwrap().as_slice(),
            data.as_slice()
        );
    }

    proptest! {
        #[test]
        fn round_trip(data in prop::collection::vec(0u8..4, 0..600), dynamic: bool) {
            let packed = deflate(&data, dynamic);
            let out = inflate(&packed, data.len()).unwrap();
            prop_assert_eq!(out.as_slice(), data.as_slice());
        }

        #[test]
        fn never_panics(data in prop::collection::vec(any::<u8>(), 0..200), len in 0usize..500) {
            let _ = inflate(&data, len);
        }
    }
}
