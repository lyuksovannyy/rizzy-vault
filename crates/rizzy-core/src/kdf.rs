//! Key derivation: the `kdf_id` table (CRYPTO.md §6), Argon2id (§2, §12.2), password
//! normalisation (§2, ADR 0004) and the crate-private HKDF-SHA-256 helper (§2, §4.3).
//!
//! **The client decides; the server only names** (§1 rule 5, §6.2). The Argon2id parameters are
//! compiled in. A [`KdfId`] can only be built from an id on [`CLIENT_ALLOW_LIST`] whose table
//! entry is enabled, and no function here builds Argon2 parameters from anything else. An
//! unknown or disallowed `kdf_id` is a hard error ([`KdfError::NotAllowed`]), never a fallback.
//!
//! **Memory.** argon2 0.6.0 is built without its `alloc` feature, so its non-wiping
//! `hash_password_into` does not exist in this build. [`argon2id`] allocates the block matrix
//! once, at its final size, in a `Zeroizing<Vec<argon2::Block>>` and passes it to
//! `hash_password_into_with_memory`; the matrix is wiped when the call returns (§12.2).

use argon2::{Algorithm, Argon2, Block, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization as _;
use unicode_normalization::char::is_public_assigned;
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::{DerivationError, KdfError};
use crate::labels::Label;
use crate::secret::SecretBytes;

/// Argon2id cost parameters, as RFC 9106 names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Argon2Params {
    /// Memory `m`, in KiB.
    pub m_kib: u32,
    /// Passes `t`.
    pub t: u32,
    /// Lanes `p`.
    pub p: u32,
}

/// Status of a `kdf_id` in the compiled table (CRYPTO.md §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KdfStatus {
    /// Never valid (`kdf_id` 0).
    Invalid,
    /// Enabled: may be used, if it is also on the client allow-list.
    Enabled,
    /// Reserved, not enabled. Enabling it is a release that changes this table.
    Reserved,
}

/// One row of the `kdf_id` table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KdfEntry {
    /// The id the server and the file formats name.
    pub kdf_id: u16,
    /// Whether the id is usable.
    pub status: KdfStatus,
    /// Argon2id v0x13 parameters, or `None` for the invalid id.
    pub params: Option<Argon2Params>,
}

/// The compiled `kdf_id` table (CRYPTO.md §6.1). Every id not listed is invalid.
pub const KDF_TABLE: &[KdfEntry] = &[
    KdfEntry {
        kdf_id: 0,
        status: KdfStatus::Invalid,
        params: None,
    },
    // M1 default and floor: RFC 9106's second recommended option.
    KdfEntry {
        kdf_id: 1,
        status: KdfStatus::Enabled,
        params: Some(Argon2Params {
            m_kib: 65_536,
            t: 3,
            p: 4,
        }),
    },
    // Reserved, not enabled: needs evidence that every client, including iOS AutoFill, can run it.
    KdfEntry {
        kdf_id: 2,
        status: KdfStatus::Reserved,
        params: Some(Argon2Params {
            m_kib: 262_144,
            t: 3,
            p: 4,
        }),
    },
];

/// The ids this client accepts (CRYPTO.md §6.2). M1 accepts only `{1}`.
pub const CLIENT_ALLOW_LIST: &[u16] = &[1];

/// The floor every enabled table entry must meet (CRYPTO.md §6.2): `m ≥ 65 536 KiB`, `t ≥ 3`,
/// `p = 4`. A unit test checks the table against it, so the floor is a CI-checked invariant.
pub const FLOOR: Argon2Params = Argon2Params {
    m_kib: 65_536,
    t: 3,
    p: 4,
};

/// Length of every Argon2id salt in CRYPTO.md (§6.1): 16 zero bytes for the OPAQUE KSF, a
/// random 16-byte `device_salt`, `export_salt` or `backup_salt`, or the 16-byte `share_id`.
pub const SALT_LEN: usize = 16;

/// Output length of Argon2id outside OPAQUE (§6.1).
pub const OUTPUT_LEN: usize = 32;

/// Output length of Argon2id as the OPAQUE KSF: Nh for SHA-512 (§6.1).
pub const KSF_OUTPUT_LEN: usize = 64;

/// A `kdf_id` on this client's allow-list, with its compiled parameters.
///
/// The only constructors are [`KdfId::from_u16`], which checks the allow-list and the table,
/// and [`KdfId::DEFAULT`]. Holding a `KdfId` is proof the id was checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KdfId {
    id: u16,
    params: Argon2Params,
}

impl KdfId {
    /// `kdf_id` 1: Argon2id v0x13, 64 MiB, t = 3, p = 4. The M1 default for new accounts,
    /// exports and backups.
    pub const DEFAULT: Self = Self {
        id: 1,
        params: FLOOR,
    };

    /// Checks a `kdf_id` named by the server, a file or local state.
    ///
    /// # Errors
    /// [`KdfError::NotAllowed`] unless the id is on [`CLIENT_ALLOW_LIST`] and enabled in
    /// [`KDF_TABLE`]. This covers `0`, the reserved `2` and every unknown id.
    pub fn from_u16(kdf_id: u16) -> Result<Self, KdfError> {
        let not_allowed = KdfError::NotAllowed { kdf_id };
        if !CLIENT_ALLOW_LIST.contains(&kdf_id) {
            return Err(not_allowed);
        }
        let entry = KDF_TABLE
            .iter()
            .find(|e| e.kdf_id == kdf_id)
            .ok_or(not_allowed)?;
        match (entry.status, entry.params) {
            (KdfStatus::Enabled, Some(params)) => Ok(Self { id: kdf_id, params }),
            _ => Err(not_allowed),
        }
    }

    /// The id as it is encoded: `u16(kdf_id)`.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.id
    }

    /// The compiled Argon2id parameters.
    #[must_use]
    pub const fn params(self) -> Argon2Params {
        self.params
    }
}

#[cfg(test)]
impl KdfId {
    /// Test only: a cheap Argon2id profile (32 KiB, `t` passes, p = 4) under an id no client
    /// allow-list contains, so tests of the OPAQUE wrapper and the file keys can run many KSF
    /// calls, and can give two sides different `kdf_id`s (with different or equal parameters).
    /// It does not exist outside `cfg(test)`.
    pub(crate) const fn test_cheap(id: u16, t: u32) -> Self {
        Self {
            id,
            params: Argon2Params { m_kib: 32, t, p: 4 },
        }
    }
}

/// `Argon2id(P, S, kdf_id, T)` from CRYPTO.md §2: Argon2id version 0x13 with the parameters of
/// `kdf_id`, no secret value `K` and no associated data `X`, writing the `T = out.len()` byte
/// tag into `out`.
///
/// `out` must be 32 bytes ([`OUTPUT_LEN`]) or 64 bytes ([`KSF_OUTPUT_LEN`], the OPAQUE KSF);
/// CRYPTO.md §6.1 uses no other length. The block matrix is allocated once and wiped on return.
///
/// # Errors
/// [`KdfError::InvalidOutputLength`] for any other `out` length; [`KdfError::InvalidInput`] if
/// argon2 rejects the password (longer than `u32::MAX` bytes).
pub fn argon2id(
    kdf_id: KdfId,
    password: &[u8],
    salt: &[u8; SALT_LEN],
    out: &mut [u8],
) -> Result<(), KdfError> {
    if out.len() != OUTPUT_LEN && out.len() != KSF_OUTPUT_LEN {
        return Err(KdfError::InvalidOutputLength);
    }
    let argon = argon2id_context(kdf_id.params(), out.len())?;
    let mut memory = new_block_memory(&argon);
    let result = argon
        .hash_password_into_with_memory(password, salt, out, memory.as_mut_slice())
        .map_err(|_| KdfError::InvalidInput);
    wipe_block_memory(memory);
    result
}

/// Wipes the block matrix before it is freed. Every block is wiped in place first, keeping the
/// length, so that the test-only hook can inspect the wiped matrix (CRYPTO.md §15 item 9).
/// Dropping the `Zeroizing` wrapper then runs `Vec::zeroize`, which wipes the blocks again,
/// clears the vector and wipes its spare capacity.
fn wipe_block_memory(mut memory: Zeroizing<Vec<Block>>) {
    #[cfg(test)]
    let held_data = crate::secret::wipe_hooks::capturing()
        && memory
            .iter()
            .any(|block| block.as_ref().iter().any(|word| *word != 0));
    memory.iter_mut().zeroize();
    #[cfg(test)]
    crate::secret::wipe_hooks::observe(
        "argon2 blocks",
        memory.len() * core::mem::size_of::<Block>(),
        held_data,
        memory
            .iter()
            .all(|block| block.as_ref().iter().all(|word| *word == 0)),
    );
}

fn argon2id_context(params: Argon2Params, out_len: usize) -> Result<Argon2<'static>, KdfError> {
    let params = argon2::Params::new(params.m_kib, params.t, params.p, Some(out_len))
        .map_err(|_| KdfError::Internal)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// The Argon2 block matrix, allocated once at its final size and wiped on drop.
fn new_block_memory(argon: &Argon2<'_>) -> Zeroizing<Vec<Block>> {
    Zeroizing::new(vec![Block::new(); argon.params().block_count()])
}

/// `UTF-8(NFC(password))` (CRYPTO.md §2): Unicode Normalization Form C, then UTF-8. No trimming
/// and no case folding. Used for master passwords, export passwords, share passphrases and the
/// server-secrets backup passphrase.
///
/// The output buffer is allocated once at its exact final size. Limit: the normalisation
/// iterator of `unicode-normalization` buffers characters internally and does not wipe them,
/// like the other upstream limits listed in CRYPTO.md §12.2.
///
/// # Errors
/// [`KdfError::InvalidInput`] if the normalised length overflows `usize`.
pub fn normalize_password(password: &str) -> Result<SecretBytes, KdfError> {
    nfc_utf8(password).map(SecretBytes::from_vec)
}

fn nfc_utf8(text: &str) -> Result<Vec<u8>, KdfError> {
    // First pass: the exact output length, so the buffer never reallocates. NFC can expand
    // text (for example U+0344 becomes U+0308 U+0301), so the input length is not enough.
    let len = text
        .nfc()
        .try_fold(0usize, |acc, c| acc.checked_add(c.len_utf8()))
        .ok_or(KdfError::InvalidInput)?;
    let mut out = Vec::with_capacity(len);
    let mut buf = [0u8; 4];
    for c in text.nfc() {
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    buf.zeroize();
    Ok(out)
}

/// Rejects a newly chosen password that contains a code point unassigned in the pinned Unicode
/// tables (ADR 0004 owner decision 3, CRYPTO.md §16 question 4).
///
/// Why: once a later Unicode version assigns such a code point, `NFC(password)` can change,
/// and the password would stop working. Call this when a user sets a new master password;
/// CRYPTO.md recommends it for every newly chosen password (export password, share passphrase)
/// for the same reason. Never call it on a password that already exists (login, unlock,
/// import): that could lock a user out after a table update.
///
/// "Assigned" means `General_Category ≠ Cn` in the Unicode version of the pinned
/// `unicode-normalization` (17.0.0 for 0.1.25). Private-use code points are assigned (`Co`)
/// and their normalisation is stable by Unicode policy, so they are accepted. Noncharacters
/// (for example U+FFFF) are `Cn` and rejected.
///
/// Every character is checked, with no early exit.
///
/// # Errors
/// [`KdfError::UnassignedCodePoint`].
pub fn check_new_password(password: &str) -> Result<(), KdfError> {
    let all_assigned = password.chars().fold(true, |ok, c| {
        ok & (is_public_assigned(c) | is_private_use(c))
    });
    if all_assigned {
        Ok(())
    } else {
        Err(KdfError::UnassignedCodePoint)
    }
}

/// The three private-use areas. Fixed by the Unicode stability policy.
const fn is_private_use(c: char) -> bool {
    matches!(c, '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{FFFFD}' | '\u{100000}'..='\u{10FFFD}')
}

/// `HKDF(ikm, salt, info = LABEL(x) ‖ 0x00 ‖ ctx, L)` with HKDF-SHA-256 (CRYPTO.md §2), writing
/// `L = okm.len()` bytes into `okm`.
///
/// `salt = None` and an empty salt both mean `HashLen` zero bytes, as in RFC 5869. Crate-private:
/// raw HKDF never appears in the public API (ADR 0009, "One entry point per construction").
/// Limit: hkdf 0.13 does not wipe its internal PRK and expand blocks (CRYPTO.md §12.2).
///
/// # Errors
/// [`DerivationError`] if `okm` is empty or longer than 255 × 32 bytes.
pub(crate) fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    label: Label,
    ctx: &[u8],
    okm: &mut [u8],
) -> Result<(), DerivationError> {
    hkdf_sha256_raw(ikm, salt, &[label.as_bytes(), &[0x00], ctx], okm)
}

/// HKDF-SHA-256 with `info` given as parts that are concatenated. Only [`hkdf_sha256`] and the
/// RFC 5869 tests call it.
fn hkdf_sha256_raw(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[&[u8]],
    okm: &mut [u8],
) -> Result<(), DerivationError> {
    if okm.is_empty() {
        return Err(DerivationError);
    }
    let salt = salt.filter(|s| !s.is_empty());
    Hkdf::<Sha256>::new(salt, ikm)
        .expand_multi_info(info, okm)
        .map_err(|_| DerivationError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels;
    use crate::test_util::hex;

    // ---- §6.2: the CI-checked floor and the allow-list ----

    #[test]
    fn every_enabled_table_entry_meets_the_floor() {
        let enabled: Vec<_> = KDF_TABLE
            .iter()
            .filter(|e| e.status == KdfStatus::Enabled)
            .collect();
        assert!(!enabled.is_empty());
        for entry in enabled {
            let p = entry.params.unwrap();
            assert!(
                p.m_kib >= FLOOR.m_kib,
                "kdf_id {}: m below floor",
                entry.kdf_id
            );
            assert!(p.t >= FLOOR.t, "kdf_id {}: t below floor", entry.kdf_id);
            assert_eq!(p.p, FLOOR.p, "kdf_id {}: p must be 4", entry.kdf_id);
        }
    }

    #[test]
    fn table_matches_crypto_md_6_1() {
        let ids: Vec<u16> = KDF_TABLE.iter().map(|e| e.kdf_id).collect();
        assert_eq!(ids, [0, 1, 2]);
        assert_eq!(KDF_TABLE[0].status, KdfStatus::Invalid);
        assert_eq!(KDF_TABLE[0].params, None);
        assert_eq!(KDF_TABLE[1].status, KdfStatus::Enabled);
        assert_eq!(KDF_TABLE[1].params, Some(FLOOR));
        assert_eq!(KDF_TABLE[2].status, KdfStatus::Reserved);
        assert_eq!(
            KDF_TABLE[2].params,
            Some(Argon2Params {
                m_kib: 262_144,
                t: 3,
                p: 4
            })
        );
    }

    #[test]
    fn allow_list_is_exactly_kdf_id_1_and_enabled() {
        assert_eq!(CLIENT_ALLOW_LIST, &[1]);
        for id in CLIENT_ALLOW_LIST {
            let kdf = KdfId::from_u16(*id).unwrap();
            assert_eq!(kdf.get(), *id);
        }
        assert_eq!(KdfId::from_u16(1).unwrap(), KdfId::DEFAULT);
        assert_eq!(KdfId::DEFAULT.params(), FLOOR);
    }

    #[test]
    fn anything_else_is_a_hard_error() {
        for id in [0u16, 2, 3, 0x00ff, 0x0100, u16::MAX] {
            assert_eq!(
                KdfId::from_u16(id),
                Err(KdfError::NotAllowed { kdf_id: id })
            );
        }
        let err = KdfId::from_u16(2).unwrap_err();
        assert_eq!(
            err.to_string(),
            "KDF settings not allowed by this client (kdf_id 2)"
        );
    }

    // ---- Argon2id ----

    /// RFC 9106 §5.3 Argon2id test vector, run through `hash_password_into_with_memory` with a
    /// `Zeroizing` block buffer: the path `argon2id` uses, on the pinned crate.
    #[test]
    fn rfc9106_argon2id_vector() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[0x04; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let argon =
            Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params)
                .unwrap();
        let mut memory = new_block_memory(&argon);
        let mut out = [0u8; 32];
        argon
            .hash_password_into_with_memory(
                &[0x01; 32],
                &[0x02; 16],
                &mut out,
                memory.as_mut_slice(),
            )
            .unwrap();
        assert_eq!(
            out.as_slice(),
            hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }

    /// `kdf_id` 1 through the public function. Expected values computed independently with the
    /// Argon2 reference C implementation (Python `argon2-cffi` 25.1.0,
    /// `hash_secret_raw(..., time_cost=3, memory_cost=65536, parallelism=4, type=Type.ID,
    /// version=19)`).
    #[test]
    fn argon2id_kdf_id_1_known_answers() {
        let mut out = [0u8; OUTPUT_LEN];
        argon2id(
            KdfId::DEFAULT,
            b"correct horse battery staple",
            &[0x02; SALT_LEN],
            &mut out,
        )
        .unwrap();
        assert_eq!(out.as_slice(), hex(ARGON2ID_KDF1_T32));

        // The OPAQUE KSF shape: 64-byte input, 16 zero bytes of salt, 64-byte tag.
        let mut out = [0u8; KSF_OUTPUT_LEN];
        argon2id(KdfId::DEFAULT, &[0x5a; 64], &[0u8; SALT_LEN], &mut out).unwrap();
        assert_eq!(out.as_slice(), hex(ARGON2ID_KDF1_T64));
    }

    const ARGON2ID_KDF1_T32: &str =
        "39461411013d822de866eb0406316013c8187a31d5a1c42ace6fece7142dca35";
    const ARGON2ID_KDF1_T64: &str = "52b05696945ceeb256726a21d37b77f5ee056640c650d4b4772f52549fdcf74f
                                     e145aac380994e60eb541d6b306495d43849d3f4506d60dc61979cf62f204088";

    #[test]
    fn argon2id_rejects_other_output_lengths() {
        for len in [0usize, 16, 31, 33, 63, 65, 128] {
            let mut out = vec![0u8; len];
            assert_eq!(
                argon2id(KdfId::DEFAULT, b"pw", &[0; SALT_LEN], &mut out),
                Err(KdfError::InvalidOutputLength),
                "{len}"
            );
        }
    }

    /// CRYPTO.md §15 item 9: the block buffer holds password-dependent data after hashing, and
    /// the wipe that `Zeroizing<Vec<Block>>` runs on drop clears it. Uses tiny test parameters.
    ///
    /// `Vec::<Block>::zeroize` first zeroizes every initialised element in place, then clears
    /// the vector and zeroes its spare capacity. The first step is inspected here; freed memory
    /// cannot be read back without `unsafe`, which the workspace forbids.
    #[test]
    fn argon2_block_buffer_is_wiped() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let tiny = Argon2Params {
            m_kib: 32,
            t: 1,
            p: 4,
        };
        let argon = argon2id_context(tiny, OUTPUT_LEN).unwrap();
        let mut memory = new_block_memory(&argon);
        assert_zeroize_on_drop(&memory);
        assert_eq!(
            memory.capacity(),
            memory.len(),
            "allocated at its final size"
        );
        let mut out = [0u8; OUTPUT_LEN];
        argon
            .hash_password_into_with_memory(b"pw", &[0; SALT_LEN], &mut out, memory.as_mut_slice())
            .unwrap();
        let nonzero = memory
            .iter()
            .any(|block| block.as_ref().iter().any(|word| *word != 0));
        assert!(nonzero, "hashing filled the buffer");

        memory.iter_mut().zeroize();
        let wiped = memory
            .iter()
            .all(|block| block.as_ref().iter().all(|word| *word == 0));
        assert!(wiped, "every block is zero after the element wipe");

        memory.zeroize();
        assert!(memory.is_empty());
    }

    /// CRYPTO.md §15 item 9, through the production path: [`argon2id`] fills the block
    /// matrix with password-dependent data and wipes every block before the matrix is freed.
    /// Observed through the test-only hook in `wipe_block_memory`.
    #[test]
    fn argon2id_wipes_its_block_matrix() {
        use crate::secret::wipe_hooks::capture;
        let kdf_id = KdfId::test_cheap(0xfff1, 1);
        let mut out = [0u8; OUTPUT_LEN];
        let (result, log) = capture(|| argon2id(kdf_id, b"pw", &[7; SALT_LEN], &mut out));
        result.unwrap();
        let blocks: Vec<_> = log.iter().filter(|o| o.site == "argon2 blocks").collect();
        assert_eq!(blocks.len(), 1, "{log:?}");
        let expected_len = usize::try_from(kdf_id.params().m_kib).unwrap() * 1024;
        assert_eq!(blocks[0].len, expected_len);
        assert!(blocks[0].held_data, "hashing filled the matrix");
        assert!(
            blocks[0].wiped,
            "every block is zero before the matrix is freed"
        );
    }

    // ---- NFC ----

    #[test]
    fn nfc_composes_and_does_not_trim_or_fold() {
        let cases: [(&str, &str); 6] = [
            ("e\u{0301}", "\u{00e9}"),
            ("\u{212B}", "\u{00C5}"),           // Angstrom sign → Å
            ("\u{1100}\u{1161}", "\u{AC00}"),   // Hangul jamo compose
            ("\u{0344}", "\u{0308}\u{0301}"),   // expands under NFC
            ("  Pass Word  ", "  Pass Word  "), // no trimming, no case folding
            ("\u{FB01}", "\u{FB01}"),           // compatibility ligature stays (NFC, not NFKC)
        ];
        for (input, expected) in cases {
            let got = normalize_password(input).unwrap();
            assert_eq!(got.expose_secret(), expected.as_bytes(), "{input:?}");
        }
    }

    #[test]
    fn nfc_output_is_allocated_at_its_final_size() {
        for input in [
            "",
            "abc",
            "e\u{0301}\u{0344}\u{0344}",
            "\u{0344}\u{0344}\u{0344}",
        ] {
            let v = nfc_utf8(input).unwrap();
            assert_eq!(v.capacity(), v.len(), "{input:?}");
        }
    }

    #[test]
    fn new_passwords_reject_unassigned_code_points() {
        for ok in [
            "correct horse battery staple",
            "Pässwörd \u{1F511}",
            "\u{E000}\u{F0000}\u{10FFFD}", // private use is assigned (Co)
            "",
        ] {
            assert_eq!(check_new_password(ok), Ok(()), "{ok:?}");
        }
        for bad in ["a\u{0378}b", "\u{FFFF}", "\u{10FFFF}", "x\u{FDD0}"] {
            assert_eq!(
                check_new_password(bad),
                Err(KdfError::UnassignedCodePoint),
                "{bad:?}"
            );
        }
        assert_eq!(unicode_normalization::UNICODE_VERSION, (17, 0, 0));
    }

    // ---- HKDF: RFC 5869 Appendix A, test cases 1–3 (SHA-256) ----

    #[test]
    fn rfc5869_sha256_vectors() {
        struct Case {
            ikm: Vec<u8>,
            salt: Vec<u8>,
            info: Vec<u8>,
            okm: Vec<u8>,
        }
        let cases = [
            Case {
                ikm: vec![0x0b; 22],
                salt: (0x00..=0x0c).collect(),
                info: (0xf0..=0xf9).collect(),
                okm: hex(
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
                     34007208d5b887185865",
                ),
            },
            Case {
                ikm: (0x00..=0x4f).collect(),
                salt: (0x60..=0xaf).collect(),
                info: (0xb0..=0xff).collect(),
                okm: hex(
                    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c
                     59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71
                     cc30c58179ec3e87c14c01d5c1f3434f1d87",
                ),
            },
            Case {
                ikm: vec![0x0b; 22],
                salt: vec![],
                info: vec![],
                okm: hex(
                    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d
                     9d201395faa4b61a96c8",
                ),
            },
        ];
        for case in cases {
            let mut okm = vec![0u8; case.okm.len()];
            hkdf_sha256_raw(&case.ikm, Some(&case.salt), &[&case.info], &mut okm).unwrap();
            assert_eq!(okm, case.okm);
            // Split info gives the same result as concatenated info.
            let (a, b) = case.info.split_at(case.info.len() / 2);
            let mut split = vec![0u8; case.okm.len()];
            hkdf_sha256_raw(&case.ikm, Some(&case.salt), &[a, b], &mut split).unwrap();
            assert_eq!(split, case.okm);
        }
    }

    #[test]
    fn empty_salt_equals_hashlen_zeros_and_none() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        hkdf_sha256(b"ikm", None, labels::RELAY_KEY, b"ctx", &mut a).unwrap();
        hkdf_sha256(b"ikm", Some(&[]), labels::RELAY_KEY, b"ctx", &mut b).unwrap();
        hkdf_sha256(b"ikm", Some(&[0u8; 32]), labels::RELAY_KEY, b"ctx", &mut c).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn labelled_hkdf_uses_label_nul_ctx() {
        let mut got = [0u8; 32];
        hkdf_sha256(b"ikm", None, labels::EXPORT_KEY, b"\x01\x02", &mut got).unwrap();
        let mut expected = [0u8; 32];
        hkdf_sha256_raw(
            b"ikm",
            None,
            &[b"rizzy-vault/v1/export/key\x00\x01\x02"],
            &mut expected,
        )
        .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn hkdf_length_limits() {
        assert_eq!(
            hkdf_sha256(b"k", None, labels::RELAY_KEY, &[], &mut []),
            Err(DerivationError)
        );
        let mut max = vec![0u8; 255 * 32];
        assert!(hkdf_sha256(b"k", None, labels::RELAY_KEY, &[], &mut max).is_ok());
        let mut too_long = vec![0u8; 255 * 32 + 1];
        assert_eq!(
            hkdf_sha256(b"k", None, labels::RELAY_KEY, &[], &mut too_long),
            Err(DerivationError)
        );
    }
}
