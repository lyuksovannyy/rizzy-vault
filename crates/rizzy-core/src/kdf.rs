//! Key derivation: the `kdf_id` table (CRYPTO.md §6), Argon2id (§2, §12.2), password
//! normalisation (§2, ADR 0004) and the crate-private HKDF-SHA-256 helper (§2, §4.3).
//!
//! Every password this crate stretches is stretched here, and every HKDF-SHA-256 derivation
//! of §4.3 that the crate computes itself goes through the helper at the end of this file
//! (HPKE and opaque-ke run their own internal HKDFs). The users of this module:
//!
//! - the OPAQUE key-stretching function ([`crate::opaque::RizzyArgon2idKsf`]):
//!   `Argon2id(P = oprf_output, S = 16 zero bytes, kdf_id, T = 64)` (§5.1, §6.1);
//! - the device-local unlock key ([`crate::keys::LocalUnlockKey`]):
//!   `Argon2id(P = pw_in, S = device_salt, kdf_id, T = 32)`, then HKDF (§4.3, §5.4);
//! - the export file key and the server-secrets backup key:
//!   `Argon2id(P = UTF-8(NFC(password)), S = a random 16-byte salt, kdf_id, T = 32)`, then HKDF
//!   (§4.3, §5.11, §11.14);
//! - the OPAQUE password input `pw_in` ([`crate::opaque::PasswordInput`]): HKDF over
//!   `UTF-8(NFC(password))` with the Secret Key as salt (§5.2).
//!
//! # The `kdf_id` table
//!
//! **The client decides; the server only names** (§1 rule 5, §6.2). The Argon2id parameters are
//! compiled in ([`KDF_TABLE`]). A [`KdfId`] can only be built from an id on
//! [`CLIENT_ALLOW_LIST`] whose table entry is enabled, and no function here builds Argon2
//! parameters from anything else. An unknown or disallowed `kdf_id` is a hard error
//! ([`KdfError::NotAllowed`]), never a fallback. A `kdf_id` named by the server, a file or local
//! state goes through these steps:
//!
//! 1. [`KdfId::from_u16`] checks it against [`CLIENT_ALLOW_LIST`], then looks it up in
//!    [`KDF_TABLE`], and returns a [`KdfId`] that carries the compiled parameters only if the
//!    entry is enabled.
//! 2. [`argon2id`] takes that [`KdfId`], never raw numbers, and runs Argon2id v0x13 with its
//!    parameters.
//! 3. Elsewhere, the same id is bound into the OPAQUE Context (§5.3) and into the AAD of every
//!    password-derived wrap (§8.4), so a lie about it makes the login or the unwrap fail
//!    (threat model INV-5).
//!
//! Invariant: every enabled entry meets [`FLOOR`] (`m ≥ 65 536 KiB`, `t ≥ 3`, `p = 4`). A unit
//! test checks the table against the literals of §6.2, not against [`FLOOR`] itself, so
//! lowering both together still fails CI (§15 item 10, threat model INV-3).
//!
//! **What this defends against.** A malicious or compromised server cannot lower the cost of a
//! guess by naming weaker parameters: the server-supplied iteration-count attack Palant
//! reported against Bitwarden, and the KDF-downgrade attack class of Scarlata et al. (§6.2,
//! §14). The worst a lie about `kdf_id` achieves is a failed login. **What it does not defend
//! against:** an attacker who holds a stretched value's salt and verifier, such as a device's
//! `E_local` with its `device_salt` and Secret Key, or an export file, can still guess offline
//! at the cost of one Argon2id per guess (§5.5).
//!
//! # Argon2id memory
//!
//! argon2 0.6.0 is built without its `alloc` feature, so its non-wiping
//! `hash_password_into` does not exist in this build. [`argon2id`] allocates the block matrix
//! once, at its final size, in a `Zeroizing<Vec<argon2::Block>>` and passes it to
//! `hash_password_into_with_memory`; the matrix is wiped when the call returns (§12.2). A few
//! stack copies inside argon2 cannot be reached from here; CRYPTO.md §12.2 lists them
//! ("argon2 0.6.0 locals").
//!
//! # Passwords
//!
//! [`normalize_password`] computes `UTF-8(NFC(password))`, with no trimming and no case folding
//! (§2, ADR 0004 decision 7). [`check_new_password`] rejects code points that are unassigned in
//! the pinned Unicode tables; it runs only where a password is chosen, never where one is used
//! (ADR 0004 owner decision 3). With `unicode-normalization` exact-pinned and every bump
//! reviewed like a crypto bump (§3, §16 question 4), this keeps `NFC(password)` stable across
//! releases, so an update cannot lock anyone out.
//!
//! # HKDF
//!
//! The crate-private helper computes `HKDF(ikm, salt, info = LABEL(x) ‖ 0x00 ‖ ctx, L)` with
//! HKDF-SHA-256 (§2). The label comes from the one registry in [`crate::labels`], and labels
//! never contain `0x00`, so `info` is prefix-free. Raw HKDF never appears in the public API
//! (ADR 0009, "One entry point per construction").

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
///
/// The values that matter are compiled constants of this module ([`KDF_TABLE`], [`FLOOR`]).
/// The fields are public so callers can display or compare them, but a value built elsewhere
/// grants nothing: [`argon2id`] takes a [`KdfId`], which cannot be built from an
/// `Argon2Params` (CRYPTO.md §6.2, "no code path that builds Argon2 parameters from
/// server-supplied numbers").
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
///
/// Only [`KdfStatus::Enabled`] entries can become a [`KdfId`], and only if the id is also on
/// [`CLIENT_ALLOW_LIST`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KdfStatus {
    /// Never valid (`kdf_id` 0).
    Invalid,
    /// Enabled: may be used, if it is also on the client allow-list.
    Enabled,
    /// Reserved, not enabled. Enabling it is a release that changes this table.
    Reserved,
}

/// One row of the `kdf_id` table (CRYPTO.md §6.1).
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
///
/// Changing a row, or enabling `kdf_id` 2, is a release that changes this table; the server
/// has no way to add or alter an entry. Adopting a new id follows the upgrade path of §6.3:
/// re-registration with the same password at the next online password entry, never a move to
/// a lower id.
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
///
/// An id must be both on this list and enabled in [`KDF_TABLE`] to be usable. Once a newer id
/// exists, an old one stays on this list until a later major release, and is removed only
/// when the server's count of records on it is close to zero (§6.3 step 4).
pub const CLIENT_ALLOW_LIST: &[u16] = &[1];

/// The floor every enabled table entry must meet (CRYPTO.md §6.2): `m ≥ 65 536 KiB`, `t ≥ 3`,
/// `p = 4`. A unit test checks the table against it, so the floor is a CI-checked invariant.
///
/// It equals the parameters of `kdf_id` 1 (RFC 9106's second recommended option), which is
/// also [`KdfId::DEFAULT`]. `m_kib` and `t` are minimums; `p` must equal 4 exactly.
pub const FLOOR: Argon2Params = Argon2Params {
    m_kib: 65_536,
    t: 3,
    p: 4,
};

/// Length of every Argon2id salt in CRYPTO.md (§6.1): 16 zero bytes for the OPAQUE KSF, a
/// random 16-byte `device_salt`, `export_salt` or `backup_salt`, or the 16-byte `share_id`.
///
/// The zero salt of the KSF is what RFC 9807 specifies: the per-user OPRF key already acts as
/// a secret salt there (§5.1, ADR 0004 decision 4).
pub const SALT_LEN: usize = 16;

/// Output length of Argon2id outside OPAQUE (§6.1): the local unlock key's `a`, the export
/// file key's `e` and the backup key's `b` (§4.3).
pub const OUTPUT_LEN: usize = 32;

/// Output length of Argon2id as the OPAQUE KSF: Nh for SHA-512 (§6.1).
pub const KSF_OUTPUT_LEN: usize = 64;

/// A `kdf_id` on this client's allow-list, with its compiled parameters.
///
/// The only constructors are [`KdfId::from_u16`], which checks the allow-list and the table,
/// and [`KdfId::DEFAULT`]. Holding a `KdfId` is proof the id was checked.
///
/// Every stretching entry point in this crate takes a `KdfId` rather than a number or an
/// [`Argon2Params`], so the type system carries the "client decides" rule of §6.2 to every
/// call site. The id is public protocol data, so `Debug` shows it in full.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KdfId {
    /// The `kdf_id` as encoded on the wire and in files: `u16(kdf_id)`.
    id: u16,
    /// The compiled parameters of `id`: copied from its [`KDF_TABLE`] row by
    /// [`KdfId::from_u16`], or [`FLOOR`] for [`KdfId::DEFAULT`] (a unit test checks that the
    /// two agree). Only the `cfg(test)` constructor sets anything else.
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
    /// This is the only way to turn a number into a usable `kdf_id`. Call it before any
    /// password processing, so a refused id aborts the flow before Argon2id runs (CRYPTO.md
    /// §11.2 step 4, threat model INV-3).
    ///
    /// # Errors
    /// [`KdfError::NotAllowed`] unless the id is on [`CLIENT_ALLOW_LIST`] and enabled in
    /// [`KDF_TABLE`]. This covers `0`, the reserved `2` and every unknown id.
    pub fn from_u16(kdf_id: u16) -> Result<Self, KdfError> {
        let not_allowed = KdfError::NotAllowed { kdf_id };
        // The allow-list first: an id this client does not accept is refused even if a table
        // row exists for it (the reserved `2`).
        if !CLIENT_ALLOW_LIST.contains(&kdf_id) {
            return Err(not_allowed);
        }
        let entry = KDF_TABLE
            .iter()
            .find(|e| e.kdf_id == kdf_id)
            .ok_or(not_allowed)?;
        // Only an enabled row with parameters yields a `KdfId`; `Invalid` and `Reserved` rows
        // are refused like unknown ids.
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
/// Cost: one full Argon2id at `kdf_id`'s parameters, 64 MiB and three passes for `kdf_id` 1,
/// single-threaded (argon2 is built without `parallel`, CRYPTO.md §6.4). Threat model INV-6
/// requires that no path from the master password to a key is cheaper than one such call.
///
/// Security notes:
/// - `out` receives a password-equivalent. The caller must hold it in a buffer that is wiped
///   on drop, as the callers in this crate do (`Zeroizing` or a secret type).
/// - `password` is borrowed and not wiped here; wiping it is the caller's job.
///
/// # Errors
/// [`KdfError::InvalidOutputLength`] for any other `out` length; [`KdfError::InvalidInput`] if
/// argon2 rejects the password (longer than `u32::MAX` bytes); [`KdfError::Internal`] if argon2
/// rejects the compiled parameters (unreachable for the table's entries).
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
    // One allocation of exactly `block_count` blocks (64 MiB for `kdf_id` 1), owned here so
    // that it can be wiped; argon2 fills it in place.
    let mut memory = new_block_memory(&argon);
    let result = argon
        .hash_password_into_with_memory(password, salt, out, memory.as_mut_slice())
        .map_err(|_| KdfError::InvalidInput);
    // Wipe on the error path too: the result is held until the matrix is gone.
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

/// Builds the argon2 context: Argon2id, version 0x13, the given cost parameters and tag length,
/// and no secret or associated data (the `Argon2id` of CRYPTO.md §2).
///
/// # Errors
/// [`KdfError::Internal`] if argon2 rejects the parameters. The table's entries, and the
/// 32- and 64-byte tag lengths, are all within argon2's limits.
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
/// NFC makes the same password typed on different platforms (precomposed `é` or `e` plus a
/// combining accent) give the same bytes. It is NFC, not NFKC, so compatibility characters
/// such as ligatures are kept as typed. This function never rejects a password for its
/// content: login, unlock and opening a file must accept every password that was accepted
/// when it was set. [`check_new_password`] is the separate check for a newly chosen one.
///
/// The output buffer is allocated once at its exact final size and wiped on drop. Limit: the
/// normalisation iterator of `unicode-normalization` buffers characters internally and does
/// not wipe them (CRYPTO.md §12.2, Limits).
///
/// # Errors
/// [`KdfError::InvalidInput`] if the normalised length overflows `usize`.
pub fn normalize_password(password: &str) -> Result<SecretBytes, KdfError> {
    nfc_utf8(password).map(SecretBytes::from_vec)
}

/// NFC-normalises `text` into a new UTF-8 buffer whose capacity equals its length, so no
/// reallocation leaves a partial copy behind (CRYPTO.md §12.2, "Secret `Vec`s are allocated at
/// their final capacity"). The caller wraps the result in a wiping type at once.
///
/// # Errors
/// [`KdfError::InvalidInput`] if the normalised length overflows `usize`.
fn nfc_utf8(text: &str) -> Result<Vec<u8>, KdfError> {
    // First pass: the exact output length, so the buffer never reallocates. NFC can expand
    // text (for example U+0344 becomes U+0308 U+0301), so the input length is not enough.
    let len = text
        .nfc()
        .try_fold(0usize, |acc, c| acc.checked_add(c.len_utf8()))
        .ok_or(KdfError::InvalidInput)?;
    let mut out = Vec::with_capacity(len);
    // Second pass: encode each normalised character through a 4-byte scratch buffer, which is
    // wiped afterwards because it still holds password bytes.
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
/// CRYPTO.md §2 ("New passwords") requires it for every newly chosen master, export and
/// backup password for the same reason. Never call it on a password that already exists
/// (login, unlock, import): that could lock a user out after a table update.
///
/// "Assigned" means `General_Category ≠ Cn` in the Unicode version of the pinned
/// `unicode-normalization` (17.0.0 for 0.1.25). Private-use code points are assigned (`Co`)
/// and their normalisation is stable by Unicode policy, so they are accepted. Noncharacters
/// (for example U+FFFF) are `Cn` and rejected.
///
/// Every character is checked, with no early exit, so the position of the first rejected
/// character does not show in the running time. The per-character table lookup is upstream
/// code (`unicode_normalization::char::is_public_assigned`) and is not claimed to be constant
/// time.
///
/// This function does not reject an empty password; the callers do that first
/// ([`crate::opaque::PasswordInput::derive_for_new_password`] and the export and backup
/// paths), as CRYPTO.md §2 requires.
///
/// # Errors
/// [`KdfError::UnassignedCodePoint`].
pub fn check_new_password(password: &str) -> Result<(), KdfError> {
    // Non-short-circuit `&` and `|`: every character is looked up, whatever came before it.
    let all_assigned = password.chars().fold(true, |ok, c| {
        ok & (is_public_assigned(c) | is_private_use(c))
    });
    if all_assigned {
        Ok(())
    } else {
        Err(KdfError::UnassignedCodePoint)
    }
}

/// Whether `c` is in one of the three private-use areas (U+E000–U+F8FF, planes 15 and 16 up to
/// U+xFFFD). Fixed by the Unicode stability policy. `is_public_assigned` reports these as not
/// assigned, so [`check_new_password`] accepts them through this function.
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
/// `label` is a [`Label`] from the one registry in [`crate::labels`], so a label cannot be
/// typed inline at a call site, and the `0x00` separator keeps `info` prefix-free because no
/// label contains `0x00` (CRYPTO.md §2, §4.3). `okm` is written in place; the caller owns the
/// buffer and is responsible for wiping it.
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
///
/// # Errors
/// [`DerivationError`] if `okm` is empty or longer than 255 × 32 bytes.
fn hkdf_sha256_raw(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[&[u8]],
    okm: &mut [u8],
) -> Result<(), DerivationError> {
    // hkdf 0.13 accepts a zero-length output and writes nothing; no derivation here wants that,
    // so it is refused. The upper bound (255 blocks of 32 bytes) is hkdf's own check.
    if okm.is_empty() {
        return Err(DerivationError);
    }
    // RFC 5869: a missing salt is `HashLen` zero bytes, which is what `Hkdf::new(None, ..)`
    // uses. An empty slice is mapped to `None` so both spellings take the same path; a unit test
    // checks that `None`, an empty salt and 32 zero bytes agree.
    let salt = salt.filter(|s| !s.is_empty());
    Hkdf::<Sha256>::new(salt, ikm)
        .expand_multi_info(info, okm)
        .map_err(|_| DerivationError)
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    use super::*;
    use crate::labels;
    use crate::test_util::hex;

    // ---- §6.2: the CI-checked floor and the allow-list ----

    /// CRYPTO.md §6.2: "every enabled entry has m ≥ 65 536, t ≥ 3 and p = 4". Checked against
    /// the spec's literals, not against [`FLOOR`], so lowering `FLOOR` together with a table
    /// entry still fails here.
    #[test]
    fn every_enabled_table_entry_meets_the_floor() {
        let enabled: Vec<_> = KDF_TABLE
            .iter()
            .filter(|e| e.status == KdfStatus::Enabled)
            .collect();
        assert!(!enabled.is_empty());
        for entry in enabled {
            let p = entry.params.unwrap();
            assert!(p.m_kib >= 65_536, "kdf_id {}: m below floor", entry.kdf_id);
            assert!(p.t >= 3, "kdf_id {}: t below floor", entry.kdf_id);
            assert_eq!(p.p, 4, "kdf_id {}: p must be 4", entry.kdf_id);
        }
    }

    /// The documented constant is the §6.2 floor itself.
    #[test]
    fn floor_is_the_crypto_md_6_2_floor() {
        assert_eq!(
            FLOOR,
            Argon2Params {
                m_kib: 65_536,
                t: 3,
                p: 4
            }
        );
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
