//! `RizzySuiteV1` and `RizzyArgon2idKsf` (CRYPTO.md §5.1, §6.1, §12.2; ADR 0003 decisions 2
//! and 3).
//!
//! The ciphersuite fixes every algorithm opaque-ke runs for rizzy-vault, and the KSF is where
//! the OPAQUE side of signup and login stretches the password. How the KSF fits into
//! opaque-ke 4.0.1 (its `get_password_derived_key`), on the client only:
//!
//! 1. The client unblinds the server's OPRF evaluation of `pw_in` and gets the 64-byte
//!    `oprf_output`.
//! 2. opaque-ke calls `Ksf::hash` on a copy of it. Here that runs
//!    `Argon2id(P = oprf_output, S = 16 zero bytes, kdf_id, T = 64)` through
//!    [`kdf::argon2id`], and wipes the copy it was given.
//! 3. opaque-ke computes `randomized_password = HKDF-Extract(salt = empty, oprf_output ‖
//!    stretched)`, from which opaque-ke builds the envelope (registration) or opens it
//!    (login) and derives `export_key`.
//!
//! So a guess against an OPAQUE record costs an OPRF evaluation, which needs the server's
//! OPRF seed or an online, rate-limited request, plus one Argon2id at the record's `kdf_id`.
//! Because `pw_in` is keyed by the Secret Key, it also needs the Secret Key (§5.2, §5.5). The
//! server never runs the KSF.
//!
//! This module is private; the parent module re-exports [`RizzySuiteV1`],
//! [`RizzyArgon2idKsf`] and [`SUITE_ID`].

use opaque_ke::errors::InternalError;
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use zeroize::Zeroize as _;

use crate::kdf::{self, KdfId};

/// The OPAQUE ciphersuite, `suite_id = 1` (CRYPTO.md §5.1): RFC 9807's first recommended
/// configuration. ristretto255-SHA512 OPRF, HKDF-SHA-512 and HMAC-SHA-512, 3DH over
/// ristretto255, and [`RizzyArgon2idKsf`] as the key-stretching function.
///
/// `sha2_010::Sha512` is sha2 0.10.9, a direct renamed dependency, because opaque-ke 4.0.1 is on
/// digest 0.10 and does not re-export sha2 (ADR 0009).
///
/// All use goes through the [`opaque`](super) wrapper module, which always passes the KSF.
///
/// Its `suite_id`, [`SUITE_ID`], is bound into the OPAQUE Context (§5.3). The type has no
/// fields; it only names the configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RizzySuiteV1;

impl opaque_ke::CipherSuite for RizzySuiteV1 {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_010::Sha512>;
    type Ksf = RizzyArgon2idKsf;
}

/// The `suite_id` of [`RizzySuiteV1`], bound into the OPAQUE Context (§5.3).
pub const SUITE_ID: u16 = 1;

/// The OPAQUE key-stretching function (CRYPTO.md §5.1):
/// `Argon2id(P = oprf_output, S = 16 zero bytes, kdf_id, T = 64)`, through argon2 0.6 with this
/// crate's zeroizing block memory ([`kdf::argon2id`]).
///
/// - The all-zero salt is what RFC 9807 specifies; the OPRF key already acts as a secret
///   per-user salt.
/// - **`Default` is a sentinel that refuses to run** (CRYPTO.md §5.1: "a sentinel (`kdf_id = 0`)
///   whose `hash` returns `InternalError::KsfError`"). opaque-ke requires `Ksf: Default` and
///   silently uses `Default` when a caller passes `ksf: None`; with this sentinel a forgotten
///   `Some(..)` is a hard `ProtocolError::LibraryError(KsfError)`, never a silent `kdf_id` 1
///   that would lock the account out once `kdf_id` 2 exists.
/// - Only a [`KdfId`] from the client's allow-list can be passed to [`RizzyArgon2idKsf::new`], so
///   no Argon2 parameters ever come from the server.
/// - Its copy of the OPRF output is wiped after use. opaque-ke's own copies of the OPRF output
///   and of the stretched output are not (a listed limit, §12.2).
///
/// The value holds only a `kdf_id`, which is public, so it is `Copy` and its `Debug` shows the
/// id. Outside tests, only the wrapper module builds one, with [`RizzyArgon2idKsf::new`], for
/// each OPAQUE call that stretches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RizzyArgon2idKsf {
    /// The `kdf_id` to stretch with. `None` only in the `Default` sentinel, whose `hash`
    /// refuses to run; [`RizzyArgon2idKsf::new`] always sets `Some`.
    kdf_id: Option<KdfId>,
}

impl RizzyArgon2idKsf {
    /// The KSF for `kdf_id`.
    ///
    /// `kdf_id` must be the one the Context binds (login) or the one the new record will be
    /// stored with (registration), so the stretching and the binding agree (§5.3, §11.1 step 8).
    /// Taking a [`KdfId`] means it can only come from the client's allow-list (§6.2).
    #[must_use]
    pub const fn new(kdf_id: KdfId) -> Self {
        Self {
            kdf_id: Some(kdf_id),
        }
    }

    /// The `kdf_id` this KSF stretches with; `None` for the refusing sentinel.
    #[must_use]
    pub const fn kdf_id(&self) -> Option<KdfId> {
        self.kdf_id
    }

    /// The stretching step: `Argon2id(P = input, S = 16 zero bytes, kdf_id, T = 64)` into a new
    /// array. Takes the input by reference, so that [`Ksf::hash`] can wipe its by-value copy
    /// whatever the outcome.
    ///
    /// The returned array holds the stretched output, a password-equivalent; opaque-ke takes it
    /// and does not wipe it (§12.2, "opaque-ke internals").
    ///
    /// # Errors
    /// [`InternalError::KsfError`] for the sentinel, for an input length other than 64 bytes,
    /// and if Argon2id fails. opaque-ke reports it as `ProtocolError::LibraryError(KsfError)`.
    fn stretch<L: ArrayLength<u8>>(
        &self,
        input: &GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        // The `Default` sentinel stops here, before any work (§5.1).
        let kdf_id = self.kdf_id.ok_or(InternalError::KsfError)?;
        // T = 64 = Nh for SHA-512: opaque-ke passes the 64-byte OPRF output.
        if L::USIZE != kdf::KSF_OUTPUT_LEN {
            return Err(InternalError::KsfError);
        }
        #[cfg(test)]
        test_hooks::note_ksf_run(kdf_id);
        let mut output = GenericArray::<u8, L>::default();
        // RFC 9807's all-zero salt; the per-user OPRF key already acts as a secret salt.
        kdf::argon2id(
            kdf_id,
            input.as_slice(),
            &[0u8; kdf::SALT_LEN],
            output.as_mut_slice(),
        )
        .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

/// opaque-ke's hook for the key-stretching function. It receives the OPRF output by value,
/// stretches it, and wipes that copy before returning, on success and on failure alike.
impl Ksf for RizzyArgon2idKsf {
    fn hash<L: ArrayLength<u8>>(
        &self,
        mut input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let result = self.stretch(&input);
        input.as_mut_slice().zeroize();
        result
    }
}

/// Test-only instrumentation: which `kdf_id`s the KSF ran with on this thread, so tests can
/// prove that a refused `kdf_id` aborts before any stretching and that the KSF runs with the
/// Context's `kdf_id`.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::RefCell;

    use crate::kdf::KdfId;

    std::thread_local! {
        static RUNS: RefCell<Vec<u16>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn note_ksf_run(kdf_id: KdfId) {
        RUNS.with(|r| r.borrow_mut().push(kdf_id.get()));
    }

    /// The `kdf_id`s of every KSF run on this thread so far.
    pub(crate) fn ksf_runs() -> Vec<u16> {
        RUNS.with(|r| r.borrow().clone())
    }
}
