//! `RizzySuiteV1` and `RizzyArgon2idKsf` (CRYPTO.md §5.1, §6.1, §12.2).

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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RizzyArgon2idKsf {
    kdf_id: Option<KdfId>,
}

impl RizzyArgon2idKsf {
    /// The KSF for `kdf_id`.
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

    fn stretch<L: ArrayLength<u8>>(
        &self,
        input: &GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let kdf_id = self.kdf_id.ok_or(InternalError::KsfError)?;
        // T = 64 = Nh for SHA-512: opaque-ke passes the 64-byte OPRF output.
        if L::USIZE != kdf::KSF_OUTPUT_LEN {
            return Err(InternalError::KsfError);
        }
        #[cfg(test)]
        test_hooks::note_ksf_run(kdf_id);
        let mut output = GenericArray::<u8, L>::default();
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
