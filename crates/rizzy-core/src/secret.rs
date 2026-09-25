//! Secret types (CRYPTO.md §12.2, ADR 0009 "Memory hygiene").
//!
//! Every type here:
//! - zeroizes its bytes on drop,
//! - does not implement `Clone`, `Copy`, `Display` or `serde::Serialize`,
//! - prints `[REDACTED]` from `Debug`,
//! - gives access only through an explicit, greppable `expose_secret()`,
//! - is allocated once at its final size, so no reallocation leaves a copy behind.
//!
//! Fixed-size secrets live on the heap ([`SecretArray`]), so moving the owner moves a pointer,
//! not the bytes.

use core::fmt;

use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{DerivationError, ParseError};
use crate::ids::SymmetricKeyId;

/// Length of every symmetric key in the key hierarchy (CRYPTO.md §4.2).
pub const KEY_LEN: usize = 32;

/// A fixed-size secret of `N` bytes, heap-allocated and wiped on drop.
pub struct SecretArray<const N: usize> {
    bytes: Box<[u8; N]>,
}

/// A 32-byte symmetric key: account, vault, item keys, unlock keys, derived keys
/// (CRYPTO.md §4.2).
pub type Key32 = SecretArray<KEY_LEN>;

impl<const N: usize> SecretArray<N> {
    /// All-zero secret, filled in place by the constructors below.
    fn zeroed() -> Self {
        Self {
            bytes: Box::new([0u8; N]),
        }
    }

    /// Draws `N` fresh bytes from the injected CSPRNG, directly into the final buffer.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut secret = Self::zeroed();
        rng.fill_bytes(secret.bytes.as_mut_slice());
        secret
    }

    /// Copies a secret out of `bytes`. Wiping the source is the caller's job; prefer
    /// constructing secrets in place where possible.
    ///
    /// # Errors
    /// [`ParseError::InvalidLength`] if `bytes` is not exactly `N` bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() != N {
            return Err(ParseError::InvalidLength);
        }
        let mut secret = Self::zeroed();
        secret.bytes.copy_from_slice(bytes);
        Ok(secret)
    }

    /// Builds a secret in place: `fill` writes the `N` bytes (for example a derived key) into
    /// the final heap buffer, so no copy exists elsewhere. If `fill` fails, the partly written
    /// buffer is wiped.
    ///
    /// # Errors
    /// Whatever `fill` returns.
    pub fn try_init_with<E>(fill: impl FnOnce(&mut [u8; N]) -> Result<(), E>) -> Result<Self, E> {
        let mut secret = Self::zeroed();
        fill(&mut secret.bytes)?;
        Ok(secret)
    }

    /// The secret bytes. Every call site is a place where the secret is used; keep them few.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl SecretArray<KEY_LEN> {
    /// The key's symmetric key id, `HKDF(K, salt = empty, LABEL("key-id/symmetric") ‖ 0x00, 16)`
    /// (CRYPTO.md §4.3, §4.4).
    ///
    /// # Errors
    /// [`DerivationError`], which cannot happen for this fixed output length.
    pub fn key_id(&self) -> Result<SymmetricKeyId, DerivationError> {
        SymmetricKeyId::derive(self)
    }
}

impl<const N: usize> Drop for SecretArray<N> {
    fn drop(&mut self) {
        #[cfg(test)]
        let held_data = wipe_hooks::capturing() && self.bytes.iter().any(|b| *b != 0);
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        wipe_hooks::observe(
            "SecretArray",
            N,
            held_data,
            self.bytes.iter().all(|b| *b == 0),
        );
    }
}

impl<const N: usize> ZeroizeOnDrop for SecretArray<N> {}

impl<const N: usize> fmt::Debug for SecretArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretArray<{N}>([REDACTED])")
    }
}

/// A variable-length secret: plaintext, a normalised password, a serialized secret key.
pub struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    /// Takes ownership of `bytes`. Allocate the vector at its final capacity before writing
    /// the secret into it; this type cannot see earlier reallocations.
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Takes ownership of an already zeroizing buffer.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self { bytes }
    }

    /// Copies `bytes` into a new buffer of exactly that size. Wiping the source is the caller's
    /// job.
    #[must_use]
    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        Self::from_vec(bytes.to_vec())
    }

    /// The secret bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` if the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for SecretBytes {
    /// Wipes the bytes in place, keeping the length, so that the test-only hook can inspect
    /// the wiped buffer (CRYPTO.md §15 item 9). `Zeroizing`'s own drop then runs
    /// `Vec::zeroize`, which wipes the bytes again, clears the vector and wipes its spare
    /// capacity.
    fn drop(&mut self) {
        #[cfg(test)]
        let held_data = wipe_hooks::capturing() && self.bytes.iter().any(|b| *b != 0);
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        wipe_hooks::observe(
            "SecretBytes",
            self.bytes.len(),
            held_data,
            self.bytes.iter().all(|b| *b == 0),
        );
    }
}

impl ZeroizeOnDrop for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

/// Test-only instrumentation for the memory tests of CRYPTO.md §15 item 9.
///
/// Freed memory cannot be read back without `unsafe`, which the workspace forbids. Instead, the
/// wiping code itself reports what it saw: right after a secret buffer is wiped, and before it
/// is freed, the wipe site calls [`observe`] with the buffer's length, whether it held data
/// before the wipe, and whether every byte is zero after it. The sites are the drops of
/// [`SecretArray`] and [`SecretBytes`] and the Argon2 block matrix in
/// [`crate::kdf::argon2id`]. The observations carry no secret bytes.
///
/// Recording is off unless a test turns it on for its own thread with [`capture`].
#[cfg(test)]
pub(crate) mod wipe_hooks {
    use std::cell::RefCell;

    /// One wipe, as the wiping code saw it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Observation {
        /// Which buffer: `"SecretArray"`, `"SecretBytes"` or `"argon2 blocks"`.
        pub(crate) site: &'static str,
        /// Its length, in bytes.
        pub(crate) len: usize,
        /// Whether it held a non-zero byte before the wipe.
        pub(crate) held_data: bool,
        /// Whether every byte was zero after the wipe.
        pub(crate) wiped: bool,
    }

    std::thread_local! {
        static LOG: RefCell<Option<Vec<Observation>>> = const { RefCell::new(None) };
    }

    /// Whether this thread is recording.
    pub(crate) fn capturing() -> bool {
        LOG.with(|log| log.borrow().is_some())
    }

    /// Records one wipe if this thread is recording.
    pub(crate) fn observe(site: &'static str, len: usize, held_data: bool, wiped: bool) {
        LOG.with(|log| {
            if let Some(entries) = log.borrow_mut().as_mut() {
                entries.push(Observation {
                    site,
                    len,
                    held_data,
                    wiped,
                });
            }
        });
    }

    /// Runs `f` with recording on and returns what it observed.
    pub(crate) fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<Observation>) {
        LOG.with(|log| *log.borrow_mut() = Some(Vec::new()));
        let out = f();
        let entries = LOG.with(|log| log.borrow_mut().take()).unwrap_or_default();
        (out, entries)
    }
}

#[cfg(test)]
mod tests {
    use super::wipe_hooks::{Observation, capture};
    use super::*;
    use crate::test_util::seeded_rng;

    #[test]
    fn debug_is_redacted() {
        let key = Key32::from_slice(&[0x41; 32]).unwrap();
        let text = format!("{key:?}");
        assert_eq!(text, "SecretArray<32>([REDACTED])");
        let bytes = SecretBytes::copy_from_slice(b"hunter2");
        let text = format!("{bytes:?} {bytes:#?}");
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("104")); // no numeric byte dump either
        assert!(text.contains("[REDACTED]"));
    }

    #[test]
    fn generate_uses_the_injected_rng() {
        let a = Key32::generate(&mut seeded_rng(1));
        let b = Key32::generate(&mut seeded_rng(1));
        let c = Key32::generate(&mut seeded_rng(2));
        assert_eq!(a.expose_secret(), b.expose_secret());
        assert_ne!(a.expose_secret(), c.expose_secret());
        assert_ne!(a.expose_secret(), &[0u8; 32]);
    }

    #[test]
    fn from_slice_checks_length() {
        assert_eq!(
            Key32::from_slice(&[0u8; 31]).map(|_| ()),
            Err(ParseError::InvalidLength)
        );
        assert_eq!(
            Key32::from_slice(&[0u8; 33]).map(|_| ()),
            Err(ParseError::InvalidLength)
        );
        let key = Key32::from_slice(&[7u8; 32]).unwrap();
        assert_eq!(key.expose_secret(), &[7u8; 32]);
    }

    #[test]
    fn try_init_with_fills_in_place() {
        let key = Key32::try_init_with(|buf| {
            buf.fill(9);
            Ok::<(), ()>(())
        })
        .unwrap();
        assert_eq!(key.expose_secret(), &[9u8; 32]);
        assert!(Key32::try_init_with(|_| Err::<(), _>(())).is_err());
    }

    // Compile-time trait probes. An inherent associated const wins over the blanket trait const
    // only when the inherent impl's bound holds, so `<ProbeX<T>>::IMPLS` is `true` exactly when
    // `T` implements X. This checks a missing impl without a negative trait bound.
    trait DoesNotImpl {
        const IMPLS: bool = false;
    }
    impl<T: ?Sized> DoesNotImpl for T {}

    struct ProbeClone<T: ?Sized>(core::marker::PhantomData<T>);
    impl<T: Clone> ProbeClone<T> {
        const IMPLS: bool = true;
    }

    struct ProbeCopy<T: ?Sized>(core::marker::PhantomData<T>);
    impl<T: Copy> ProbeCopy<T> {
        const IMPLS: bool = true;
    }

    struct ProbeDisplay<T: ?Sized>(core::marker::PhantomData<T>);
    impl<T: ?Sized + fmt::Display> ProbeDisplay<T> {
        const IMPLS: bool = true;
    }

    // Checked at compile time: the test build fails if a secret type gains one of these impls.
    const _: () = {
        // The probes detect an existing impl.
        assert!(<ProbeClone<Vec<u8>>>::IMPLS);
        assert!(<ProbeCopy<u8>>::IMPLS);
        assert!(<ProbeDisplay<u8>>::IMPLS);
        // ADR 0009 / CRYPTO.md §12.2: no Clone, Copy or Display on secret types.
        assert!(!<ProbeClone<Key32>>::IMPLS);
        assert!(!<ProbeCopy<Key32>>::IMPLS);
        assert!(!<ProbeDisplay<Key32>>::IMPLS);
        assert!(!<ProbeClone<SecretArray<16>>>::IMPLS);
        assert!(!<ProbeClone<SecretBytes>>::IMPLS);
        assert!(!<ProbeCopy<SecretBytes>>::IMPLS);
        assert!(!<ProbeDisplay<SecretBytes>>::IMPLS);
    };

    #[test]
    fn secret_types_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Key32>();
        assert_zeroize_on_drop::<SecretArray<16>>();
        assert_zeroize_on_drop::<SecretBytes>();
    }

    /// CRYPTO.md §15 item 9: a fixed-size secret is wiped when it is dropped, before it is
    /// freed. Observed through the test-only hook in `Drop`.
    #[test]
    fn secret_array_is_wiped_on_drop() {
        let ((), log) = capture(|| {
            let key = Key32::generate(&mut seeded_rng(9));
            let code = SecretArray::<16>::from_slice(&[0x5a; 16]).unwrap();
            drop(key);
            drop(code);
        });
        assert_eq!(
            log,
            [
                Observation {
                    site: "SecretArray",
                    len: 32,
                    held_data: true,
                    wiped: true
                },
                Observation {
                    site: "SecretArray",
                    len: 16,
                    held_data: true,
                    wiped: true
                },
            ]
        );
    }

    /// CRYPTO.md §15 item 9: a variable-length secret (the `Zeroizing<Vec<u8>>` inside
    /// `SecretBytes`) is wiped when it is dropped.
    #[test]
    fn secret_bytes_are_wiped_on_drop() {
        let ((), log) = capture(|| {
            drop(SecretBytes::copy_from_slice(
                b"correct horse battery staple",
            ));
            drop(SecretBytes::from_zeroizing(Zeroizing::new(vec![
                0xff;
                1000
            ])));
        });
        assert_eq!(
            log,
            [
                Observation {
                    site: "SecretBytes",
                    len: 28,
                    held_data: true,
                    wiped: true
                },
                Observation {
                    site: "SecretBytes",
                    len: 1000,
                    held_data: true,
                    wiped: true
                },
            ]
        );
    }

    /// The wipe runs wherever the secret lives: a key inside a typed key, a decrypted
    /// plaintext, a derived key, all dropped at the end of a real flow.
    #[test]
    fn secrets_from_real_flows_are_wiped() {
        use crate::envelope::purpose::AccountSettingsCtx;
        use crate::envelope::{open, seal};
        use crate::ids::AccountId;
        use crate::keys::AccountKey;

        let mut rng = seeded_rng(10);
        let ctx = AccountSettingsCtx {
            account_id: AccountId::from_bytes([1; 16]),
            settings_seq: 1,
        };
        let ((), log) = capture(|| {
            let account_key = AccountKey::generate(&mut rng, 0);
            let envelope = seal(&mut rng, account_key.key(), &ctx, b"settings").unwrap();
            let plaintext = open(account_key.key(), &ctx, &envelope).unwrap();
            assert_eq!(plaintext.expose_secret(), b"settings");
        });
        // The plaintext and the account key were dropped, and both were wiped. (Key ids and
        // okm buffers are `Zeroizing` arrays on the stack or inside hkdf; see §12.2.)
        assert!(
            log.iter().any(|o| o.site == "SecretBytes" && o.len == 8),
            "{log:?}"
        );
        assert!(
            log.iter().any(|o| o.site == "SecretArray" && o.len == 32),
            "{log:?}"
        );
        assert!(log.iter().all(|o| o.wiped), "{log:?}");
    }

    #[test]
    fn nothing_is_recorded_unless_a_test_captures() {
        drop(Key32::from_slice(&[1; 32]).unwrap());
        let ((), log) = capture(|| {});
        assert!(log.is_empty());
        assert!(!super::wipe_hooks::capturing());
    }

    #[test]
    fn secret_bytes_accessors() {
        let s = SecretBytes::from_vec(vec![1, 2, 3]);
        assert_eq!(s.expose_secret(), &[1, 2, 3]);
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());
        assert!(SecretBytes::from_zeroizing(Zeroizing::new(Vec::new())).is_empty());
    }
}
