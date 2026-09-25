//! Derivations of CRYPTO.md §4.3 for the key hierarchy: `server_unlock_key`,
//! `local_unlock_key`, the recovery wrap key and auth token, the device-set hash, the settings
//! hash and the account fingerprint.

use core::fmt;

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::IdentityPublicKeys;
use crate::error::{DerivationError, KdfError};
use crate::ids::{AccountId, DeviceId, ID_LEN};
use crate::kdf::{self, KdfId};
use crate::labels::{self, Label};
use crate::secret::{Key32, SecretArray};
use crate::sign::{DeviceCertificate, DeviceRevocation, Verified};

/// Length of OPAQUE's `export_key` (Nh for SHA-512, §4.2).
pub const EXPORT_KEY_LEN: usize = 64;

/// Length of a recovery code (§4.2).
pub const RECOVERY_CODE_LEN: usize = 16;

/// Length of a `device_salt` (§4.2, §6.1).
pub const DEVICE_SALT_LEN: usize = kdf::SALT_LEN;

/// `HKDF(ikm, salt = empty, info = LABEL ‖ 0x00 ‖ ctx, 32)` into a new key.
fn hkdf_key(ikm: &[u8], label: Label, ctx: &[u8]) -> Result<Key32, DerivationError> {
    Key32::try_init_with(|out| kdf::hkdf_sha256(ikm, None, label, ctx, out))
}

/// `server_unlock_key` (§4.3, §5.4): the key of `E_srv`,
/// `HKDF(ikm = export_key, salt = empty, info = LABEL("unlock-key/server") ‖ 0x00 ‖ account_id,
/// 32)`.
///
/// It remembers the account it was derived for; wrapping or unwrapping with a context for
/// another account fails.
pub struct ServerUnlockKey {
    pub(super) key: Key32,
    pub(super) account_id: AccountId,
}

impl ServerUnlockKey {
    /// Derives the key from OPAQUE's 64-byte `export_key`.
    ///
    /// # Errors
    /// [`DerivationError`] (unreachable).
    pub fn derive(
        export_key: &SecretArray<EXPORT_KEY_LEN>,
        account_id: AccountId,
    ) -> Result<Self, DerivationError> {
        Ok(Self {
            key: hkdf_key(
                export_key.expose_secret(),
                labels::UNLOCK_KEY_SERVER,
                account_id.as_bytes(),
            )?,
            account_id,
        })
    }
}

/// `local_unlock_key` (§4.3, §5.4): the key of `E_local`,
/// `a = Argon2id(P = pw_in, S = device_salt, kdf_id, T = 32)`, then
/// `HKDF(ikm = a, salt = empty, info = LABEL("unlock-key/local") ‖ 0x00 ‖ account_id ‖
/// device_id, 32)`.
///
/// It remembers the account and device it was derived for.
pub struct LocalUnlockKey {
    pub(super) key: Key32,
    pub(super) account_id: AccountId,
    pub(super) device_id: DeviceId,
}

impl LocalUnlockKey {
    /// Derives the key. `pw_in` is the 32-byte OPAQUE password input of §5.2; `kdf_id` comes
    /// from the device's own state, never from the server (§5.6). This runs one Argon2id at the
    /// cost of `kdf_id` (64 MiB for `kdf_id` 1); the intermediate `a` is wiped.
    ///
    /// # Errors
    /// [`KdfError`].
    pub fn derive(
        pw_in: &Key32,
        device_salt: &[u8; DEVICE_SALT_LEN],
        kdf_id: KdfId,
        account_id: AccountId,
        device_id: DeviceId,
    ) -> Result<Self, KdfError> {
        let mut a = Zeroizing::new([0u8; kdf::OUTPUT_LEN]);
        kdf::argon2id(kdf_id, pw_in.expose_secret(), device_salt, a.as_mut_slice())?;
        let mut ctx = [0u8; 2 * ID_LEN];
        let (acc, dev) = ctx.split_at_mut(ID_LEN);
        acc.copy_from_slice(account_id.as_bytes());
        dev.copy_from_slice(device_id.as_bytes());
        let key = hkdf_key(a.as_slice(), labels::UNLOCK_KEY_LOCAL, &ctx)
            .map_err(|_| KdfError::Internal)?;
        Ok(Self {
            key,
            account_id,
            device_id,
        })
    }
}

/// The recovery wrap key (§4.3, §11.9): the key of `E_rec`,
/// `HKDF(ikm = recovery_code, salt = empty, info = LABEL("recovery/wrap-key") ‖ 0x00, 32)`.
pub struct RecoveryWrapKey {
    pub(super) key: Key32,
}

impl RecoveryWrapKey {
    /// Derives the key from the 16-byte recovery code.
    ///
    /// # Errors
    /// [`DerivationError`] (unreachable).
    pub fn derive(recovery_code: &SecretArray<RECOVERY_CODE_LEN>) -> Result<Self, DerivationError> {
        Ok(Self {
            key: hkdf_key(
                recovery_code.expose_secret(),
                labels::RECOVERY_WRAP_KEY,
                &[],
            )?,
        })
    }
}

/// The recovery auth token (§4.3, §11.9):
/// `HKDF(ikm = recovery_code, salt = empty, info = LABEL("recovery/auth-token") ‖ 0x00, 32)`.
/// The client sends it; the server stores only `H_rec = SHA-256(token)`.
pub struct RecoveryAuthToken {
    token: Key32,
}

impl RecoveryAuthToken {
    /// Derives the token from the 16-byte recovery code.
    ///
    /// # Errors
    /// [`DerivationError`] (unreachable).
    pub fn derive(recovery_code: &SecretArray<RECOVERY_CODE_LEN>) -> Result<Self, DerivationError> {
        Ok(Self {
            token: hkdf_key(
                recovery_code.expose_secret(),
                labels::RECOVERY_AUTH_TOKEN,
                &[],
            )?,
        })
    }

    /// The token bytes, to send to the server.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.token.expose_secret()
    }

    /// `H_rec = SHA-256(token)`, what the server stores (§11.1 step 5).
    #[must_use]
    pub fn server_hash(&self) -> [u8; 32] {
        Sha256::digest(self.token.expose_secret()).into()
    }

    /// Server side: whether a received token hashes to the stored `H_rec`, compared in
    /// constant time (§11.9 step 2, §12.3). The lookup by name happens before this; a dummy
    /// comparison for unknown names is the caller's.
    #[must_use]
    pub fn matches_server_hash(received_token: &[u8], stored_hash: &[u8; 32]) -> bool {
        let h: [u8; 32] = Sha256::digest(received_token).into();
        h.ct_eq(stored_hash).into()
    }
}

/// Test-only access to the derived keys, for the known-answer vector files (CRYPTO.md §15
/// item 1), which publish each §4.3 output itself, not only its key id.
#[cfg(test)]
macro_rules! key_for_tests {
    ($($name:ident),+) => {$(
        impl $name {
            pub(crate) const fn key_for_tests(&self) -> &Key32 {
                &self.key
            }
        }
    )+};
}

#[cfg(test)]
key_for_tests!(ServerUnlockKey, LocalUnlockKey, RecoveryWrapKey);

macro_rules! redacted_debug {
    ($($name:ident),+) => {$(
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    )+};
}

redacted_debug!(
    ServerUnlockKey,
    LocalUnlockKey,
    RecoveryWrapKey,
    RecoveryAuthToken
);

/// The device set cannot be hashed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeviceSetError {
    /// A certificate or revocation belongs to another account.
    AccountMismatch,
    /// Two certificates in the set name the same device. The caller must pass exactly the
    /// current certificate of each device (after a full rotation, the re-issued one).
    DuplicateDevice,
}

impl fmt::Display for DeviceSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AccountMismatch => "device certificate of another account",
            Self::DuplicateDevice => "two certificates for one device",
        })
    }
}

impl core::error::Error for DeviceSetError {}

/// The device-set hash (§4.3, §10.2):
/// `SHA-256(LABEL("device-set") ‖ 0x00 ‖ h_1 ‖ … ‖ h_n)`, where `h_i` is `SHA-256` of the signed
/// message of each non-revoked certificate with `device_kind ≠ 4`, sorted bytewise. The empty
/// set, `SHA-256(LABEL("device-set") ‖ 0x00)`, is valid (web-vault signup, §11.1).
///
/// Kind-4 certificates and certificates whose device a revocation names are left out here, so
/// the caller can pass everything the server served.
///
/// # Errors
/// [`DeviceSetError`].
pub fn device_set_hash<'a>(
    account_id: AccountId,
    certificates: impl IntoIterator<Item = &'a Verified<DeviceCertificate>>,
    revocations: impl IntoIterator<Item = &'a Verified<DeviceRevocation>>,
) -> Result<[u8; 32], DeviceSetError> {
    let mut revoked = Vec::new();
    for revocation in revocations {
        if revocation.account_id != account_id {
            return Err(DeviceSetError::AccountMismatch);
        }
        revoked.push(revocation.device_id);
    }
    let mut members: Vec<(DeviceId, [u8; 32])> = Vec::new();
    for cert in certificates {
        if cert.account_id != account_id {
            return Err(DeviceSetError::AccountMismatch);
        }
        if cert.in_device_set() && !revoked.contains(&cert.device_id) {
            members.push((cert.device_id, *cert.message_hash()));
        }
    }
    members.sort_unstable_by_key(|(device_id, _)| *device_id);
    if members
        .windows(2)
        .any(|w| matches!(w, [a, b] if a.0 == b.0))
    {
        return Err(DeviceSetError::DuplicateDevice);
    }
    let mut hashes: Vec<[u8; 32]> = members.into_iter().map(|(_, h)| h).collect();
    hashes.sort_unstable();
    let mut digest = Sha256::new();
    digest.update(labels::DEVICE_SET.as_bytes());
    digest.update([0x00]);
    for h in &hashes {
        digest.update(h);
    }
    Ok(digest.finalize().into())
}

/// The settings hash (§4.3, §10.2): `SHA-256(ACCOUNT_SETTINGS envelope bytes)`, or 32 zero
/// bytes while `settings_seq = 0`.
///
/// Returns `None` when the inputs contradict each other: an envelope while `settings_seq = 0`,
/// or none while `settings_seq > 0`.
#[must_use]
pub fn settings_hash(settings_seq: u64, settings_envelope: Option<&[u8]>) -> Option<[u8; 32]> {
    match (settings_seq, settings_envelope) {
        (0, None) => Some([0u8; 32]),
        (1.., Some(envelope)) => Some(Sha256::digest(envelope).into()),
        _ => None,
    }
}

/// The account fingerprint (§4.3, §10.3):
/// `SHA-256(LABEL("fingerprint") ‖ 0x00 ‖ account_id ‖ identity_ed25519_pk ‖
/// identity_x25519_pk)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AccountFingerprint {
    account_id: AccountId,
    hash: [u8; 32],
}

impl AccountFingerprint {
    /// Computes the fingerprint of an account's identity keys.
    #[must_use]
    pub fn compute(account_id: AccountId, identity: &IdentityPublicKeys) -> Self {
        let hash = Sha256::new()
            .chain_update(labels::FINGERPRINT.as_bytes())
            .chain_update([0x00])
            .chain_update(account_id.as_bytes())
            .chain_update(identity.ed25519.as_bytes())
            .chain_update(identity.x25519.as_bytes())
            .finalize()
            .into();
        Self { account_id, hash }
    }

    /// The 32-byte fingerprint.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.hash
    }

    /// The account.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// The 30-digit safety number (§10.3): the first 30 bytes as six 5-byte big-endian chunks,
    /// each rendered as `u40 mod 100000`, zero-padded to 5 digits.
    #[must_use]
    pub fn safety_number(&self) -> String {
        let mut d = [0u64; 6];
        for (digits, chunk) in d.iter_mut().zip(self.hash.chunks_exact(5)) {
            *digits = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)) % 100_000;
        }
        format!(
            "{:05}{:05}{:05}{:05}{:05}{:05}",
            d[0], d[1], d[2], d[3], d[4], d[5]
        )
    }

    /// The 60-digit number two users compare (§10.3): both accounts' 30 digits, concatenated in
    /// `account_id` order.
    #[must_use]
    pub fn pair_safety_number(&self, other: &Self) -> String {
        let (first, second) = if self.account_id <= other.account_id {
            (self, other)
        } else {
            (other, self)
        };
        first.safety_number() + &second.safety_number()
    }
}

impl PartialEq<[u8; 32]> for AccountFingerprint {
    /// Constant-time (§12.3).
    fn eq(&self, other: &[u8; 32]) -> bool {
        self.hash.ct_eq(other).into()
    }
}
