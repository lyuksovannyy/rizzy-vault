//! Derivations of CRYPTO.md §4.3 for the key hierarchy: `server_unlock_key`,
//! `local_unlock_key`, the recovery wrap key and auth token, the device-set hash, the settings
//! hash and the account fingerprint.
//!
//! All HKDF here is HKDF-SHA-256 with an empty salt (RFC 5869: 32 zero bytes) and
//! `info = LABEL(x) ‖ 0x00 ‖ ctx`, 32 bytes of output (CRYPTO.md §2, §4.3):
//!
//! ```text
//! server_unlock_key = HKDF(export_key, LABEL("unlock-key/server") ‖ 0x00 ‖ account_id)
//! a                 = Argon2id(P = pw_in, S = device_salt, kdf_id, T = 32)
//! local_unlock_key  = HKDF(a, LABEL("unlock-key/local") ‖ 0x00 ‖ account_id ‖ device_id)
//! recovery wrap key = HKDF(recovery_code, LABEL("recovery/wrap-key") ‖ 0x00)
//! auth token        = HKDF(recovery_code, LABEL("recovery/auth-token") ‖ 0x00)
//! H_rec             = SHA-256(auth token)
//! device_set_hash   = SHA-256(LABEL("device-set") ‖ 0x00 ‖ h_1 ‖ … ‖ h_n), h_i sorted bytewise
//! settings_hash     = SHA-256(ACCOUNT_SETTINGS envelope), or 32 zero bytes if settings_seq = 0
//! fingerprint       = SHA-256(LABEL("fingerprint") ‖ 0x00 ‖ account_id
//!                             ‖ identity Ed25519 pk ‖ identity X25519 pk)
//! ```
//!
//! **Why two unlock keys.** The server path (new device, web vault, re-authentication) gets its
//! key from OPAQUE's `export_key`, so the server's copy `E_srv` can be attacked offline only by
//! someone who holds both the server's OPRF secrets and the Secret Key (§5.5). The device path
//! (every unlock on an enrolled device, online or offline) gets its key from one local Argon2id
//! run, so no OPRF round trip is needed and each unlock stretches the password exactly once
//! (§5.4, INV-6).
//!
//! **Invariants.**
//! - Each derived key is written by HKDF straight into its final heap buffer
//!   ([`Key32::try_init_with`]); the Argon2id output `a` sits in a `Zeroizing` array and is
//!   wiped on return. No derived key type is `Clone`, and every `Debug` prints `[REDACTED]`.
//! - The unlock keys remember what they were derived for (account, device, `kdf_id`), and the
//!   wrap and unwrap methods in the `wrap` module refuse a context that names anything else
//!   (INV-5).
//! - The `kdf_id` of a local derivation comes from the device's own state, never from the
//!   server (§5.6); a [`KdfId`] exists only for an allow-listed id (§6.2).
//!
//! **Attacker-relevant properties.**
//! - The recovery wrap key and the auth token are independent HKDF outputs of the same
//!   128-bit code under different labels. The server stores only `SHA-256(token)`, which gives
//!   it nothing towards the wrap key; brute-forcing either means searching 128 random bits
//!   (ADR 0008 decision 3).
//! - `local_unlock_key` is password-derived. Its key id and the `E_local` commitment are guess
//!   verifiers, but each guess costs one full Argon2id behind the random `device_salt` (§4.4).
//!   Whoever copies a device's state file (`E_local`, `device_salt`, SK) can guess at that rate;
//!   OS keystore binding (M3/M7) is the mitigation, not this module (§5.5).
//! - The device-set and settings hashes are what the signed `account-state` commits to, so a
//!   server cannot hide an enrolled device from a new device or serve an older settings object
//!   (§10.2, INV-14, INV-25). This module computes them; comparing them with the verified state
//!   is the caller's step.
//! - Not wiped: the PRK and expand blocks inside `hkdf` 0.13 and the Argon2 tag copies inside
//!   `argon2` 0.6.0 (CRYPTO.md §12.2 "Limits").

use core::fmt;

use sha2::{Digest as _, Sha256};
use subtle::{Choice, ConstantTimeEq};
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

/// Length of a recovery code (§4.2): 128 bits from the CSPRNG.
pub const RECOVERY_CODE_LEN: usize = 16;

/// Length of a `device_salt` (§4.2, §6.1): 16 random bytes per device, stored in the device
/// state file next to `E_local` and replaced at each local re-wrap after a password change.
pub const DEVICE_SALT_LEN: usize = kdf::SALT_LEN;

/// `HKDF(ikm, salt = empty, info = LABEL ‖ 0x00 ‖ ctx, 32)` into a new key.
///
/// `None` as the salt is RFC 5869's empty salt (32 zero bytes). The output is written in place
/// into the key's heap buffer, so this crate makes no other copy of the derived key (the
/// unwiped blocks inside `hkdf` itself are a listed limit, CRYPTO.md §12.2).
fn hkdf_key(ikm: &[u8], label: Label, ctx: &[u8]) -> Result<Key32, DerivationError> {
    Key32::try_init_with(|out| kdf::hkdf_sha256(ikm, None, label, ctx, out))
}

/// `server_unlock_key` (§4.3, §5.4): the key of `E_srv`,
/// `HKDF(ikm = export_key, salt = empty, info = LABEL("unlock-key/server") ‖ 0x00 ‖ account_id,
/// 32)`.
///
/// It remembers the account it was derived for and the `kdf_id` of the OPAQUE run whose
/// `export_key` it comes from; wrapping or unwrapping with a context for another account or
/// another `kdf_id` fails (§8.4, INV-5).
///
/// Never stored (§4.2): derive it after each OPAQUE registration or login, use it for `E_srv`,
/// and drop it. A new OPAQUE registration (password or SK change, `kdf_id` upgrade, lost
/// server secrets) gives a new `export_key` and so a new key.
pub struct ServerUnlockKey {
    /// The 32 derived key bytes, wiped on drop.
    pub(super) key: Key32,
    /// The account whose `account_id` went into the HKDF `info`; the `E_srv` context must name
    /// it.
    pub(super) account_id: AccountId,
    /// The `kdf_id` of the OPAQUE run that produced the `export_key`; the `E_srv` context must
    /// name it. Carried alongside the key, not mixed into it.
    pub(super) kdf_id: KdfId,
}

impl ServerUnlockKey {
    /// Derives the key from OPAQUE's 64-byte `export_key`. `kdf_id` is the one the OPAQUE
    /// registration or login that produced `export_key` stretched with, which the `E_srv`
    /// context must name (§8.4, §11.2 step 6); it does not enter the derivation.
    ///
    /// Crate-private: outside this crate the only way to get a `ServerUnlockKey` is
    /// [`ExportKey::server_unlock_key`](crate::opaque::ExportKey::server_unlock_key), which
    /// passes the `kdf_id` of its own OPAQUE run, so a caller cannot pair an `export_key` with
    /// another `kdf_id`.
    ///
    /// # Errors
    /// [`DerivationError`] (unreachable).
    pub(crate) fn derive(
        export_key: &SecretArray<EXPORT_KEY_LEN>,
        account_id: AccountId,
        kdf_id: KdfId,
    ) -> Result<Self, DerivationError> {
        Ok(Self {
            key: hkdf_key(
                export_key.expose_secret(),
                labels::UNLOCK_KEY_SERVER,
                account_id.as_bytes(),
            )?,
            account_id,
            kdf_id,
        })
    }

    /// The `kdf_id` the `E_srv` context must name.
    #[must_use]
    pub const fn kdf_id(&self) -> KdfId {
        self.kdf_id
    }
}

/// `local_unlock_key` (§4.3, §5.4): the key of `E_local`,
/// `a = Argon2id(P = pw_in, S = device_salt, kdf_id, T = 32)`, then
/// `HKDF(ikm = a, salt = empty, info = LABEL("unlock-key/local") ‖ 0x00 ‖ account_id ‖
/// device_id, 32)`.
///
/// It remembers the account and device it was derived for and the `kdf_id` it was stretched
/// with; wrapping or unwrapping with a context that names another one fails (§8.4, INV-5).
///
/// Never stored (§4.2). After a password unlock that crosses a rotation, the caller keeps it in
/// memory only until the online part completes, to re-wrap `E_local` under the new account key
/// (§11.3 step 4).
pub struct LocalUnlockKey {
    /// The 32 derived key bytes, wiped on drop.
    pub(super) key: Key32,
    /// The account named in the HKDF `info`; the `E_local` context must name it.
    pub(super) account_id: AccountId,
    /// The device named in the HKDF `info`; the `E_local` context must name it.
    pub(super) device_id: DeviceId,
    /// The `kdf_id` of the Argon2id run; the `E_local` context must name it.
    pub(super) kdf_id: KdfId,
}

impl LocalUnlockKey {
    /// Derives the key. `pw_in` is the 32-byte OPAQUE password input of §5.2; `kdf_id` comes
    /// from the device's own state, never from the server (§5.6). This runs one Argon2id at the
    /// cost of `kdf_id` (64 MiB for `kdf_id` 1); the intermediate `a` is wiped.
    ///
    /// `device_salt` is the salt stored next to the `E_local` being opened, or a fresh random
    /// salt when a new `E_local` is created. A wrong password is not detected here: it yields a
    /// different key, and the `E_local` unwrap then fails ([`LocalUnlockKey::unwrap_account_key`]).
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
        // a = Argon2id(P = pw_in, S = device_salt, kdf_id, T = 32), in a wiped-on-drop buffer.
        let mut a = Zeroizing::new([0u8; kdf::OUTPUT_LEN]);
        kdf::argon2id(kdf_id, pw_in.expose_secret(), device_salt, a.as_mut_slice())?;
        // ctx = account_id ‖ device_id (16 + 16 bytes, public identifiers).
        let mut ctx = [0u8; 2 * ID_LEN];
        let (acc, dev) = ctx.split_at_mut(ID_LEN);
        acc.copy_from_slice(account_id.as_bytes());
        dev.copy_from_slice(device_id.as_bytes());
        // HKDF cannot fail for a 32-byte output; the error is mapped rather than unwrapped.
        let key = hkdf_key(a.as_slice(), labels::UNLOCK_KEY_LOCAL, &ctx)
            .map_err(|_| KdfError::Internal)?;
        Ok(Self {
            key,
            account_id,
            device_id,
            kdf_id,
        })
    }

    /// The `kdf_id` this key was stretched with, which the `E_local` context must name (§5.6).
    #[must_use]
    pub const fn kdf_id(&self) -> KdfId {
        self.kdf_id
    }
}

/// The recovery wrap key (§4.3, §11.9): the key of `E_rec`,
/// `HKDF(ikm = recovery_code, salt = empty, info = LABEL("recovery/wrap-key") ‖ 0x00, 32)`.
///
/// The derivation has no context: the key depends on the code alone and records nothing, so
/// the `E_rec` context's `account_id` and `recovery_epoch` are the caller's to get right. The
/// wrap is symmetric on purpose, so a stored `E_rec` is not exposed to harvest-now-decrypt-later
/// (ADR 0008 decision 3, CRYPTO.md §13). In On-device mode (M4) the same key wraps the backup
/// key of the backup file (§11.9).
pub struct RecoveryWrapKey {
    /// The 32 derived key bytes, wiped on drop.
    pub(super) key: Key32,
}

impl RecoveryWrapKey {
    /// Derives the key from the 16-byte recovery code.
    ///
    /// Usually reached through [`crate::secret_key::RecoveryCode::wrap_key`], which holds the
    /// code parsed from the Emergency Kit or freshly generated. No client stores the code
    /// (§4.2).
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
///
/// It authorises a recovery request (`/recovery/start`, `/recovery/complete`, §11.9 steps 2–3)
/// and proves possession of the code without revealing it: the token is an HKDF output under a
/// different label from the wrap key, so neither the token nor `H_rec` helps open `E_rec`.
pub struct RecoveryAuthToken {
    /// The 32 token bytes, wiped on drop. A bearer secret while in transit to the server.
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
    ///
    /// The token is a credential for the recovery endpoints: send it only over the
    /// authenticated TLS connection to the account's server, and never log it (§12.2).
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.token.expose_secret()
    }

    /// `H_rec = SHA-256(token)`, what the server stores (§11.1 step 5).
    ///
    /// Computed on the client and uploaded with `E_rec`; the server never needs the token
    /// itself until a recovery request arrives.
    #[must_use]
    pub fn server_hash(&self) -> [u8; 32] {
        Sha256::digest(self.token.expose_secret()).into()
    }

    /// Server side: whether a received token hashes to the stored `H_rec`, compared in
    /// constant time (§11.9 step 2, §12.3). The lookup by name happens before this; a dummy
    /// comparison for unknown names is the caller's.
    ///
    /// `received_token` is untrusted request data of any length; it is hashed, never compared
    /// directly. Rate limiting and the same response for unknown names and wrong codes (§5.9)
    /// are the server's.
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

/// Implements `Debug` for each listed secret type as `Name([REDACTED])`, so formatting one
/// never prints key bytes, the account, the device or the `kdf_id` (CRYPTO.md §12.2).
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
///
/// Either error means the inputs are not one account's device set, which the caller treats as
/// a failed check of the served data (§11.2 step 6), never as an empty set.
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
/// How to use it: verify every certificate and revocation first, under the identity key of
/// the current `identity_epoch` (a [`Verified`] value proves that a signature check passed, not
/// which key the caller chose), pass exactly the current certificate of each device, then
/// compare the result with `state.device_set_hash` of the verified `account-state`. A mismatch means the server hid or added a device and the flow
/// aborts (§11.2 step 6). Revocations are matched by `device_id` alone.
///
/// # Errors
/// [`DeviceSetError`].
pub fn device_set_hash<'a>(
    account_id: AccountId,
    certificates: impl IntoIterator<Item = &'a Verified<DeviceCertificate>>,
    revocations: impl IntoIterator<Item = &'a Verified<DeviceRevocation>>,
) -> Result<[u8; 32], DeviceSetError> {
    // Collect the revoked device ids; every revocation must be this account's.
    let mut revoked = Vec::new();
    for revocation in revocations {
        if revocation.account_id != account_id {
            return Err(DeviceSetError::AccountMismatch);
        }
        revoked.push(revocation.device_id);
    }
    // Members: this account's certificates of durable devices (kinds 1–3) that no revocation
    // names, each with h_i = SHA-256 of its full signed message.
    let mut members: Vec<(DeviceId, [u8; 32])> = Vec::new();
    for cert in certificates {
        if cert.account_id != account_id {
            return Err(DeviceSetError::AccountMismatch);
        }
        if cert.in_device_set() && !revoked.contains(&cert.device_id) {
            members.push((cert.device_id, *cert.message_hash()));
        }
    }
    // One certificate per device: sort by device id so duplicates are adjacent, then reject
    // any adjacent pair with the same id.
    members.sort_unstable_by_key(|(device_id, _)| *device_id);
    if members
        .windows(2)
        .any(|w| matches!(w, [a, b] if a.0 == b.0))
    {
        return Err(DeviceSetError::DuplicateDevice);
    }
    // The hash input is the h_i sorted bytewise (not by device id), so every device computes
    // the same value whatever order the server served the certificates in.
    let mut hashes: Vec<[u8; 32]> = members.into_iter().map(|(_, h)| h).collect();
    hashes.sort_unstable();
    // SHA-256(LABEL("device-set") ‖ 0x00 ‖ h_1 ‖ … ‖ h_n); with no members this is the valid
    // empty-set value.
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
///
/// The hash is over the envelope bytes exactly as stored, so a server that serves an older,
/// still validly encrypted `ACCOUNT_SETTINGS` object produces another hash and is caught by the
/// comparison with the signed `account-state` (§8.4, §10.2 "Settings freshness", INV-25).
/// [`crate::sign::AccountState::matches_settings`] does that comparison in constant time.
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
///
/// `==` between two fingerprints, and with 32 raw bytes, is constant-time (§12.3).
///
/// Users compare the rendered safety numbers out of band to detect a substituted identity key
/// (§10.3); after a full rotation elsewhere, each device shows the new fingerprint and moves to
/// the new key only after the user confirms it (§11.3 step 3). Changing either identity key or
/// the account changes the fingerprint. The values are public: `Debug` prints them.
#[derive(Clone, Copy, Debug, Eq)]
pub struct AccountFingerprint {
    /// The account the fingerprint belongs to; also orders a pair's safety numbers.
    account_id: AccountId,
    /// The 32-byte SHA-256 fingerprint.
    hash: [u8; 32],
}

impl AccountFingerprint {
    /// Computes the fingerprint of an account's identity keys.
    ///
    /// Pass the identity public keys of a verified bundle (or of a just-opened `E_id`, after
    /// checking them against the bundle), never keys taken from an unverified server response.
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
    ///
    /// Digits only, with no separators; grouping for display (12 groups of 5 for a pair) and
    /// the QR code are the UI's.
    #[must_use]
    pub fn safety_number(&self) -> String {
        let mut d = [0u64; 6];
        // `chunks_exact(5)` over 32 bytes yields six 5-byte chunks (bytes 0..30) and drops the
        // last two bytes; each chunk is read as a big-endian 40-bit integer.
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
    ///
    /// The order is the bytewise order of the two `account_id`s, so both users see the same
    /// 60 digits whichever side computes them.
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

// Constant-time equality over both fields, so a programmatic comparison of fingerprints never
// branches on their bytes (§12.3). The `Hash` impl below hashes the same two fields, which keeps
// it consistent with `Eq`.
impl ConstantTimeEq for AccountFingerprint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.account_id
            .as_bytes()
            .ct_eq(other.account_id.as_bytes())
            & self.hash.ct_eq(&other.hash)
    }
}

impl PartialEq for AccountFingerprint {
    /// Constant-time (§12.3).
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl core::hash::Hash for AccountFingerprint {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.account_id.hash(state);
        self.hash.hash(state);
    }
}

impl PartialEq<[u8; 32]> for AccountFingerprint {
    /// Constant-time (§12.3).
    fn eq(&self, other: &[u8; 32]) -> bool {
        self.hash.ct_eq(other).into()
    }
}
