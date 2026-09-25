//! OPAQUE (RFC 9807) integration (CRYPTO.md §5; ADR 0003, ADR 0004).
//!
//! **This module is the one wrapper through which every opaque-ke call goes** (§5.1, ADR 0009
//! "One entry point per construction"). It always passes `ksf: Some(&RizzyArgon2idKsf::new(..))`
//! with a `kdf_id` from the client's allow-list, and the Context of §5.3 on both sides. Calling
//! opaque-ke's `finish` functions from anywhere else is a review blocker.
//!
//! The API is sans-I/O: every function takes the bytes of the protocol message it consumes and
//! returns the bytes of the one it produces. The server functions take the [`ServerSetup`] and
//! the stored [`PasswordFile`] as inputs; they never read storage themselves.
//!
//! | Step | Client | Server |
//! |---|---|---|
//! | Registration (§11.1 step 4) | [`client_registration_start`] → M1 | |
//! | | | [`server_registration_start`] → M2 |
//! | | [`client_registration_finish`] → upload, [`ExportKey`] | |
//! | | | [`server_registration_finish`] → [`PasswordFile`] |
//! | Login (§11.2 steps 2–5) | [`client_login_start`] → KE1 | |
//! | | | [`server_login_start`] → KE2 and [`ServerLoginState`] (sealed as `SERVER_LOGIN_STATE`) |
//! | | [`client_login_finish`] → KE3, [`ExportKey`] | |
//! | | | [`server_login_finish`] |
//!
//! Inputs and bindings:
//! - The OPAQUE password is [`PasswordInput`], `pw_in = HKDF(UTF-8(NFC(password)), salt = SK,
//!   LABEL("opaque/password") ‖ 0x00, 32)` (§5.2): every guess also needs the 128-bit Secret Key.
//! - The Context is [`OpaqueContext`], `LABEL("opaque/context") ‖ 0x00 ‖ u16(suite_id) ‖
//!   u16(kdf_id) ‖ str(server_origin)` (§5.3). A server that lies about `kdf_id`, or a phishing
//!   server under another origin that relays the messages, makes the client's KE2 check fail
//!   before it sends KE3.
//! - Identifiers stay at their defaults (the public keys); the login name is not bound.
//! - The `credential_identifier` is the `account_id`, or for an unknown login name the fake id
//!   of §4.3 ([`CredentialIdentifier`]); the fake-record path is [`server_login_start`] with no
//!   record (§5.9).
//! - `export_key` becomes `server_unlock_key` through [`ExportKey::server_unlock_key`] (§4.3).
//!   The OPAQUE `session_key` is used only for OPAQUE's own key confirmation (§5.10), so this
//!   module never returns it and wipes it.

mod ksf;

#[cfg(test)]
mod tests;

use core::fmt;

use hmac::{Hmac, Mac as _};
use opaque_ke::errors::{InternalError, ProtocolError};
use opaque_ke::generic_array::typenum::Unsigned;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialFinalizationLen,
    CredentialRequest, CredentialRequestLen, CredentialResponse, CredentialResponseLen,
    Identifiers, RegistrationRequest, RegistrationRequestLen, RegistrationResponse,
    RegistrationResponseLen, RegistrationUpload, RegistrationUploadLen, ServerLogin,
    ServerLoginParameters, ServerRegistration,
};
use rand_core::CryptoRng;
use sha2::{Digest as _, Sha256};
use subtle::{Choice, ConditionallySelectable as _};
use zeroize::Zeroize as _;

pub use ksf::{RizzyArgon2idKsf, RizzySuiteV1, SUITE_ID};

use crate::encoding;
use crate::error::{DerivationError, KdfError, ParseError};
use crate::ids::{AccountId, DeviceId, ID_LEN};
use crate::kdf::{self, KdfId};
use crate::keys::{DEVICE_SALT_LEN, EXPORT_KEY_LEN, LocalUnlockKey, ServerUnlockKey};
use crate::labels;
use crate::normalize::{LoginName, ServerOrigin};
use crate::rng::OpaqueRng;
use crate::secret::{Key32, SecretArray, SecretBytes};
use crate::secret_key::SecretKey;

type Suite = RizzySuiteV1;

/// Length of the registration request M1.
pub const REGISTRATION_REQUEST_LEN: usize = <RegistrationRequestLen<Suite> as Unsigned>::USIZE;
/// Length of the registration response M2.
pub const REGISTRATION_RESPONSE_LEN: usize = <RegistrationResponseLen<Suite> as Unsigned>::USIZE;
/// Length of the registration upload, which is also the stored [`PasswordFile`].
pub const REGISTRATION_UPLOAD_LEN: usize = <RegistrationUploadLen<Suite> as Unsigned>::USIZE;
/// Length of KE1.
pub const KE1_LEN: usize = <CredentialRequestLen<Suite> as Unsigned>::USIZE;
/// Length of KE2.
pub const KE2_LEN: usize = <CredentialResponseLen<Suite> as Unsigned>::USIZE;
/// Length of KE3.
pub const KE3_LEN: usize = <CredentialFinalizationLen<Suite> as Unsigned>::USIZE;
/// Length of a serialised [`ServerLoginState`]: the session key and the expected client MAC,
/// 64 bytes each for SHA-512.
pub const SERVER_LOGIN_STATE_LEN: usize = 128;
/// Length of a serialised [`ServerSetup`]: the 64-byte OPRF seed, the 32-byte AKE private key
/// and the 32-byte public key of the fake keypair.
pub const SERVER_SETUP_LEN: usize = 128;

/// Why an OPAQUE step failed. Carries no secret and never says which secret was wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OpaqueError {
    /// The login failed: wrong password, wrong Secret Key, a Context that differs between the
    /// two sides (origin, `kdf_id`), an unknown account, or a wrong KE3. These cases are
    /// deliberately indistinguishable (§11.2 step 4: "wrong password or Secret Key").
    InvalidLogin,
    /// A protocol message or stored value has the wrong length or does not decode.
    MalformedMessage,
    /// The key-stretching function refused (the `Default` sentinel) or failed.
    KsfFailed,
    /// Any other protocol failure, such as a server reflecting the client's OPRF element.
    Protocol,
    /// Server side: the Context names another `kdf_id` than the stored record. A wiring error
    /// in the server; the login is refused instead of answered under the wrong parameters.
    ContextMismatch,
}

impl fmt::Display for OpaqueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLogin => "wrong password or Secret Key",
            Self::MalformedMessage => "malformed OPAQUE message",
            Self::KsfFailed => "key stretching failed",
            Self::Protocol => "OPAQUE protocol error",
            Self::ContextMismatch => "OPAQUE context does not match the stored record",
        })
    }
}

impl core::error::Error for OpaqueError {}

impl From<ProtocolError> for OpaqueError {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::InvalidLoginError => Self::InvalidLogin,
            ProtocolError::SerializationError | ProtocolError::SizeError { .. } => {
                Self::MalformedMessage
            }
            ProtocolError::LibraryError(InternalError::KsfError) => Self::KsfFailed,
            ProtocolError::LibraryError(_)
            | ProtocolError::ReflectedValueError
            | ProtocolError::Custom(_) => Self::Protocol,
        }
    }
}

/// Checks the exact length of a fixed-size protocol message before opaque-ke parses it, so no
/// truncated or extended input reaches its parsers. Every parse failure after that is also
/// reported as [`OpaqueError::MalformedMessage`], whatever opaque-ke calls it.
fn exact(bytes: &[u8], len: usize) -> Result<&[u8], OpaqueError> {
    if bytes.len() == len {
        Ok(bytes)
    } else {
        Err(OpaqueError::MalformedMessage)
    }
}

// ---------------------------------------------------------------------------------------------
// Inputs: pw_in, the Context, credential identifiers
// ---------------------------------------------------------------------------------------------

/// The OPAQUE password input `pw_in` (CRYPTO.md §5.2):
/// `HKDF(ikm = UTF-8(NFC(password)), salt = SK, info = LABEL("opaque/password") ‖ 0x00, 32)`.
///
/// The extract step is `HMAC-SHA-256(key = SK, msg = password)`, a PRF of the password keyed by
/// the 128-bit Secret Key, so a server breach alone gives nothing to guess against (§5.5).
pub struct PasswordInput {
    key: Key32,
}

impl PasswordInput {
    /// Derives `pw_in` for login and unlock. It never rejects a password: the password was
    /// accepted when it was set.
    ///
    /// # Errors
    /// [`KdfError::InvalidInput`] for an absurdly long password, [`KdfError::Internal`]
    /// (unreachable).
    pub fn derive(password: &str, secret_key: &SecretKey) -> Result<Self, KdfError> {
        let normalized = kdf::normalize_password(password)?;
        let key = Key32::try_init_with(|out| {
            kdf::hkdf_sha256(
                normalized.expose_secret(),
                Some(secret_key.expose_secret()),
                labels::OPAQUE_PASSWORD,
                &[],
                out,
            )
        })
        .map_err(|_| KdfError::Internal)?;
        Ok(Self { key })
    }

    /// Derives `pw_in` for a newly chosen master password (signup, password or SK change).
    /// First rejects code points that are unassigned in the pinned Unicode tables
    /// (ADR 0004 owner decision 3, [`kdf::check_new_password`]).
    ///
    /// # Errors
    /// [`KdfError::UnassignedCodePoint`], or as [`PasswordInput::derive`].
    pub fn derive_for_new_password(
        password: &str,
        secret_key: &SecretKey,
    ) -> Result<Self, KdfError> {
        kdf::check_new_password(password)?;
        Self::derive(password, secret_key)
    }

    /// The device path's `local_unlock_key` (§4.3, §5.4): one Argon2id run over `pw_in` with the
    /// device's own salt and `kdf_id`.
    ///
    /// # Errors
    /// [`KdfError`].
    pub fn local_unlock_key(
        &self,
        device_salt: &[u8; DEVICE_SALT_LEN],
        kdf_id: KdfId,
        account_id: AccountId,
        device_id: DeviceId,
    ) -> Result<LocalUnlockKey, KdfError> {
        LocalUnlockKey::derive(&self.key, device_salt, kdf_id, account_id, device_id)
    }

    /// The 32 bytes of `pw_in`.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.key.expose_secret()
    }
}

impl fmt::Debug for PasswordInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordInput([REDACTED])")
    }
}

/// The OPAQUE Context (CRYPTO.md §5.3):
/// `LABEL("opaque/context") ‖ 0x00 ‖ u16(suite_id = 1) ‖ u16(kdf_id) ‖ str(server_origin)`.
///
/// It is passed on both sides (`ClientLoginFinishParameters.context`,
/// `ServerLoginParameters.context`) and enters only the AKE transcript. It also fixes the
/// `kdf_id` the client's KSF runs with, so the stretching and the binding cannot disagree.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct OpaqueContext {
    bytes: Vec<u8>,
    kdf_id: KdfId,
}

/// Why the client refused the server's login hints before running the KSF (§11.2 step 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LoginHintError {
    /// "The server asked for KDF settings this client does not allow" (§6.2): the `kdf_id` is
    /// not on this client's allow-list.
    KdfNotAllowed(KdfError),
    /// "This is not the server's configured address" (§5.3): the server's canonical origin is
    /// not the origin the client dialled. Unauthenticated; it only drives the message, the
    /// Context check is the control.
    OriginMismatch,
}

impl fmt::Display for LoginHintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KdfNotAllowed(e) => write!(f, "{e}"),
            Self::OriginMismatch => f.write_str("this is not the server's configured address"),
        }
    }
}

impl core::error::Error for LoginHintError {}

impl OpaqueContext {
    /// Builds the Context for `kdf_id` and a canonical origin.
    #[must_use]
    pub fn new(kdf_id: KdfId, server_origin: &ServerOrigin) -> Self {
        let origin = server_origin.as_str().as_bytes();
        let label = labels::OPAQUE_CONTEXT.as_bytes();
        let mut bytes = Vec::with_capacity(label.len() + 1 + 2 + 2 + 4 + origin.len());
        bytes.extend_from_slice(label);
        bytes.push(0x00);
        encoding::put_u16(&mut bytes, SUITE_ID);
        encoding::put_u16(&mut bytes, kdf_id.get());
        // A canonical origin is at most a few hundred bytes (normalize::ORIGIN_INPUT_MAX_LEN),
        // far below the u32 prefix and opaque-ke's 2^16-byte Context limit.
        let origin_len = u32::try_from(origin.len()).unwrap_or(u32::MAX);
        encoding::put_u32(&mut bytes, origin_len);
        bytes.extend_from_slice(origin);
        Self { bytes, kdf_id }
    }

    /// The client's Context for a login (§11.2 step 4). The server answered KE1 with a
    /// `kdf_id` and its canonical origin; before running the KSF the client checks that the
    /// `kdf_id` is on its allow-list and that the origin equals the one it dialled, and aborts
    /// with the matching error otherwise. The Context then binds the dialled origin.
    ///
    /// # Errors
    /// [`LoginHintError`].
    pub fn for_login(
        dialled: &ServerOrigin,
        served_kdf_id: u16,
        served_origin: &str,
    ) -> Result<Self, LoginHintError> {
        let kdf_id = KdfId::from_u16(served_kdf_id).map_err(LoginHintError::KdfNotAllowed)?;
        match ServerOrigin::parse(served_origin) {
            Ok(served) if served == *dialled => Ok(Self::new(kdf_id, dialled)),
            _ => Err(LoginHintError::OriginMismatch),
        }
    }

    /// The Context bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The `kdf_id` bound into the Context.
    #[must_use]
    pub const fn kdf_id(&self) -> KdfId {
        self.kdf_id
    }
}

impl fmt::Debug for OpaqueContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueContext")
            .field("kdf_id", &self.kdf_id.get())
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// An OPAQUE `credential_identifier` (CRYPTO.md §5.3, §5.9): the `account_id` of a real
/// account, or the fake id of an unknown login name. It selects the per-user OPRF key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialIdentifier([u8; ID_LEN]);

impl CredentialIdentifier {
    /// The credential identifier of a real account: its `account_id`.
    #[must_use]
    pub const fn for_account(account_id: AccountId) -> Self {
        Self(account_id.to_bytes())
    }

    /// The fake credential id of an unknown login name (§4.3):
    /// `SHA-256(LABEL("opaque/fake-credential-id") ‖ 0x00 ‖ str(login_name))[0..16]`.
    /// Deterministic, so repeated probes of one name get consistent answers.
    #[must_use]
    pub fn fake(login_name: &LoginName) -> Self {
        let name = login_name.as_str().as_bytes();
        let name_len = u32::try_from(name.len()).unwrap_or(u32::MAX);
        let digest = Sha256::new()
            .chain_update(labels::OPAQUE_FAKE_CREDENTIAL_ID.as_bytes())
            .chain_update([0x00])
            .chain_update(name_len.to_be_bytes())
            .chain_update(name)
            .finalize();
        let mut id = [0u8; ID_LEN];
        for (dst, src) in id.iter_mut().zip(digest.iter()) {
            *dst = *src;
        }
        Self(id)
    }

    /// Wraps 16 bytes read back from storage (the `SERVER_LOGIN_STATE` context).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The 16 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }
}

impl fmt::Debug for CredentialIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialIdentifier(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

/// `enum_key`: 32 random bytes in the server secrets file (§5.9, §5.11), which keys the fake
/// `kdf_id` selector.
pub struct EnumKey {
    key: SecretArray<32>,
}

impl EnumKey {
    /// Draws a new key from the injected CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self {
            key: SecretArray::generate(rng),
        }
    }

    /// Reads the key from the secrets file.
    ///
    /// # Errors
    /// [`ParseError::InvalidLength`] unless 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseError> {
        Ok(Self {
            key: SecretArray::from_slice(bytes)?,
        })
    }

    /// The 32 bytes, for writing the secrets file.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.key.expose_secret()
    }

    /// The fake `kdf_id` selector of an unknown login name (§4.3, §5.9):
    /// `u64(HMAC-SHA-256(key = enum_key, msg = LABEL("opaque/fake-kdf") ‖ 0x00 ‖
    /// str(login_name))[0..8])`.
    ///
    /// The server gives an unknown name a newer `kdf_id` when `selector / 2^64` is below the
    /// fraction of records already on it. In M1 every record is on `kdf_id` 1, so unknown names
    /// always get 1 and the selector is not consulted yet.
    ///
    /// # Errors
    /// [`DerivationError`] (unreachable: HMAC accepts keys of any length).
    pub fn fake_kdf_selector(&self, login_name: &LoginName) -> Result<u64, DerivationError> {
        let name = login_name.as_str().as_bytes();
        let name_len = u32::try_from(name.len()).map_err(|_| DerivationError)?;
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.expose_secret())
            .map_err(|_| DerivationError)?;
        mac.update(labels::OPAQUE_FAKE_KDF.as_bytes());
        mac.update(&[0x00]);
        mac.update(&name_len.to_be_bytes());
        mac.update(name);
        let mut tag = mac.finalize().into_bytes();
        let mut first = [0u8; 8];
        for (dst, src) in first.iter_mut().zip(tag.iter()) {
            *dst = *src;
        }
        tag.as_mut_slice().zeroize();
        Ok(u64::from_be_bytes(first))
    }
}

impl fmt::Debug for EnumKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnumKey([REDACTED])")
    }
}

// ---------------------------------------------------------------------------------------------
// Server-side state
// ---------------------------------------------------------------------------------------------

/// opaque-ke's `ServerSetup` (§5.8): the OPRF seed, the server's AKE keypair and the fake
/// keypair. It lives in the server secrets file, never in the database.
pub struct ServerSetup {
    inner: opaque_ke::ServerSetup<Suite>,
}

impl ServerSetup {
    /// Generates a new setup from the injected CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self {
            inner: opaque_ke::ServerSetup::new(&mut OpaqueRng::new(rng)),
        }
    }

    /// The serialised setup, for the secrets file, in a buffer wiped on drop.
    #[must_use]
    pub fn to_bytes(&self) -> SecretBytes {
        let mut bytes = self.inner.serialize();
        let out = SecretBytes::copy_from_slice(&bytes);
        bytes.as_mut_slice().zeroize();
        out
    }

    /// Reads a setup back from the secrets file.
    ///
    /// # Errors
    /// [`OpaqueError::MalformedMessage`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OpaqueError> {
        let inner = opaque_ke::ServerSetup::<Suite>::deserialize(exact(bytes, SERVER_SETUP_LEN)?)
            .map_err(|_| OpaqueError::MalformedMessage)?;
        Ok(Self { inner })
    }

    /// `SHA-256(server AKE public key)`, which the database stores so the server can refuse to
    /// start with a setup that does not match its records (§5.8).
    #[must_use]
    pub fn public_key_hash(&self) -> [u8; 32] {
        Sha256::digest(self.inner.keypair().public().serialize()).into()
    }
}

impl fmt::Debug for ServerSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerSetup([REDACTED])")
    }
}

/// A registered OPAQUE record (opaque-ke's `ServerRegistration`): what the server stores per
/// account. It holds the client's public key, the masking key and the envelope.
pub struct PasswordFile {
    inner: ServerRegistration<Suite>,
}

impl PasswordFile {
    /// The stored form.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.serialize().to_vec()
    }

    /// Reads a stored record.
    ///
    /// # Errors
    /// [`OpaqueError::MalformedMessage`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OpaqueError> {
        let inner =
            ServerRegistration::<Suite>::deserialize(exact(bytes, REGISTRATION_UPLOAD_LEN)?)
                .map_err(|_| OpaqueError::MalformedMessage)?;
        Ok(Self { inner })
    }
}

impl fmt::Debug for PasswordFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordFile([REDACTED])")
    }
}

/// The server's pending login (opaque-ke's `ServerLogin`): the session key and the expected
/// client MAC. Kept between KE2 and KE3 for at most 60 s, sealed as `SERVER_LOGIN_STATE`
/// ([`crate::server_seal`], §5.10, §5.11) under a `ctx` that names its credential identifier.
pub struct ServerLoginState {
    inner: ServerLogin<Suite>,
    credential_identifier: CredentialIdentifier,
}

impl ServerLoginState {
    /// `ServerLogin::serialize()`, the `SERVER_LOGIN_STATE` plaintext, in a buffer wiped on
    /// drop.
    #[must_use]
    pub fn to_bytes(&self) -> SecretBytes {
        let mut bytes = self.inner.serialize();
        let out = SecretBytes::copy_from_slice(&bytes);
        bytes.as_mut_slice().zeroize();
        out
    }

    /// Rebuilds the state from the opened `SERVER_LOGIN_STATE` plaintext and the credential
    /// identifier its context named.
    ///
    /// # Errors
    /// [`OpaqueError::MalformedMessage`].
    pub fn from_bytes(
        bytes: &[u8],
        credential_identifier: CredentialIdentifier,
    ) -> Result<Self, OpaqueError> {
        let inner = ServerLogin::<Suite>::deserialize(exact(bytes, SERVER_LOGIN_STATE_LEN)?)
            .map_err(|_| OpaqueError::MalformedMessage)?;
        Ok(Self {
            inner,
            credential_identifier,
        })
    }

    /// The credential identifier this login ran under: the account's id, or the fake id.
    #[must_use]
    pub const fn credential_identifier(&self) -> CredentialIdentifier {
        self.credential_identifier
    }
}

impl fmt::Debug for ServerLoginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerLoginState")
            .field("inner", &"[REDACTED]")
            .field("credential_identifier", &self.credential_identifier)
            .finish()
    }
}

// ---------------------------------------------------------------------------------------------
// Client-side state and outputs
// ---------------------------------------------------------------------------------------------

/// OPAQUE's 64-byte `export_key` (§4.2). Never stored; it becomes `server_unlock_key`.
pub struct ExportKey {
    key: SecretArray<EXPORT_KEY_LEN>,
}

impl ExportKey {
    fn from_output(output: &mut [u8]) -> Result<Self, OpaqueError> {
        let key = SecretArray::from_slice(output).map_err(|_| OpaqueError::Protocol);
        output.zeroize();
        Ok(Self { key: key? })
    }

    /// `server_unlock_key = HKDF(ikm = export_key, salt = empty, info =
    /// LABEL("unlock-key/server") ‖ 0x00 ‖ account_id, 32)` (§4.3), the key of `E_srv`.
    ///
    /// # Errors
    /// [`DerivationError`] (unreachable).
    pub fn server_unlock_key(
        &self,
        account_id: AccountId,
    ) -> Result<ServerUnlockKey, DerivationError> {
        ServerUnlockKey::derive(&self.key, account_id)
    }

    /// The 64 bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; EXPORT_KEY_LEN] {
        self.key.expose_secret()
    }
}

impl fmt::Debug for ExportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExportKey([REDACTED])")
    }
}

/// The client's state between M1 and M2 (holds the OPRF blind; wiped on drop).
pub struct ClientRegistrationState {
    inner: ClientRegistration<Suite>,
}

impl fmt::Debug for ClientRegistrationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientRegistrationState([REDACTED])")
    }
}

/// The client's state between KE1 and KE2 (holds the OPRF blind and the ephemeral key; wiped on
/// drop).
pub struct ClientLoginState {
    inner: ClientLogin<Suite>,
}

impl fmt::Debug for ClientLoginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientLoginState([REDACTED])")
    }
}

/// The result of [`client_registration_finish`].
pub struct ClientRegistrationFinish {
    /// The registration upload for the server ([`server_registration_finish`]).
    pub upload: Vec<u8>,
    /// OPAQUE's `export_key`.
    pub export_key: ExportKey,
}

/// The result of [`client_login_finish`].
pub struct ClientLoginFinish {
    /// KE3 for the server.
    pub ke3: Vec<u8>,
    /// OPAQUE's `export_key`.
    pub export_key: ExportKey,
}

/// The result of [`server_login_start`].
pub struct ServerLoginStart {
    /// KE2 for the client.
    pub ke2: Vec<u8>,
    /// The pending login, to seal as `SERVER_LOGIN_STATE` until KE3 arrives.
    pub state: ServerLoginState,
}

/// A found account for [`server_login_start`].
#[derive(Debug)]
pub struct RegisteredCredential {
    /// The account; its id is the credential identifier.
    pub account_id: AccountId,
    /// The account's stored OPAQUE record.
    pub password_file: PasswordFile,
    /// The `kdf_id` stored with the record (§11.1 step 8). The login's Context must name it.
    pub kdf_id: KdfId,
}

/// Protocol messages are public, but the registration upload is the stored record; `Debug`
/// shows only lengths so none of them lands in logs by accident.
impl fmt::Debug for ClientRegistrationFinish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRegistrationFinish")
            .field("upload_len", &self.upload.len())
            .field("export_key", &self.export_key)
            .finish()
    }
}

impl fmt::Debug for ClientLoginFinish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientLoginFinish")
            .field("ke3_len", &self.ke3.len())
            .field("export_key", &self.export_key)
            .finish()
    }
}

impl fmt::Debug for ServerLoginStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerLoginStart")
            .field("ke2_len", &self.ke2.len())
            .field("state", &self.state)
            .finish()
    }
}

fn ksf_for(kdf_id: KdfId) -> RizzyArgon2idKsf {
    RizzyArgon2idKsf::new(kdf_id)
}

// ---------------------------------------------------------------------------------------------
// Registration (§11.1 step 4)
// ---------------------------------------------------------------------------------------------

/// Client, registration step 1: blinds `pw_in` and returns the state and M1.
///
/// # Errors
/// [`OpaqueError::Protocol`] (unreachable for this suite).
pub fn client_registration_start<R: CryptoRng + ?Sized>(
    rng: &mut R,
    pw_in: &PasswordInput,
) -> Result<(ClientRegistrationState, Vec<u8>), OpaqueError> {
    let start =
        ClientRegistration::<Suite>::start(&mut OpaqueRng::new(rng), pw_in.expose_secret())?;
    let message = start.message.serialize().to_vec();
    Ok((ClientRegistrationState { inner: start.state }, message))
}

/// Server, registration step 2: evaluates the OPRF on M1 under the key for
/// `credential_identifier` (the new `account_id`) and returns M2. The server keeps no state.
///
/// # Errors
/// [`OpaqueError::MalformedMessage`] for a malformed M1.
pub fn server_registration_start(
    setup: &ServerSetup,
    request: &[u8],
    credential_identifier: &CredentialIdentifier,
) -> Result<Vec<u8>, OpaqueError> {
    let request =
        RegistrationRequest::<Suite>::deserialize(exact(request, REGISTRATION_REQUEST_LEN)?)
            .map_err(|_| OpaqueError::MalformedMessage)?;
    let result = ServerRegistration::<Suite>::start(
        &setup.inner,
        request,
        credential_identifier.as_bytes(),
    )?;
    Ok(result.message.serialize().to_vec())
}

/// Client, registration step 3: runs the KSF (`kdf_id` from the client's allow-list; this is the
/// signup's Argon2id run) and returns the upload and `export_key`.
///
/// # Errors
/// [`OpaqueError::MalformedMessage`] for a malformed M2, [`OpaqueError::KsfFailed`],
/// [`OpaqueError::Protocol`] for a reflected OPRF element.
pub fn client_registration_finish<R: CryptoRng + ?Sized>(
    rng: &mut R,
    state: ClientRegistrationState,
    pw_in: &PasswordInput,
    response: &[u8],
    kdf_id: KdfId,
) -> Result<ClientRegistrationFinish, OpaqueError> {
    let response =
        RegistrationResponse::<Suite>::deserialize(exact(response, REGISTRATION_RESPONSE_LEN)?)
            .map_err(|_| OpaqueError::MalformedMessage)?;
    let ksf = ksf_for(kdf_id);
    let params = ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf));
    let mut result = state.inner.finish(
        &mut OpaqueRng::new(rng),
        pw_in.expose_secret(),
        response,
        params,
    )?;
    let upload = result.message.serialize().to_vec();
    let export_key = ExportKey::from_output(result.export_key.as_mut_slice())?;
    Ok(ClientRegistrationFinish { upload, export_key })
}

/// Server, registration step 4: turns the client's upload into the record to store.
///
/// # Errors
/// [`OpaqueError::MalformedMessage`].
pub fn server_registration_finish(upload: &[u8]) -> Result<PasswordFile, OpaqueError> {
    let upload = RegistrationUpload::<Suite>::deserialize(exact(upload, REGISTRATION_UPLOAD_LEN)?)
        .map_err(|_| OpaqueError::MalformedMessage)?;
    Ok(PasswordFile {
        inner: ServerRegistration::finish(upload),
    })
}

// ---------------------------------------------------------------------------------------------
// Login (§11.2 steps 2–5)
// ---------------------------------------------------------------------------------------------

/// Client, login step 1: blinds `pw_in` and returns the state and KE1.
///
/// # Errors
/// [`OpaqueError::Protocol`] (unreachable for this suite).
pub fn client_login_start<R: CryptoRng + ?Sized>(
    rng: &mut R,
    pw_in: &PasswordInput,
) -> Result<(ClientLoginState, Vec<u8>), OpaqueError> {
    let start = ClientLogin::<Suite>::start(&mut OpaqueRng::new(rng), pw_in.expose_secret())?;
    let message = start.message.serialize().to_vec();
    Ok((ClientLoginState { inner: start.state }, message))
}

/// Server, login step 2 (§5.9, §11.2 step 3).
///
/// `login_name` is the normalised name the lookup used. With a `record`, the account's id is the
/// credential identifier and `context` must name the record's `kdf_id`. Without one (unknown
/// name), the **fake-record path** runs: the credential identifier is the name's fake id, and
/// opaque-ke builds a dummy record, so the response looks like a real account's. Both paths run
/// the same code: the fake id is always computed and selected in constant time, and opaque-ke
/// ≥ 4.0.0 always creates the dummy record. The caller builds `context` with the record's
/// `kdf_id`, or for an unknown name the `kdf_id` of §5.9 (always 1 in M1), and the server's
/// canonical origin.
///
/// # Errors
/// [`OpaqueError::MalformedMessage`] for a malformed KE1, [`OpaqueError::ContextMismatch`] if
/// the Context's `kdf_id` is not the record's.
pub fn server_login_start<R: CryptoRng + ?Sized>(
    rng: &mut R,
    setup: &ServerSetup,
    login_name: &LoginName,
    record: Option<RegisteredCredential>,
    ke1: &[u8],
    context: &OpaqueContext,
) -> Result<ServerLoginStart, OpaqueError> {
    let request = CredentialRequest::<Suite>::deserialize(exact(ke1, KE1_LEN)?)
        .map_err(|_| OpaqueError::MalformedMessage)?;
    if record
        .as_ref()
        .is_some_and(|r| r.kdf_id != context.kdf_id())
    {
        return Err(OpaqueError::ContextMismatch);
    }
    let fake = CredentialIdentifier::fake(login_name);
    let found = Choice::from(u8::from(record.is_some()));
    let (real, password_file) = match record {
        Some(r) => (r.account_id.to_bytes(), Some(r.password_file.inner)),
        None => ([0u8; ID_LEN], None),
    };
    let mut id = [0u8; ID_LEN];
    for ((dst, fake_byte), real_byte) in id.iter_mut().zip(fake.as_bytes()).zip(&real) {
        *dst = u8::conditional_select(fake_byte, real_byte, found);
    }
    let credential_identifier = CredentialIdentifier(id);
    let params = ServerLoginParameters {
        context: Some(context.as_bytes()),
        identifiers: Identifiers::default(),
    };
    let result = ServerLogin::start(
        &mut OpaqueRng::new(rng),
        &setup.inner,
        password_file,
        request,
        credential_identifier.as_bytes(),
        params,
    )?;
    Ok(ServerLoginStart {
        ke2: result.message.serialize().to_vec(),
        state: ServerLoginState {
            inner: result.state,
            credential_identifier,
        },
    })
}

/// Client, login step 3 (§11.2 step 4): runs the KSF with the Context's `kdf_id` (the one
/// Argon2id run of the login), opens the envelope, checks the server's KE2 MAC over a transcript
/// that includes the Context, and returns KE3 and `export_key`.
///
/// Build `context` with [`OpaqueContext::for_login`], which refuses a `kdf_id` outside the
/// allow-list and a foreign origin before any stretching.
///
/// # Errors
/// [`OpaqueError::InvalidLogin`] for a wrong password or Secret Key, a Context mismatch or an
/// unknown account (all alike); [`OpaqueError::MalformedMessage`]; [`OpaqueError::KsfFailed`];
/// [`OpaqueError::Protocol`].
pub fn client_login_finish<R: CryptoRng + ?Sized>(
    rng: &mut R,
    state: ClientLoginState,
    pw_in: &PasswordInput,
    ke2: &[u8],
    context: &OpaqueContext,
) -> Result<ClientLoginFinish, OpaqueError> {
    let response = CredentialResponse::<Suite>::deserialize(exact(ke2, KE2_LEN)?)
        .map_err(|_| OpaqueError::MalformedMessage)?;
    let ksf = ksf_for(context.kdf_id());
    let params = ClientLoginFinishParameters::new(
        Some(context.as_bytes()),
        Identifiers::default(),
        Some(&ksf),
    );
    let mut result = state.inner.finish(
        &mut OpaqueRng::new(rng),
        pw_in.expose_secret(),
        response,
        params,
    )?;
    // The session key only confirms keys inside OPAQUE (§5.10); it is not used.
    result.session_key.as_mut_slice().zeroize();
    let ke3 = result.message.serialize().to_vec();
    let export_key = ExportKey::from_output(result.export_key.as_mut_slice())?;
    Ok(ClientLoginFinish { ke3, export_key })
}

/// Server, login step 4 (§11.2 step 5): checks KE3 against the pending state. Success means the
/// client knew `pw_in` for this record under the same Context.
///
/// # Errors
/// [`OpaqueError::InvalidLogin`] (always, on the fake-record path),
/// [`OpaqueError::MalformedMessage`].
pub fn server_login_finish(
    state: ServerLoginState,
    ke3: &[u8],
    context: &OpaqueContext,
) -> Result<(), OpaqueError> {
    let message = CredentialFinalization::<Suite>::deserialize(exact(ke3, KE3_LEN)?)
        .map_err(|_| OpaqueError::MalformedMessage)?;
    let params = ServerLoginParameters {
        context: Some(context.as_bytes()),
        identifiers: Identifiers::default(),
    };
    let mut result = state.inner.finish(message, params)?;
    result.session_key.as_mut_slice().zeroize();
    Ok(())
}
