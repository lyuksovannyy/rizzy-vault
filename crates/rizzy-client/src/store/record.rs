//! The device-state record, record version 1 ([ADR 0026] §2): the one opaque byte string a
//! durable device persists for its enrolment (ADR 0013 §3 rule 2).
//!
//! ```text
//! device_state = u16(record_version = 1) ‖ u8(stage: 1 committed | 2 signup-pending)
//!              ‖ str(server_origin) ‖ account_id (16) ‖ device_id (16) ‖ u8(device_kind: 1–3)
//!              ‖ secret_key (16) ‖ device_salt (16) ‖ u16(kdf_id) ‖ bytes(E_dev)
//!              ‖ u8(has_local: 0 | 1) ‖ [u32(local_account_key_epoch) ‖ u32(local_password_epoch) ‖ bytes(E_local)]
//!              ‖ u8(pending: 0 | 1) ‖ [pending]
//! pending      = secret_key' (16) ‖ device_salt' (16) ‖ u16(kdf_id') ‖ u32(account_key_epoch')
//!              ‖ u32(password_epoch') ‖ bytes(E_local') ‖ bytes(E_dev' or empty)
//! ```
//!
//! # Parsing (untrusted input)
//!
//! The record is read back from a file anyone with the user's rights can change, so
//! [`DeviceRecord::parse`] treats it as untrusted: the total length is checked first
//! ([`MAX_DEVICE_STATE_LEN`]); the origin goes through the one origin parser of CRYPTO.md §2
//! and must already be canonical; `device_kind` is 1–3; each `kdf_id` is on the client
//! allow-list; each envelope is at most 256 bytes and parses as a symmetric envelope
//! (`rizzy_core::envelope::parse`); a `stage` or flag outside its values, a signup-pending
//! record without `E_local` or with a pending record, and a trailing byte are refused. One
//! state has one encoding: [`DeviceRecord::encode`] of a parsed record gives the input back.
//! A record version above 1 is [`ClientError::CacheUpdateRequired`]; everything else is
//! [`ClientError::CacheCorrupt`]. Nothing panics, and no error carries a byte of the record.
//! The fuzz target `client_device_state` runs the parser.
//!
//! # Secrets
//!
//! The record holds the Secret Key unwrapped (CRYPTO.md §4.2, until an OS keystore holds it):
//! [`DeviceRecord`] is not `Clone`, its `Debug` shows ids only, and the encoded bytes come in a
//! zeroizing buffer. The pending record holds the Secret Key that will be current after the
//! commit; the recovery code is never stored (CRYPTO.md §11 "Secrets before commit").
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md

use core::fmt;

use rizzy_core::encoding::{Reader, put_bytes, put_str, put_u8, put_u16, put_u32};
use rizzy_core::envelope::parse::{EnvelopeRef, parse as parse_envelope};
use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::DEVICE_SALT_LEN;
use rizzy_core::normalize::ServerOrigin;
use rizzy_core::secret_key::{CODE_LEN, SecretKey};
use rizzy_core::sign::DeviceKind;
use rizzy_proto::limits::MAX_KEY_ENVELOPE_LEN;
use zeroize::Zeroizing;

use crate::account::AccountPin;
use crate::device::{DeviceState, LocalWrap, OfflineUnlock, UnlockedDevice, offline_unlock};
use crate::error::{ClientError, internal};

/// The record version this build writes and reads (ADR 0026 §2).
pub const RECORD_VERSION: u16 = 1;

/// The most bytes of a device-state record, checked before anything is parsed (ADR 0026 §2).
pub const MAX_DEVICE_STATE_LEN: usize = 4096;

/// The stage of a device-state record (ADR 0026 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The enrolment is committed on the server.
    Committed,
    /// A signup whose `register/finish` has not been acknowledged (CRYPTO.md §11.1 step 7).
    /// The stored request is resent; nothing else runs in this stage.
    SignupPending,
}

impl Stage {
    /// The stage's byte in the record.
    const fn to_u8(self) -> u8 {
        match self {
            Self::Committed => 1,
            Self::SignupPending => 2,
        }
    }

    /// The stage of a record byte.
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Committed),
            2 => Some(Self::SignupPending),
            _ => None,
        }
    }
}

/// The pending record of CRYPTO.md §11 "Secrets before commit" step 3 (ADR 0026 §2): what the
/// device state becomes once the commit stored next to it (`pending_commit`) is acknowledged.
/// Holds a Secret Key; not `Clone`, `Debug` shows the epochs only.
pub struct PendingRecord {
    /// The Secret Key that is current after the commit.
    pub(crate) secret_key: SecretKey,
    /// The salt of the local Argon2id run after the commit.
    pub(crate) device_salt: [u8; DEVICE_SALT_LEN],
    /// The local `kdf_id` after the commit.
    pub(crate) kdf_id: KdfId,
    /// `E_local'`: the account key after the commit, under the local unlock key of the
    /// password that is current after the commit, with the epochs of its context.
    pub(crate) local_wrap: LocalWrap,
    /// `E_dev'` when the account key rotates; `None` (an empty byte string in the record) when
    /// `E_dev` stays.
    pub(crate) device_keys_wrap: Option<Vec<u8>>,
}

impl fmt::Debug for PendingRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingRecord")
            .field("account_key_epoch", &self.local_wrap.account_key_epoch)
            .field("password_epoch", &self.local_wrap.password_epoch)
            .finish_non_exhaustive()
    }
}

/// A device-state record (see the module docs). Not `Clone`; `Debug` shows ids and the stage
/// only.
pub struct DeviceRecord {
    /// Committed or signup-pending.
    pub(crate) stage: Stage,
    /// The origin this device is enrolled with.
    pub(crate) server_origin: ServerOrigin,
    /// The account.
    pub(crate) account_id: AccountId,
    /// This device.
    pub(crate) device_id: DeviceId,
    /// Its kind (1–3).
    pub(crate) device_kind: DeviceKind,
    /// The Secret Key.
    pub(crate) secret_key: SecretKey,
    /// The salt of the local Argon2id run.
    pub(crate) device_salt: [u8; DEVICE_SALT_LEN],
    /// The local `kdf_id`.
    pub(crate) kdf_id: KdfId,
    /// `E_dev`.
    pub(crate) device_keys_wrap: Vec<u8>,
    /// `E_local` with its context epochs; `None` is `has_local = 0`.
    pub(crate) local_wrap: Option<LocalWrap>,
    /// The pending record, if a commit is outstanding.
    pub(crate) pending: Option<PendingRecord>,
}

impl fmt::Debug for DeviceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceRecord")
            .field("stage", &self.stage)
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("has_local", &self.local_wrap.is_some())
            .field("pending", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

/// Reads one key envelope: at most [`MAX_KEY_ENVELOPE_LEN`] bytes, and a well-formed symmetric
/// envelope (`E_local` and `E_dev` are symmetric, CRYPTO.md §8.4).
fn key_envelope(reader: &mut Reader<'_>) -> Result<Vec<u8>, ClientError> {
    optional_key_envelope(reader)?.ok_or(ClientError::CacheCorrupt)
}

/// Reads `bytes(envelope or empty)`: `None` for the empty string, otherwise as
/// [`key_envelope`].
fn optional_key_envelope(reader: &mut Reader<'_>) -> Result<Option<Vec<u8>>, ClientError> {
    let bytes = reader
        .bytes_max(MAX_KEY_ENVELOPE_LEN)
        .map_err(|_| ClientError::CacheCorrupt)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    match parse_envelope(bytes) {
        Ok(EnvelopeRef::Symmetric(_)) => Ok(Some(bytes.to_vec())),
        _ => Err(ClientError::CacheCorrupt),
    }
}

/// Reads a flag byte that must be 0 or 1.
fn flag(reader: &mut Reader<'_>) -> Result<bool, ClientError> {
    match reader.u8() {
        Ok(0) => Ok(false),
        Ok(1) => Ok(true),
        _ => Err(ClientError::CacheCorrupt),
    }
}

/// Reads a `kdf_id` and checks it against the client allow-list (CRYPTO.md §6.2).
fn kdf_id(reader: &mut Reader<'_>) -> Result<KdfId, ClientError> {
    let raw = reader.u16().map_err(|_| ClientError::CacheCorrupt)?;
    KdfId::from_u16(raw).map_err(|_| ClientError::CacheCorrupt)
}

/// Reads a Secret Key and a device salt, in that order.
fn key_and_salt(
    reader: &mut Reader<'_>,
) -> Result<(SecretKey, [u8; DEVICE_SALT_LEN]), ClientError> {
    let bad = |_| ClientError::CacheCorrupt;
    let secret_key = SecretKey::from_slice(reader.array::<CODE_LEN>().map_err(bad)?)
        .map_err(|_| ClientError::CacheCorrupt)?;
    let salt = *reader.array::<DEVICE_SALT_LEN>().map_err(bad)?;
    Ok((secret_key, salt))
}

impl DeviceRecord {
    /// Parses a device-state record (see the module docs, "Parsing").
    ///
    /// # Errors
    /// [`ClientError::CacheUpdateRequired`] for a record version this build does not know;
    /// [`ClientError::CacheCorrupt`] for every other failure.
    pub fn parse(bytes: &[u8]) -> Result<Self, ClientError> {
        let bad = |_| ClientError::CacheCorrupt;
        if bytes.len() > MAX_DEVICE_STATE_LEN {
            return Err(ClientError::CacheCorrupt);
        }
        let mut reader = Reader::new(bytes);
        match reader.u16().map_err(bad)? {
            RECORD_VERSION => {}
            0 => return Err(ClientError::CacheCorrupt),
            _ => return Err(ClientError::CacheUpdateRequired),
        }
        let stage = Stage::from_u8(reader.u8().map_err(bad)?).ok_or(ClientError::CacheCorrupt)?;
        let origin_text = reader.str().map_err(bad)?;
        let server_origin =
            ServerOrigin::parse(origin_text).map_err(|_| ClientError::CacheCorrupt)?;
        // One state has one encoding: only the canonical spelling of the origin is accepted.
        if server_origin.as_str() != origin_text {
            return Err(ClientError::CacheCorrupt);
        }
        let account_id = AccountId::from_bytes(*reader.array().map_err(bad)?);
        let device_id = DeviceId::from_bytes(*reader.array().map_err(bad)?);
        let device_kind = DeviceKind::from_u8(reader.u8().map_err(bad)?)
            .ok()
            .filter(|kind| kind.is_durable())
            .ok_or(ClientError::CacheCorrupt)?;
        let (secret_key, device_salt) = key_and_salt(&mut reader)?;
        let kdf = kdf_id(&mut reader)?;
        let device_keys_wrap = key_envelope(&mut reader)?;
        let local_wrap = if flag(&mut reader)? {
            let account_key_epoch = reader.u32().map_err(bad)?;
            let password_epoch = reader.u32().map_err(bad)?;
            Some(LocalWrap {
                envelope: key_envelope(&mut reader)?,
                account_key_epoch,
                password_epoch,
            })
        } else {
            None
        };
        let pending = if flag(&mut reader)? {
            let (secret_key, device_salt) = key_and_salt(&mut reader)?;
            let kdf_id = kdf_id(&mut reader)?;
            let account_key_epoch = reader.u32().map_err(bad)?;
            let password_epoch = reader.u32().map_err(bad)?;
            let envelope = key_envelope(&mut reader)?;
            // `bytes(E_dev' or empty)`: an empty string means `E_dev` stays.
            let device_keys_wrap = optional_key_envelope(&mut reader)?;
            Some(PendingRecord {
                secret_key,
                device_salt,
                kdf_id,
                local_wrap: LocalWrap {
                    envelope,
                    account_key_epoch,
                    password_epoch,
                },
                device_keys_wrap,
            })
        } else {
            None
        };
        reader.finish().map_err(bad)?;
        if stage == Stage::SignupPending && (local_wrap.is_none() || pending.is_some()) {
            return Err(ClientError::CacheCorrupt);
        }
        Ok(Self {
            stage,
            server_origin,
            account_id,
            device_id,
            device_kind,
            secret_key,
            device_salt,
            kdf_id: kdf,
            device_keys_wrap,
            local_wrap,
            pending,
        })
    }

    /// Encodes the record (the inverse of [`DeviceRecord::parse`]). The bytes hold the Secret
    /// Key, so they come in a buffer wiped on drop; the host writes them to its store and
    /// nowhere else.
    ///
    /// # Errors
    /// [`ClientError::Internal`] if the record breaks a rule the parser enforces (a
    /// signup-pending record without `E_local` or with a pending record, an over-long
    /// envelope, a record above [`MAX_DEVICE_STATE_LEN`]): no such record is written.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ClientError> {
        if self.stage == Stage::SignupPending
            && (self.local_wrap.is_none() || self.pending.is_some())
        {
            return Err(ClientError::Internal);
        }
        let envelope = |out: &mut Vec<u8>, bytes: &[u8]| {
            if bytes.len() > MAX_KEY_ENVELOPE_LEN {
                return Err(ClientError::Internal);
            }
            put_bytes(out, bytes).map_err(internal)
        };
        let mut out = Zeroizing::new(Vec::with_capacity(512));
        put_u16(&mut out, RECORD_VERSION);
        put_u8(&mut out, self.stage.to_u8());
        put_str(&mut out, self.server_origin.as_str()).map_err(internal)?;
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(self.device_id.as_bytes());
        put_u8(&mut out, self.device_kind.to_u8());
        out.extend_from_slice(self.secret_key.expose_secret());
        out.extend_from_slice(&self.device_salt);
        put_u16(&mut out, self.kdf_id.get());
        envelope(&mut out, &self.device_keys_wrap)?;
        match &self.local_wrap {
            None => put_u8(&mut out, 0),
            Some(local) => {
                put_u8(&mut out, 1);
                put_u32(&mut out, local.account_key_epoch);
                put_u32(&mut out, local.password_epoch);
                envelope(&mut out, &local.envelope)?;
            }
        }
        match &self.pending {
            None => put_u8(&mut out, 0),
            Some(pending) => {
                put_u8(&mut out, 1);
                out.extend_from_slice(pending.secret_key.expose_secret());
                out.extend_from_slice(&pending.device_salt);
                put_u16(&mut out, pending.kdf_id.get());
                put_u32(&mut out, pending.local_wrap.account_key_epoch);
                put_u32(&mut out, pending.local_wrap.password_epoch);
                envelope(&mut out, &pending.local_wrap.envelope)?;
                match &pending.device_keys_wrap {
                    Some(wrap) if !wrap.is_empty() => envelope(&mut out, wrap)?,
                    Some(_) => return Err(ClientError::Internal),
                    None => put_bytes(&mut out, &[]).map_err(internal)?,
                }
            }
        }
        if out.len() > MAX_DEVICE_STATE_LEN {
            return Err(ClientError::Internal);
        }
        Ok(out)
    }

    /// The stage.
    #[must_use]
    pub const fn stage(&self) -> Stage {
        self.stage
    }

    /// The account.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// This device.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The origin this device is enrolled with.
    #[must_use]
    pub const fn server_origin(&self) -> &ServerOrigin {
        &self.server_origin
    }

    /// Whether the record holds `E_local` (`has_local = 1`).
    #[must_use]
    pub const fn has_local(&self) -> bool {
        self.local_wrap.is_some()
    }

    /// Whether a pending record is present (a commit is outstanding).
    #[must_use]
    pub const fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// The Secret Key as the Emergency Kit prints it, for the re-authentication a rotation or
    /// a resend of the pending commit needs (the login takes the typed form). A secret: never
    /// log it.
    #[must_use]
    pub fn secret_key_text(&self) -> Zeroizing<String> {
        self.secret_key.to_formatted()
    }

    /// The offline unlock from this record (CRYPTO.md §5.6; ADR 0026 §4 step 5).
    ///
    /// # Errors
    /// [`ClientError::SignupPending`] in stage 2 and [`ClientError::LocalUnlockUnavailable`]
    /// without `E_local`: neither state unlocks (ADR 0026 §2);
    /// [`ClientError::WrongPasswordOrSecretKey`]; [`ClientError::CacheCorrupt`] when `E_dev`
    /// does not open; [`ClientError::InvalidInput`]; [`ClientError::Internal`].
    pub fn unlock(&self, password: &str) -> Result<UnlockedDevice, ClientError> {
        if self.stage == Stage::SignupPending {
            return Err(ClientError::SignupPending);
        }
        let local_wrap = self
            .local_wrap
            .as_ref()
            .ok_or(ClientError::LocalUnlockUnavailable)?;
        offline_unlock(
            password,
            &OfflineUnlock {
                account_id: self.account_id,
                device_id: self.device_id,
                secret_key: &self.secret_key,
                device_salt: &self.device_salt,
                kdf_id: self.kdf_id,
                local_wrap,
                device_keys_wrap: &self.device_keys_wrap,
            },
        )
    }

    /// The offline unlock from the **pending** record: the keys this device holds once the
    /// outstanding commit is applied (CRYPTO.md §11 "Secrets before commit": "On restart with a
    /// pending record, the client fetches `account-state`: if the server holds the new state
    /// it finalises").
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] without a pending record; otherwise as
    /// [`DeviceRecord::unlock`].
    pub fn unlock_pending(&self, password: &str) -> Result<UnlockedDevice, ClientError> {
        let pending = self.pending.as_ref().ok_or(ClientError::InvalidInput)?;
        offline_unlock(
            password,
            &OfflineUnlock {
                account_id: self.account_id,
                device_id: self.device_id,
                secret_key: &pending.secret_key,
                device_salt: &pending.device_salt,
                kdf_id: pending.kdf_id,
                local_wrap: &pending.local_wrap,
                device_keys_wrap: pending
                    .device_keys_wrap
                    .as_deref()
                    .unwrap_or(&self.device_keys_wrap),
            },
        )
    }

    /// This record with `pending` stored in it (CRYPTO.md §11 step 3), replacing any earlier
    /// pending record.
    #[must_use]
    pub fn with_pending(mut self, pending: PendingRecord) -> Self {
        self.pending = Some(pending);
        self
    }

    /// Finalises the record after the commit was acknowledged (CRYPTO.md §11 step 5): the
    /// pending Secret Key, salt, `kdf_id`, `E_local'` and `E_dev'` become the record's, in one
    /// value, so they cannot disagree (ADR 0026 §2 "`E_local` lifecycle"). Without a pending
    /// record the record is returned unchanged.
    #[must_use]
    pub fn promote_pending(mut self) -> Self {
        if let Some(pending) = self.pending.take() {
            self.secret_key = pending.secret_key;
            self.device_salt = pending.device_salt;
            self.kdf_id = pending.kdf_id;
            self.local_wrap = Some(pending.local_wrap);
            if let Some(wrap) = pending.device_keys_wrap {
                self.device_keys_wrap = wrap;
            }
        }
        self
    }

    /// This record without its pending record: the commit was refused for good and its new
    /// keys are abandoned.
    #[must_use]
    pub fn without_pending(mut self) -> Self {
        self.pending = None;
        self
    }

    /// This record as committed (`stage = 1`), after the server acknowledged the signup
    /// (CRYPTO.md §11.1 step 9).
    #[must_use]
    pub const fn committed(mut self) -> Self {
        self.stage = Stage::Committed;
        self
    }

    /// The in-memory device state of this record with `pin`, the pin rebuilt from the cache's
    /// account objects (ADR 0026 §4 step 5). A pending record is not carried: the host keeps
    /// the record it parsed until the commit is settled.
    ///
    /// # Errors
    /// [`ClientError::LocalUnlockUnavailable`] without `E_local`;
    /// [`ClientError::CacheCorrupt`] if the pin is another account's; [`ClientError::Internal`].
    pub fn to_state(&self, pin: AccountPin) -> Result<DeviceState, ClientError> {
        let local_wrap = self
            .local_wrap
            .clone()
            .ok_or(ClientError::LocalUnlockUnavailable)?;
        if pin.state.account_id != self.account_id {
            return Err(ClientError::CacheCorrupt);
        }
        Ok(DeviceState {
            server_origin: self.server_origin.clone(),
            account_id: self.account_id,
            device_id: self.device_id,
            device_kind: self.device_kind,
            secret_key: SecretKey::from_slice(self.secret_key.expose_secret()).map_err(internal)?,
            device_salt: self.device_salt,
            kdf_id: self.kdf_id,
            local_wrap,
            device_keys_wrap: self.device_keys_wrap.clone(),
            pin,
        })
    }
}
