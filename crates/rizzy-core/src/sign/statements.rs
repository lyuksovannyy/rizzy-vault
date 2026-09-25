//! The signed statements of CRYPTO.md §10.2, except the key bundle ([`super::bundle`]).
//!
//! | Statement | Body | Signed by |
//! |---|---|---|
//! | [`DeviceCertificate`] | `account_id ‖ device_id ‖ u32 identity_epoch ‖ device Ed25519 pk ‖ device X25519 pk ‖ u8 device_kind ‖ u64 created_at_ms ‖ u64 expires_at_ms` | identity key of that `identity_epoch` |
//! | [`DeviceRevocation`] | `account_id ‖ device_id ‖ u64 last_accepted_device_seq ‖ u64 revoked_at_ms` | identity key |
//! | [`AccountState`] | `account_id ‖ u64 state_seq ‖ u32 identity_epoch ‖ u32 account_key_epoch ‖ account_key_id ‖ u32 password_epoch ‖ u16 kdf_id ‖ u32 recovery_epoch ‖ u8 recovery_enabled ‖ u8 sync_mode ‖ u32 mail_key_epoch ‖ bundle_hash ‖ device_set_hash ‖ u64 settings_seq ‖ settings_hash` | identity key of the state's `identity_epoch` |
//! | [`OpStatement`] | `bytes(canonical op header) ‖ SHA-256(op envelope) ‖ SHA-256(ITEM_KEY_WRAP envelope) or 32 zero bytes` | device key |
//! | [`SnapshotStatement`] | the same, with the canonical snapshot header and envelope | device key |
//! | [`KeyGrant`] | `u16(purpose) ‖ sender public key id ‖ recipient public key id ‖ bytes(hpke_envelope)` (§10.1) | device key, or identity key |
//! | [`DeviceAuth`] | `str(server_origin) ‖ account_id ‖ device_id ‖ challenge` (§5.10) | device key |
//! | [`DeviceRequest`] | `str(server_origin) ‖ account_id ‖ device_id ‖ session_id ‖ u64 request_counter ‖ str(method) ‖ str(path_and_query) ‖ SHA-256(request body)` (§5.10) | device key |
//!
//! **Canonical op and snapshot headers.** [ADR 0012] §3 defines both layouts, and §13 places
//! the op and snapshot record formats in `rizzy-sync`. This module therefore takes each header
//! as an opaque canonical byte string. It only bounds its length by the ADR 0012 layout: the
//! fixed part (97 bytes for an op, 73 for a snapshot) plus at most `u16::MAX` version-vector
//! entries of 24 bytes. The caller (`rizzy-sync`) parses the header and picks the verifying key
//! from the certificate of the device the header names.
//!
//! [ADR 0012]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0012-sync-engine.md

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::{
    DeviceSigningKey, DeviceVerifyingKey, IdentitySigningKey, IdentityVerifyingKey,
    SignatureContainer, SignerRole, SigningKey, Statement, Verified, VerifyingKey, sign_single,
    signed_message, verify_single,
};
use crate::encoding::{Reader, put_bytes, put_str, put_u8, put_u16, put_u32, put_u64};
use crate::envelope::Purpose;
use crate::envelope::parse::{self, EnvelopeRef, HPKE_OVERHEAD};
use crate::envelope::symmetric::MAX_PLAINTEXT_LEN;
use crate::error::{EncodeError, ParseError, SignError, VerifyError};
use crate::hpke::HpkePublicKey;
use crate::ids::{
    AccountId, DeviceId, ID_LEN, PUBLIC_KEY_LEN, PublicKeyId, SessionId, SymmetricKeyId,
};
use crate::kdf::KdfId;
use crate::labels;

/// Upper bound of a web-vault (`device_kind` 4) certificate's lifetime: 12 h in milliseconds
/// (§10.2, §11.4).
pub const WEB_CERT_MAX_LIFETIME_MS: u64 = 12 * 60 * 60 * 1000;

/// Length of a `SHA-256` output.
const HASH_LEN: usize = 32;

/// `device_kind` (§10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DeviceKind {
    /// 1: desktop app or CLI.
    DesktopCli = 1,
    /// 2: browser extension.
    Extension = 2,
    /// 3: mobile app.
    Mobile = 3,
    /// 4: web vault, ephemeral. Never in the device set; its certificate expires within 12 h.
    WebEphemeral = 4,
}

impl DeviceKind {
    /// The `u8` encoding.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Parses a `device_kind` byte.
    ///
    /// # Errors
    /// [`ParseError::InvalidValue`] for anything other than 1–4.
    pub const fn from_u8(value: u8) -> Result<Self, ParseError> {
        match value {
            1 => Ok(Self::DesktopCli),
            2 => Ok(Self::Extension),
            3 => Ok(Self::Mobile),
            4 => Ok(Self::WebEphemeral),
            _ => Err(ParseError::InvalidValue),
        }
    }

    /// Durable devices (kinds 1–3) are in the signed device set; the web vault (kind 4) never
    /// is (§10.2).
    #[must_use]
    pub const fn is_durable(self) -> bool {
        !matches!(self, Self::WebEphemeral)
    }
}

// ---------------------------------------------------------------------------------------------
// device-certificate
// ---------------------------------------------------------------------------------------------

/// `device-certificate` (§10.2), signed by the identity key of its `identity_epoch`.
///
/// Rules, checked when signing and when verifying:
/// - `device_kind` is 1–4;
/// - a non-zero `expires_at_ms` must be later than `created_at_ms` (a certificate that expires
///   before it is created is not something a conforming writer produces);
/// - kind 4 must expire (`expires_at_ms ≠ 0`) and at most 12 h after `created_at_ms`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCertificate {
    /// The account.
    pub account_id: AccountId,
    /// The device.
    pub device_id: DeviceId,
    /// The identity epoch whose identity key signs this certificate.
    pub identity_epoch: u32,
    /// The device's Ed25519 key: ops, snapshots, grants, device authentication.
    pub device_ed25519: DeviceVerifyingKey,
    /// The device's X25519 key: the recipient of device grants.
    pub device_x25519: HpkePublicKey,
    /// The kind of device.
    pub device_kind: DeviceKind,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_ms: u64,
    /// Expiry, milliseconds since the Unix epoch; 0 means none.
    pub expires_at_ms: u64,
}

impl DeviceCertificate {
    const BODY_LEN: usize = 2 * ID_LEN + 4 + 2 * PUBLIC_KEY_LEN + 1 + 8 + 8;

    fn validate(&self) -> Result<(), ParseError> {
        if self.expires_at_ms != 0 && self.expires_at_ms <= self.created_at_ms {
            return Err(ParseError::InvalidValue);
        }
        if self.device_kind == DeviceKind::WebEphemeral {
            let latest = self
                .created_at_ms
                .checked_add(WEB_CERT_MAX_LIFETIME_MS)
                .ok_or(ParseError::InvalidValue)?;
            if self.expires_at_ms == 0 || self.expires_at_ms > latest {
                return Err(ParseError::InvalidValue);
            }
        }
        Ok(())
    }

    /// Signs the certificate with the identity key.
    ///
    /// # Errors
    /// [`SignError::Encode`] if a rule above is broken.
    pub fn sign(&self, identity: &IdentitySigningKey) -> Result<Vec<u8>, SignError> {
        sign_single(self, identity)
    }

    /// Verifies a certificate under the identity key of `identity_epoch`.
    ///
    /// Pass the identity key of the **current** `identity_epoch` when accepting ops from a
    /// kind-4 device (§10.2 rule (a)); a full rotation re-issues every certificate under the
    /// new key (§11.6 step 7).
    ///
    /// # Errors
    /// [`VerifyError`]; [`VerifyError::Mismatch`] if the certificate names another
    /// `identity_epoch`.
    pub fn verify(
        wire: &[u8],
        identity: &IdentityVerifyingKey,
        identity_epoch: u32,
    ) -> Result<Verified<Self>, VerifyError> {
        let verified: Verified<Self> = verify_single(wire, identity)?;
        if verified.identity_epoch != identity_epoch {
            return Err(VerifyError::Mismatch);
        }
        Ok(verified)
    }

    /// Whether this device belongs in the signed device set: kinds 1–3 (§10.2).
    #[must_use]
    pub const fn in_device_set(&self) -> bool {
        self.device_kind.is_durable()
    }

    /// Whether an op or snapshot with this `hlc`, read as milliseconds (its top 48 bits), falls
    /// within the certificate's validity: `hlc_ms ≤ expires_at_ms`, or no expiry (§10.2 rule
    /// (c) for kind 4).
    ///
    /// The rule is written for kind 4. A durable certificate with an expiry is treated the same
    /// way, which is the conservative reading.
    #[must_use]
    pub const fn permits_hlc(&self, hlc: u64) -> bool {
        self.expires_at_ms == 0 || (hlc >> 16) <= self.expires_at_ms
    }
}

impl Statement for DeviceCertificate {
    const LABEL: labels::Label = labels::SIG_DEVICE_CERTIFICATE;
    const MAX_BODY_LEN: usize = Self::BODY_LEN;

    fn encode_body(&self) -> Result<Vec<u8>, EncodeError> {
        self.validate().map_err(|_| EncodeError::InvalidField)?;
        let mut out = Vec::with_capacity(Self::BODY_LEN);
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(self.device_id.as_bytes());
        put_u32(&mut out, self.identity_epoch);
        out.extend_from_slice(self.device_ed25519.as_bytes());
        out.extend_from_slice(self.device_x25519.as_bytes());
        put_u8(&mut out, self.device_kind.to_u8());
        put_u64(&mut out, self.created_at_ms);
        put_u64(&mut out, self.expires_at_ms);
        Ok(out)
    }

    fn decode_body(body: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(body);
        let cert = Self {
            account_id: AccountId::from_bytes(*r.array()?),
            device_id: DeviceId::from_bytes(*r.array()?),
            identity_epoch: r.u32()?,
            device_ed25519: DeviceVerifyingKey::from_bytes(r.array()?)?,
            device_x25519: HpkePublicKey::x25519(*r.array()?),
            device_kind: DeviceKind::from_u8(r.u8()?)?,
            created_at_ms: r.u64()?,
            expires_at_ms: r.u64()?,
        };
        r.finish()?;
        cert.validate()?;
        Ok(cert)
    }
}

// ---------------------------------------------------------------------------------------------
// device-revocation
// ---------------------------------------------------------------------------------------------

/// `device-revocation` (§10.2, §11.8), signed by the identity key.
///
/// The body names no identity epoch, so the verifier must pass the identity key of the current
/// `identity_epoch`: after a full rotation, revocations signed only by a superseded key are
/// rejected (§10.2, INV-30), and the rotation re-issues them under the new key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceRevocation {
    /// The account.
    pub account_id: AccountId,
    /// The revoked device.
    pub device_id: DeviceId,
    /// The highest `device_seq` of the revoked device that peers still accept.
    pub last_accepted_device_seq: u64,
    /// Revocation time, milliseconds since the Unix epoch.
    pub revoked_at_ms: u64,
}

impl DeviceRevocation {
    const BODY_LEN: usize = 2 * ID_LEN + 8 + 8;

    /// Signs the revocation with the identity key.
    ///
    /// # Errors
    /// [`SignError`] (unreachable for this fixed layout).
    pub fn sign(&self, identity: &IdentitySigningKey) -> Result<Vec<u8>, SignError> {
        sign_single(self, identity)
    }

    /// Verifies a revocation under the current identity key.
    ///
    /// # Errors
    /// [`VerifyError`].
    pub fn verify(
        wire: &[u8],
        identity: &IdentityVerifyingKey,
    ) -> Result<Verified<Self>, VerifyError> {
        verify_single(wire, identity)
    }

    /// Whether an op with this `device_seq` from the revoked device is still accepted:
    /// `device_seq ≤ last_accepted_device_seq` (§11.8 step 4).
    #[must_use]
    pub const fn permits_device_seq(&self, device_seq: u64) -> bool {
        device_seq <= self.last_accepted_device_seq
    }
}

impl Statement for DeviceRevocation {
    const LABEL: labels::Label = labels::SIG_DEVICE_REVOCATION;
    const MAX_BODY_LEN: usize = Self::BODY_LEN;

    fn encode_body(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(Self::BODY_LEN);
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(self.device_id.as_bytes());
        put_u64(&mut out, self.last_accepted_device_seq);
        put_u64(&mut out, self.revoked_at_ms);
        Ok(out)
    }

    fn decode_body(body: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(body);
        let revocation = Self {
            account_id: AccountId::from_bytes(*r.array()?),
            device_id: DeviceId::from_bytes(*r.array()?),
            last_accepted_device_seq: r.u64()?,
            revoked_at_ms: r.u64()?,
        };
        r.finish()?;
        Ok(revocation)
    }
}

// ---------------------------------------------------------------------------------------------
// account-state
// ---------------------------------------------------------------------------------------------

/// `sync_mode` in `account-state` (§10.2). 0 and every other value are rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SyncMode {
    /// 1: Server mode.
    Server = 1,
    /// 2: On-device mode (M4).
    OnDevice = 2,
}

impl SyncMode {
    /// Parses a `sync_mode` byte.
    ///
    /// # Errors
    /// [`ParseError::InvalidValue`] for anything other than 1 or 2.
    pub const fn from_u8(value: u8) -> Result<Self, ParseError> {
        match value {
            1 => Ok(Self::Server),
            2 => Ok(Self::OnDevice),
            _ => Err(ParseError::InvalidValue),
        }
    }

    /// The `u8` encoding.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// `account-state` (§10.2), signed by the identity key of the state's own `identity_epoch`.
///
/// Rules, checked when signing and when verifying:
/// - `state_seq ≥ 1` (it is 1 at signup, §4.4);
/// - `recovery_enabled` is 0 or 1, and 1 requires `recovery_epoch ≥ 1` (0 means no code was
///   ever issued, §4.4);
/// - `sync_mode` is 1 or 2;
/// - `kdf_id` is on this client's allow-list ([`KdfId`]); anything else fails closed;
/// - `settings_hash` is 32 zero bytes exactly when `settings_seq = 0` (§4.3, §10.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountState {
    /// The account.
    pub account_id: AccountId,
    /// Sequence number of this state; compare-and-swap key.
    pub state_seq: u64,
    /// Current identity epoch.
    pub identity_epoch: u32,
    /// Current account-key epoch.
    pub account_key_epoch: u32,
    /// Symmetric key id of the current account key (§4.4).
    pub account_key_id: SymmetricKeyId,
    /// Current password epoch.
    pub password_epoch: u32,
    /// `kdf_id` of the current password registration.
    pub kdf_id: KdfId,
    /// Current recovery epoch; 0 means no recovery code was ever issued.
    pub recovery_epoch: u32,
    /// Whether a recovery code is valid now.
    pub recovery_enabled: bool,
    /// Sync mode.
    pub sync_mode: SyncMode,
    /// Current mail-key epoch (M6); 0 means no mail key yet.
    pub mail_key_epoch: u32,
    /// `SHA-256` of the current key bundle's signed message.
    pub bundle_hash: [u8; HASH_LEN],
    /// The device-set hash ([`crate::keys::device_set_hash`]).
    pub device_set_hash: [u8; HASH_LEN],
    /// Current settings sequence number; 0 while no `ACCOUNT_SETTINGS` exists.
    pub settings_seq: u64,
    /// `SHA-256` of the current `ACCOUNT_SETTINGS` envelope, or 32 zero bytes while
    /// `settings_seq = 0`.
    pub settings_hash: [u8; HASH_LEN],
}

/// What the loser of an `account-state` compare-and-swap does (§10.2 "Device set").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CasRetry {
    /// Only `state_seq` and `device_set_hash` changed: re-apply the change on top of the
    /// current state and retry.
    Reapply,
    /// Anything else changed (an epoch, `kdf_id`, `bundle_hash`, `settings_seq`,
    /// `account_key_id`, or any other field): restart the flow.
    Restart,
    /// The server's state is older than the one the change was built on: a rollback. Warn and
    /// go read-only (§11.3 step 2.5).
    Rollback,
}

impl AccountState {
    const BODY_LEN: usize =
        ID_LEN + 8 + 4 + 4 + ID_LEN + 4 + 2 + 4 + 1 + 1 + 4 + HASH_LEN + HASH_LEN + 8 + HASH_LEN;

    fn validate(&self) -> Result<(), ParseError> {
        let settings_hash_is_zero = self.settings_hash == [0u8; HASH_LEN];
        if self.state_seq == 0
            || (self.recovery_enabled && self.recovery_epoch == 0)
            || (self.settings_seq == 0) != settings_hash_is_zero
        {
            return Err(ParseError::InvalidValue);
        }
        Ok(())
    }

    /// Signs the state with the identity key of `self.identity_epoch`: after a full rotation,
    /// the **new** key (§10.2).
    ///
    /// # Errors
    /// [`SignError::Encode`] if a rule above is broken.
    pub fn sign(&self, identity: &IdentitySigningKey) -> Result<Vec<u8>, SignError> {
        sign_single(self, identity)
    }

    /// Verifies a state under the identity key of `identity_epoch`.
    ///
    /// # Errors
    /// [`VerifyError`]; [`VerifyError::Mismatch`] if the state names another
    /// `identity_epoch`.
    pub fn verify(
        wire: &[u8],
        identity: &IdentityVerifyingKey,
        identity_epoch: u32,
    ) -> Result<Verified<Self>, VerifyError> {
        let verified: Verified<Self> = verify_single(wire, identity)?;
        if verified.identity_epoch != identity_epoch {
            return Err(VerifyError::Mismatch);
        }
        Ok(verified)
    }

    /// Decides what to do after losing a compare-and-swap on `state_seq` (§10.2). `self` is the
    /// state the change was built on; `current` is the state re-fetched and re-verified from
    /// the server.
    ///
    /// [`CasRetry::Reapply`] only if every field other than `state_seq` and `device_set_hash`
    /// is unchanged and `current` is not older. Equal `state_seq` with other content is a fork
    /// of the signed state and restarts.
    #[must_use]
    pub fn cas_retry(&self, current: &Self) -> CasRetry {
        if current.state_seq < self.state_seq {
            return CasRetry::Rollback;
        }
        let mut probe = current.clone();
        probe.state_seq = self.state_seq;
        probe.device_set_hash = self.device_set_hash;
        if probe == *self {
            CasRetry::Reapply
        } else {
            CasRetry::Restart
        }
    }

    /// Whether this state goes backwards against the highest values this device persisted:
    /// a lower `state_seq` or `settings_seq` is a possible server rollback (§11.3 step 2.5,
    /// INV-25).
    #[must_use]
    pub const fn is_rollback(&self, persisted_state_seq: u64, persisted_settings_seq: u64) -> bool {
        self.state_seq < persisted_state_seq || self.settings_seq < persisted_settings_seq
    }

    /// Whether `bundle` is the bundle this state commits to: same account, same
    /// `identity_epoch`, and `bundle_hash = SHA-256` of the bundle's signed message
    /// (§11.2 step 6).
    #[must_use]
    pub fn matches_bundle(&self, bundle: &super::VerifiedBundle) -> bool {
        self.account_id == bundle.account_id
            && self.identity_epoch == bundle.identity_epoch
            && bool::from(self.bundle_hash.ct_eq(bundle.hash()))
    }

    /// Whether the served `ACCOUNT_SETTINGS` envelope (or its absence) is the one this state
    /// commits to (§10.2 "Settings freshness").
    #[must_use]
    pub fn matches_settings(&self, settings_envelope: Option<&[u8]>) -> bool {
        crate::keys::settings_hash(self.settings_seq, settings_envelope)
            .is_some_and(|h| bool::from(h.ct_eq(&self.settings_hash)))
    }

    /// Whether `account_key` is the current account key: same epoch, and its derived key id is
    /// `account_key_id` (§11.2 step 6, §11.3 step 4).
    #[must_use]
    pub fn matches_account_key(&self, account_key: &crate::keys::AccountKey) -> bool {
        account_key.epoch() == self.account_key_epoch
            && account_key
                .key_id()
                .is_ok_and(|id| id == self.account_key_id)
    }
}

impl Statement for AccountState {
    const LABEL: labels::Label = labels::SIG_ACCOUNT_STATE;
    const MAX_BODY_LEN: usize = Self::BODY_LEN;

    fn encode_body(&self) -> Result<Vec<u8>, EncodeError> {
        self.validate().map_err(|_| EncodeError::InvalidField)?;
        let mut out = Vec::with_capacity(Self::BODY_LEN);
        out.extend_from_slice(self.account_id.as_bytes());
        put_u64(&mut out, self.state_seq);
        put_u32(&mut out, self.identity_epoch);
        put_u32(&mut out, self.account_key_epoch);
        out.extend_from_slice(self.account_key_id.as_bytes());
        put_u32(&mut out, self.password_epoch);
        put_u16(&mut out, self.kdf_id.get());
        put_u32(&mut out, self.recovery_epoch);
        put_u8(&mut out, u8::from(self.recovery_enabled));
        put_u8(&mut out, self.sync_mode.to_u8());
        put_u32(&mut out, self.mail_key_epoch);
        out.extend_from_slice(&self.bundle_hash);
        out.extend_from_slice(&self.device_set_hash);
        put_u64(&mut out, self.settings_seq);
        out.extend_from_slice(&self.settings_hash);
        Ok(out)
    }

    fn decode_body(body: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(body);
        let state = Self {
            account_id: AccountId::from_bytes(*r.array()?),
            state_seq: r.u64()?,
            identity_epoch: r.u32()?,
            account_key_epoch: r.u32()?,
            account_key_id: SymmetricKeyId::from_bytes(*r.array()?),
            password_epoch: r.u32()?,
            kdf_id: KdfId::from_u16(r.u16()?).map_err(|_| ParseError::InvalidValue)?,
            recovery_epoch: r.u32()?,
            recovery_enabled: match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(ParseError::InvalidValue),
            },
            sync_mode: SyncMode::from_u8(r.u8()?)?,
            mail_key_epoch: r.u32()?,
            bundle_hash: *r.array()?,
            device_set_hash: *r.array()?,
            settings_seq: r.u64()?,
            settings_hash: *r.array()?,
        };
        r.finish()?;
        state.validate()?;
        Ok(state)
    }
}

// ---------------------------------------------------------------------------------------------
// op and snapshot
// ---------------------------------------------------------------------------------------------

/// Length of one version-vector entry in an ADR 0012 header: `device_id ‖ u64 seq`.
pub const VV_ENTRY_LEN: usize = ID_LEN + 8;

/// Smallest canonical op header (ADR 0012 §3): `u8 header_version ‖ vault_id ‖ item_id ‖
/// op_id ‖ device_id ‖ u64 device_seq ‖ u64 vault_prev_seq ‖ u64 hlc ‖ u16 item_schema_version
/// ‖ u32 vault_key_epoch ‖ u16 n`, with an empty causal context.
pub const OP_HEADER_MIN_LEN: usize = 1 + 4 * ID_LEN + 8 + 8 + 8 + 2 + 4 + 2;

/// Largest canonical op header: `u16::MAX` causal-context entries.
pub const OP_HEADER_MAX_LEN: usize = OP_HEADER_MIN_LEN + u16::MAX as usize * VV_ENTRY_LEN;

/// Smallest canonical snapshot header (ADR 0012 §3): `u8 header_version ‖ vault_id ‖ item_id ‖
/// snapshot_id ‖ author device_id ‖ u16 item_schema_version ‖ u32 vault_key_epoch ‖ u16 n`,
/// with an empty covered version vector.
pub const SNAPSHOT_HEADER_MIN_LEN: usize = 1 + 4 * ID_LEN + 2 + 4 + 2;

/// Largest canonical snapshot header: `u16::MAX` version-vector entries.
pub const SNAPSHOT_HEADER_MAX_LEN: usize =
    SNAPSHOT_HEADER_MIN_LEN + u16::MAX as usize * VV_ENTRY_LEN;

const _: () = assert!(OP_HEADER_MIN_LEN == 97 && SNAPSHOT_HEADER_MIN_LEN == 73);

/// Defines the `op` and `snapshot` statements, which share one hashed layout (§10.2).
macro_rules! record_statement {
    (
        $(#[$doc:meta])*
        $name:ident, $label:expr, $min:expr, $max:expr, $what:literal
    ) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name {
            header: Vec<u8>,
            envelope_hash: [u8; HASH_LEN],
            wrap_hash: Option<[u8; HASH_LEN]>,
        }

        impl $name {
            #[doc = concat!("Builds the statement over the canonical ", $what, " header, the ",
                $what, " envelope and the `ITEM_KEY_WRAP` envelope carried with it, if any.")]
            ///
            /// # Errors
            /// [`EncodeError::InvalidField`] if the header length is outside the ADR 0012
            /// bounds.
            pub fn new(
                canonical_header: &[u8],
                envelope: &[u8],
                item_key_wrap: Option<&[u8]>,
            ) -> Result<Self, EncodeError> {
                if !($min..=$max).contains(&canonical_header.len()) {
                    return Err(EncodeError::InvalidField);
                }
                Ok(Self {
                    header: canonical_header.to_vec(),
                    envelope_hash: Sha256::digest(envelope).into(),
                    wrap_hash: item_key_wrap.map(|w| Sha256::digest(w).into()),
                })
            }

            #[doc = concat!("The canonical ", $what, " header, as signed.")]
            #[must_use]
            pub fn header(&self) -> &[u8] {
                &self.header
            }

            #[doc = concat!("`SHA-256` of the canonical ", $what, " header: the last field of \
                the envelope's AAD context.")]
            #[must_use]
            pub fn header_hash(&self) -> [u8; HASH_LEN] {
                Sha256::digest(&self.header).into()
            }

            #[doc = concat!("The signed `SHA-256` of the ", $what, " envelope.")]
            #[must_use]
            pub const fn envelope_hash(&self) -> &[u8; HASH_LEN] {
                &self.envelope_hash
            }

            /// The signed `SHA-256` of the carried `ITEM_KEY_WRAP` envelope; `None` when the
            /// record carries no wrap (encoded as 32 zero bytes).
            #[must_use]
            pub const fn wrap_hash(&self) -> Option<&[u8; HASH_LEN]> {
                self.wrap_hash.as_ref()
            }

            #[doc = concat!("Whether `envelope` is the signed ", $what, " envelope. A receiver \
                checks this before anything else (§10.2).")]
            #[must_use]
            pub fn matches_envelope(&self, envelope: &[u8]) -> bool {
                let h: [u8; HASH_LEN] = Sha256::digest(envelope).into();
                h.ct_eq(&self.envelope_hash).into()
            }

            /// Whether `wrap` is the signed `ITEM_KEY_WRAP` envelope. Always `false` when the
            /// record signed none. A delivered wrap that does not match is ignored (§11.6).
            #[must_use]
            pub fn matches_wrap(&self, wrap: &[u8]) -> bool {
                let h: [u8; HASH_LEN] = Sha256::digest(wrap).into();
                self.wrap_hash.is_some_and(|w| bool::from(h.ct_eq(&w)))
            }

            /// Signs the statement with the authoring device's key.
            ///
            /// # Errors
            /// [`SignError`] (the header bounds were checked by [`Self::new`]).
            pub fn sign(&self, device: &DeviceSigningKey) -> Result<Vec<u8>, SignError> {
                sign_single(self, device)
            }

            #[doc = concat!("Verifies the statement under the key of the device that the ",
                $what, " header names, taken from its certificate by the caller.")]
            ///
            /// # Errors
            /// [`VerifyError`].
            pub fn verify(
                wire: &[u8],
                device: &DeviceVerifyingKey,
            ) -> Result<Verified<Self>, VerifyError> {
                verify_single(wire, device)
            }
        }

        impl Statement for $name {
            const LABEL: labels::Label = $label;
            const MAX_BODY_LEN: usize = 4 + $max + 2 * HASH_LEN;

            fn encode_body(&self) -> Result<Vec<u8>, EncodeError> {
                let mut out = Vec::with_capacity(4 + self.header.len() + 2 * HASH_LEN);
                put_bytes(&mut out, &self.header)?;
                out.extend_from_slice(&self.envelope_hash);
                out.extend_from_slice(&self.wrap_hash.unwrap_or([0u8; HASH_LEN]));
                Ok(out)
            }

            fn decode_body(body: &[u8]) -> Result<Self, ParseError> {
                let mut r = Reader::new(body);
                let header = r.bytes_max($max)?;
                if header.len() < $min {
                    return Err(ParseError::InvalidLength);
                }
                let envelope_hash = *r.array::<HASH_LEN>()?;
                let wrap_hash = *r.array::<HASH_LEN>()?;
                r.finish()?;
                Ok(Self {
                    header: header.to_vec(),
                    envelope_hash,
                    wrap_hash: (wrap_hash != [0u8; HASH_LEN]).then_some(wrap_hash),
                })
            }
        }
    };
}

record_statement! {
    /// `op` (§10.2, ADR 0012 §3): `bytes(canonical op header) ‖ SHA-256(op envelope) ‖
    /// SHA-256(ITEM_KEY_WRAP envelope)`, or 32 zero bytes in place of the second hash when the
    /// op carries no wrap. Signed by the authoring device.
    ///
    /// The body and the wrap are signed by hash, so the server can drop a compacted op's body
    /// and keep its signed header (ADR 0012 §7).
    OpStatement, labels::SIG_OP, OP_HEADER_MIN_LEN, OP_HEADER_MAX_LEN, "op"
}

record_statement! {
    /// `snapshot` (§10.2, ADR 0012 §3): `bytes(canonical snapshot header) ‖ SHA-256(snapshot
    /// envelope) ‖ SHA-256(ITEM_KEY_WRAP envelope)`, or 32 zero bytes in place of the second
    /// hash when it carries none. Signed by the authoring device.
    SnapshotStatement, labels::SIG_SNAPSHOT, SNAPSHOT_HEADER_MIN_LEN, SNAPSHOT_HEADER_MAX_LEN,
    "snapshot"
}

// ---------------------------------------------------------------------------------------------
// key-grant
// ---------------------------------------------------------------------------------------------

/// Longest HPKE envelope a key grant may carry: the 16 MiB M1 plaintext limit plus the
/// 66-byte overhead. M1 grants are 98 bytes.
pub const MAX_GRANT_ENVELOPE_LEN: usize = MAX_PLAINTEXT_LEN + HPKE_OVERHEAD;

/// `key-grant` (§10.1): the sender's signature over a signed HPKE grant.
///
/// Signed message: `LABEL("sig/key-grant") ‖ 0x00 ‖ u16(1) ‖ u16(purpose) ‖ sender public key
/// id ‖ recipient public key id ‖ bytes(hpke_envelope)`. The wire form carries the HPKE
/// envelope inside the statement, so a signed grant travels as one object.
///
/// Checked when signing and when verifying:
/// - the purpose is one of the signed-grant purposes: `ACCOUNT_KEY_DEVICE_GRANT`,
///   `PASSWORD_VERIFIER_GRANT` (M4) or `VAULT_KEY_MEMBER_GRANT` (M9);
/// - the envelope parses as an HPKE envelope whose algorithm is on that purpose's allow-list;
/// - the envelope header names the recipient public key id of the statement;
/// - the container's signer and the statement's sender key id are the verifying key's id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyGrant {
    purpose: Purpose,
    sender_key_id: PublicKeyId,
    recipient_key_id: PublicKeyId,
    envelope: Vec<u8>,
}

impl KeyGrant {
    /// The purposes whose grants are signed (§10.1 "Signed grants").
    pub const SIGNED_PURPOSES: [Purpose; 3] = [
        Purpose::AccountKeyDeviceGrant,
        Purpose::PasswordVerifierGrant,
        Purpose::VaultKeyMemberGrant,
    ];

    /// Checks the envelope against the purpose and returns the recipient key id it names.
    fn check_envelope(purpose: Purpose, envelope: &[u8]) -> Result<PublicKeyId, ParseError> {
        if !Self::SIGNED_PURPOSES.contains(&purpose) || envelope.len() > MAX_GRANT_ENVELOPE_LEN {
            return Err(ParseError::InvalidValue);
        }
        match parse::parse(envelope)? {
            EnvelopeRef::Hpke(env)
                if purpose.client_decrypt_allow_list().contains(&env.alg_id()) =>
            {
                Ok(PublicKeyId::from_bytes(*env.key_id()))
            }
            _ => Err(ParseError::InvalidValue),
        }
    }

    /// Signs a grant: `sender` signs the HPKE `envelope` sealed for `purpose`. The recipient
    /// key id is taken from the envelope header, and the sender key id from `sender`.
    ///
    /// # Errors
    /// [`SignError::Encode`] if the purpose is not a signed-grant purpose or the envelope does
    /// not fit it.
    pub fn sign<R: SignerRole>(
        purpose: Purpose,
        sender: &SigningKey<R>,
        envelope: &[u8],
    ) -> Result<Vec<u8>, SignError> {
        let recipient_key_id = Self::check_envelope(purpose, envelope)
            .map_err(|_| SignError::Encode(EncodeError::InvalidField))?;
        let grant = Self {
            purpose,
            sender_key_id: sender.key_id(),
            recipient_key_id,
            envelope: envelope.to_vec(),
        };
        sign_single(&grant, sender)
    }

    /// Verifies a signed grant under `sender`, the key the verifier expects for the sender the
    /// AAD names (§10.1): a device certificate's key, or an identity key.
    ///
    /// # Errors
    /// [`VerifyError`]; [`VerifyError::WrongSigner`] if the statement names another sender.
    pub fn verify<R: SignerRole>(
        wire: &[u8],
        sender: &VerifyingKey<R>,
    ) -> Result<Verified<Self>, VerifyError> {
        let verified: Verified<Self> = verify_single(wire, sender)?;
        if verified.sender_key_id != sender.key_id() {
            return Err(VerifyError::WrongSigner);
        }
        Ok(verified)
    }

    /// The purpose of the carried envelope.
    #[must_use]
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// The sender's public key id.
    #[must_use]
    pub const fn sender_key_id(&self) -> &PublicKeyId {
        &self.sender_key_id
    }

    /// The recipient's public key id (also the envelope header's key id).
    #[must_use]
    pub const fn recipient_key_id(&self) -> &PublicKeyId {
        &self.recipient_key_id
    }

    /// The HPKE envelope.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
}

impl Statement for KeyGrant {
    const LABEL: labels::Label = labels::SIG_KEY_GRANT;
    const MAX_BODY_LEN: usize = 2 + 2 * ID_LEN + 4 + MAX_GRANT_ENVELOPE_LEN;

    fn encode_body(&self) -> Result<Vec<u8>, EncodeError> {
        if Self::check_envelope(self.purpose, &self.envelope) != Ok(self.recipient_key_id) {
            return Err(EncodeError::InvalidField);
        }
        let mut out = Vec::with_capacity(2 + 2 * ID_LEN + 4 + self.envelope.len());
        put_u16(&mut out, self.purpose.id());
        out.extend_from_slice(self.sender_key_id.as_bytes());
        out.extend_from_slice(self.recipient_key_id.as_bytes());
        put_bytes(&mut out, &self.envelope)?;
        Ok(out)
    }

    fn decode_body(body: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(body);
        let purpose = Purpose::from_id(r.u16()?).ok_or(ParseError::InvalidValue)?;
        let sender_key_id = PublicKeyId::from_bytes(*r.array()?);
        let recipient_key_id = PublicKeyId::from_bytes(*r.array()?);
        let envelope = r.bytes_max(MAX_GRANT_ENVELOPE_LEN)?;
        r.finish()?;
        if Self::check_envelope(purpose, envelope)? != recipient_key_id {
            return Err(ParseError::InvalidValue);
        }
        Ok(Self {
            purpose,
            sender_key_id,
            recipient_key_id,
            envelope: envelope.to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// device-auth and device-request
// ---------------------------------------------------------------------------------------------

/// Length of a device-authentication challenge (§5.10).
pub const CHALLENGE_LEN: usize = 32;

/// Signs `body` framed with `label` as a bare container (device-auth, device-request).
fn sign_detached(
    label: labels::Label,
    body: &[u8],
    device: &DeviceSigningKey,
) -> Result<SignatureContainer, SignError> {
    device.sign_message(&signed_message(label, body))
}

/// Verifies a bare container over `body` framed with `label`.
fn verify_detached(
    label: labels::Label,
    body: &[u8],
    container: &[u8],
    device: &DeviceVerifyingKey,
) -> Result<(), VerifyError> {
    let container = SignatureContainer::from_bytes(container)?;
    device.verify_container(&signed_message(label, body), &container)
}

/// `device-auth` (§5.10): the answer to a device-authentication challenge.
///
/// Message: `LABEL("sig/device-auth") ‖ 0x00 ‖ u16(1) ‖ str(server_origin) ‖ account_id ‖
/// device_id ‖ challenge`. It travels as a bare [`SignatureContainer`]; the server rebuilds the
/// message from its own canonical origin, the account and device the session is for, and the
/// challenge it issued, then checks the container with [`DeviceAuth::verify`] against the
/// registered, non-revoked device key. The origin binding stops a signature for server A from
/// being replayed at server B.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceAuth<'a> {
    /// `server_origin` (§2): the origin the client dialled, or the server's canonical origin.
    pub server_origin: &'a str,
    /// The account.
    pub account_id: AccountId,
    /// The authenticating device.
    pub device_id: DeviceId,
    /// The 32-byte random challenge the server sent.
    pub challenge: [u8; CHALLENGE_LEN],
}

impl DeviceAuth<'_> {
    fn body(&self) -> Result<Vec<u8>, EncodeError> {
        if self.server_origin.is_empty() {
            return Err(EncodeError::InvalidField);
        }
        let len = crate::encoding::bytes_encoded_len(self.server_origin.len())?
            .checked_add(2 * ID_LEN + CHALLENGE_LEN)
            .ok_or(EncodeError::TooLong)?;
        let mut out = Vec::with_capacity(len);
        put_str(&mut out, self.server_origin)?;
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(self.device_id.as_bytes());
        out.extend_from_slice(&self.challenge);
        Ok(out)
    }

    /// Signs the challenge answer with the device key.
    ///
    /// # Errors
    /// [`SignError::Encode`] for an empty origin.
    pub fn sign(&self, device: &DeviceSigningKey) -> Result<SignatureContainer, SignError> {
        sign_detached(labels::SIG_DEVICE_AUTH, &self.body()?, device)
    }

    /// Verifies a container against the message rebuilt from `self`.
    ///
    /// # Errors
    /// [`VerifyError`].
    pub fn verify(&self, container: &[u8], device: &DeviceVerifyingKey) -> Result<(), VerifyError> {
        let body = self
            .body()
            .map_err(|_| VerifyError::Malformed(ParseError::InvalidValue))?;
        verify_detached(labels::SIG_DEVICE_AUTH, &body, container, device)
    }
}

/// `device-request` (§5.10, §10.2; M1 by owner decision): request signing for native clients.
///
/// Message: `LABEL("sig/device-request") ‖ 0x00 ‖ u16(1) ‖ str(server_origin) ‖ account_id ‖
/// device_id ‖ session_id ‖ u64 request_counter ‖ str(method) ‖ str(path_and_query) ‖
/// SHA-256(request body)`. It travels as a bare [`SignatureContainer`]; the server rebuilds the
/// message from the request it received and checks it against the session's device key. The
/// once-per-session and sliding-window-of-64 rule for `request_counter` is server state, not
/// part of this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceRequest<'a> {
    /// `server_origin` (§2).
    pub server_origin: &'a str,
    /// The account.
    pub account_id: AccountId,
    /// The device.
    pub device_id: DeviceId,
    /// The 16-byte session id the server returned with the session.
    pub session_id: SessionId,
    /// Per-session request counter.
    pub request_counter: u64,
    /// The HTTP method.
    pub method: &'a str,
    /// The path and query.
    pub path_and_query: &'a str,
    /// `SHA-256(request body)`; see [`DeviceRequest::body_hash`].
    pub body_hash: [u8; HASH_LEN],
}

impl DeviceRequest<'_> {
    /// `SHA-256(request body)`, for [`DeviceRequest::body_hash`].
    #[must_use]
    pub fn body_hash(request_body: &[u8]) -> [u8; HASH_LEN] {
        Sha256::digest(request_body).into()
    }

    fn body(&self) -> Result<Vec<u8>, EncodeError> {
        if self.server_origin.is_empty() || self.method.is_empty() {
            return Err(EncodeError::InvalidField);
        }
        let mut out = Vec::new();
        put_str(&mut out, self.server_origin)?;
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(self.device_id.as_bytes());
        out.extend_from_slice(self.session_id.as_bytes());
        put_u64(&mut out, self.request_counter);
        put_str(&mut out, self.method)?;
        put_str(&mut out, self.path_and_query)?;
        out.extend_from_slice(&self.body_hash);
        Ok(out)
    }

    /// Signs the request with the device key.
    ///
    /// # Errors
    /// [`SignError::Encode`] for an empty origin or method, or a field longer than
    /// `u32::MAX` bytes.
    pub fn sign(&self, device: &DeviceSigningKey) -> Result<SignatureContainer, SignError> {
        sign_detached(labels::SIG_DEVICE_REQUEST, &self.body()?, device)
    }

    /// Verifies a container against the message rebuilt from `self`.
    ///
    /// # Errors
    /// [`VerifyError`].
    pub fn verify(&self, container: &[u8], device: &DeviceVerifyingKey) -> Result<(), VerifyError> {
        let body = self
            .body()
            .map_err(|_| VerifyError::Malformed(ParseError::InvalidValue))?;
        verify_detached(labels::SIG_DEVICE_REQUEST, &body, container, device)
    }
}
