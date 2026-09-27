//! The signed statements of CRYPTO.md §10.2, except the key bundle ([`super::bundle`]).
//!
//! Each statement is a plain struct with its canonical body layout, a `sign` function that
//! takes the signer role §10.2 names for it (for [`KeyGrant`], either role, checked against
//! the purpose at run time), and a `verify` function. The wire-form statements return
//! [`Verified`]; [`DeviceAuth`] and [`DeviceRequest`] sign into and verify a bare
//! [`SignatureContainer`]. The framing, the wire form and the generic sign and verify steps
//! are in the parent module ([`super`]).
//!
//! | Statement | Body | Signed by |
//! |---|---|---|
//! | [`DeviceCertificate`] | `account_id ‖ device_id ‖ u32 identity_epoch ‖ device Ed25519 pk ‖ device X25519 pk ‖ u8 device_kind ‖ u64 created_at_ms ‖ u64 expires_at_ms` | identity key of that `identity_epoch` |
//! | [`DeviceRevocation`] | `account_id ‖ device_id ‖ u64 last_accepted_device_seq ‖ u64 revoked_at_ms` | identity key |
//! | [`AccountState`] | `account_id ‖ u64 state_seq ‖ u32 identity_epoch ‖ u32 account_key_epoch ‖ account_key_id ‖ u32 password_epoch ‖ u16 kdf_id ‖ u32 recovery_epoch ‖ u8 recovery_enabled ‖ u8 sync_mode ‖ u32 mail_key_epoch ‖ bundle_hash ‖ device_set_hash ‖ u64 settings_seq ‖ settings_hash` | identity key of the state's `identity_epoch` |
//! | [`OpStatement`] | `bytes(canonical op header) ‖ SHA-256(op envelope) ‖ SHA-256(ITEM_KEY_WRAP envelope) or 32 zero bytes` | device key |
//! | [`SnapshotStatement`] | the same, with the canonical snapshot header and envelope | device key |
//! | [`KeyGrant`] | `u16(purpose) ‖ sender public key id ‖ recipient public key id ‖ bytes(hpke_envelope)` (§10.1) | device key (device and password-verifier grants), or identity key (member grants, and device grants from a kind-4 client) |
//! | [`DeviceAuth`] | `str(server_origin) ‖ account_id ‖ device_id ‖ challenge` (§5.10) | device key |
//! | [`DeviceRequest`] | `str(server_origin) ‖ account_id ‖ device_id ‖ session_id ‖ u64 request_counter ‖ str(method) ‖ str(path_and_query) ‖ SHA-256(request body)` (§5.10) | device key |
//!
//! **Canonical op and snapshot headers.** [ADR 0012] §3 defines both layouts, and §13 places
//! the op and snapshot record formats in `rizzy-sync`. This module therefore takes each header
//! as an opaque canonical byte string. It only bounds its length by the ADR 0012 layout: the
//! fixed part (97 bytes for an op, 73 for a snapshot) plus at most `u16::MAX` version-vector
//! entries of 24 bytes. No header field is read before the signature is checked: the caller
//! picks the verifying key from the device certificate that the container's signer key id (or
//! the session) names, verifies, parses the verified header strictly with `rizzy-sync`
//! (`header::OpHeader::parse_statement` or `header::SnapshotHeader::parse_statement`), and
//! then checks that the device the header names is that certificate's device.
//!
//! **Rules checked here.** Each statement's field rules run both when signing and when
//! verifying, so a conforming writer never produces what a verifier rejects:
//! - `device-certificate`: the web-vault (kind 4) lifetime of at most 12 h, and an expiry after
//!   creation;
//! - `account-state`: `state_seq ≥ 1`, the `recovery_enabled` and `settings_hash` consistency
//!   rules, `sync_mode` and `kdf_id` on their allow-lists;
//! - `key-grant`: a signed-grant purpose, an HPKE envelope on that purpose's allow-list that
//!   names the statement's recipient, and a signer role allowed for the purpose;
//! - `op` and `snapshot`: the header length bounds of ADR 0012.
//!
//! **Rules left to the caller.** Freshness and context are not in a single statement, so the
//! caller checks them with the helpers here and its persisted state: rollback and fork of
//! `account-state` ([`AccountState::is_rollback`], [`AccountState::is_fork`],
//! [`AccountState::cas_retry`]), the commitments of `account-state` to the bundle, the
//! settings and the account key (`matches_*`), membership of the signed device set, revocation
//! cut-offs ([`DeviceRevocation::permits_device_seq`]), kind-4 expiry against an op's HLC
//! ([`DeviceCertificate::permits_hlc`]), the challenge TTL and the `request_counter` window of
//! §5.10, and above all which verifying key to pass.
//!
//! **What this defends against.** A server that injects a device (a certificate needs the
//! identity key, INV-16), forges or edits an op or snapshot (INV-22), changes the signed
//! account state such as `kdf_id`, epochs, the device set or the settings commitment (INV-14),
//! strips and re-signs a key grant with another key (§10.1), or replays a device-auth answer
//! or request signature at another server (the origin is signed, §5.10).
//!
//! **What it does not defend against, on its own.** Replay of an older validly signed state,
//! certificate or revocation, and the hiding of a device: these need the caller's persisted
//! state (INV-25). Ending a web-vault session early is server-enforced only, apart from the
//! revocations a mode switch or full rotation signs (§10.2, threat model AR-9). A signing key
//! that is compromised: that is what revocation and rotation address (§11.6, §11.8).
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
    AccountId, DeviceId, ID_LEN, KeyType, PUBLIC_KEY_LEN, PublicKeyId, SessionId, SymmetricKeyId,
};
use crate::kdf::KdfId;
use crate::labels;
use crate::normalize::ServerOrigin;

/// Upper bound of a web-vault (`device_kind` 4) certificate's lifetime: 12 h in milliseconds
/// (§10.2, §11.4).
pub const WEB_CERT_MAX_LIFETIME_MS: u64 = 12 * 60 * 60 * 1000;

/// Length of a `SHA-256` output.
const HASH_LEN: usize = 32;

/// `device_kind` (§10.2).
///
/// The kind decides whether a device is durable, and so whether its certificate belongs in
/// the signed device set: kinds 1–3 must be in it, kind 4 never is (§10.2 "Web-vault
/// certificates"). Any other value is rejected.
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
///
/// The device Ed25519 key must be a canonical, non-small-order encoding
/// ([`VerifyingKey::from_bytes`]); the device X25519 key is taken as raw 32 bytes, and a
/// small-order one fails when a sender seals to it.
///
/// A certificate binds a device's two keys to its `device_id` and account, so the server
/// cannot enrol a device of its own: only a holder of the identity key, which needs the
/// unlocked account key, can sign one (INV-16). A verified certificate says nothing about
/// whether the device is still trusted: the caller also checks revocations, the signed device
/// set for a durable device ([`crate::keys::device_set_hash`]), and for kind 4 the expiry
/// against the op's HLC ([`DeviceCertificate::permits_hlc`]).
///
/// A full rotation re-issues every certificate under the new identity key, identical except
/// for `identity_epoch` (§11.6 step 7).
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
    /// The fixed body length: two ids, the epoch, two 32-byte keys, the kind and two times
    /// (117 bytes).
    const BODY_LEN: usize = 2 * ID_LEN + 4 + 2 * PUBLIC_KEY_LEN + 1 + 8 + 8;

    /// The expiry rules listed on [`DeviceCertificate`], shared by the writer and the parser.
    /// The kind itself is already valid: a [`DeviceKind`] holds only 1–4.
    fn validate(&self) -> Result<(), ParseError> {
        if self.expires_at_ms != 0 && self.expires_at_ms <= self.created_at_ms {
            return Err(ParseError::InvalidValue);
        }
        if self.device_kind == DeviceKind::WebEphemeral {
            // An overflowing `created_at_ms + 12 h` cannot be a real time; reject rather than
            // saturate.
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
    /// Use the identity key of `self.identity_epoch`; this function cannot check that the key
    /// belongs to that epoch.
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
    /// After a full rotation, a certificate signed only by a superseded identity key is
    /// rejected (INV-30): pass the key and epoch the device has accepted as current. The
    /// caller still checks `account_id` against the account in use.
    ///
    /// # Errors
    /// [`VerifyError`]; [`VerifyError::Mismatch`] if the certificate names another
    /// `identity_epoch`. The signature is checked first, so a certificate signed by another
    /// identity key fails with [`VerifyError::WrongSigner`].
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
    /// The rule is written for kind 4. A durable certificate (kinds 1–3) may also carry an
    /// expiry, and then the same rule applies to it (§10.2, owner decision of 2026-09-27).
    ///
    /// The rule reads the HLC the op header carries, not a local clock, so every replica
    /// reaches the same answer (§10.2; HLC layout in [ADR 0012] §2). Rules (a) and (b) of §10.2
    /// are checked by [`DeviceCertificate::verify`] and the certificate's own rules.
    ///
    /// [ADR 0012]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0012-sync-engine.md
    #[must_use]
    pub const fn permits_hlc(&self, hlc: u64) -> bool {
        // The top 48 bits of the HLC are its wall-clock milliseconds; the low 16 are the
        // logical counter.
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
///
/// A revocation is a cut-off, not an erasure: ops of the revoked device up to
/// `last_accepted_device_seq` stay valid, so history already accepted stays verifiable, and
/// every later op is rejected ([`DeviceRevocation::permits_device_seq`], §11.8 step 4). The
/// body has no field rules beyond its fixed layout.
///
/// Revocation protects future data only: it cannot take back what the device already read
/// (§11.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceRevocation {
    /// The account.
    pub account_id: AccountId,
    /// The revoked device.
    pub device_id: DeviceId,
    /// The highest `device_seq` of the revoked device that peers still accept: the highest
    /// `device_seq` the server holds from that device when it is revoked (§11.8 steps 0–1,
    /// §11.6 step 7).
    pub last_accepted_device_seq: u64,
    /// Revocation time, milliseconds since the Unix epoch.
    pub revoked_at_ms: u64,
}

impl DeviceRevocation {
    /// The fixed body length: two ids and two `u64` (48 bytes).
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
    /// The caller checks `account_id` against the account in use.
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
    /// 2: On-device mode (reserved, On-device parked (ADR 0022)).
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
///
/// The state is the account's signed root of trust for everything a server could otherwise
/// change: the KDF, every epoch, the current account key's id, recovery status, sync mode, the
/// current bundle, the durable device set and the settings version (§10.2, INV-14). The server
/// applies each new state as a compare-and-swap on `state_seq` (§10.2 "Device set").
///
/// **Using a fetched state.** Verify it with the key of its `identity_epoch`
/// ([`AccountState::verify`]); check it against the persisted state
/// ([`AccountState::is_rollback`], [`AccountState::is_fork`]); check its commitments
/// ([`AccountState::matches_bundle`], [`AccountState::matches_settings`],
/// [`AccountState::matches_account_key`], and the device-set hash); then persist the whole
/// verified state, not only its `state_seq` (INV-25). A rollback or a fork is a hard alarm: warn
/// and go read-only (§11.3 step 2.5).
///
/// `==` compares every field, and the body layout is fixed and canonical, so two states are
/// equal exactly when their signed messages are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountState {
    /// The account.
    pub account_id: AccountId,
    /// Sequence number of this state; compare-and-swap key. 1 at signup, `+1` on every change
    /// (§4.4).
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
///
/// Returned by [`AccountState::cas_retry`]. Only [`CasRetry::Reapply`] lets the change go
/// ahead automatically; the other three stop it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CasRetry {
    /// A newer state in which only `state_seq` and `device_set_hash` changed, or the very state
    /// the change was built on (a spurious conflict): re-apply the change on top of the
    /// current state and retry.
    Reapply,
    /// A newer state in which anything else changed (an epoch, `kdf_id`, `bundle_hash`,
    /// `settings_seq`, `account_key_id`, or any other field): restart the flow. An enrolling
    /// device discards its local `E_local` and `E_dev` and restarts from §11.2 step 2.
    Restart,
    /// The server's state is older than the one the change was built on: a rollback. Warn and
    /// go read-only (§11.3 step 2.5).
    Rollback,
    /// The server's state has the same `state_seq` as the one the change was built on but
    /// different content: two verified states at one position, a fork of the signed state.
    /// Never re-applied, because re-applying would silently adopt the other branch (for
    /// example drop a device the base state enrolled). Alarm and go read-only (§10.2, §11.3
    /// step 2.5, INV-25).
    Fork,
}

impl AccountState {
    /// The fixed body length, field by field in body order (168 bytes).
    const BODY_LEN: usize =
        ID_LEN + 8 + 4 + 4 + ID_LEN + 4 + 2 + 4 + 1 + 1 + 4 + HASH_LEN + HASH_LEN + 8 + HASH_LEN;

    /// Checks `state_seq ≥ 1` and the cross-field rules listed on [`AccountState`]
    /// (`recovery_enabled` ⇒ `recovery_epoch ≥ 1`, and `settings_hash` all zero ⇔
    /// `settings_seq = 0`), shared by the writer and the parser. The remaining single-field
    /// rules (`sync_mode`, `kdf_id`, `recovery_enabled` as 0 or 1) are enforced by the field
    /// types and by the decoder.
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
    /// This function cannot check that `identity` belongs to that epoch; a state signed with
    /// another key fails [`AccountState::verify`] under that epoch's key.
    ///
    /// # Errors
    /// [`SignError::Encode`] if a rule above is broken.
    pub fn sign(&self, identity: &IdentitySigningKey) -> Result<Vec<u8>, SignError> {
        sign_single(self, identity)
    }

    /// Verifies a state under the identity key of `identity_epoch`.
    ///
    /// A device passes its cached identity key. If the state was signed by a newer identity key
    /// (a full rotation elsewhere), verification fails, and the device first walks the bundle
    /// chain and has the user confirm the new fingerprint (§11.3 steps 2.3 and 3). The caller
    /// still checks `account_id` and the commitments (see [`AccountState`]).
    ///
    /// # Errors
    /// [`VerifyError`]; [`VerifyError::Mismatch`] if the state names another
    /// `identity_epoch`. The signature is checked first, so a state signed by another identity
    /// key fails with [`VerifyError::WrongSigner`].
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
    /// - A lower `state_seq` is [`CasRetry::Rollback`].
    /// - The same `state_seq` is [`CasRetry::Reapply`] only for the same state (a spurious
    ///   conflict), and [`CasRetry::Fork`] for any other content: the body layout is fixed and
    ///   canonical, so equal fields are exactly equal signed messages.
    /// - A higher `state_seq` is [`CasRetry::Reapply`] if every field other than `state_seq`
    ///   and `device_set_hash` is unchanged, and [`CasRetry::Restart`] otherwise.
    ///
    /// The caller also checks `current` against its persisted state with
    /// [`AccountState::is_rollback`] and [`AccountState::is_fork`], as for any state it
    /// fetches.
    #[must_use]
    pub fn cas_retry(&self, current: &Self) -> CasRetry {
        if current.state_seq < self.state_seq {
            return CasRetry::Rollback;
        }
        // Same position: the same state is a spurious conflict; any other content is a fork.
        if current.state_seq == self.state_seq {
            return if current == self {
                CasRetry::Reapply
            } else {
                CasRetry::Fork
            };
        }
        // Newer state: copy the two fields a concurrent enrolment or revocation may change onto
        // `current`; if what is left equals the base, nothing else moved.
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
    ///
    /// Call it on every verified state fetched, together with [`AccountState::is_fork`]; the
    /// same `state_seq` is not a rollback, but may be a fork.
    #[must_use]
    pub const fn is_rollback(&self, persisted_state_seq: u64, persisted_settings_seq: u64) -> bool {
        self.state_seq < persisted_state_seq || self.settings_seq < persisted_settings_seq
    }

    /// Whether this state and `persisted`, the last verified state this device persisted, are a
    /// **fork**: the same `state_seq` with different content (§10.2, §11.3 step 2.5, INV-25).
    /// The body layout is fixed and canonical, so equal fields are exactly equal signed
    /// messages.
    ///
    /// Both states must have verified. A fork is a hard alarm: the client warns and goes
    /// read-only, as for a rollback, and never adopts either branch silently. The same state
    /// fetched again is not a fork.
    #[must_use]
    pub fn is_fork(&self, persisted: &Self) -> bool {
        self.state_seq == persisted.state_seq && self != persisted
    }

    /// Whether `bundle` is the bundle this state commits to: same account, same
    /// `identity_epoch`, and `bundle_hash = SHA-256` of the bundle's signed message
    /// (§11.2 step 6).
    ///
    /// The hash comparison is constant-time.
    #[must_use]
    pub fn matches_bundle(&self, bundle: &super::VerifiedBundle) -> bool {
        self.account_id == bundle.account_id
            && self.identity_epoch == bundle.identity_epoch
            && bool::from(self.bundle_hash.ct_eq(bundle.hash()))
    }

    /// Whether the served `ACCOUNT_SETTINGS` envelope (or its absence) is the one this state
    /// commits to (§10.2 "Settings freshness").
    ///
    /// `None` matches only `settings_seq = 0`, and an envelope matches only a non-zero
    /// `settings_seq` whose `settings_hash` is its `SHA-256`. A client rejects a settings
    /// envelope that does not match (INV-25), so the server cannot serve an older, validly
    /// encrypted one. The hash comparison is constant-time.
    #[must_use]
    pub fn matches_settings(&self, settings_envelope: Option<&[u8]>) -> bool {
        crate::keys::settings_hash(self.settings_seq, settings_envelope)
            .is_some_and(|h| bool::from(h.ct_eq(&self.settings_hash)))
    }

    /// Whether `account_key` is the current account key: same epoch, and its derived key id is
    /// `account_key_id` (§11.2 step 6, §11.3 step 4).
    ///
    /// This is what authenticates a key delivered by device grants, in addition to the grants'
    /// signatures: the key the last grant delivers must match (§10.1, §11.3 step 4.2). A key
    /// whose id cannot be derived does not match.
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
            // Fails closed: a `kdf_id` that is not on this client's allow-list, or not enabled
            // in its KDF table, is rejected, whatever the signature says (§6.2).
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

/// Length of one version-vector entry in an ADR 0012 header: `device_id ‖ u64 seq`
/// (24 bytes).
pub const VV_ENTRY_LEN: usize = ID_LEN + 8;

/// Smallest canonical op header (ADR 0012 §3): `u8 header_version ‖ vault_id ‖ item_id ‖
/// op_id ‖ device_id ‖ u64 device_seq ‖ u64 vault_prev_seq ‖ u64 hlc ‖ u16 item_schema_version
/// ‖ u32 vault_key_epoch ‖ u16 n`, with an empty causal context.
pub const OP_HEADER_MIN_LEN: usize = 1 + 4 * ID_LEN + 8 + 8 + 8 + 2 + 4 + 2;

/// Largest canonical op header: `u16::MAX` causal-context entries (the `u16 n` count cannot
/// express more).
pub const OP_HEADER_MAX_LEN: usize = OP_HEADER_MIN_LEN + u16::MAX as usize * VV_ENTRY_LEN;

/// Smallest canonical snapshot header (ADR 0012 §3): `u8 header_version ‖ vault_id ‖ item_id ‖
/// snapshot_id ‖ author device_id ‖ u16 item_schema_version ‖ u32 vault_key_epoch ‖ u16 n`,
/// with an empty covered version vector.
pub const SNAPSHOT_HEADER_MIN_LEN: usize = 1 + 4 * ID_LEN + 2 + 4 + 2;

/// Largest canonical snapshot header: `u16::MAX` version-vector entries.
pub const SNAPSHOT_HEADER_MAX_LEN: usize =
    SNAPSHOT_HEADER_MIN_LEN + u16::MAX as usize * VV_ENTRY_LEN;

// The fixed parts of the ADR 0012 §3 headers; this fails the build if a constant drifts.
const _: () = assert!(OP_HEADER_MIN_LEN == 97 && SNAPSHOT_HEADER_MIN_LEN == 73);

/// Defines the `op` and `snapshot` statements, which share one hashed layout (§10.2).
///
/// Arguments: the struct's doc attributes, the struct name, its `LABEL("sig/<type>")`, the
/// minimum and maximum canonical header length, and the record's name as it appears in the
/// generated docs (`"op"` or `"snapshot"`).
///
/// The generated struct keeps the header bytes and only the hashes of the envelope and the
/// wrap. Building it needs the envelopes; verifying and storing it does not, which is what
/// lets the server drop a compacted op's body and keep its signed header (ADR 0012 §7).
macro_rules! record_statement {
    (
        $(#[$doc:meta])*
        $name:ident, $label:expr, $min:expr, $max:expr, $what:literal
    ) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name {
            /// The canonical header bytes, as signed. Not parsed here: `rizzy-sync` owns the
            /// layout (ADR 0012 §13).
            header: Vec<u8>,
            /// `SHA-256` of the record's envelope (`ITEM_OP` or `ITEM_SNAPSHOT`).
            envelope_hash: [u8; HASH_LEN],
            /// `SHA-256` of the `ITEM_KEY_WRAP` envelope carried with the record, or `None`
            /// (32 zero bytes in the body) when it carries none.
            wrap_hash: Option<[u8; HASH_LEN]>,
        }

        impl $name {
            #[doc = concat!("Builds the statement over the canonical ", $what, " header, the ",
                $what, " envelope and the `ITEM_KEY_WRAP` envelope carried with it, if any.")]
            ///
            /// Only the length of the header is checked; its fields are the caller's (it must be
            /// the canonical encoding `rizzy-sync` produced). The envelopes are hashed, not
            /// kept.
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

            /// Signs the statement with the authoring device's key: the key of the device the
            /// header names.
            ///
            /// # Errors
            /// [`SignError`] (the header bounds were checked by [`Self::new`]).
            pub fn sign(&self, device: &DeviceSigningKey) -> Result<Vec<u8>, SignError> {
                sign_single(self, device)
            }

            #[doc = concat!("Verifies the statement under the key of the device that the ",
                $what, " header names, taken from its certificate by the caller.")]
            ///
            /// A verified statement proves only that `device` signed this header and these
            /// hashes. The caller still parses the header, checks that it names the device
            /// whose certificate supplied `device`, checks the envelope and any wrap against
            /// the signed hashes before using them, and applies the device-set, revocation and
            /// kind-4 expiry rules (§10.2, INV-22).
            ///
            /// # Errors
            /// [`VerifyError`]: [`VerifyError::Malformed`] also for a header outside the
            /// ADR 0012 length bounds.
            pub fn verify(
                wire: &[u8],
                device: &DeviceVerifyingKey,
            ) -> Result<Verified<Self>, VerifyError> {
                verify_single(wire, device)
            }
        }

        impl Statement for $name {
            const LABEL: labels::Label = $label;
            // `bytes(header)` (a `u32` prefix and at most `$max` bytes) and two hashes.
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
                // 32 zero bytes stand for "no wrap" (§10.2). A real `SHA-256` output of all
                // zeros is not a practical concern.
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
/// 66-byte overhead. M1 grants are 98 bytes (a 32-byte key plus the overhead).
///
/// It bounds the length prefix before the envelope is read or copied.
pub const MAX_GRANT_ENVELOPE_LEN: usize = MAX_PLAINTEXT_LEN + HPKE_OVERHEAD;

/// `key-grant` (§10.1): the sender's signature over a signed HPKE grant.
///
/// Signed message: `LABEL("sig/key-grant") ‖ 0x00 ‖ u16(1) ‖ u16(purpose) ‖ sender public key
/// id ‖ recipient public key id ‖ bytes(hpke_envelope)`. The wire form carries the HPKE
/// envelope inside the statement, so a signed grant travels as one object.
///
/// Checked when signing and when verifying:
/// - the purpose is one of the signed-grant purposes: `ACCOUNT_KEY_DEVICE_GRANT`,
///   `PASSWORD_VERIFIER_GRANT` (reserved, On-device parked (ADR 0022)) or
///   `VAULT_KEY_MEMBER_GRANT` (M9);
/// - the envelope parses as an HPKE envelope whose algorithm is on that purpose's allow-list;
/// - the envelope header names the recipient public key id of the statement;
/// - the container's signer and the statement's sender key id are the verifying key's id;
/// - the signer's role may sign that purpose (§10.2 `key-grant` row, §10.1): a device key
///   signs device grants and password-verifier grants, and the identity key signs member
///   grants and the device grants of a kind-4 client. The role is not in the body (a key id
///   is a hash), so this is checked in [`KeyGrant::sign`] and [`KeyGrant::verify`], where the
///   role is the key's type.
///
/// **Why it exists.** HPKE Base and PSK modes do not authenticate the sender (§10.1 "Why not
/// Auth mode"). The signature does. The envelope's AAD names the sender by id, so a server that
/// strips the signature and re-signs the envelope with another key fails the recipient's check
/// that the signing key belongs to that sender (§10.1).
///
/// **What the caller still checks.** This type does not open the envelope and does not see
/// its AAD. The caller picks `sender` for [`KeyGrant::verify`] from the sender id the AAD
/// names: that device's certificate, even if since revoked, or the identity key for a member
/// grant or a kind-4 client's device grant (§10.1, §11.3 step 4.2). Which of the two is
/// right is the caller's decision: an identity-signed device grant verifies here whether or
/// not its sender was a kind-4 client. Opening the envelope checks that its recipient key id
/// is the recipient's own key (§9.5), and a delivered account key is checked against
/// `account_key_id` ([`AccountState::matches_account_key`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyGrant {
    /// The purpose of the carried envelope: one of [`KeyGrant::SIGNED_PURPOSES`].
    purpose: Purpose,
    /// Id of the signing key, `PublicKeyId(key_type, public_key)`. This is the only place the
    /// sender key id appears (§10.1).
    sender_key_id: PublicKeyId,
    /// Id of the recipient's X25519 key, equal to the key id in the envelope header.
    recipient_key_id: PublicKeyId,
    /// The whole HPKE envelope, signed as `bytes(hpke_envelope)`.
    envelope: Vec<u8>,
}

impl KeyGrant {
    /// The purposes whose grants are signed (§10.1 "Signed grants").
    pub const SIGNED_PURPOSES: [Purpose; 3] = [
        Purpose::AccountKeyDeviceGrant,
        Purpose::PasswordVerifierGrant,
        Purpose::VaultKeyMemberGrant,
    ];

    /// Whether a key of role `R` may sign a grant of `purpose` (§10.2 `key-grant` row, §10.1
    /// "Signed grants"):
    ///
    /// | Purpose | Device key (`0x04`) | Identity key (`0x01`) |
    /// |---|---|---|
    /// | `ACCOUNT_KEY_DEVICE_GRANT` | yes | yes (kind-4 client) |
    /// | `PASSWORD_VERIFIER_GRANT` | yes | no |
    /// | `VAULT_KEY_MEMBER_GRANT` | no | yes |
    ///
    /// Every other purpose is refused for both roles.
    const fn signer_allowed<R: SignerRole>(purpose: Purpose) -> bool {
        matches!(
            (purpose, R::KEY_TYPE),
            (
                Purpose::AccountKeyDeviceGrant | Purpose::PasswordVerifierGrant,
                KeyType::DeviceEd25519
            ) | (
                Purpose::AccountKeyDeviceGrant | Purpose::VaultKeyMemberGrant,
                KeyType::IdentityEd25519
            )
        )
    }

    /// Checks the envelope against the purpose and returns the recipient key id it names.
    ///
    /// The purpose must be a signed-grant purpose, the envelope at most
    /// [`MAX_GRANT_ENVELOPE_LEN`], and it must parse as an HPKE envelope whose algorithm is on
    /// the purpose's client decrypt allow-list (`0x12` for the device and password-verifier
    /// grants, `0x10` for member grants, §9.5 rule 2). So a grant cannot carry a Base-mode
    /// envelope for a PSK purpose, or a symmetric one. Only the layout is checked, never the
    /// ciphertext.
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
    /// Use a device key for device and password-verifier grants, and the identity key for
    /// member grants and for the device grants a web-vault (kind-4) client makes (§11.6 step
    /// 6).
    ///
    /// # Errors
    /// [`SignError::Encode`] if the purpose is not a signed-grant purpose, the envelope does
    /// not fit it, or a key of role `R` may not sign it.
    pub fn sign<R: SignerRole>(
        purpose: Purpose,
        sender: &SigningKey<R>,
        envelope: &[u8],
    ) -> Result<Vec<u8>, SignError> {
        let recipient_key_id = Self::check_envelope(purpose, envelope)
            .map_err(|_| SignError::Encode(EncodeError::InvalidField))?;
        if !Self::signer_allowed::<R>(purpose) {
            return Err(SignError::Encode(EncodeError::InvalidField));
        }
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
    /// The purpose, the envelope layout and the recipient key id are checked while decoding,
    /// before the signature; the sender key id and the role after it.
    ///
    /// # Errors
    /// [`VerifyError`]; [`VerifyError::WrongSigner`] if the statement names another sender, or
    /// a key of role `R` may not sign its purpose.
    pub fn verify<R: SignerRole>(
        wire: &[u8],
        sender: &VerifyingKey<R>,
    ) -> Result<Verified<Self>, VerifyError> {
        let verified: Verified<Self> = verify_single(wire, sender)?;
        let role_allowed = Self::signer_allowed::<R>(verified.purpose);
        if verified.sender_key_id != sender.key_id() || !role_allowed {
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

    /// The HPKE envelope, ready to open with the recipient's X25519 key (and, for a PSK
    /// purpose, the PSK).
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
}

impl Statement for KeyGrant {
    const LABEL: labels::Label = labels::SIG_KEY_GRANT;
    const MAX_BODY_LEN: usize = 2 + 2 * ID_LEN + 4 + MAX_GRANT_ENVELOPE_LEN;

    fn encode_body(&self) -> Result<Vec<u8>, EncodeError> {
        // `sign` already checked this; the encoder checks again, so no path writes a grant
        // whose envelope and recipient key id disagree.
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
        // The signed recipient key id must be the one the envelope header names, so a grant
        // cannot claim one recipient and carry an envelope sealed to another.
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
///
/// The framing is the same as every statement's, `LABEL ‖ 0x00 ‖ u16(1) ‖ body`; only the wire
/// form differs: no `bytes(u16(1) ‖ body)`, because the verifier rebuilds the body (§9.6).
fn sign_detached(
    label: labels::Label,
    body: &[u8],
    device: &DeviceSigningKey,
) -> Result<SignatureContainer, SignError> {
    device.sign_message(&signed_message(label, body))
}

/// Verifies a bare container over `body` framed with `label`.
///
/// `body` is the verifier's own rebuild, never bytes the client sent. Errors as for
/// [`SignatureContainer::from_bytes`], then [`VerifyError::WrongSigner`] or
/// [`VerifyError::BadSignature`].
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
///
/// The origin is a [`ServerOrigin`], so both sides sign and rebuild the one §2 canonical form
/// and a non-canonical spelling cannot reach the signed bytes.
///
/// The server's side of the protocol is not in this type: the challenge must be fresh random
/// bytes with a 60 s TTL, and the key must be the registered, non-revoked device key (§5.10).
/// A MITM that relays the challenge through intercepted TLS obtains a valid answer; request
/// signing ([`DeviceRequest`]) limits what it can do with the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceAuth<'a> {
    /// `server_origin` (§2), canonical. On the client it is the origin the client dialled,
    /// never one the server supplied (§5.3 step 4); on the server it is its configured
    /// canonical origin.
    pub server_origin: &'a ServerOrigin,
    /// The account.
    pub account_id: AccountId,
    /// The authenticating device.
    pub device_id: DeviceId,
    /// The 32-byte random challenge the server sent.
    pub challenge: [u8; CHALLENGE_LEN],
}

impl DeviceAuth<'_> {
    /// The body `str(server_origin) ‖ account_id ‖ device_id ‖ challenge`, allocated at its
    /// final size. Signer and verifier both build it here.
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] if the origin does not fit a `u32` length (unreachable for a
    /// [`ServerOrigin`]).
    fn body(&self) -> Result<Vec<u8>, EncodeError> {
        let origin = self.server_origin.as_str();
        let len = crate::encoding::bytes_encoded_len(origin.len())?
            .checked_add(2 * ID_LEN + CHALLENGE_LEN)
            .ok_or(EncodeError::TooLong)?;
        let mut out = Vec::with_capacity(len);
        put_str(&mut out, origin)?;
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(self.device_id.as_bytes());
        out.extend_from_slice(&self.challenge);
        Ok(out)
    }

    /// Signs the challenge answer with the device key.
    ///
    /// # Errors
    /// [`SignError`] (unreachable: a canonical origin is short and never empty).
    pub fn sign(&self, device: &DeviceSigningKey) -> Result<SignatureContainer, SignError> {
        sign_detached(labels::SIG_DEVICE_AUTH, &self.body()?, device)
    }

    /// Verifies a container against the message rebuilt from `self`.
    ///
    /// Build `self` from the server's own values: its canonical origin, the account and device
    /// of the session being authenticated, and the challenge it issued. `container` is the
    /// 82 bytes the client sent.
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
///
/// Native clients (kinds 1–3) sign every request made over a device-authenticated session;
/// the web vault (kind 4) keeps short-lived bearer tokens instead (§5.10). With it, a stolen
/// bearer token alone is useless, and a MITM that relayed the device-auth challenge can forward
/// the client's own requests but cannot make its own. The signature covers the origin, the
/// session, the counter, the method, the path and query, and a hash of the body; nothing else
/// in the HTTP request, such as its headers, is covered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceRequest<'a> {
    /// `server_origin` (§2), canonical, as for [`DeviceAuth::server_origin`].
    pub server_origin: &'a ServerOrigin,
    /// The account.
    pub account_id: AccountId,
    /// The device.
    pub device_id: DeviceId,
    /// The 16-byte session id the server returned with the session.
    pub session_id: SessionId,
    /// Per-session request counter, sent by the client with the request. The server accepts
    /// each value at most once per session, within a sliding window of 64 (§5.10).
    pub request_counter: u64,
    /// The HTTP method. Must not be empty.
    pub method: &'a str,
    /// The path and query of the request.
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

    /// The body `str(server_origin) ‖ account_id ‖ device_id ‖ session_id ‖ u64
    /// request_counter ‖ str(method) ‖ str(path_and_query) ‖ body_hash`. Signer and verifier
    /// both build it here.
    ///
    /// # Errors
    /// [`EncodeError::InvalidField`] for an empty method; [`EncodeError::TooLong`] for a field
    /// longer than `u32::MAX` bytes.
    fn body(&self) -> Result<Vec<u8>, EncodeError> {
        if self.method.is_empty() {
            return Err(EncodeError::InvalidField);
        }
        let mut out = Vec::new();
        put_str(&mut out, self.server_origin.as_str())?;
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
    /// [`SignError::Encode`] for an empty method, or a field longer than `u32::MAX` bytes.
    pub fn sign(&self, device: &DeviceSigningKey) -> Result<SignatureContainer, SignError> {
        sign_detached(labels::SIG_DEVICE_REQUEST, &self.body()?, device)
    }

    /// Verifies a container against the message rebuilt from `self`.
    ///
    /// Build `self` from the server's canonical origin, the session (account, device,
    /// `session_id`) and the request as received: the client's `request_counter`, the method,
    /// the path and query, and [`DeviceRequest::body_hash`] of the body. Check the counter
    /// window separately.
    ///
    /// # Errors
    /// [`VerifyError`]; [`VerifyError::Malformed`] also when `self` has an empty method.
    pub fn verify(&self, container: &[u8], device: &DeviceVerifyingKey) -> Result<(), VerifyError> {
        let body = self
            .body()
            .map_err(|_| VerifyError::Malformed(ParseError::InvalidValue))?;
        verify_detached(labels::SIG_DEVICE_REQUEST, &body, container, device)
    }
}
