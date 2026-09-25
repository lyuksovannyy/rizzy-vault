//! The purpose registry (CRYPTO.md §8.4, §5.11, §9.5) and the typed contexts.
//!
//! Every purpose in §8.4 is registered here with its `u16` id, its one encrypt algorithm, its
//! decrypt allow-list, its plaintext rule (§8.5) and the milestone that first uses it. The
//! server-only range `0x0100`–`0x01FF` (§5.11) is part of the registry, but those purposes
//! appear only in the server's allow-list table, never in a client's.
//!
//! A context (`ctx`) is the ordered list of fields that says where a ciphertext belongs. Each
//! M1 purpose has a context type implementing [`Context`]; the type fixes the purpose, so a
//! caller cannot pair a context with the wrong purpose id. Purposes of later milestones are
//! registered (their ids are reserved) but have no context type yet, so nothing can seal or
//! open them until their milestone defines and reviews the layout.

use sha2::{Digest as _, Sha256};

use super::AlgId;
use crate::ids::{
    AccountId, BackupId, DeviceId, ExportId, ItemId, KeyType, LoginId, OpId, PublicKeyId,
    SnapshotId, VaultId,
};
use crate::kdf::KdfId;

/// What a purpose's plaintext looks like (CRYPTO.md §8.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlaintextRule {
    /// Key wraps and other fixed-size secrets: unpadded, exactly this many bytes.
    Fixed(usize),
    /// Framed and Padmé-padded ([`crate::padding`]). The envelope frames on seal and unframes
    /// on open.
    Padded,
    /// Variable length, not padded.
    Unpadded,
    /// Defined by a later ADR (the M3 attachments ADR, the M4 backup ADR).
    Unspecified,
}

/// The milestone that first uses a purpose (CRYPTO.md §8.4, "First used").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Milestone {
    /// M1.
    M1,
    /// M3.
    M3,
    /// M3 on desktop, M7 on mobile.
    M3M7,
    /// M4.
    M4,
    /// M5.
    M5,
    /// M6.
    M6,
    /// M9.
    M9,
}

/// Which allow-list table a purpose's decryption belongs to (CRYPTO.md §9.5 rule 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// Client purposes: every purpose outside `0x0100`–`0x01FF`.
    Client,
    /// Server-only purposes, `0x0100`–`0x01FF` (§5.11). No client allow-list contains them.
    Server,
}

/// The registry row of one purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PurposeSpec {
    /// The `u16` purpose id bound into the AAD.
    pub id: u16,
    /// The name CRYPTO.md uses.
    pub name: &'static str,
    /// The one algorithm this purpose encrypts with.
    pub encrypt: AlgId,
    /// The algorithms this purpose accepts on decryption.
    pub decrypt: &'static [AlgId],
    /// The plaintext rule.
    pub plaintext: PlaintextRule,
    /// First milestone.
    pub first_used: Milestone,
}

const SYMMETRIC: &[AlgId] = &[AlgId::XChaCha20Poly1305Committed];
const CHUNKED: &[AlgId] = &[AlgId::ChunkedXChaCha20Poly1305];
const HPKE_BASE: &[AlgId] = &[AlgId::HpkeBaseX25519];
const HPKE_PSK: &[AlgId] = &[AlgId::HpkePskX25519];

/// First id of the server-only range (§5.11).
pub const SERVER_ONLY_FIRST: u16 = 0x0100;
/// Last id of the server-only range (§5.11).
pub const SERVER_ONLY_LAST: u16 = 0x01FF;

/// Every purpose in CRYPTO.md §8.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum Purpose {
    /// `E_srv`: the account key under `server_unlock_key`.
    AccountKeyServerWrap = 0x0001,
    /// `E_local`: the account key under `local_unlock_key`.
    AccountKeyLocalWrap = 0x0002,
    /// `E_rec`: the account key under the recovery wrap key.
    AccountKeyRecoveryWrap = 0x0003,
    /// The account key sealed to a device (HPKE PSK mode).
    AccountKeyDeviceGrant = 0x0004,
    /// A password verifier sealed to a device (HPKE PSK mode, M4).
    PasswordVerifierGrant = 0x0005,
    /// `E_ks`: the account key under the keystore unlock secret (M3/M7).
    AccountKeyKeystoreWrap = 0x0006,
    /// The new account key under the previous one, device-local (M3/M7).
    AccountKeyForward = 0x0007,
    /// `E_id`: the identity secret keys under the account key.
    IdentitySecretKeys = 0x0010,
    /// `E_dev`: the device secret keys under the account key, device-local.
    DeviceSecretKeys = 0x0011,
    /// The mail secret key under the account key (M6).
    MailSecretKey = 0x0012,
    /// A retired secret key under the account key.
    RetiredSecretKey = 0x0013,
    /// Security-relevant account settings under the account key.
    AccountSettings = 0x0014,
    /// A vault key under the account key.
    VaultKeySelfGrant = 0x0020,
    /// A vault key sealed to another member (HPKE Base mode, M9).
    VaultKeyMemberGrant = 0x0021,
    /// An item key under the vault key.
    ItemKeyWrap = 0x0030,
    /// One sync op under the item key.
    ItemOp = 0x0031,
    /// One item snapshot under the item key.
    ItemSnapshot = 0x0032,
    /// An attachment chunk (M3; algorithm `0x03`, layout by the M3 ADR).
    AttachmentChunk = 0x0033,
    /// An attachment key under the item key (M3).
    AttachmentKeyWrap = 0x0034,
    /// A relay batch under the relay key (M4).
    RelayBatch = 0x0040,
    /// A pairing message under `k_pair` (M4).
    PairingTransfer = 0x0041,
    /// A pairing transfer chunk sealed to the new device (HPKE PSK mode, M4).
    PairingTransferSealed = 0x0042,
    /// A re-sync transfer chunk sealed to a stale device (HPKE PSK mode, M4).
    ResyncTransfer = 0x0043,
    /// A share snapshot under the share key (M5).
    ShareSnapshot = 0x0050,
    /// A mail message sealed to the mail key (HPKE Base mode, M6).
    MailMessage = 0x0060,
    /// An encrypted export file.
    ExportFile = 0x0070,
    /// A backup file (M4, layout by the M4 backup ADR).
    BackupFile = 0x0071,
    /// The local cache index (M3).
    LocalCacheIndex = 0x0090,
    /// A TOTP secret sealed by the server (server only).
    ServerTotpSecret = 0x0100,
    /// Pending OPAQUE `ServerLogin` state sealed by the server (server only).
    ServerLoginState = 0x0101,
    /// The server-secrets backup (server only).
    ServerSecretsBackup = 0x0102,
}

impl Purpose {
    /// Every purpose, in id order.
    pub const ALL: [Self; 31] = [
        Self::AccountKeyServerWrap,
        Self::AccountKeyLocalWrap,
        Self::AccountKeyRecoveryWrap,
        Self::AccountKeyDeviceGrant,
        Self::PasswordVerifierGrant,
        Self::AccountKeyKeystoreWrap,
        Self::AccountKeyForward,
        Self::IdentitySecretKeys,
        Self::DeviceSecretKeys,
        Self::MailSecretKey,
        Self::RetiredSecretKey,
        Self::AccountSettings,
        Self::VaultKeySelfGrant,
        Self::VaultKeyMemberGrant,
        Self::ItemKeyWrap,
        Self::ItemOp,
        Self::ItemSnapshot,
        Self::AttachmentChunk,
        Self::AttachmentKeyWrap,
        Self::RelayBatch,
        Self::PairingTransfer,
        Self::PairingTransferSealed,
        Self::ResyncTransfer,
        Self::ShareSnapshot,
        Self::MailMessage,
        Self::ExportFile,
        Self::BackupFile,
        Self::LocalCacheIndex,
        Self::ServerTotpSecret,
        Self::ServerLoginState,
        Self::ServerSecretsBackup,
    ];

    /// The registry row: CRYPTO.md §8.4 with the allow-lists of §9.5 and the plaintext rules
    /// of §8.5, one line per purpose.
    #[must_use]
    #[rustfmt::skip] // One row per purpose, laid out like the CRYPTO.md §8.4 table.
    pub const fn spec(self) -> PurposeSpec {
        use Milestone as M;
        use PlaintextRule::{Fixed, Padded, Unpadded, Unspecified};
        // (name, encrypt, decrypt, plaintext, first used)
        let (name, encrypt, decrypt, plaintext, first_used) = match self {
            Self::AccountKeyServerWrap => ("ACCOUNT_KEY_SERVER_WRAP", SYM, SYMMETRIC, Fixed(32), M::M1),
            Self::AccountKeyLocalWrap => ("ACCOUNT_KEY_LOCAL_WRAP", SYM, SYMMETRIC, Fixed(32), M::M1),
            Self::AccountKeyRecoveryWrap => ("ACCOUNT_KEY_RECOVERY_WRAP", SYM, SYMMETRIC, Fixed(32), M::M1),
            Self::AccountKeyDeviceGrant => ("ACCOUNT_KEY_DEVICE_GRANT", PSK, HPKE_PSK, Fixed(32), M::M1),
            // Carries an `E_local` record and possibly the new SK (§11.5); layout set in M4.
            Self::PasswordVerifierGrant => ("PASSWORD_VERIFIER_GRANT", PSK, HPKE_PSK, Unpadded, M::M4),
            Self::AccountKeyKeystoreWrap => ("ACCOUNT_KEY_KEYSTORE_WRAP", SYM, SYMMETRIC, Fixed(32), M::M3M7),
            Self::AccountKeyForward => ("ACCOUNT_KEY_FORWARD", SYM, SYMMETRIC, Fixed(32), M::M3M7),
            // `ed25519_seed (32) ‖ x25519_sk (32)` (§11.1 step 5).
            Self::IdentitySecretKeys => ("IDENTITY_SECRET_KEYS", SYM, SYMMETRIC, Fixed(64), M::M1),
            // `u8 version = 1 ‖ Ed25519 seed (32) ‖ X25519 secret key (32)` (§8.4).
            Self::DeviceSecretKeys => ("DEVICE_SECRET_KEYS", SYM, SYMMETRIC, Fixed(65), M::M1),
            // One X25519 secret key (§4.2).
            Self::MailSecretKey => ("MAIL_SECRET_KEY", SYM, SYMMETRIC, Fixed(32), M::M6),
            // `u8 key_type ‖ secret key (32)` (§8.4).
            Self::RetiredSecretKey => ("RETIRED_SECRET_KEY", SYM, SYMMETRIC, Fixed(33), M::M1),
            Self::AccountSettings => ("ACCOUNT_SETTINGS", SYM, SYMMETRIC, Unpadded, M::M1),
            Self::VaultKeySelfGrant => ("VAULT_KEY_SELF_GRANT", SYM, SYMMETRIC, Fixed(32), M::M1),
            Self::VaultKeyMemberGrant => ("VAULT_KEY_MEMBER_GRANT", BASE, HPKE_BASE, Fixed(32), M::M9),
            // `u8 wrap_version = 1 ‖ u32 created_vault_key_epoch ‖ item_key (32)` (§8.4).
            Self::ItemKeyWrap => ("ITEM_KEY_WRAP", SYM, SYMMETRIC, Fixed(37), M::M1),
            Self::ItemOp => ("ITEM_OP", SYM, SYMMETRIC, Padded, M::M1),
            Self::ItemSnapshot => ("ITEM_SNAPSHOT", SYM, SYMMETRIC, Padded, M::M1),
            Self::AttachmentChunk => ("ATTACHMENT_CHUNK", CHUNK, CHUNKED, Unspecified, M::M3),
            Self::AttachmentKeyWrap => ("ATTACHMENT_KEY_WRAP", SYM, SYMMETRIC, Fixed(32), M::M3),
            Self::RelayBatch => ("RELAY_BATCH", SYM, SYMMETRIC, Padded, M::M4),
            Self::PairingTransfer => ("PAIRING_TRANSFER", SYM, SYMMETRIC, Unpadded, M::M4),
            Self::PairingTransferSealed => ("PAIRING_TRANSFER_SEALED", PSK, HPKE_PSK, Padded, M::M4),
            Self::ResyncTransfer => ("RESYNC_TRANSFER", PSK, HPKE_PSK, Padded, M::M4),
            Self::ShareSnapshot => ("SHARE_SNAPSHOT", SYM, SYMMETRIC, Padded, M::M5),
            Self::MailMessage => ("MAIL_MESSAGE", BASE, HPKE_BASE, Padded, M::M6),
            Self::ExportFile => ("EXPORT_FILE", SYM, SYMMETRIC, Unpadded, M::M1),
            Self::BackupFile => ("BACKUP_FILE", SYM, SYMMETRIC, Unspecified, M::M4),
            Self::LocalCacheIndex => ("LOCAL_CACHE_INDEX", SYM, SYMMETRIC, Unpadded, M::M3),
            Self::ServerTotpSecret => ("SERVER_TOTP_SECRET", SYM, SYMMETRIC, Unpadded, M::M1),
            Self::ServerLoginState => ("SERVER_LOGIN_STATE", SYM, SYMMETRIC, Unpadded, M::M1),
            Self::ServerSecretsBackup => ("SERVER_SECRETS_BACKUP", SYM, SYMMETRIC, Unpadded, M::M1),
        };
        PurposeSpec {
            id: self as u16,
            name,
            encrypt,
            decrypt,
            plaintext,
            first_used,
        }
    }

    /// The `u16` id bound into the AAD.
    #[must_use]
    pub const fn id(self) -> u16 {
        self as u16
    }

    /// Looks up a purpose by id. Unregistered ids give `None`.
    #[must_use]
    pub fn from_id(id: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.id() == id)
    }

    /// The name CRYPTO.md uses, such as `"ITEM_OP"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.spec().name
    }

    /// The one algorithm this purpose encrypts with.
    #[must_use]
    pub const fn encrypt_alg(self) -> AlgId {
        self.spec().encrypt
    }

    /// The plaintext rule (§8.5).
    #[must_use]
    pub const fn plaintext_rule(self) -> PlaintextRule {
        self.spec().plaintext
    }

    /// Whether the purpose is in the server-only range `0x0100`–`0x01FF` (§5.11).
    #[must_use]
    pub const fn side(self) -> Side {
        let id = self.id();
        if id >= SERVER_ONLY_FIRST && id <= SERVER_ONLY_LAST {
            Side::Server
        } else {
            Side::Client
        }
    }

    /// The client's decrypt allow-list for this purpose. Empty for server-only purposes: no
    /// client allow-list contains them (§9.5 rule 2).
    #[must_use]
    pub const fn client_decrypt_allow_list(self) -> &'static [AlgId] {
        match self.side() {
            Side::Client => self.spec().decrypt,
            Side::Server => &[],
        }
    }

    /// The server's decrypt allow-list for this purpose. Non-empty only for the server-only
    /// purposes: the server never decrypts client data.
    #[must_use]
    pub const fn server_decrypt_allow_list(self) -> &'static [AlgId] {
        match self.side() {
            Side::Server => self.spec().decrypt,
            Side::Client => &[],
        }
    }

    /// For an HPKE purpose, the type of the recipient's public key (§4.4, §8.4 "Key /
    /// algorithm"). The HPKE envelope header carries the id of that key, derived with this
    /// type (§9.2), so a key of another role never matches. `None` for symmetric purposes.
    ///
    /// - device grants, password-verifier grants, pairing and re-sync transfers: the
    ///   recipient device's X25519 key (`0x05`);
    /// - member grants (M9): the grantee's identity X25519 key (`0x02`);
    /// - mail (M6): the recipient's mail X25519 key (`0x03`).
    #[must_use]
    pub const fn hpke_recipient_key_type(self) -> Option<KeyType> {
        match self {
            Self::AccountKeyDeviceGrant
            | Self::PasswordVerifierGrant
            | Self::PairingTransferSealed
            | Self::ResyncTransfer => Some(KeyType::DeviceX25519),
            Self::VaultKeyMemberGrant => Some(KeyType::IdentityX25519),
            Self::MailMessage => Some(KeyType::MailX25519),
            _ => None,
        }
    }
}

// Short names for the registry rows above.
const SYM: AlgId = AlgId::XChaCha20Poly1305Committed;
const CHUNK: AlgId = AlgId::ChunkedXChaCha20Poly1305;
const BASE: AlgId = AlgId::HpkeBaseX25519;
const PSK: AlgId = AlgId::HpkePskX25519;

mod sealed {
    /// Only this module defines contexts.
    pub trait Sealed {}
}

/// The context (`ctx`) of one purpose: the fields, in order, that say where a ciphertext
/// belongs (CRYPTO.md §8.4). The reader builds it from where it expected the object, never from
/// the wire.
///
/// Sealed: every implementation is a context type in this module, and each one fixes its
/// purpose.
pub trait Context: sealed::Sealed {
    /// The purpose this context belongs to.
    const PURPOSE: Purpose;

    /// Appends the canonical `ctx` bytes: the fields in §8.4 order, each at its fixed width,
    /// with no length prefixes.
    fn write_ctx(&self, out: &mut Vec<u8>);

    /// The exact length of the `ctx` bytes.
    fn ctx_len(&self) -> usize;

    /// The `ctx` bytes as a new vector.
    fn ctx_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.ctx_len());
        self.write_ctx(&mut out);
        out
    }
}

/// A client purpose sealed with the symmetric envelope `0x01`
/// ([`seal`](super::symmetric::seal), [`open`](super::symmetric::open)).
pub trait SymmetricContext: Context {}

/// A server-only purpose (`0x0100`–`0x01FF`) sealed with `0x01` by the server for the server
/// ([`server_seal`](super::symmetric::server_seal),
/// [`server_open`](super::symmetric::server_open)).
pub trait ServerContext: Context {}

/// A purpose sealed with HPKE (`0x10` or `0x12`). The HPKE envelope ([`crate::hpke`]) uses
/// these. Every HPKE context is also exactly one of [`HpkeBaseContext`] or
/// [`HpkePskContext`], which fixes the HPKE mode at compile time (§9.5 rule 2).
pub trait HpkeContext: Context {}

/// An HPKE purpose whose one encrypt algorithm and whole decrypt allow-list are Base mode
/// (`0x10`): `VAULT_KEY_MEMBER_GRANT` (M9) and `MAIL_MESSAGE` (M6). No M1 purpose uses Base
/// mode, so this trait has no implementation outside tests yet.
pub trait HpkeBaseContext: HpkeContext {}

/// An HPKE purpose whose one encrypt algorithm and whole decrypt allow-list are PSK mode
/// (`0x12`): `ACCOUNT_KEY_DEVICE_GRANT` in M1; `PASSWORD_VERIFIER_GRANT`,
/// `PAIRING_TRANSFER_SEALED` and `RESYNC_TRANSFER` in M4. A PSK-mode purpose never accepts
/// Base mode (§9.5 rule 2).
pub trait HpkePskContext: HpkeContext {}

/// A fixed-width field of a context.
trait CtxField {
    const LEN: usize;
    fn put(&self, out: &mut Vec<u8>);
}

impl CtxField for u8 {
    const LEN: usize = 1;
    fn put(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
}

impl CtxField for u16 {
    const LEN: usize = 2;
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl CtxField for u32 {
    const LEN: usize = 4;
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl CtxField for u64 {
    const LEN: usize = 8;
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl<const N: usize> CtxField for [u8; N] {
    const LEN: usize = N;
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

/// `u16(kdf_id)`.
impl CtxField for KdfId {
    const LEN: usize = 2;
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.get().to_be_bytes());
    }
}

impl CtxField for PublicKeyId {
    const LEN: usize = crate::ids::ID_LEN;
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}

macro_rules! id_ctx_fields {
    ($($id:ty),+) => {$(
        impl CtxField for $id {
            const LEN: usize = crate::ids::ID_LEN;
            fn put(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(self.as_bytes());
            }
        }
    )+};
}

id_ctx_fields!(
    AccountId, DeviceId, VaultId, ItemId, OpId, SnapshotId, ExportId, BackupId, LoginId
);

/// Defines one context type: its fields in §8.4 order, its purpose and its marker traits.
macro_rules! context {
    (
        $(#[$doc:meta])*
        $name:ident: $purpose:ident, $marker:ident $(+ $extra:ident)* {
            $( $(#[$fdoc:meta])* $field:ident: $ty:ty, )+
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name {
            $( $(#[$fdoc])* pub $field: $ty, )+
        }

        impl sealed::Sealed for $name {}

        impl Context for $name {
            const PURPOSE: Purpose = Purpose::$purpose;

            fn write_ctx(&self, out: &mut Vec<u8>) {
                $( CtxField::put(&self.$field, out); )+
            }

            fn ctx_len(&self) -> usize {
                0 $( + <$ty as CtxField>::LEN )+
            }
        }

        impl $marker for $name {}
        $( impl $extra for $name {} )*
    };
}

context! {
    /// `ACCOUNT_KEY_SERVER_WRAP` (`E_srv`):
    /// `account_id ‖ u32 account_key_epoch ‖ u32 password_epoch ‖ u16 kdf_id`.
    AccountKeyServerWrapCtx: AccountKeyServerWrap, SymmetricContext {
        /// The account.
        account_id: AccountId,
        /// Epoch of the wrapped account key.
        account_key_epoch: u32,
        /// Password epoch of the OPAQUE registration.
        password_epoch: u32,
        /// `kdf_id` of the OPAQUE registration.
        kdf_id: KdfId,
    }
}

context! {
    /// `ACCOUNT_KEY_LOCAL_WRAP` (`E_local`):
    /// `account_id ‖ device_id ‖ u32 account_key_epoch ‖ u32 password_epoch ‖ u16 kdf_id`.
    AccountKeyLocalWrapCtx: AccountKeyLocalWrap, SymmetricContext {
        /// The account.
        account_id: AccountId,
        /// The device holding `E_local`.
        device_id: DeviceId,
        /// Epoch of the wrapped account key.
        account_key_epoch: u32,
        /// Password epoch of the local wrap.
        password_epoch: u32,
        /// `kdf_id` of the local Argon2id run.
        kdf_id: KdfId,
    }
}

context! {
    /// `ACCOUNT_KEY_RECOVERY_WRAP` (`E_rec`):
    /// `account_id ‖ u32 account_key_epoch ‖ u32 recovery_epoch`.
    AccountKeyRecoveryWrapCtx: AccountKeyRecoveryWrap, SymmetricContext {
        /// The account.
        account_id: AccountId,
        /// Epoch of the wrapped account key.
        account_key_epoch: u32,
        /// Epoch of the recovery code.
        recovery_epoch: u32,
    }
}

context! {
    /// `ACCOUNT_KEY_DEVICE_GRANT` (HPKE PSK mode):
    /// `account_id ‖ u32 account_key_epoch (new) ‖ sender device_id ‖ recipient device_id`.
    AccountKeyDeviceGrantCtx: AccountKeyDeviceGrant, HpkeContext + HpkePskContext {
        /// The account.
        account_id: AccountId,
        /// Epoch of the granted (new) account key.
        account_key_epoch: u32,
        /// The device that made the grant.
        sender_device_id: DeviceId,
        /// The device the grant is sealed to.
        recipient_device_id: DeviceId,
    }
}

// Test only: `VAULT_KEY_MEMBER_GRANT` is an M9 purpose and gets its real context type in M9.
// Its §8.4 layout is fully specified, so the tests use it to exercise HPKE Base mode (`0x10`),
// which no M1 purpose uses.
#[cfg(test)]
context! {
    /// `VAULT_KEY_MEMBER_GRANT` (HPKE Base mode, M9; test only in M1):
    /// `vault_id ‖ u32 vault_key_epoch ‖ granter account_id ‖ grantee account_id`.
    VaultKeyMemberGrantCtx: VaultKeyMemberGrant, HpkeContext + HpkeBaseContext {
        /// The vault.
        vault_id: VaultId,
        /// Epoch of the granted vault key.
        vault_key_epoch: u32,
        /// The granting account.
        granter_account_id: AccountId,
        /// The account the grant is sealed to.
        grantee_account_id: AccountId,
    }
}

context! {
    /// `IDENTITY_SECRET_KEYS` (`E_id`): `account_id ‖ u32 identity_epoch`.
    IdentitySecretKeysCtx: IdentitySecretKeys, SymmetricContext {
        /// The account.
        account_id: AccountId,
        /// Epoch of the identity keys.
        identity_epoch: u32,
    }
}

context! {
    /// `DEVICE_SECRET_KEYS` (`E_dev`): `account_id ‖ device_id`.
    DeviceSecretKeysCtx: DeviceSecretKeys, SymmetricContext {
        /// The account.
        account_id: AccountId,
        /// The device whose keys these are.
        device_id: DeviceId,
    }
}

context! {
    /// `RETIRED_SECRET_KEY`: `account_id ‖ retired public key id (16)`.
    RetiredSecretKeyCtx: RetiredSecretKey, SymmetricContext {
        /// The account.
        account_id: AccountId,
        /// Public key id of the retired key.
        retired_key_id: PublicKeyId,
    }
}

context! {
    /// `ACCOUNT_SETTINGS`: `account_id ‖ u64 settings_seq`.
    AccountSettingsCtx: AccountSettings, SymmetricContext {
        /// The account.
        account_id: AccountId,
        /// Settings sequence number, committed in `account-state`.
        settings_seq: u64,
    }
}

context! {
    /// `VAULT_KEY_SELF_GRANT`:
    /// `account_id ‖ vault_id ‖ u32 account_key_epoch ‖ u32 vault_key_epoch`.
    VaultKeySelfGrantCtx: VaultKeySelfGrant, SymmetricContext {
        /// The account.
        account_id: AccountId,
        /// The vault.
        vault_id: VaultId,
        /// Epoch of the wrapping account key.
        account_key_epoch: u32,
        /// Epoch of the wrapped vault key.
        vault_key_epoch: u32,
    }
}

context! {
    /// `ITEM_KEY_WRAP`: `vault_id ‖ item_id ‖ u32 vault_key_epoch` (of the wrapping vault key).
    ItemKeyWrapCtx: ItemKeyWrap, SymmetricContext {
        /// The vault.
        vault_id: VaultId,
        /// The item.
        item_id: ItemId,
        /// Epoch of the wrapping vault key.
        vault_key_epoch: u32,
    }
}

context! {
    /// `ITEM_OP`: `vault_id ‖ item_id ‖ u16 item_schema_version ‖ op_id ‖ device_id ‖
    /// u64 device_seq ‖ u64 hlc ‖ SHA-256(canonical op header)`.
    ///
    /// The canonical op header is defined by ADR 0012 §3; hash it with
    /// [`ItemOpCtx::header_hash`].
    ItemOpCtx: ItemOp, SymmetricContext {
        /// The vault.
        vault_id: VaultId,
        /// The item.
        item_id: ItemId,
        /// Version of the item-record encoding (1 in M1).
        item_schema_version: u16,
        /// The op.
        op_id: OpId,
        /// The authoring device.
        device_id: DeviceId,
        /// The authoring device's sequence number.
        device_seq: u64,
        /// The op's hybrid logical clock.
        hlc: u64,
        /// `SHA-256(canonical op header)`.
        op_header_hash: [u8; 32],
    }
}

context! {
    /// `ITEM_SNAPSHOT`: `vault_id ‖ item_id ‖ u16 item_schema_version ‖ snapshot_id ‖
    /// SHA-256(canonical snapshot header)`.
    ItemSnapshotCtx: ItemSnapshot, SymmetricContext {
        /// The vault.
        vault_id: VaultId,
        /// The item.
        item_id: ItemId,
        /// Version of the item-record encoding (1 in M1).
        item_schema_version: u16,
        /// The snapshot.
        snapshot_id: SnapshotId,
        /// `SHA-256(canonical snapshot header)`.
        snapshot_header_hash: [u8; 32],
    }
}

context! {
    /// `EXPORT_FILE`: `export_id ‖ u64 created_at_ms ‖ u16 kdf_id ‖ export_salt`.
    ExportFileCtx: ExportFile, SymmetricContext {
        /// The export.
        export_id: ExportId,
        /// Creation time, milliseconds since the Unix epoch (the file's `created_at`).
        created_at_ms: u64,
        /// `kdf_id` of the export key.
        kdf_id: KdfId,
        /// The 16-byte random Argon2id salt.
        export_salt: [u8; 16],
    }
}

context! {
    /// `SERVER_TOTP_SECRET` (server only): `account_id ‖ u32 totp_credential_seq`.
    ServerTotpSecretCtx: ServerTotpSecret, ServerContext {
        /// The account.
        account_id: AccountId,
        /// Counts the account's TOTP enrolments from 1.
        totp_credential_seq: u32,
    }
}

context! {
    /// `SERVER_LOGIN_STATE` (server only):
    /// `login_id ‖ credential_identifier (16) ‖ u64 expires_at_ms`.
    ServerLoginStateCtx: ServerLoginState, ServerContext {
        /// The pending login.
        login_id: LoginId,
        /// The OPAQUE credential identifier: the `account_id`, or the fake id (§5.9).
        credential_identifier: [u8; 16],
        /// Expiry, milliseconds since the Unix epoch.
        expires_at_ms: u64,
    }
}

context! {
    /// `SERVER_SECRETS_BACKUP` (server only):
    /// `backup_id ‖ u64 created_at_ms ‖ u16 kdf_id ‖ backup_salt`.
    ServerSecretsBackupCtx: ServerSecretsBackup, ServerContext {
        /// The backup.
        backup_id: BackupId,
        /// Creation time, milliseconds since the Unix epoch.
        created_at_ms: u64,
        /// `kdf_id` of the backup key.
        kdf_id: KdfId,
        /// The 16-byte random Argon2id salt.
        backup_salt: [u8; 16],
    }
}

impl ItemOpCtx {
    /// `SHA-256(canonical op header)` for [`ItemOpCtx::op_header_hash`].
    #[must_use]
    pub fn header_hash(canonical_op_header: &[u8]) -> [u8; 32] {
        Sha256::digest(canonical_op_header).into()
    }
}

impl ItemSnapshotCtx {
    /// `SHA-256(canonical snapshot header)` for [`ItemSnapshotCtx::snapshot_header_hash`].
    #[must_use]
    pub fn header_hash(canonical_snapshot_header: &[u8]) -> [u8; 32] {
        Sha256::digest(canonical_snapshot_header).into()
    }
}
