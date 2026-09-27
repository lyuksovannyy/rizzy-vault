//! Server-side sealing (CRYPTO.md §5.11; audit target 10 in §1).
//!
//! These objects are sealed **by the server, for the server**. That protects them from a reader
//! of the database alone, not from someone who also holds the secrets file. It is not zero
//! knowledge and never touches client data.
//!
//! - **Keys.** Each `server_data_key` (32 random bytes, identified by a `u32 data_key_id`, one
//!   marked current in the secrets file) yields one subkey per purpose:
//!   `k = HKDF(ikm = server_data_key, salt = empty, info = LABEL("server/<purpose>") ‖ 0x00 ‖
//!   u32(data_key_id), 32)`, with `<purpose>` = `totp-secret` or `login-state`. The
//!   server-secrets backup key is derived like the export file key, from the operator
//!   passphrase ([`ServerSecretsBackupKey`]).
//! - **Envelope.** Algorithm `0x01` with the server-only purposes `SERVER_TOTP_SECRET` (0x0100),
//!   `SERVER_LOGIN_STATE` (0x0101) and `SERVER_SECRETS_BACKUP` (0x0102), sealed and opened only
//!   through [`crate::envelope::symmetric::server_seal`] and `server_open`, which use the
//!   server's allow-list table. No client allow-list contains these purposes, so a client never
//!   opens them, and the server functions here accept only these contexts.
//! - The database records the `data_key_id` of every sealed row. The envelope header carries the
//!   subkey's key id, so opening under the wrong data key fails at the key-id check.
//!
//! Sealing, step by step: check the purpose-specific preconditions (a TOTP enrolment counts
//! from 1 and its secret has at least [`MIN_SERVER_SECRET_LEN`] bytes; a login state's context
//! names its own credential identifier), derive the purpose's subkey, then seal with a fresh
//! nonce from the injected RNG. Opening refuses an expired login state before any crypto,
//! derives the same subkey, runs the envelope's checks in the §9.5 order (length, version, the
//! server's allow-list, key id, then the commitment and the AEAD), and then the
//! purpose-specific checks on the plaintext. Every opening failure is the same
//! [`DecryptError`].
//!
//! # Attacker model
//!
//! What this defends against:
//! - **A reader of the database or its backups** without the secrets file: TOTP secrets
//!   (threat model INV-8) and pending login states (CRYPTO.md §5.11) are ciphertext, and the
//!   subkeys come from a key that is not in the database.
//! - **A writer to the database** without the secrets file: every context field is in the
//!   AAD, so a sealed row moved to another account, another TOTP enrolment or another login,
//!   or given a later `expires_at_ms`, fails to open. Each purpose has its own subkey and its
//!   purpose id in the AAD, so a row cannot be opened as another purpose either.
//! - **Cheap offline guessing on a stolen backup.** Each guess at the operator passphrase costs
//!   one Argon2id run at the `kdf_id` cost, behind a random salt. A new backup's passphrase is
//!   checked like a new export password: not empty, no unassigned code point (§2).
//!
//! What it does not do:
//! - Anyone who holds the secrets file and the database can open everything here. This is not
//!   zero knowledge (§5.11), and a malicious server can read its own secrets at will.
//! - Replay of a login-state row within its TTL is prevented by the caller reading and
//!   deleting the row in one transaction, not by this module.
//! - The secrets file's own format, its storage outside the database, rotation of the current
//!   data key and re-sealing are the server's job.

use core::fmt;

use rand_core::CryptoRng;

use crate::envelope::purpose::{ServerLoginStateCtx, ServerSecretsBackupCtx, ServerTotpSecretCtx};
use crate::envelope::symmetric::{server_open, server_seal};
use crate::error::{DecryptError, DerivationError, EncryptError, KdfError, ParseError};
use crate::export::{self, ExportError, SALT_LEN, check_new_file_password, password_file_key};
use crate::ids::BackupId;
use crate::kdf::{self, KdfId};
use crate::labels::{self, Label};
use crate::opaque::{CredentialIdentifier, ServerLoginState};
use crate::secret::{KEY_LEN, Key32, SecretBytes};
use crate::totp::{MIN_SERVER_SECRET_LEN, TotpSecret};

/// How long a pending OPAQUE login may be kept (§5.10): 60 s.
///
/// When sealing a state, set `expires_at_ms` of its [`ServerLoginStateCtx`] to the server's
/// clock plus this value; [`ServerDataKey::open_login_state`] refuses the state from then on.
pub const LOGIN_STATE_TTL_MS: u64 = 60_000;

/// One `server_data_key` from the secrets file, with its `data_key_id`.
///
/// Server code only. The key belongs in the secrets file, outside the database (threat model
/// INV-8); the database records only the `data_key_id` of each row. The key is wiped on drop
/// and `Debug` shows only the id. Build one per key listed in the secrets file, and seal new
/// rows under the one marked current.
pub struct ServerDataKey {
    /// The 32 random key bytes, wiped on drop. Used only as HKDF input for the subkeys.
    key: Key32,
    /// The id the secrets file and the database use for this key; bound into every subkey.
    data_key_id: u32,
}

impl ServerDataKey {
    /// Draws a new data key from the injected CSPRNG (`rizzy-vault secrets rotate --data-key`).
    ///
    /// Choosing a `data_key_id` that no other key in the secrets file uses is the caller's job.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R, data_key_id: u32) -> Self {
        Self {
            key: Key32::generate(rng),
            data_key_id,
        }
    }

    /// Reads a data key from the secrets file.
    ///
    /// # Errors
    /// [`ParseError::InvalidLength`] unless 32 bytes.
    pub fn from_slice(bytes: &[u8], data_key_id: u32) -> Result<Self, ParseError> {
        Ok(Self {
            key: Key32::from_slice(bytes)?,
            data_key_id,
        })
    }

    /// The `data_key_id` the database records next to every row sealed under this key.
    #[must_use]
    pub const fn data_key_id(&self) -> u32 {
        self.data_key_id
    }

    /// The 32 key bytes, for writing the secrets file.
    ///
    /// Write them only to the secrets file, never to the database, a log or an error.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; KEY_LEN] {
        self.key.expose_secret()
    }

    /// `HKDF(server_data_key, salt = empty, LABEL("server/<purpose>") ‖ 0x00 ‖ u32(data_key_id),
    /// 32)`.
    ///
    /// One subkey per purpose, so the raw data key is never a cipher key (CRYPTO.md §1 rule 4).
    /// Binding `data_key_id` gives each key generation its own subkeys and key ids.
    ///
    /// # Errors
    /// [`DerivationError`] if HKDF fails (unreachable for a 32-byte output).
    fn subkey(&self, label: Label) -> Result<Key32, DerivationError> {
        Key32::try_init_with(|out| {
            kdf::hkdf_sha256(
                self.key.expose_secret(),
                None,
                label,
                &self.data_key_id.to_be_bytes(),
                out,
            )
        })
    }

    /// Seals an account's TOTP secret as `SERVER_TOTP_SECRET`, ctx
    /// `account_id ‖ u32 totp_credential_seq`. The plaintext is the raw secret (§11.15); the
    /// server's 2FA uses [`crate::totp::TotpParams::DEFAULT`].
    ///
    /// Here rizzy-vault is the issuer, so the secret must have at least
    /// [`MIN_SERVER_SECRET_LEN`] bytes, the RFC 4226 §4 R6 floor (§11.15).
    /// [`TotpSecret::generate`] draws 20. Item secrets, accepted as issued from 1 byte, never
    /// come here.
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] for `totp_credential_seq = 0` (it counts from 1),
    /// [`EncryptError::InvalidPlaintextLength`] for a secret shorter than
    /// [`MIN_SERVER_SECRET_LEN`], otherwise [`EncryptError`] as for any envelope.
    pub fn seal_totp_secret<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &ServerTotpSecretCtx,
        secret: &TotpSecret,
    ) -> Result<Vec<u8>, EncryptError> {
        // Preconditions first, before any key material is touched.
        if ctx.totp_credential_seq == 0 {
            return Err(EncryptError::ContextMismatch);
        }
        if secret.expose_secret().len() < MIN_SERVER_SECRET_LEN {
            return Err(EncryptError::InvalidPlaintextLength);
        }
        let key = self.subkey(labels::SERVER_TOTP_SECRET)?;
        server_seal(rng, &key, ctx, secret.expose_secret())
    }

    /// Opens a `SERVER_TOTP_SECRET` row.
    ///
    /// A secret shorter than [`MIN_SERVER_SECRET_LEN`] is refused even though it authenticated:
    /// defence in depth, since only a holder of the data key could have sealed it.
    ///
    /// # Errors
    /// [`DecryptError`] for every failure, including another account's row or another
    /// enrolment's, and a secret shorter than [`MIN_SERVER_SECRET_LEN`].
    pub fn open_totp_secret(
        &self,
        ctx: &ServerTotpSecretCtx,
        envelope: &[u8],
    ) -> Result<TotpSecret, DecryptError> {
        let key = self.subkey(labels::SERVER_TOTP_SECRET)?;
        let plaintext = server_open(&key, ctx, envelope)?;
        let bytes = plaintext.expose_secret();
        // Only authenticated plaintext reaches these checks. `from_slice` also enforces the
        // upper bound, MAX_SECRET_LEN.
        if bytes.len() < MIN_SERVER_SECRET_LEN {
            return Err(DecryptError);
        }
        TotpSecret::from_slice(bytes).map_err(|_| DecryptError)
    }

    /// Seals a pending OPAQUE login as `SERVER_LOGIN_STATE`, ctx
    /// `login_id ‖ credential_identifier (16) ‖ u64 expires_at_ms`. The plaintext is
    /// `ServerLogin::serialize()`. The fake-record path is sealed the same way (§5.9).
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] if the ctx names another credential identifier than the
    /// state's, otherwise [`EncryptError`] as for any envelope.
    pub fn seal_login_state<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &ServerLoginStateCtx,
        state: &ServerLoginState,
    ) -> Result<Vec<u8>, EncryptError> {
        // The opener rebuilds the state with the credential identifier from the ctx, so the
        // two must agree when sealing. The identifier is public, so `!=` is fine here.
        if ctx.credential_identifier != *state.credential_identifier().as_bytes() {
            return Err(EncryptError::ContextMismatch);
        }
        let key = self.subkey(labels::SERVER_LOGIN_STATE)?;
        server_seal(rng, &key, ctx, state.to_bytes().expose_secret())
    }

    /// Opens a `SERVER_LOGIN_STATE` row read (and deleted) in one transaction. `now_ms` is the
    /// caller's clock (this crate reads none): a state at or past `expires_at_ms` is refused
    /// like any other failure, so the 60 s TTL holds even if the row outlived its cleanup.
    ///
    /// # Errors
    /// [`DecryptError`] for every failure, expiry included.
    pub fn open_login_state(
        &self,
        ctx: &ServerLoginStateCtx,
        envelope: &[u8],
        now_ms: u64,
    ) -> Result<ServerLoginState, DecryptError> {
        // `expires_at_ms` comes from the row, but it is in the AAD: a row whose expiry was
        // moved later fails the commitment below, so checking it before the crypto is safe.
        if now_ms >= ctx.expires_at_ms {
            return Err(DecryptError);
        }
        let key = self.subkey(labels::SERVER_LOGIN_STATE)?;
        let plaintext = server_open(&key, ctx, envelope)?;
        ServerLoginState::from_bytes(
            plaintext.expose_secret(),
            CredentialIdentifier::from_bytes(ctx.credential_identifier),
        )
        .map_err(|_| DecryptError)
    }
}

#[cfg(test)]
impl ServerDataKey {
    /// Test-only: the subkey for `label`, for the known-answer vector files (CRYPTO.md §15
    /// item 1).
    pub(crate) fn subkey_for_tests(&self, label: Label) -> Result<Key32, DerivationError> {
        self.subkey(label)
    }
}

impl fmt::Debug for ServerDataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerDataKey")
            .field("key", &"[REDACTED]")
            .field("data_key_id", &self.data_key_id)
            .finish()
    }
}

/// The header fields of a server-secrets backup: everything the key derivation and the
/// `SERVER_SECRETS_BACKUP` context need. All public.
///
/// The backup file follows the export file's shape (§5.11, §11.14): JSON with these fields in
/// clear and the envelope base64url-encoded in `data`. CRYPTO.md does not name its `format`
/// string, so none is defined here; the byte fields use base64url without padding like the
/// export's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BackupHeader {
    /// The backup's random id; also the HKDF context of the backup key.
    pub backup_id: BackupId,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_ms: u64,
    /// The Argon2id parameters, from the allow-list.
    pub kdf_id: KdfId,
    /// The random Argon2id salt.
    pub backup_salt: [u8; SALT_LEN],
}

impl BackupHeader {
    /// The `SERVER_SECRETS_BACKUP` context these fields describe.
    #[must_use]
    pub const fn ctx(&self) -> ServerSecretsBackupCtx {
        ServerSecretsBackupCtx {
            backup_id: self.backup_id,
            created_at_ms: self.created_at_ms,
            kdf_id: self.kdf_id,
            backup_salt: self.backup_salt,
        }
    }

    /// Builds a header from its stored fields: `kdf_id` must be on the allow-list, and the salt
    /// and id are base64url of 16 bytes.
    ///
    /// The fields are untrusted (they come from a backup file). A `kdf_id` too large for a
    /// `u16` is reported as [`KdfError::NotAllowed`] with `kdf_id = u16::MAX`. The file only
    /// names a `kdf_id`; the Argon2id parameters are the compiled ones for an allow-listed id
    /// (CRYPTO.md §1 rule 5).
    ///
    /// # Errors
    /// [`ExportError::Kdf`] or [`ExportError::InvalidField`].
    pub fn from_fields(
        kdf_id: u64,
        backup_salt: &str,
        backup_id: &str,
        created_at_ms: u64,
    ) -> Result<Self, ExportError> {
        let kdf_id = u16::try_from(kdf_id)
            .map_err(|_| KdfError::NotAllowed { kdf_id: u16::MAX })
            .and_then(KdfId::from_u16)?;
        Ok(Self {
            backup_id: BackupId::from_bytes(export::decode_16(backup_id)?),
            created_at_ms,
            kdf_id,
            backup_salt: export::decode_16(backup_salt)?,
        })
    }
}

/// The server-secrets backup key (§4.3, §5.11):
/// `b = Argon2id(P = UTF-8(NFC(passphrase)), S = backup_salt, kdf_id, T = 32)`, then
/// `HKDF(ikm = b, salt = empty, info = LABEL("server/secrets-backup") ‖ 0x00 ‖ backup_id, 32)`.
///
/// It encrypts a backup copy of the secrets file under an operator passphrase. The
/// construction is the export file key's with a different label; the key is bound to its
/// header, and sealing and opening use that header's context.
/// A wrong passphrase, a header that does not match the envelope and a tampered envelope all
/// give the same [`DecryptError`].
pub struct ServerSecretsBackupKey {
    /// The derived 32-byte key, wiped on drop.
    key: Key32,
    /// The public header the key was derived for; its context binds every seal and open.
    header: BackupHeader,
}

impl ServerSecretsBackupKey {
    /// Starts a new backup: draws `backup_id` and `backup_salt` from the injected CSPRNG and
    /// derives the key from the operator passphrase (one Argon2id run).
    ///
    /// # Errors
    /// [`ExportError::EmptyPassword`], or [`ExportError::Kdf`] for an unassigned code point or
    /// an Argon2id failure.
    pub fn derive_new<R: CryptoRng + ?Sized>(
        rng: &mut R,
        passphrase: &str,
        created_at_ms: u64,
        kdf_id: KdfId,
    ) -> Result<Self, ExportError> {
        check_new_file_password(passphrase)?;
        let mut backup_salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut backup_salt);
        let header = BackupHeader {
            backup_id: BackupId::generate(rng),
            created_at_ms,
            kdf_id,
            backup_salt,
        };
        Ok(Self::derive(passphrase, &header)?)
    }

    /// Derives the key of an existing backup from its header (one Argon2id run).
    ///
    /// The new-password checks are not run here, so a passphrase accepted when the backup was
    /// made keeps working after a Unicode table update (§2, "New passwords"). Build the header
    /// with [`BackupHeader::from_fields`], which checks `kdf_id` against the allow-list.
    ///
    /// # Errors
    /// [`KdfError`].
    pub fn derive(passphrase: &str, header: &BackupHeader) -> Result<Self, KdfError> {
        Ok(Self {
            key: password_file_key(
                passphrase,
                &header.backup_salt,
                header.kdf_id,
                labels::SERVER_SECRETS_BACKUP,
                header.backup_id.as_bytes(),
            )?,
            header: *header,
        })
    }

    /// The header this key belongs to.
    #[must_use]
    pub const fn header(&self) -> &BackupHeader {
        &self.header
    }

    /// Seals the secrets file as `SERVER_SECRETS_BACKUP`, with a fresh nonce from `rng`.
    ///
    /// The plaintext is not padded, so the envelope reveals the secrets file's exact length.
    ///
    /// # Errors
    /// [`EncryptError`], for example [`EncryptError::PlaintextTooLong`] above 16 MiB.
    pub fn seal<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        secrets_file: &[u8],
    ) -> Result<Vec<u8>, EncryptError> {
        server_seal(rng, &self.key, &self.header.ctx(), secrets_file)
    }

    /// Opens a `SERVER_SECRETS_BACKUP` envelope. The plaintext comes back in a wiped buffer.
    ///
    /// # Errors
    /// [`DecryptError`] for every failure, without saying which check failed.
    pub fn open(&self, envelope: &[u8]) -> Result<SecretBytes, DecryptError> {
        server_open(&self.key, &self.header.ctx(), envelope)
    }
}

impl fmt::Debug for ServerSecretsBackupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSecretsBackupKey")
            .field("key", &"[REDACTED]")
            .field("header", &self.header)
            .finish()
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    //! Known answers for the subkeys and the backup key, round trips, context and purpose
    //! binding, the 2FA secret floor, the login-state TTL and the server-only allow-lists.

    use super::*;
    use crate::envelope::Purpose;
    use crate::envelope::symmetric::test_hooks::aead_opens;
    use crate::ids::{AccountId, LoginId};
    use crate::normalize::{LoginName, ServerOrigin};
    use crate::opaque::{OpaqueContext, PasswordInput, client_login_start, server_login_start};
    use crate::secret_key::SecretKey;
    use crate::test_util::{hex, seeded_rng};

    fn data_key() -> ServerDataKey {
        ServerDataKey::from_slice(&[0x11; 32], 7).unwrap()
    }

    fn totp_ctx(seq: u32) -> ServerTotpSecretCtx {
        ServerTotpSecretCtx {
            account_id: AccountId::from_bytes([0xa1; 16]),
            totp_credential_seq: seq,
        }
    }

    /// A real pending login from the fake-record path (no password file needed).
    fn login_state(rng: &mut impl CryptoRng) -> ServerLoginState {
        let setup = crate::opaque::ServerSetup::generate(rng);
        let secret_key = SecretKey::from_slice(&[1; 16]).unwrap();
        let pw_in = PasswordInput::derive("pw", &secret_key).unwrap();
        let (_, ke1) = client_login_start(rng, &pw_in).unwrap();
        let name = LoginName::parse("alice").unwrap();
        let origin = ServerOrigin::parse("https://vault.example.com").unwrap();
        let ctx = OpaqueContext::new(KdfId::DEFAULT, &origin);
        server_login_start(rng, &setup, &name, None, &ke1, &ctx)
            .unwrap()
            .state
    }

    fn login_ctx(state: &ServerLoginState, expires_at_ms: u64) -> ServerLoginStateCtx {
        ServerLoginStateCtx {
            login_id: LoginId::from_bytes([0xb2; 16]),
            credential_identifier: *state.credential_identifier().as_bytes(),
            expires_at_ms,
        }
    }

    #[test]
    fn subkeys_known_answers() {
        // Independent: Python cryptography HKDF, from CRYPTO.md §4.3 and §5.11. The subkeys are
        // private, so their symmetric key ids (the envelope header) are compared.
        let k = data_key();
        let totp = k.subkey(labels::SERVER_TOTP_SECRET).unwrap();
        let login = k.subkey(labels::SERVER_LOGIN_STATE).unwrap();
        assert_eq!(
            totp.key_id().unwrap().as_bytes().to_vec(),
            hex("506c09267878c41760150f5b6b4263ff")
        );
        assert_eq!(
            login.key_id().unwrap().as_bytes().to_vec(),
            hex("898634420863d41482bd797c61a9d547")
        );
        let mut rng = seeded_rng(1);
        let secret = TotpSecret::from_slice(b"12345678901234567890").unwrap();
        let env = k.seal_totp_secret(&mut rng, &totp_ctx(1), &secret).unwrap();
        assert_eq!(env[2..18], *totp.key_id().unwrap().as_bytes());
    }

    #[test]
    fn totp_secret_round_trip_and_binding() {
        let mut rng = seeded_rng(2);
        let k = data_key();
        let secret = TotpSecret::generate(&mut rng);
        let env = k.seal_totp_secret(&mut rng, &totp_ctx(1), &secret).unwrap();
        let opened = k.open_totp_secret(&totp_ctx(1), &env).unwrap();
        assert_eq!(opened.expose_secret(), secret.expose_secret());

        // Another enrolment, another account, another data key id or key: all rejected.
        assert!(k.open_totp_secret(&totp_ctx(2), &env).is_err());
        let other_account = ServerTotpSecretCtx {
            account_id: AccountId::from_bytes([0xa2; 16]),
            ..totp_ctx(1)
        };
        assert!(k.open_totp_secret(&other_account, &env).is_err());
        let rotated = ServerDataKey::from_slice(&[0x11; 32], 8).unwrap();
        assert!(rotated.open_totp_secret(&totp_ctx(1), &env).is_err());
        assert!(
            ServerDataKey::generate(&mut rng, 7)
                .open_totp_secret(&totp_ctx(1), &env)
                .is_err()
        );
        // totp_credential_seq counts from 1.
        assert_eq!(
            k.seal_totp_secret(&mut rng, &totp_ctx(0), &secret),
            Err(EncryptError::ContextMismatch)
        );
    }

    /// Owner decision 2026-09-26 (CRYPTO.md §11.15): a server 2FA secret has at least 16 bytes,
    /// checked when sealing and again when opening.
    #[test]
    fn server_totp_secret_floor() {
        let mut rng = seeded_rng(6);
        let k = data_key();
        assert_eq!(MIN_SERVER_SECRET_LEN, 16);
        let at_floor = TotpSecret::from_slice(&[7; MIN_SERVER_SECRET_LEN]).unwrap();
        let env = k
            .seal_totp_secret(&mut rng, &totp_ctx(1), &at_floor)
            .unwrap();
        assert_eq!(
            k.open_totp_secret(&totp_ctx(1), &env)
                .unwrap()
                .expose_secret(),
            at_floor.expose_secret()
        );

        // Item secrets may be this short; the server's own may not.
        let key = k.subkey(labels::SERVER_TOTP_SECRET).unwrap();
        for len in [1, 10, MIN_SERVER_SECRET_LEN - 1] {
            let short = TotpSecret::from_slice(&vec![7; len]).unwrap();
            assert_eq!(
                k.seal_totp_secret(&mut rng, &totp_ctx(1), &short),
                Err(EncryptError::InvalidPlaintextLength),
                "{len}"
            );
            // Sealed around the check, straight through the envelope API: refused on open.
            let forged = server_seal(&mut rng, &key, &totp_ctx(1), &vec![7; len]).unwrap();
            assert!(k.open_totp_secret(&totp_ctx(1), &forged).is_err(), "{len}");
        }
    }

    #[test]
    fn login_state_round_trip_ttl_and_binding() {
        let mut rng = seeded_rng(3);
        let k = data_key();
        let state = login_state(&mut rng);
        let now = 1_700_000_000_000;
        let ctx = login_ctx(&state, now + LOGIN_STATE_TTL_MS);
        let env = k.seal_login_state(&mut rng, &ctx, &state).unwrap();
        let opened = k.open_login_state(&ctx, &env, now).unwrap();
        assert_eq!(
            opened.to_bytes().expose_secret(),
            state.to_bytes().expose_secret()
        );
        assert_eq!(
            opened.credential_identifier(),
            state.credential_identifier()
        );

        // Expired, or at the exact expiry.
        assert!(
            k.open_login_state(&ctx, &env, now + LOGIN_STATE_TTL_MS)
                .is_err()
        );
        // Every ctx field is bound; a DB writer cannot extend the expiry or swap the login.
        for bad in [
            ServerLoginStateCtx {
                expires_at_ms: ctx.expires_at_ms + 1,
                ..ctx
            },
            ServerLoginStateCtx {
                login_id: LoginId::from_bytes([0; 16]),
                ..ctx
            },
            ServerLoginStateCtx {
                credential_identifier: [0; 16],
                ..ctx
            },
        ] {
            assert!(k.open_login_state(&bad, &env, now).is_err());
        }
        // The ctx must name the state's own credential identifier.
        let wrong = ServerLoginStateCtx {
            credential_identifier: [9; 16],
            ..ctx
        };
        assert_eq!(
            k.seal_login_state(&mut rng, &wrong, &state).map(|_| ()),
            Err(EncryptError::ContextMismatch)
        );
    }

    #[test]
    fn purposes_do_not_cross() {
        let mut rng = seeded_rng(4);
        let k = data_key();
        let state = login_state(&mut rng);
        let login_env = k
            .seal_login_state(&mut rng, &login_ctx(&state, u64::MAX), &state)
            .unwrap();
        let secret = TotpSecret::from_slice(&[7; 20]).unwrap();
        let totp_env = k.seal_totp_secret(&mut rng, &totp_ctx(1), &secret).unwrap();

        // Each purpose has its own subkey, so a row opened as the other purpose fails at the
        // key-id check, before any AEAD.
        let before = aead_opens();
        assert!(k.open_totp_secret(&totp_ctx(1), &login_env).is_err());
        assert!(
            k.open_login_state(&login_ctx(&state, u64::MAX), &totp_env, 0)
                .is_err()
        );
        assert_eq!(aead_opens(), before);

        // Same key and same ctx bytes under another purpose still fail: the purpose is in the
        // AAD. Seal a TOTP-shaped plaintext under the login-state subkey via the raw API.
        let login_key = k.subkey(labels::SERVER_LOGIN_STATE).unwrap();
        let forged = server_seal(&mut rng, &login_key, &totp_ctx(1), &[7; 20]).unwrap();
        assert!(server_open(&login_key, &login_ctx(&state, u64::MAX), &forged).is_err());
    }

    #[test]
    fn server_purposes_are_in_no_client_allow_list() {
        for p in [
            Purpose::ServerTotpSecret,
            Purpose::ServerLoginState,
            Purpose::ServerSecretsBackup,
        ] {
            assert!((0x0100..=0x01ff).contains(&p.id()));
            assert!(p.client_decrypt_allow_list().is_empty(), "{p:?}");
            assert!(!p.server_decrypt_allow_list().is_empty(), "{p:?}");
        }
        for p in Purpose::ALL {
            if (0x0100..=0x01ff).contains(&p.id()) {
                continue;
            }
            assert!(p.server_decrypt_allow_list().is_empty(), "{p:?}");
        }
    }

    #[test]
    fn backup_key_known_answer_and_round_trip() {
        // Independent: argon2-cffi 25.1.0 and Python cryptography HKDF, from CRYPTO.md §4.3.
        let header = BackupHeader {
            backup_id: BackupId::from_bytes([0x66; 16]),
            created_at_ms: 1_700_000_000_000,
            kdf_id: KdfId::DEFAULT,
            backup_salt: [0x55; 16],
        };
        let key = ServerSecretsBackupKey::derive("operator passphrase", &header).unwrap();
        assert_eq!(
            key.key.key_id().unwrap().as_bytes().to_vec(),
            hex("fb73b905cb64b0fbd3aa53f112c2c3dd")
        );

        let mut rng = seeded_rng(5);
        let cheap = KdfId::test_cheap(0xfff1, 1);
        let key = ServerSecretsBackupKey::derive_new(&mut rng, "operator", 5, cheap).unwrap();
        let env = key.seal(&mut rng, b"secrets file v1").unwrap();
        let h = *key.header();
        let reader = ServerSecretsBackupKey::derive("operator", &h).unwrap();
        assert_eq!(
            reader.open(&env).unwrap().expose_secret(),
            b"secrets file v1"
        );
        for bad in [
            BackupHeader {
                created_at_ms: 6,
                ..h
            },
            BackupHeader {
                backup_salt: [0; 16],
                ..h
            },
            BackupHeader {
                backup_id: BackupId::from_bytes([0; 16]),
                ..h
            },
        ] {
            let k = ServerSecretsBackupKey::derive("operator", &bad).unwrap();
            assert!(k.open(&env).is_err());
        }
        assert!(
            ServerSecretsBackupKey::derive("operator!", &h)
                .unwrap()
                .open(&env)
                .is_err()
        );
        assert_eq!(
            ServerSecretsBackupKey::derive_new(&mut rng, "", 5, cheap).map(|_| ()),
            Err(ExportError::EmptyPassword)
        );
        // Header fields from storage.
        let parsed = BackupHeader::from_fields(
            1,
            &crate::encoding::b64url_encode(&h.backup_salt),
            &crate::encoding::b64url_encode(h.backup_id.as_bytes()),
            5,
        )
        .unwrap();
        assert_eq!(parsed.backup_salt, h.backup_salt);
        assert_eq!(parsed.kdf_id, KdfId::DEFAULT);
        assert!(BackupHeader::from_fields(2, "", "", 5).is_err());
        assert!(!format!("{key:?}").contains("operator"));
    }

    #[test]
    fn debug_is_redacted() {
        let k = data_key();
        let text = format!("{k:?}");
        assert!(text.contains("[REDACTED]") && text.contains("data_key_id: 7"));
        assert!(ServerDataKey::from_slice(&[0; 31], 1).is_err());
        assert_eq!(k.expose_secret(), &[0x11; 32]);
        assert_eq!(k.data_key_id(), 7);
    }
}
