//! `rizzy-vault backup-secrets`: the secrets file encrypted under an operator passphrase
//! ([ADR 0011] "Backups" and owner decision 3; CRYPTO.md §5.11 `SERVER_SECRETS_BACKUP`).
//!
//! CRYPTO.md §5.11 places the file's `format` string and its JSON writer and reader here, and
//! gives it "the shape of §11.14: JSON, the header fields in clear, the envelope in `data`".
//! `rizzy-core` defines the header fields, the context and the key
//! ([`ServerSecretsBackupKey`]). So the file mirrors the export file's layout field for field:
//!
//! ```json
//! {"format":"rizzy-vault-secrets-backup","version":1,"kdf_id":1,
//!  "backup_salt":"<22 chars>","backup_id":"<22 chars>","created_at":<ms>,
//!  "data":"<b64url SERVER_SECRETS_BACKUP envelope>"}
//! ```
//!
//! The plaintext is the secrets file exactly as read ([`crate::secrets_file`]), after checking
//! that it parses, so a restore gets back the same bytes. The file is written with mode 0600
//! and never overwrites; the docs tell the operator to store it apart from the database
//! backups (ADR 0011).
//!
//! **Reading it back.** [`open`] decrypts a backup file. No Accepted ADR names a command that
//! restores the secrets from it, so none exists; [`open`] is what such a command, and the tests,
//! call. It checks every field's length before decoding it, as §11.14 "Field sizes" requires.
//!
//! [ADR 0011]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0011-storage.md

use core::fmt;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use rizzy_domain_auth::types::CryptoRng;
use rizzy_domain_auth::types::KdfId;
use rizzy_domain_auth::types::MAX_DATA_FIELD_LEN;
use rizzy_domain_auth::types::SecretBytes;
use rizzy_domain_auth::types::{BackupHeader, ServerSecretsBackupKey};
use serde::{Deserialize, Serialize};

/// The backup file's `format` value.
pub const FORMAT: &str = "rizzy-vault-secrets-backup";

/// The backup file's `version` value.
pub const VERSION: u32 = 1;

/// The longest backup file [`open`] reads: the `data` field's limit plus room for the header.
pub const MAX_BACKUP_FILE_LEN: usize = MAX_DATA_FIELD_LEN + 4096;

/// Why a backup could not be written or opened. Never carries the passphrase or any secret.
#[derive(Debug)]
#[non_exhaustive]
pub enum BackupError {
    /// The passphrase is empty or not acceptable as a new passphrase (CRYPTO.md §2).
    Passphrase,
    /// The file is not a secrets backup of this version, or a field is malformed.
    Malformed,
    /// Wrong passphrase, or a tampered file. One error for both (CRYPTO.md §9.5).
    Decrypt,
    /// Sealing failed.
    Seal,
}

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Passphrase => "the passphrase is empty or not acceptable",
            Self::Malformed => "not a rizzy-vault secrets backup file",
            Self::Decrypt => "wrong passphrase, or the backup file was changed",
            Self::Seal => "the backup could not be sealed",
        })
    }
}

impl std::error::Error for BackupError {}

/// The backup file as stored.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupFile {
    /// [`FORMAT`].
    format: String,
    /// [`VERSION`].
    version: u32,
    /// The `kdf_id` of the passphrase key.
    kdf_id: u64,
    /// The Argon2id salt, base64url of 16 bytes.
    backup_salt: String,
    /// The backup id, base64url of 16 bytes.
    backup_id: String,
    /// Creation time, ms since the Unix epoch; the `created_at_ms` of the context.
    created_at: u64,
    /// The `SERVER_SECRETS_BACKUP` envelope, base64url.
    data: String,
}

/// Encrypts `secrets_file` under `passphrase` (one Argon2id run at `kdf_id` 1) and returns the
/// backup file's bytes.
///
/// # Errors
/// [`BackupError::Passphrase`] for an empty or unacceptable passphrase; [`BackupError::Seal`].
pub fn seal<R: CryptoRng + ?Sized>(
    rng: &mut R,
    passphrase: &str,
    secrets_file: &[u8],
    created_at_ms: u64,
) -> Result<Vec<u8>, BackupError> {
    let key = ServerSecretsBackupKey::derive_new(rng, passphrase, created_at_ms, KdfId::DEFAULT)
        .map_err(|_| BackupError::Passphrase)?;
    let envelope = key.seal(rng, secrets_file).map_err(|_| BackupError::Seal)?;
    let header = key.header();
    let file = BackupFile {
        format: FORMAT.to_owned(),
        version: VERSION,
        kdf_id: u64::from(header.kdf_id.get()),
        backup_salt: Base64UrlUnpadded::encode_string(&header.backup_salt),
        backup_id: Base64UrlUnpadded::encode_string(header.backup_id.as_bytes()),
        created_at: header.created_at_ms,
        data: Base64UrlUnpadded::encode_string(&envelope),
    };
    let mut out = serde_json::to_vec(&file).map_err(|_| BackupError::Seal)?;
    out.push(b'\n');
    Ok(out)
}

/// Decrypts a backup file: checks its size, its format and version, and each header field's
/// length before decoding it (CRYPTO.md §11.14 "Field sizes"), then derives the key (one
/// Argon2id run) and opens the envelope. Returns the secrets file's bytes.
///
/// # Errors
/// [`BackupError::Malformed`] for a file that is not a backup of this version;
/// [`BackupError::Decrypt`] for a wrong passphrase or a changed file.
pub fn open(file: &[u8], passphrase: &str) -> Result<SecretBytes, BackupError> {
    if file.len() > MAX_BACKUP_FILE_LEN {
        return Err(BackupError::Malformed);
    }
    let file: BackupFile = serde_json::from_slice(file).map_err(|_| BackupError::Malformed)?;
    if file.format != FORMAT || file.version != VERSION {
        return Err(BackupError::Malformed);
    }
    if file.data.len() > MAX_DATA_FIELD_LEN {
        return Err(BackupError::Malformed);
    }
    let header = BackupHeader::from_fields(
        file.kdf_id,
        &file.backup_salt,
        &file.backup_id,
        file.created_at,
    )
    .map_err(|_| BackupError::Malformed)?;
    let envelope = Base64UrlUnpadded::decode_vec(&file.data).map_err(|_| BackupError::Malformed)?;
    let key =
        ServerSecretsBackupKey::derive(passphrase, &header).map_err(|_| BackupError::Decrypt)?;
    key.open(&envelope).map_err(|_| BackupError::Decrypt)
}

/// Reads a passphrase from a file's bytes: UTF-8, with one trailing `\n` (or `\r\n`) removed.
/// The operator's passphrase never comes from the command line or the environment (threat
/// model §7.5).
///
/// # Errors
/// [`BackupError::Passphrase`] for bytes that are not UTF-8 or a passphrase that is empty.
pub fn passphrase_from_bytes(bytes: &[u8]) -> Result<zeroize::Zeroizing<String>, BackupError> {
    let text = core::str::from_utf8(bytes).map_err(|_| BackupError::Passphrase)?;
    let text = text
        .strip_suffix('\n')
        .map_or(text, |t| t.strip_suffix('\r').unwrap_or(t));
    if text.is_empty() {
        return Err(BackupError::Passphrase);
    }
    Ok(zeroize::Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
mod tests {
    //! A backup opens with its passphrase and only with it; a changed header is refused.

    use chacha20::ChaCha20Rng;
    use chacha20::rand_core::SeedableRng as _;

    use super::*;

    #[test]
    fn round_trip_and_refusals() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let plaintext = b"{\"format\":1}\n";
        let file = seal(&mut rng, "correct horse", plaintext, 1_790_000_000_000).unwrap();
        assert_eq!(
            open(&file, "correct horse").unwrap().expose_secret(),
            plaintext
        );
        assert!(matches!(open(&file, "wrong"), Err(BackupError::Decrypt)));
        let mut value: serde_json::Value = serde_json::from_slice(&file).unwrap();
        value["created_at"] = 1.into();
        assert!(matches!(
            open(value.to_string().as_bytes(), "correct horse"),
            Err(BackupError::Decrypt)
        ));
        value["format"] = "rizzy-vault-export".into();
        assert!(matches!(
            open(value.to_string().as_bytes(), "correct horse"),
            Err(BackupError::Malformed)
        ));
        assert!(matches!(
            seal(&mut rng, "", plaintext, 1),
            Err(BackupError::Passphrase)
        ));
        let text = String::from_utf8(file).unwrap();
        assert!(!text.contains("correct horse"));
        assert!(text.starts_with("{\"format\":\"rizzy-vault-secrets-backup\",\"version\":1,"));
    }

    #[test]
    fn passphrase_file_trims_one_newline() {
        assert_eq!(passphrase_from_bytes(b"pw\n").unwrap().as_str(), "pw");
        assert_eq!(passphrase_from_bytes(b"pw\r\n").unwrap().as_str(), "pw");
        assert_eq!(passphrase_from_bytes(b"pw \n\n").unwrap().as_str(), "pw \n");
        assert!(passphrase_from_bytes(b"\n").is_err());
        assert!(passphrase_from_bytes(&[0xff]).is_err());
    }
}
