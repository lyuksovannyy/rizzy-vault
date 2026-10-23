// SPDX-License-Identifier: AGPL-3.0-only

//! The server secrets file (CRYPTO.md §5.8, §5.11; ADR 0010 §4; threat model INV-50, INV-69).
//!
//! CRYPTO.md §5.11 fixes the file's **contents** ("the single normative list") and its version,
//! `format = 1`: `server_setup` per `setup_id`, `enum_key`, `server_data_key` per `data_key_id`
//! with one marked current, the first-run bootstrap token, and, once a backup key exists,
//! `backup_keys` per `backup_key_id` with one marked current (M8, ADR 0071). ADR 0028 item 13 owns the JSON
//! **layout**, and this module mirrors it: the smallest layout that carries exactly that list,
//! in the JSON shape CRYPTO.md §11.14 already uses for files, at most 256 KiB, unknown members
//! refused:
//!
//! ```json
//! {
//!   "format": 1,
//!   "setups": [{"setup_id": 1, "server_setup": "<b64url, 128 bytes>"}],
//!   "enum_key": "<b64url, 32 bytes>",
//!   "data_keys": [{"data_key_id": 1, "key": "<b64url, 32 bytes>"}],
//!   "current_data_key_id": 1,
//!   "bootstrap_token": "<b64url, 32 bytes>",
//!   "backup_keys": [{"backup_key_id": 1, "key": "<b64url, 32 bytes>"}],
//!   "current_backup_key_id": 1
//! }
//! ```
//!
//! Binary fields are base64url without padding (CRYPTO.md §9.6), decoded strictly. Unknown
//! fields are refused; `bootstrap_token` may be absent, and `backup_keys` and
//! `current_backup_key_id` are present together or absent together (ADR 0028 item 13 as ADR
//! 0071 replaces it). **Compatibility is one-way:** a file with `backup_keys` is refused by an
//! older binary, which does not know the members. The file is untrusted input only in the
//! sense that an operator can damage it: it is read with a size limit
//! ([`MAX_SECRETS_FILE_LEN`]) and parsed without panics (fuzz target `server_secrets_file`).
//!
//! **Handling** (ADR 0010 §4, CRYPTO.md §5.8): the file lives on its own mount, never inside the
//! data directory (the caller checks, [`crate::fsutil::is_inside`]); mode 0600; the running
//! server only reads it. `rizzy-vault secrets init` writes it once and `secrets rotate`
//! replaces it atomically, both as one-offs with the mount writable. Every buffer that holds
//! the file's bytes or a decoded secret is wiped on drop; nothing here is logged, and the
//! errors name a field, never a value.

use core::fmt;
use std::path::Path;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use rizzy_domain_auth::ServerSecrets;
use rizzy_domain_auth::secrets::SECRETS_FORMAT;
use rizzy_domain_auth::types::{EnumKey, ServerSetup};
use rizzy_domain_auth::types::{ServerDataKey, ServerDbBackupKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use crate::fsutil::{self, ReadError};

/// The largest secrets file read: 256 KiB. A file with one setup and one data key is under
/// 1 KiB; this leaves room for years of rotations.
pub const MAX_SECRETS_FILE_LEN: usize = 256 * 1024;

/// Why a secrets file was refused. Names a field or a rule, never a value.
#[derive(Debug)]
#[non_exhaustive]
pub enum SecretsFileError {
    /// The file could not be read.
    Io(std::io::ErrorKind),
    /// The file is larger than [`MAX_SECRETS_FILE_LEN`].
    TooLarge,
    /// The JSON does not have the layout (module docs). `serde_json`'s own message is dropped,
    /// because it can quote the input.
    Malformed,
    /// A binary field is not base64url of the right length.
    BadField(&'static str),
    /// The contents break a rule of `ServerSecrets` (format, ids, current key).
    Invalid(rizzy_domain_auth::secrets::SecretsError),
}

impl fmt::Display for SecretsFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "secrets file cannot be read: {kind}"),
            Self::TooLarge => f.write_str("secrets file is too large"),
            Self::Malformed => f.write_str("secrets file is not in the expected layout"),
            Self::BadField(field) => write!(f, "secrets file field {field} is malformed"),
            Self::Invalid(e) => write!(f, "secrets file contents refused: {e}"),
        }
    }
}

impl std::error::Error for SecretsFileError {}

/// One setup entry as stored.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupEntry {
    /// The `setup_id`.
    setup_id: u32,
    /// `server_setup`, base64url.
    server_setup: String,
}

/// One data-key entry as stored.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DataKeyEntry {
    /// The `data_key_id`.
    data_key_id: u32,
    /// The key, base64url.
    key: String,
}

/// The file as stored. Every string holds base64url of a secret, so the whole value is wiped
/// on drop.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    /// Must be [`SECRETS_FORMAT`].
    format: u32,
    /// The setups.
    setups: Vec<SetupEntry>,
    /// `enum_key`, base64url.
    enum_key: String,
    /// The data keys.
    data_keys: Vec<DataKeyEntry>,
    /// The `data_key_id` marked current.
    current_data_key_id: u32,
    /// The bootstrap token, base64url, if the file still carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bootstrap_token: Option<String>,
    /// The backup keys (ADR 0071), present together with `current_backup_key_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_keys: Option<Vec<BackupKeyEntry>>,
    /// The `backup_key_id` marked current.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current_backup_key_id: Option<u32>,
}

/// One backup-key entry as stored (ADR 0071).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupKeyEntry {
    /// The `backup_key_id`.
    backup_key_id: u32,
    /// The key, base64url.
    key: String,
}

impl Drop for RawFile {
    fn drop(&mut self) {
        for s in &mut self.setups {
            s.server_setup.zeroize();
        }
        for k in &mut self.data_keys {
            k.key.zeroize();
        }
        self.enum_key.zeroize();
        if let Some(t) = &mut self.bootstrap_token {
            t.zeroize();
        }
        for k in self.backup_keys.iter_mut().flatten() {
            k.key.zeroize();
        }
    }
}

/// Decodes base64url `text` into a wiped buffer of exactly `len` bytes.
fn decode(
    text: &str,
    len: usize,
    field: &'static str,
) -> Result<Zeroizing<Vec<u8>>, SecretsFileError> {
    // Checked before decoding, so a long field costs nothing in proportion to its length.
    if text.len() != base64_len(len) {
        return Err(SecretsFileError::BadField(field));
    }
    let mut out = Zeroizing::new(vec![0u8; len]);
    let decoded = Base64UrlUnpadded::decode(text, out.as_mut_slice())
        .map_err(|_| SecretsFileError::BadField(field))?;
    if decoded.len() != len {
        return Err(SecretsFileError::BadField(field));
    }
    Ok(out)
}

/// The unpadded base64 length of `n` bytes.
const fn base64_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// Parses a secrets file's bytes (module docs for the layout).
///
/// # Errors
/// [`SecretsFileError`].
pub fn parse(bytes: &[u8]) -> Result<ServerSecrets, SecretsFileError> {
    if bytes.len() > MAX_SECRETS_FILE_LEN {
        return Err(SecretsFileError::TooLarge);
    }
    let raw: RawFile = serde_json::from_slice(bytes).map_err(|_| SecretsFileError::Malformed)?;
    let mut setups = Vec::with_capacity(raw.setups.len());
    for entry in &raw.setups {
        let bytes = decode(
            &entry.server_setup,
            rizzy_domain_auth::types::SERVER_SETUP_LEN,
            "server_setup",
        )?;
        let setup = ServerSetup::from_bytes(&bytes)
            .map_err(|_| SecretsFileError::BadField("server_setup"))?;
        setups.push((entry.setup_id, setup));
    }
    let enum_key = EnumKey::from_slice(&decode(&raw.enum_key, 32, "enum_key")?)
        .map_err(|_| SecretsFileError::BadField("enum_key"))?;
    let mut data_keys = Vec::with_capacity(raw.data_keys.len());
    for entry in &raw.data_keys {
        let key =
            ServerDataKey::from_slice(&decode(&entry.key, 32, "data_keys.key")?, entry.data_key_id)
                .map_err(|_| SecretsFileError::BadField("data_keys.key"))?;
        data_keys.push(key);
    }
    let bootstrap_token = raw
        .bootstrap_token
        .as_deref()
        .map(|t| {
            decode(
                t,
                rizzy_domain_auth::secrets::BOOTSTRAP_TOKEN_LEN,
                "bootstrap_token",
            )
        })
        .transpose()?;
    let secrets = ServerSecrets::from_parts(
        raw.format,
        setups,
        enum_key,
        data_keys,
        raw.current_data_key_id,
        bootstrap_token,
    )
    .map_err(SecretsFileError::Invalid)?;
    match (&raw.backup_keys, raw.current_backup_key_id) {
        (None, None) => Ok(secrets),
        (Some(entries), Some(current)) => {
            let mut keys = Vec::with_capacity(entries.len());
            for entry in entries {
                let key = ServerDbBackupKey::from_slice(
                    &decode(&entry.key, 32, "backup_keys.key")?,
                    entry.backup_key_id,
                )
                .map_err(|_| SecretsFileError::BadField("backup_keys.key"))?;
                keys.push(key);
            }
            secrets
                .with_backup_keys(keys, current)
                .map_err(SecretsFileError::Invalid)
        }
        // Present together or absent together (ADR 0028 item 13).
        _ => Err(SecretsFileError::Malformed),
    }
}

/// Serialises `secrets` in the layout of the module docs. The returned bytes hold every secret
/// and are wiped on drop.
///
/// # Errors
/// [`SecretsFileError::Malformed`] if serialisation fails (it does not for these types).
pub fn serialize(secrets: &ServerSecrets) -> Result<Zeroizing<Vec<u8>>, SecretsFileError> {
    let raw = RawFile {
        format: SECRETS_FORMAT,
        setups: secrets
            .setups()
            .map(|(setup_id, setup)| SetupEntry {
                setup_id,
                server_setup: Base64UrlUnpadded::encode_string(setup.to_bytes().expose_secret()),
            })
            .collect(),
        enum_key: Base64UrlUnpadded::encode_string(secrets.enum_key().expose_secret()),
        data_keys: secrets
            .data_keys()
            .map(|k| DataKeyEntry {
                data_key_id: k.data_key_id(),
                key: Base64UrlUnpadded::encode_string(k.expose_secret()),
            })
            .collect(),
        current_data_key_id: secrets.current_data_key_id(),
        bootstrap_token: secrets
            .bootstrap_token()
            .map(Base64UrlUnpadded::encode_string),
        backup_keys: secrets.current_backup_key_id().map(|_| {
            secrets
                .backup_keys()
                .map(|k| BackupKeyEntry {
                    backup_key_id: k.backup_key_id(),
                    key: Base64UrlUnpadded::encode_string(k.expose_secret()),
                })
                .collect()
        }),
        current_backup_key_id: secrets.current_backup_key_id(),
    };
    // Room for a file with several rotations up front, so the buffer is rarely reallocated
    // (a reallocation would leave an unwiped copy of the secrets behind).
    let mut out = Zeroizing::new(Vec::with_capacity(16 * 1024));
    serde_json::to_writer_pretty(&mut *out, &raw).map_err(|_| SecretsFileError::Malformed)?;
    out.push(b'\n');
    Ok(out)
}

/// Reads and parses the secrets file at `path`.
///
/// # Errors
/// [`SecretsFileError`].
pub fn load(path: &Path) -> Result<ServerSecrets, SecretsFileError> {
    let bytes = fsutil::read_limited(path, MAX_SECRETS_FILE_LEN).map_err(|e| match e {
        ReadError::TooLarge => SecretsFileError::TooLarge,
        ReadError::Io(e) => SecretsFileError::Io(e.kind()),
    })?;
    parse(&bytes)
}

#[cfg(test)]
mod tests {
    //! Round trips, refusals, and no secret in `Debug` or errors.

    use chacha20::ChaCha20Rng;
    use chacha20::rand_core::SeedableRng as _;
    use rizzy_domain_auth::secrets::SecretsError;

    use super::*;

    #[test]
    fn round_trip_keeps_every_part() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut secrets = ServerSecrets::generate(&mut rng);
        secrets.rotate_data_key(&mut rng).unwrap();
        secrets.rotate_setup(&mut rng).unwrap();
        let bytes = serialize(&secrets).unwrap();
        let back = parse(&bytes).unwrap();
        assert_eq!(serialize(&back).unwrap().as_slice(), bytes.as_slice());
        assert_eq!(back.current_data_key_id(), 2);
        assert_eq!(back.setups().map(|(id, _)| id).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(back.bootstrap_token(), secrets.bootstrap_token());
    }

    #[test]
    fn refusals_name_no_value() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let secrets = ServerSecrets::generate(&mut rng);
        let good = String::from_utf8(serialize(&secrets).unwrap().to_vec()).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&good).unwrap();
        value["format"] = 2.into();
        assert!(matches!(
            parse(value.to_string().as_bytes()),
            Err(SecretsFileError::Invalid(_))
        ));
        let mut value: serde_json::Value = serde_json::from_str(&good).unwrap();
        value["extra"] = 1.into();
        assert!(matches!(
            parse(value.to_string().as_bytes()),
            Err(SecretsFileError::Malformed)
        ));
        let mut value: serde_json::Value = serde_json::from_str(&good).unwrap();
        value["enum_key"] = "AAAA".into();
        let err = parse(value.to_string().as_bytes()).err().unwrap();
        assert_eq!(err.to_string(), "secrets file field enum_key is malformed");
        assert!(matches!(
            parse(&vec![b' '; MAX_SECRETS_FILE_LEN + 1]),
            Err(SecretsFileError::TooLarge)
        ));
        assert!(matches!(parse(b"{"), Err(SecretsFileError::Malformed)));
        let debug = format!("{secrets:?}");
        let enum_key = Base64UrlUnpadded::encode_string(secrets.enum_key().expose_secret());
        assert!(!debug.contains(&enum_key));
    }

    #[test]
    fn backup_keys_round_trip_and_are_present_together() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut secrets = ServerSecrets::generate(&mut rng);
        // No backup key: neither member is written (an older binary still reads the file).
        let none = String::from_utf8(serialize(&secrets).unwrap().to_vec()).unwrap();
        assert!(!none.contains("backup_key"));
        assert_eq!(
            parse(none.as_bytes()).unwrap().current_backup_key_id(),
            None
        );

        secrets.rotate_backup_key(&mut rng).unwrap();
        secrets.rotate_backup_key(&mut rng).unwrap();
        let bytes = serialize(&secrets).unwrap();
        let back = parse(&bytes).unwrap();
        assert_eq!(serialize(&back).unwrap().as_slice(), bytes.as_slice());
        assert_eq!(back.current_backup_key_id(), Some(2));
        assert_eq!(
            back.backup_key(1).unwrap().expose_secret(),
            secrets.backup_key(1).unwrap().expose_secret()
        );

        let good = String::from_utf8(bytes.to_vec()).unwrap();
        let edit = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut value: serde_json::Value = serde_json::from_str(&good).unwrap();
            f(&mut value);
            parse(value.to_string().as_bytes())
        };
        // One member without the other.
        let only_keys = edit(&|v| {
            v.as_object_mut().unwrap().remove("current_backup_key_id");
        });
        assert!(matches!(only_keys, Err(SecretsFileError::Malformed)));
        let only_current = edit(&|v| {
            v.as_object_mut().unwrap().remove("backup_keys");
        });
        assert!(matches!(only_current, Err(SecretsFileError::Malformed)));
        // A current id no key has, an empty list, a duplicate id, an unknown entry member.
        assert!(matches!(
            edit(&|v| v["current_backup_key_id"] = 9.into()),
            Err(SecretsFileError::Invalid(SecretsError::NoCurrentBackupKey))
        ));
        assert!(matches!(
            edit(&|v| v["backup_keys"] = serde_json::json!([])),
            Err(SecretsFileError::Invalid(SecretsError::NoCurrentBackupKey))
        ));
        assert!(matches!(
            edit(&|v| v["backup_keys"][1]["backup_key_id"] = 1.into()),
            Err(SecretsFileError::Invalid(SecretsError::DuplicateId))
        ));
        assert!(matches!(
            edit(&|v| v["backup_keys"][0]["extra"] = 1.into()),
            Err(SecretsFileError::Malformed)
        ));
        let short = edit(&|v| v["backup_keys"][0]["key"] = "AAAA".into());
        assert_eq!(
            short.err().unwrap().to_string(),
            "secrets file field backup_keys.key is malformed"
        );
        // A backup key equal to the data key (INV-98).
        let data_key =
            Base64UrlUnpadded::encode_string(secrets.data_keys().next().unwrap().expose_secret());
        assert!(matches!(
            edit(&|v| v["backup_keys"][0]["key"] = data_key.clone().into()),
            Err(SecretsFileError::Invalid(SecretsError::BackupKeyReused))
        ));
        let debug = format!("{back:?}");
        let key = Base64UrlUnpadded::encode_string(back.backup_key(2).unwrap().expose_secret());
        assert!(!debug.contains(&key));
    }
}
