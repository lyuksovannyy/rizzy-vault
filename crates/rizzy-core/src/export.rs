//! Encrypted export (CRYPTO.md §11.14; §4.3 "Export file key"; §8.4 `EXPORT_FILE`; §9.6
//! "Files").
//!
//! The user chooses an export password, separate from the master password. The Secret Key is
//! not used, so the file is portable. The file key is
//!
//! ```text
//! e        = Argon2id(P = UTF-8(NFC(export_password)), S = export_salt (16 B random), kdf_id, T = 32)
//! file_key = HKDF(ikm = e, salt = empty, info = LABEL("export/key") ‖ 0x00 ‖ export_id, 32)
//! ```
//!
//! and the payload is one symmetric envelope `Envelope(file_key, EXPORT_FILE, export_id ‖
//! u64 created_at_ms ‖ u16 kdf_id ‖ export_salt)`.
//!
//! The file is JSON:
//!
//! ```text
//! {"format":"rizzy-vault-export","version":1,"kdf_id":1,"export_salt":…,"export_id":…,
//!  "created_at":…,"data":"<b64url envelope>"}
//! ```
//!
//! This module provides the byte-level pieces: [`ExportHeader`] holds the header fields (and
//! converts the byte fields to and from base64url without padding, the JSON encoding of §9.6),
//! and [`ExportFileKey`] derives the key from them and seals or opens the `data` envelope. The
//! JSON document itself is written and parsed by a later crate.
//!
//! The header fields in the JSON are repeated "for tooling", but they are not merely
//! informational here: the reader rebuilds the key and the envelope context from them, so a
//! header that disagrees with what the envelope was sealed under fails to open (§9.6: the two
//! must agree). Changing the salt or `export_id` changes the key; changing `created_at` or
//! `kdf_id` changes the context and fails the commitment.

use core::fmt;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::encoding::{b64url_decode_into, b64url_encode};
use crate::envelope::purpose::ExportFileCtx;
use crate::envelope::{open, seal};
use crate::error::{DecryptError, EncryptError, KdfError};
use crate::ids::{ExportId, ID_LEN};
use crate::kdf::{self, KdfId};
use crate::labels::{self, Label};
use crate::secret::{Key32, SecretBytes};

/// The `format` value of an export file.
pub const FORMAT: &str = "rizzy-vault-export";

/// The `version` value of an export file.
pub const VERSION: u64 = 1;

/// Length of `export_salt`.
pub const SALT_LEN: usize = kdf::SALT_LEN;

/// Why an export file's header or password was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExportError {
    /// `format` is not [`FORMAT`] or `version` is not [`VERSION`].
    UnsupportedFormat,
    /// `export_salt` or `export_id` is not base64url of exactly 16 bytes.
    InvalidField,
    /// The export password is empty.
    EmptyPassword,
    /// The `kdf_id` is not on this client's allow-list, or Argon2id failed, or a new password
    /// contains an unassigned code point.
    Kdf(KdfError),
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat => f.write_str("not a supported rizzy-vault export file"),
            Self::InvalidField => f.write_str("malformed export file header"),
            Self::EmptyPassword => f.write_str("the export password must not be empty"),
            Self::Kdf(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for ExportError {}

impl From<KdfError> for ExportError {
    fn from(e: KdfError) -> Self {
        Self::Kdf(e)
    }
}

/// The header fields of an export file: everything the key derivation and the envelope context
/// need. All of them are public.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExportHeader {
    /// The export's random id; also the HKDF context of the file key.
    pub export_id: ExportId,
    /// Creation time, milliseconds since the Unix epoch (the JSON `created_at`).
    pub created_at_ms: u64,
    /// The Argon2id parameters, from the client's allow-list.
    pub kdf_id: KdfId,
    /// The random Argon2id salt.
    pub export_salt: [u8; SALT_LEN],
}

impl ExportHeader {
    /// Builds a header from the JSON fields of an export file.
    ///
    /// # Errors
    /// [`ExportError::UnsupportedFormat`] for another format or version,
    /// [`ExportError::Kdf`] with [`KdfError::NotAllowed`] for a `kdf_id` outside this client's
    /// allow-list (§11.14 "Import"), [`ExportError::InvalidField`] for a malformed salt or id.
    pub fn from_json_fields(
        format: &str,
        version: u64,
        kdf_id: u64,
        export_salt: &str,
        export_id: &str,
        created_at: u64,
    ) -> Result<Self, ExportError> {
        if format != FORMAT || version != VERSION {
            return Err(ExportError::UnsupportedFormat);
        }
        let kdf_id = u16::try_from(kdf_id)
            .map_err(|_| KdfError::NotAllowed { kdf_id: u16::MAX })
            .and_then(KdfId::from_u16)?;
        Ok(Self {
            export_id: ExportId::from_bytes(decode_16(export_id)?),
            created_at_ms: created_at,
            kdf_id,
            export_salt: decode_16(export_salt)?,
        })
    }

    /// The JSON `export_salt` value: base64url without padding.
    #[must_use]
    pub fn export_salt_b64(&self) -> String {
        b64url_encode(&self.export_salt)
    }

    /// The JSON `export_id` value: base64url without padding.
    #[must_use]
    pub fn export_id_b64(&self) -> String {
        b64url_encode(self.export_id.as_bytes())
    }

    /// The `EXPORT_FILE` context these fields describe.
    #[must_use]
    pub const fn ctx(&self) -> ExportFileCtx {
        ExportFileCtx {
            export_id: self.export_id,
            created_at_ms: self.created_at_ms,
            kdf_id: self.kdf_id,
            export_salt: self.export_salt,
        }
    }
}

/// Decodes base64url without padding into exactly 16 bytes.
pub(crate) fn decode_16(text: &str) -> Result<[u8; ID_LEN], ExportError> {
    let mut out = [0u8; ID_LEN];
    let decoded = b64url_decode_into(text, &mut out).map_err(|_| ExportError::InvalidField)?;
    if decoded.len() != ID_LEN {
        return Err(ExportError::InvalidField);
    }
    Ok(out)
}

/// `HKDF(Argon2id(UTF-8(NFC(password)), salt, kdf_id, 32), salt = empty, LABEL ‖ 0x00 ‖ id, 32)`:
/// the shape shared by the export file key and the server-secrets backup key (§4.3, §5.11). The
/// NFC buffer and the Argon2id output are wiped.
pub(crate) fn password_file_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    kdf_id: KdfId,
    label: Label,
    id: &[u8; ID_LEN],
) -> Result<Key32, KdfError> {
    let normalized = kdf::normalize_password(password)?;
    let mut stretched = Zeroizing::new([0u8; kdf::OUTPUT_LEN]);
    kdf::argon2id(
        kdf_id,
        normalized.expose_secret(),
        salt,
        stretched.as_mut_slice(),
    )?;
    Key32::try_init_with(|out| kdf::hkdf_sha256(stretched.as_slice(), None, label, id, out))
        .map_err(|_| KdfError::Internal)
}

/// Checks a newly chosen file password: not empty, and no code point that is unassigned in the
/// pinned Unicode tables (the rule of ADR 0004 owner decision 3, applied here too because the
/// password goes through NFC the same way, and a later Unicode version could otherwise change
/// its NFC form and lock the file).
pub(crate) fn check_new_file_password(password: &str) -> Result<(), ExportError> {
    if password.is_empty() {
        return Err(ExportError::EmptyPassword);
    }
    kdf::check_new_password(password)?;
    Ok(())
}

/// The export file key, bound to the header it was derived for.
pub struct ExportFileKey {
    key: Key32,
    header: ExportHeader,
}

impl ExportFileKey {
    /// Starts a new export: draws `export_id` and `export_salt` from the injected CSPRNG and
    /// derives the key (one Argon2id run at the cost of `kdf_id`).
    ///
    /// # Errors
    /// [`ExportError::EmptyPassword`], or [`ExportError::Kdf`] for an unassigned code point
    /// or an Argon2id failure.
    pub fn derive_new<R: CryptoRng + ?Sized>(
        rng: &mut R,
        export_password: &str,
        created_at_ms: u64,
        kdf_id: KdfId,
    ) -> Result<Self, ExportError> {
        check_new_file_password(export_password)?;
        let mut export_salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut export_salt);
        let header = ExportHeader {
            export_id: ExportId::generate(rng),
            created_at_ms,
            kdf_id,
            export_salt,
        };
        Ok(Self::derive(export_password, &header)?)
    }

    /// Derives the key for an existing file from its header (one Argon2id run).
    ///
    /// # Errors
    /// [`KdfError`].
    pub fn derive(export_password: &str, header: &ExportHeader) -> Result<Self, KdfError> {
        Ok(Self {
            key: password_file_key(
                export_password,
                &header.export_salt,
                header.kdf_id,
                labels::EXPORT_KEY,
                header.export_id.as_bytes(),
            )?,
            header: *header,
        })
    }

    /// The header this key belongs to; write its fields into the file.
    #[must_use]
    pub const fn header(&self) -> &ExportHeader {
        &self.header
    }

    /// Seals the export payload as `EXPORT_FILE`.
    ///
    /// # Errors
    /// [`EncryptError`], for example [`EncryptError::PlaintextTooLong`] above 16 MiB.
    pub fn seal<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EncryptError> {
        seal(rng, &self.key, &self.header.ctx(), plaintext)
    }

    /// Opens the `EXPORT_FILE` envelope. A wrong password, a header that disagrees with the
    /// envelope and a tampered envelope all give the same [`DecryptError`].
    ///
    /// # Errors
    /// [`DecryptError`].
    pub fn open(&self, envelope: &[u8]) -> Result<SecretBytes, DecryptError> {
        open(&self.key, &self.header.ctx(), envelope)
    }

    /// Seals the payload and returns the JSON `data` value: base64url without padding.
    ///
    /// # Errors
    /// As [`ExportFileKey::seal`].
    pub fn seal_data_field<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
    ) -> Result<String, EncryptError> {
        Ok(b64url_encode(&self.seal(rng, plaintext)?))
    }

    /// Opens the JSON `data` value.
    ///
    /// # Errors
    /// [`DecryptError`], also for malformed base64url.
    pub fn open_data_field(&self, data: &str) -> Result<SecretBytes, DecryptError> {
        let envelope = crate::encoding::b64url_decode(data)?;
        self.open(&envelope)
    }
}

impl fmt::Debug for ExportFileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportFileKey")
            .field("key", &"[REDACTED]")
            .field("header", &self.header)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{hex, seeded_rng};

    fn cheap() -> KdfId {
        KdfId::test_cheap(0xfff1, 1)
    }

    #[test]
    fn known_answer_kdf_id_1() {
        // Independent: argon2-cffi 25.1.0 (reference C Argon2) and Python cryptography HKDF,
        // written from CRYPTO.md §4.3. The password contains a decomposed é, so NFC matters.
        let header = ExportHeader {
            export_id: ExportId::from_bytes([0x44; 16]),
            created_at_ms: 1_700_000_000_000,
            kdf_id: KdfId::DEFAULT,
            export_salt: [0x33; 16],
        };
        let key = ExportFileKey::derive("export pw e\u{301}", &header).unwrap();
        assert_eq!(
            key.key.key_id().unwrap().as_bytes().to_vec(),
            hex("da12ca185bff273945a4a40badc19d2f")
        );
    }

    #[test]
    fn round_trip_and_header_binding() {
        let mut rng = seeded_rng(1);
        let key =
            ExportFileKey::derive_new(&mut rng, "hunter2", 1_700_000_000_000, cheap()).unwrap();
        let plaintext = b"{\"items\":[]}";
        let data = key.seal_data_field(&mut rng, plaintext).unwrap();
        assert_eq!(
            key.open_data_field(&data).unwrap().expose_secret(),
            plaintext
        );

        // The reader rebuilds the key and context from the header fields in the file.
        let h = *key.header();
        let reader = ExportFileKey::derive("hunter2", &h).unwrap();
        assert_eq!(
            reader.open_data_field(&data).unwrap().expose_secret(),
            plaintext
        );

        // Wrong password.
        let wrong = ExportFileKey::derive("hunter3", &h).unwrap();
        assert_eq!(wrong.open_data_field(&data).map(|_| ()), Err(DecryptError));
        // Every header field is bound.
        let tampered = [
            ExportHeader {
                export_id: ExportId::from_bytes([9; 16]),
                ..h
            },
            ExportHeader {
                created_at_ms: h.created_at_ms + 1,
                ..h
            },
            ExportHeader {
                kdf_id: KdfId::test_cheap(0xfff2, 2),
                ..h
            },
            ExportHeader {
                export_salt: [9; 16],
                ..h
            },
        ];
        for header in tampered {
            let k = ExportFileKey::derive("hunter2", &header).unwrap();
            assert_eq!(
                k.open_data_field(&data).map(|_| ()),
                Err(DecryptError),
                "{header:?}"
            );
        }
        // Malformed data field.
        assert_eq!(reader.open_data_field("!!").map(|_| ()), Err(DecryptError));
        assert_eq!(reader.open_data_field("").map(|_| ()), Err(DecryptError));
    }

    #[test]
    fn json_fields() {
        use ExportError as E;
        let salt = b64url_encode(&[0x33; 16]);
        let id = b64url_encode(&[0x44; 16]);
        let h = ExportHeader::from_json_fields(FORMAT, 1, 1, &salt, &id, 5).unwrap();
        assert_eq!(h.export_salt, [0x33; 16]);
        assert_eq!(h.export_id, ExportId::from_bytes([0x44; 16]));
        assert_eq!(h.kdf_id, KdfId::DEFAULT);
        assert_eq!(h.created_at_ms, 5);
        assert_eq!(h.export_salt_b64(), salt);
        assert_eq!(h.export_id_b64(), id);
        let ctx = h.ctx();
        assert_eq!(ctx.export_id, h.export_id);
        assert_eq!(ctx.created_at_ms, 5);

        let (s, i) = (salt.as_str(), id.as_str());
        let (id_long, salt_padded) = (format!("{id}A"), format!("{salt}="));
        for (format, version, kdf, s, i, err) in [
            ("rizzy-vault-backup", 1, 1, s, i, E::UnsupportedFormat),
            (FORMAT, 2, 1, s, i, E::UnsupportedFormat),
            (
                FORMAT,
                1,
                0,
                s,
                i,
                E::Kdf(KdfError::NotAllowed { kdf_id: 0 }),
            ),
            (
                FORMAT,
                1,
                2,
                s,
                i,
                E::Kdf(KdfError::NotAllowed { kdf_id: 2 }),
            ),
            (
                FORMAT,
                1,
                65_537,
                s,
                i,
                E::Kdf(KdfError::NotAllowed { kdf_id: u16::MAX }),
            ),
            (FORMAT, 1, 1, "", i, E::InvalidField),
            (FORMAT, 1, 1, &s[1..], i, E::InvalidField),
            (FORMAT, 1, 1, s, "AAAA", E::InvalidField),
            (FORMAT, 1, 1, s, id_long.as_str(), E::InvalidField),
            (FORMAT, 1, 1, salt_padded.as_str(), i, E::InvalidField),
        ] {
            assert_eq!(
                ExportHeader::from_json_fields(format, version, kdf, s, i, 0),
                Err(err)
            );
        }
    }

    #[test]
    fn new_passwords_are_checked() {
        let mut rng = seeded_rng(2);
        assert_eq!(
            ExportFileKey::derive_new(&mut rng, "", 0, cheap()).map(|_| ()),
            Err(ExportError::EmptyPassword)
        );
        assert_eq!(
            ExportFileKey::derive_new(&mut rng, "pw\u{0378}", 0, cheap()).map(|_| ()),
            Err(ExportError::Kdf(KdfError::UnassignedCodePoint))
        );
        // Two exports get different ids and salts.
        let a = ExportFileKey::derive_new(&mut rng, "pw", 0, cheap()).unwrap();
        let b = ExportFileKey::derive_new(&mut rng, "pw", 0, cheap()).unwrap();
        assert_ne!(a.header().export_id, b.header().export_id);
        assert_ne!(a.header().export_salt, b.header().export_salt);
        assert!(!format!("{a:?}").contains("pw"));
    }
}
