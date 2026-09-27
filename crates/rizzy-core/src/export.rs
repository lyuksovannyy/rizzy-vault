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
//! `kdf_id` changes the context and fails the commitment. (Another `kdf_id` with other
//! Argon2id parameters also changes the key, which the key-id check catches first; M1 allows
//! only `kdf_id` 1, so an importer rejects any other value before deriving anything.)
//!
//! Writing a file: [`ExportFileKey::derive_new`] with the export password, then
//! [`ExportFileKey::seal_data_field`] for `data`, and the header's fields for the rest.
//! Reading one: [`ExportHeader::from_json_fields`] on the clear fields (this checks the format,
//! the version and the `kdf_id` allow-list), [`ExportFileKey::derive`] with the password, then
//! [`ExportFileKey::open_data_field`].
//!
//! # Attacker model
//!
//! What this defends against:
//! - **Anyone who gets the file** (a cloud drive, a lost USB stick): the content is one
//!   committing envelope under a key stretched from the export password, so each guess costs
//!   one Argon2id run at the `kdf_id` cost behind a random salt (threat model AST-20).
//! - **Downgraded stretching.** The file only names a `kdf_id`. Its parameters are compiled
//!   in, and an id off the client's allow-list is rejected before any password is processed
//!   (§11.14 "Import", threat model INV-3).
//! - **Tampering and header edits.** The commitment and the AEAD tag cover the envelope; the
//!   context binds every header field.
//! - **Partitioning-oracle attacks** on the password-derived key: the envelope is key-committing
//!   (§8.3), so one crafted file cannot test many password guesses at once.
//!
//! What it does not do:
//! - **Hide the size.** `EXPORT_FILE` is not padded, so the file reveals the exact length of
//!   the exported plaintext.
//! - **Protect a weak export password.** There is no strength rule (§2); only the Argon2id cost
//!   slows guessing. The Secret Key is deliberately not involved, so the file is portable.
//! - **Plaintext export** (JSON or CSV, behind the warning of ROADMAP §4.2) is not here, and the
//!   JSON document itself is written and parsed elsewhere.

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
///
/// Strict (see [`b64url_decode_into`]): padding, other alphabets and non-zero trailing bits
/// are rejected, and the output buffer is fixed at 16 bytes whatever the input says. Shared
/// with the server-secrets backup header.
///
/// # Errors
/// [`ExportError::InvalidField`] for malformed text or a decoded length other than 16.
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
///
/// Nothing is derived from the password before stretching, so the key id that later goes in
/// the envelope header (computed from the returned key) is no cheaper a guess verifier than
/// the commitment (§4.4). `kdf_id` has already been checked against the allow-list by its
/// type. Upstream copies that are not wiped (`argon2`'s tag locals, `hkdf`'s state, the `hmac`
/// key block) are listed in CRYPTO.md §12.2.
///
/// # Errors
/// [`KdfError`] if normalisation or Argon2id fails; [`KdfError::Internal`] if HKDF fails
/// (unreachable for a 32-byte output).
pub(crate) fn password_file_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    kdf_id: KdfId,
    label: Label,
    id: &[u8; ID_LEN],
) -> Result<Key32, KdfError> {
    // 1. `UTF-8(NFC(password))`, into a wiped buffer allocated at its exact size.
    let normalized = kdf::normalize_password(password)?;
    // 2. `e = Argon2id(P, S = salt, kdf_id, T = 32)`, into a wiped buffer.
    let mut stretched = Zeroizing::new([0u8; kdf::OUTPUT_LEN]);
    kdf::argon2id(
        kdf_id,
        normalized.expose_secret(),
        salt,
        stretched.as_mut_slice(),
    )?;
    // 3. `HKDF(ikm = e, salt = empty, info = LABEL ‖ 0x00 ‖ id, 32)`, written straight into the
    //    key's wiped storage.
    Key32::try_init_with(|out| kdf::hkdf_sha256(stretched.as_slice(), None, label, id, out))
        .map_err(|_| KdfError::Internal)
}

/// Checks a newly chosen file password: not empty, and no code point that is unassigned in the
/// pinned Unicode tables (the rule of ADR 0004 owner decision 3, applied here too because the
/// password goes through NFC the same way, and a later Unicode version could otherwise change
/// its NFC form and lock the file). CRYPTO.md §2, "New passwords", states both rules for export
/// and backup passwords.
pub(crate) fn check_new_file_password(password: &str) -> Result<(), ExportError> {
    if password.is_empty() {
        return Err(ExportError::EmptyPassword);
    }
    kdf::check_new_password(password)?;
    Ok(())
}

/// The export file key, bound to the header it was derived for.
///
/// Sealing and opening always use this header's `EXPORT_FILE` context, so a key cannot be
/// used with a context other than the one it was derived for. The key is wiped on drop and
/// `Debug` shows only the header. The envelope's key id and commitment let an attacker test a
/// password guess, but only after the full derivation: one Argon2id run per guess (§4.4).
pub struct ExportFileKey {
    /// The derived 32-byte file key, wiped on drop.
    key: Key32,
    /// The public header the key was derived for; its context binds every seal and open.
    header: ExportHeader,
}

impl ExportFileKey {
    /// Starts a new export: draws `export_id` and `export_salt` from the injected CSPRNG and
    /// derives the key (one Argon2id run at the cost of `kdf_id`).
    ///
    /// The password gets the new-password checks of CRYPTO.md §2 first: not empty, and no code
    /// point unassigned in the pinned Unicode tables. `created_at_ms` is the caller's clock
    /// (`rizzy-core` reads none); it is bound into the envelope context. Use
    /// [`KdfId::DEFAULT`] unless there is a reason not to.
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
    /// The new-password checks are deliberately not run, so a file made before a Unicode table
    /// update still opens (§2, "New passwords"). Build the header with
    /// [`ExportHeader::from_json_fields`], which enforces the `kdf_id` allow-list.
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

    /// Seals the export payload as `EXPORT_FILE`, with a fresh nonce from `rng`.
    ///
    /// The payload is not padded: the envelope is exactly 90 bytes longer than it.
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
    /// The base64url is decoded strictly into a buffer sized from the text's length; the
    /// envelope parser then applies the 16 MiB limit before any crypto.
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
    //! A known answer for the file key, round trips, binding of every header field, the JSON
    //! field rules and the new-password checks.

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
