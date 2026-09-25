//! The label registry (CRYPTO.md §2, §4.3 "Label registry rule").
//!
//! `LABEL(x)` is the ASCII string `"rizzy-vault/v1/" + x`. Every HKDF `info`, signed message,
//! hash domain and HPKE `info`/`psk_id` in CRYPTO.md starts with one. This module is the only
//! place a label is defined: code never spells a label string anywhere else. Adding a label
//! means amending the CRYPTO.md §4.3 table in the same change.
//!
//! Labels never contain `0x00`, so `LABEL(x) ‖ 0x00 ‖ ctx` is prefix-free: no two labels, and
//! no label with two different contexts, produce the same encoding. The unit tests assert that
//! every label is unique, is ASCII and contains no `0x00`.

use core::fmt;

/// The prefix of every label (CRYPTO.md §2). The `v1` versions the label set (§13, item 5).
pub const PREFIX: &str = "rizzy-vault/v1/";

/// One registered label: `LABEL(name) = PREFIX + name`.
///
/// Only the constants in this module exist; there is no way to build a label at run time.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Label {
    full: &'static str,
    name: &'static str,
}

impl Label {
    /// The full label, `"rizzy-vault/v1/" + name`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.full
    }

    /// The full label as bytes. This is also the form HPKE `psk_id`s use (CRYPTO.md §4.3).
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        self.full.as_bytes()
    }

    /// The name `x` without the prefix, as CRYPTO.md writes it in `LABEL("x")`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Builds `LABEL(x) ‖ 0x00 ‖ ctx`, the form of every HKDF `info`, hash-domain prefix and
    /// signed message in CRYPTO.md (§2). `ctx` may be empty.
    ///
    /// The result is allocated at its final size. Do not pass secrets as `ctx`: contexts are
    /// public identifiers and counters.
    #[must_use]
    pub fn info(self, ctx: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.full.len() + 1 + ctx.len());
        out.extend_from_slice(self.as_bytes());
        out.push(0x00);
        out.extend_from_slice(ctx);
        out
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Label").field(&self.full).finish()
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.full)
    }
}

/// Defines each label constant and the [`ALL`] list from one table, so the list cannot miss
/// a label.
macro_rules! registry {
    ($( $(#[$doc:meta])* $ident:ident = $name:literal; )+) => {
        $(
            $(#[$doc])*
            pub const $ident: Label = Label {
                full: concat!("rizzy-vault/v1/", $name),
                name: $name,
            };
        )+

        /// Every registered label, in registry order. Used by the uniqueness tests and by
        /// anything that audits the label set.
        pub const ALL: &[Label] = &[$($ident),+];
    };
}

registry! {
    // --- OPAQUE and the password input (§4.3, §5.2, §5.3, §5.9) ---
    /// `pw_in = HKDF(UTF-8(NFC(password)), salt = SK, LABEL ‖ 0x00, 32)` (§5.2).
    OPAQUE_PASSWORD = "opaque/password";
    /// OPAQUE Context: `LABEL ‖ 0x00 ‖ u16(suite_id) ‖ u16(kdf_id) ‖ str(server_origin)` (§5.3).
    OPAQUE_CONTEXT = "opaque/context";
    /// Fake credential id for unknown login names (§4.3, §5.9).
    OPAQUE_FAKE_CREDENTIAL_ID = "opaque/fake-credential-id";
    /// Fake `kdf_id` selector for unknown login names (§4.3, §5.9).
    OPAQUE_FAKE_KDF = "opaque/fake-kdf";

    // --- Key ids and fingerprints (§4.3, §4.4, §10.3) ---
    /// Symmetric key id: `HKDF(K, salt = empty, LABEL ‖ 0x00, 16)`.
    KEY_ID_SYMMETRIC = "key-id/symmetric";
    /// Public key id: `SHA-256(LABEL ‖ 0x00 ‖ u8(key_type) ‖ public_key)[0..16]`.
    KEY_ID = "key-id";
    /// Account fingerprint (safety numbers).
    FINGERPRINT = "fingerprint";
    /// Device set hash in `account-state`.
    DEVICE_SET = "device-set";
    /// Secret Key check characters (§7).
    SECRET_KEY_CHECK = "secret-key/check";
    /// Recovery code check characters (§11.9).
    RECOVERY_CODE_CHECK = "recovery-code/check";

    // --- Unlock keys (§4.3, §5.4) ---
    /// `server_unlock_key = HKDF(export_key, LABEL ‖ 0x00 ‖ account_id, 32)`.
    UNLOCK_KEY_SERVER = "unlock-key/server";
    /// `local_unlock_key = HKDF(Argon2id(pw_in, device_salt), LABEL ‖ 0x00 ‖ account_id ‖ device_id, 32)`.
    UNLOCK_KEY_LOCAL = "unlock-key/local";

    // --- Envelope (§8.3) ---
    /// Envelope subkey and commitment: `HKDF(K, salt = nonce, LABEL ‖ 0x00 ‖ aad, 64)`.
    ENVELOPE_XCHACHA20POLY1305 = "envelope/xchacha20poly1305";

    // --- Account-key derived keys (§4.3) ---
    /// Relay key (M4).
    RELAY_KEY = "relay-key";
    /// Local index key (M3).
    LOCAL_INDEX_KEY = "local-index-key";

    // --- Recovery (§4.3, §11.9) ---
    /// Recovery wrap key.
    RECOVERY_WRAP_KEY = "recovery/wrap-key";
    /// Recovery auth token; the server stores its SHA-256.
    RECOVERY_AUTH_TOKEN = "recovery/auth-token";

    // --- Shares (§4.3, §11.10, M5) ---
    /// Share key.
    SHARE_KEY = "share/key";
    /// Share link token.
    SHARE_LINK_TOKEN = "share/link-token";
    /// Share access token.
    SHARE_ACCESS_TOKEN = "share/access-token";

    // --- Export (§4.3, §11.14) ---
    /// Export file key.
    EXPORT_KEY = "export/key";

    // --- Server-side sealing (§4.3, §5.11); `LABEL("server/<purpose>")` ---
    /// Server data subkey for `SERVER_TOTP_SECRET`.
    SERVER_TOTP_SECRET = "server/totp-secret";
    /// Server data subkey for `SERVER_LOGIN_STATE`.
    SERVER_LOGIN_STATE = "server/login-state";
    /// Server-secrets backup key.
    SERVER_SECRETS_BACKUP = "server/secrets-backup";

    // --- HPKE (§4.3, §9.2, §10.1) ---
    /// HPKE `info = LABEL ‖ 0x00 ‖ u16(purpose)`.
    HPKE = "hpke";
    /// Device-grant PSK derivation label and `psk_id`.
    HPKE_PSK_DEVICE_GRANT = "hpke-psk/device-grant";
    /// Password-verifier PSK derivation label and `psk_id` (M4).
    HPKE_PSK_PASSWORD_VERIFIER = "hpke-psk/password-verifier";
    /// Re-sync PSK derivation label and `psk_id` (M4).
    HPKE_PSK_RESYNC = "hpke-psk/resync";
    /// Pairing transfer `psk_id`; the PSK is `k_pair` (M4).
    HPKE_PSK_PAIRING = "hpke-psk/pairing";

    // --- Pairing (§4.3, §11.7, M4) ---
    /// Pairing key `k_pair`.
    PAIRING_KEY = "pairing/key";
    /// Pairing commitment `c_N`.
    PAIRING_COMMIT = "pairing/commit";
    /// Pairing short authentication string.
    PAIRING_SAS = "pairing/sas";

    // --- Signed statements (§5.10, §10.1, §10.2); `LABEL("sig/<type>")` ---
    /// `public-key-bundle` statement.
    SIG_PUBLIC_KEY_BUNDLE = "sig/public-key-bundle";
    /// `device-certificate` statement.
    SIG_DEVICE_CERTIFICATE = "sig/device-certificate";
    /// `device-revocation` statement.
    SIG_DEVICE_REVOCATION = "sig/device-revocation";
    /// `account-state` statement.
    SIG_ACCOUNT_STATE = "sig/account-state";
    /// `op` statement.
    SIG_OP = "sig/op";
    /// `snapshot` statement.
    SIG_SNAPSHOT = "sig/snapshot";
    /// `key-grant` statement.
    SIG_KEY_GRANT = "sig/key-grant";
    /// `device-auth` challenge signature.
    SIG_DEVICE_AUTH = "sig/device-auth";
    /// `device-request` request signature.
    SIG_DEVICE_REQUEST = "sig/device-request";
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn every_label_is_prefix_plus_name() {
        for label in ALL {
            assert_eq!(label.as_str(), format!("{PREFIX}{}", label.name()));
            assert_eq!(label.as_bytes(), label.as_str().as_bytes());
            assert_eq!(label.to_string(), label.as_str());
        }
    }

    #[test]
    fn labels_are_unique() {
        let full: HashSet<&str> = ALL.iter().map(|l| l.as_str()).collect();
        assert_eq!(full.len(), ALL.len(), "duplicate label");
        let names: HashSet<&str> = ALL.iter().map(|l| l.name()).collect();
        assert_eq!(names.len(), ALL.len(), "duplicate label name");
    }

    #[test]
    fn labels_are_nonempty_ascii_without_nul() {
        for label in ALL {
            assert!(!label.name().is_empty());
            assert!(label.as_str().is_ascii(), "{label:?}");
            assert!(!label.as_bytes().contains(&0x00), "{label:?}");
            // Printable ASCII only: no control characters or spaces either.
            assert!(
                label.as_bytes().iter().all(u8::is_ascii_graphic),
                "{label:?}"
            );
        }
    }

    #[test]
    fn info_is_prefix_free_across_labels() {
        // No `LABEL(a) ‖ 0x00` is a prefix of `LABEL(b) ‖ 0x00 ‖ ctx` for a ≠ b. This holds
        // because labels contain no 0x00; check it explicitly for the whole registry.
        for a in ALL {
            for b in ALL {
                if a == b {
                    continue;
                }
                let ia = a.info(&[]);
                let ib = b.info(b"any context bytes");
                assert!(!ib.starts_with(&ia), "{a:?} vs {b:?}");
            }
        }
    }

    #[test]
    fn info_layout() {
        assert_eq!(
            KEY_ID_SYMMETRIC.info(&[]),
            b"rizzy-vault/v1/key-id/symmetric\x00".to_vec()
        );
        assert_eq!(
            HPKE.info(&[0x00, 0x04]),
            b"rizzy-vault/v1/hpke\x00\x00\x04".to_vec()
        );
        assert_eq!(
            ENVELOPE_XCHACHA20POLY1305.as_str(),
            "rizzy-vault/v1/envelope/xchacha20poly1305"
        );
    }

    #[test]
    fn registry_covers_every_label_in_crypto_md() {
        // Every `LABEL("…")` spelled out in CRYPTO.md (§4.3, §5.2, §5.3, §5.10, §5.11, §7,
        // §9.2, §10.1, §10.2, §11.7, §11.9), with `server/<purpose>` and `sig/<type>` expanded.
        let expected = [
            "opaque/password",
            "opaque/context",
            "opaque/fake-credential-id",
            "opaque/fake-kdf",
            "key-id/symmetric",
            "key-id",
            "fingerprint",
            "device-set",
            "secret-key/check",
            "recovery-code/check",
            "unlock-key/server",
            "unlock-key/local",
            "envelope/xchacha20poly1305",
            "relay-key",
            "local-index-key",
            "recovery/wrap-key",
            "recovery/auth-token",
            "share/key",
            "share/link-token",
            "share/access-token",
            "export/key",
            "server/totp-secret",
            "server/login-state",
            "server/secrets-backup",
            "hpke",
            "hpke-psk/device-grant",
            "hpke-psk/password-verifier",
            "hpke-psk/resync",
            "hpke-psk/pairing",
            "pairing/key",
            "pairing/commit",
            "pairing/sas",
            "sig/public-key-bundle",
            "sig/device-certificate",
            "sig/device-revocation",
            "sig/account-state",
            "sig/op",
            "sig/snapshot",
            "sig/key-grant",
            "sig/device-auth",
            "sig/device-request",
        ];
        let registered: HashSet<&str> = ALL.iter().map(|l| l.name()).collect();
        let expected: HashSet<&str> = expected.into_iter().collect();
        assert_eq!(registered, expected);
    }
}
