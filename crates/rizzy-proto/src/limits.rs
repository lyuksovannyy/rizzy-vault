//! Every size limit of the `/api/v1` types, with its source, and the character sets of the
//! [`Text`](crate::wire::Text) fields.
//!
//! Two kinds of limit:
//! - **Format limits** follow from a layout CRYPTO.md or ADR 0012 fixes: the envelope's 16 MiB
//!   plaintext limit plus its overhead, the op and snapshot headers with at most `u16::MAX`
//!   version-vector entries, a statement's fixed body plus its signature container. They are
//!   upper bounds only. The exact parse (lengths, versions, algorithm ids) stays in
//!   `rizzy-core` and `rizzy-sync`, which the server and clients run on the decoded bytes; this
//!   crate does not depend on them (ADR 0016 §3: `rizzy-proto` has no internal dependency).
//! - **Count limits** on lists have no source in the ADRs. They are this crate's conservative
//!   choice, each stated below, and a change is a pre-v1.0 wire change (ADR 0002 point 5). A
//!   whole request is further bounded by the server's body-size limit (threat model §7.6 "D").

use crate::wire::TextRule;

/// The M1 envelope plaintext limit: 16 MiB (CRYPTO.md §9.1, §9.2).
pub const MAX_PLAINTEXT_LEN: usize = 16 * 1024 * 1024;

/// Overhead of the symmetric envelope, algorithm 0x01 (CRYPTO.md §9.1). The HPKE envelope's
/// is smaller, 66 bytes (§9.2).
pub const SYMMETRIC_ENVELOPE_OVERHEAD: usize = 90;

/// The largest envelope: a 16 MiB plaintext under the symmetric envelope (CRYPTO.md §9.1).
/// Bounds op bodies, snapshots and `ACCOUNT_SETTINGS`.
pub const MAX_ENVELOPE_LEN: usize = MAX_PLAINTEXT_LEN + SYMMETRIC_ENVELOPE_OVERHEAD;

/// The largest key-wrap envelope. Key-wrap plaintexts are fixed-size and unpadded, at most 65
/// bytes (`DEVICE_SECRET_KEYS`; CRYPTO.md §8.5), so every symmetric wrap is at most 155 bytes
/// and every HPKE grant 98 (§9.1, §9.2). 256 leaves room without admitting anything large.
pub const MAX_KEY_ENVELOPE_LEN: usize = 256;

/// Length of one Ed25519 signature container (CRYPTO.md §9.3): version, algorithm, 16-byte
/// signer key id, 64-byte signature. `sig_alg` 0x02 (hybrid, §13) is reserved and has no
/// length yet; the ADR that specifies it raises this.
pub const SIGNATURE_CONTAINER_LEN: usize = 2 + 16 + 64;

/// Wire-form overhead of a signed statement around its body (CRYPTO.md §9.6):
/// `bytes(u16(statement_version) ‖ body)` adds a 4-byte length and a 2-byte version.
const STATEMENT_FRAME: usize = 4 + 2;

/// The largest account-level signed statement in wire form: `public-key-bundle` (with its two
/// containers when the identity keys change), `device-certificate`, `device-revocation` and
/// `account-state` (CRYPTO.md §10.2). The largest M1 body is the bundle's, 181 bytes with its
/// three 32-byte keys (§9.7 "the M1 limit fits three 32-byte keys"); with two containers the
/// statement is 351 bytes. 1 KiB leaves room for a PQ key the M1 parser would still reject.
pub const MAX_ACCOUNT_STATEMENT_LEN: usize = 1024;

/// Fixed part of the canonical op header, 97 bytes, and of the snapshot header, 73 bytes, each
/// including the `u16` entry count (ADR 0012 §3; rizzy-core `sign::statements`).
const OP_HEADER_FIXED: usize = 97;
/// See [`OP_HEADER_FIXED`].
const SNAPSHOT_HEADER_FIXED: usize = 73;
/// One version-vector or causal-context entry: `device_id ‖ u64 seq` (ADR 0012 §3).
const VV_ENTRY_LEN: usize = 16 + 8;
/// The most entries a canonical version vector holds (`u16 n`, ADR 0012 §3).
pub const MAX_VV_ENTRIES: usize = 65_535;

/// The largest `op` statement in wire form: the op header with `u16::MAX` causal-context
/// entries, inside `bytes(...)`, the two 32-byte hashes, and one container (CRYPTO.md §9.6,
/// §10.2; ADR 0012 §3).
pub const MAX_OP_STATEMENT_LEN: usize = STATEMENT_FRAME
    + 4
    + OP_HEADER_FIXED
    + VV_ENTRY_LEN * MAX_VV_ENTRIES
    + 32
    + 32
    + SIGNATURE_CONTAINER_LEN;

/// The largest `snapshot` statement in wire form, as [`MAX_OP_STATEMENT_LEN`] with the snapshot
/// header.
pub const MAX_SNAPSHOT_STATEMENT_LEN: usize = STATEMENT_FRAME
    + 4
    + SNAPSHOT_HEADER_FIXED
    + VV_ENTRY_LEN * MAX_VV_ENTRIES
    + 32
    + 32
    + SIGNATURE_CONTAINER_LEN;

/// The largest `key-grant` statement carrying a key-wrap envelope (CRYPTO.md §10.1): purpose,
/// two key ids, `bytes(hpke_envelope)`, one container.
pub const MAX_KEY_GRANT_STATEMENT_LEN: usize =
    STATEMENT_FRAME + 2 + 16 + 16 + 4 + MAX_KEY_ENVELOPE_LEN + SIGNATURE_CONTAINER_LEN;

/// Upper bound on one OPAQUE protocol message of the M1 suite (ristretto255-SHA512, CRYPTO.md
/// §5.1): the largest, KE2, is 320 bytes and the registration upload 192. `rizzy-core` checks
/// the exact lengths (`opaque::KE2_LEN` and the others).
pub const MAX_OPAQUE_MESSAGE_LEN: usize = 512;

/// Length of a device-authentication challenge (CRYPTO.md §5.10).
pub const CHALLENGE_LEN: usize = 32;

/// Length of a SHA-256 value: `H_rec` (CRYPTO.md §11.1 step 5).
pub const HASH_LEN: usize = 32;

/// Length of the recovery auth token (CRYPTO.md §4.3: an HKDF output of 32 bytes; §11.9 steps
/// 2–3).
pub const RECOVERY_AUTH_TOKEN_LEN: usize = 32;

/// Length of a server 2FA secret: "generated at 20 bytes (160 bits)" (CRYPTO.md §11.15).
pub const TOTP_SECRET_LEN: usize = 20;

/// Length of the restore generation (ADR 0021 §2): 128 bits.
pub const RESTORE_GENERATION_LEN: usize = 16;

/// Count limit (this crate's choice): signed bundles in one response or request. Bundles form
/// one chain per account, one link per key change, so years of rotations stay far below it.
pub const MAX_BUNDLES: usize = 1024;

/// Count limit (this crate's choice): device certificates, and separately revocations, in one
/// message. Kind-4 certificates are re-issued in a full rotation (CRYPTO.md §11.6 step 7), so
/// this is set well above a personal account's device count.
pub const MAX_DEVICE_STATEMENTS: usize = 4096;

/// Count limit (this crate's choice): vault self-grants in one message. One vault per account
/// in M1 (ADR 0021 §9), several from M9.
pub const MAX_VAULT_GRANTS: usize = 1024;

/// Count limit (this crate's choice): pending device grants in one response or request, one
/// per rotation the device has not acknowledged (CRYPTO.md §10.1).
pub const MAX_DEVICE_GRANTS: usize = 1024;

/// Count limit: `RETIRED_SECRET_KEY` envelopes in one change (ADR 0025 §1: "at most 16"). A
/// full rotation retires the two identity keys and, from M6, a mail key; the bound only keeps
/// the request small.
pub const MAX_RETIRED_KEYS: usize = 16;

/// Count limit (this crate's choice): op and snapshot records in one upload, one healing
/// request or one Fetch page.
pub const MAX_RECORDS: usize = 4096;

/// Count limit (this crate's choice): item-key wrap-set rows in one Fetch page or healing
/// request (CRYPTO.md §4.2), about one per item.
pub const MAX_ITEM_KEY_WRAPS: usize = 65_536;

/// Count limit (this crate's choice): API versions and minimum client versions in
/// `GET /api/meta` (ADR 0002 point 3).
pub const MAX_META_ENTRIES: usize = 32;

/// Login names: CRYPTO.md §2. After ASCII lowercasing, 1–254 bytes from `[a-z0-9._+@-]`,
/// anything else "rejected at signup and at login, before any lookup". The wire admits exactly
/// the inputs that lowercase into that set, so uppercase letters pass and the server applies
/// the one normalisation function (rizzy-core `normalize`). Personal data (often an email
/// address), so `Debug` prints its length only.
#[derive(Debug)]
pub enum LoginNameRule {}

impl TextRule for LoginNameRule {
    const MAX: usize = 254;
    const REDACT: bool = true;
    fn allowed(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'@' | b'-')
    }
}

/// `server_origin` (CRYPTO.md §2): at most 512 bytes of printable ASCII on input; the exact
/// grammar is rizzy-core's `normalize` parser, which fails closed.
#[derive(Debug)]
pub enum OriginRule {}

impl TextRule for OriginRule {
    const MAX: usize = 512;
    const REDACT: bool = false;
    fn allowed(byte: u8) -> bool {
        byte.is_ascii_graphic()
    }
}

/// A server or client version (ADR 0002 point 3): at most 64 bytes of `[0-9A-Za-z.+-]`, which
/// covers semantic versions with pre-release and build suffixes. No format is fixed beyond
/// that.
#[derive(Debug)]
pub enum VersionRule {}

impl TextRule for VersionRule {
    const MAX: usize = 64;
    const REDACT: bool = false;
    fn allowed(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-')
    }
}

/// A client platform in `Rizzy-Client: <platform>/<version>` and in the minimum-version list
/// (ADR 0002 point 3): at most 32 bytes of `[a-z0-9-]`. The platform names are not fixed by
/// any ADR yet.
#[derive(Debug)]
pub enum PlatformRule {}

impl TextRule for PlatformRule {
    const MAX: usize = 32;
    const REDACT: bool = false;
    fn allowed(byte: u8) -> bool {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
    }
}

/// An API version name in `GET /api/meta` (ADR 0002 point 3), such as `v1`: at most 16 bytes of
/// `[a-z0-9]`.
#[derive(Debug)]
pub enum ApiVersionRule {}

impl TextRule for ApiVersionRule {
    const MAX: usize = 16;
    const REDACT: bool = false;
    fn allowed(byte: u8) -> bool {
        byte.is_ascii_lowercase() || byte.is_ascii_digit()
    }
}

/// An admin-issued invite token (CRYPTO.md §5.9, §11.1 step 1). Its format is not specified,
/// so the wire admits at most 256 bytes of printable ASCII and treats it as a secret.
#[derive(Debug)]
pub enum InviteTokenRule {}

impl TextRule for InviteTokenRule {
    const MAX: usize = 256;
    const REDACT: bool = true;
    fn allowed(byte: u8) -> bool {
        byte.is_ascii_graphic()
    }
}

/// A TOTP code for server-side 2FA (CRYPTO.md §11.15: 6–8 digits). The wire admits 1–8 ASCII
/// digits; the server's TOTP check rejects a wrong length like a wrong code.
#[derive(Debug)]
pub enum TotpCodeRule {}

impl TextRule for TotpCodeRule {
    const MAX: usize = 8;
    const REDACT: bool = true;
    fn allowed(byte: u8) -> bool {
        byte.is_ascii_digit()
    }
}

#[cfg(test)]
mod tests {
    //! The derived limits against the layouts they come from.

    use super::*;

    #[test]
    fn statement_limits_match_the_layouts() {
        // ADR 0012 §3: header_version, vault, item, op, device ids, device_seq, vault_prev_seq,
        // hlc, item_schema_version, vault_key_epoch, u16 n.
        assert_eq!(OP_HEADER_FIXED, 1 + 16 * 4 + 8 * 3 + 2 + 4 + 2);
        // header_version, vault, item, snapshot, author ids, item_schema_version,
        // vault_key_epoch, u16 n.
        assert_eq!(SNAPSHOT_HEADER_FIXED, 1 + 16 * 4 + 2 + 4 + 2);
        assert_eq!(SIGNATURE_CONTAINER_LEN, 82);
        assert_eq!(MAX_OP_STATEMENT_LEN, 1_573_093);
        assert_eq!(MAX_VV_ENTRIES, usize::from(u16::MAX));
        // The bundle body with three keys, two containers.
        let bundle_body = 16 + 4 + 8 + 1 + 3 * (1 + 4 + 32) + 1 + 8 + 32;
        assert_eq!(bundle_body, 181);
        assert!(STATEMENT_FRAME + bundle_body + 2 * SIGNATURE_CONTAINER_LEN <= 1024);
        // DEVICE_SECRET_KEYS is the largest key-wrap plaintext (CRYPTO.md §8.5).
        const { assert!(SYMMETRIC_ENVELOPE_OVERHEAD + 65 <= MAX_KEY_ENVELOPE_LEN) };
    }
}
