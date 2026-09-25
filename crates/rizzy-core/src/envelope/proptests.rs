//! Property tests of CRYPTO.md §15 item 4 over every implemented purpose: the 13 client
//! symmetric purposes of M1, the 3 server-only purposes, and the HPKE PSK device grant.
//!
//! For random contexts, keys and plaintexts, each purpose must:
//! - round-trip, and parse → serialise must give the same bytes;
//! - reject a single-bit flip anywhere, reaching the AEAD only for a flip in the ciphertext or
//!   tag (for HPKE: nothing is decapsulated for a flip in the header);
//! - reject a wrong context field or epoch, a wrong purpose (every other implemented purpose,
//!   with the same context bytes where the layouts have the same length) and a wrong key, with
//!   the commitment failing before the AEAD (symmetric), and the key-id check failing before
//!   any crypto for a plain wrong key;
//! - reject an `alg_id` outside the purpose's allow-list, a wrong `format_version` and the other
//!   side's table (client/server) before any crypto: no `okm` derivation, no AEAD, no HPKE open;
//! - reject a truncation at any length, and an extension, without panicking.
//!
//! Case counts are small (the whole module runs in a few seconds unoptimised): 24 random cases
//! per purpose, plus deterministic sweeps of every truncation length and every single-bit flip
//! for one envelope per purpose.

use core::fmt::Debug;

use chacha20::ChaCha20Rng;
use proptest::prelude::*;
use rand_core::Rng as _;

use super::parse;
use super::purpose::{
    AccountKeyDeviceGrantCtx, AccountKeyLocalWrapCtx, AccountKeyRecoveryWrapCtx,
    AccountKeyServerWrapCtx, AccountSettingsCtx, DeviceSecretKeysCtx, ExportFileCtx,
    IdentitySecretKeysCtx, ItemKeyWrapCtx, ItemOpCtx, ItemSnapshotCtx, RetiredSecretKeyCtx,
    ServerLoginStateCtx, ServerSecretsBackupCtx, ServerTotpSecretCtx, VaultKeySelfGrantCtx,
};
use super::symmetric::{self, server_open, server_seal, test_hooks};
use super::{AlgId, Context, PlaintextRule, Purpose, open, seal};
use crate::encoding::Reader;
use crate::error::DecryptError;
use crate::hpke::{self, HpkePsk, HpkeSecretKey};
use crate::ids::{
    AccountId, BackupId, DeviceId, ExportId, ItemId, LoginId, OpId, PublicKeyId, SnapshotId,
    VaultId,
};
use crate::kdf::KdfId;
use crate::keys::AccountKey;
use crate::secret::{Key32, SecretBytes};
use crate::test_util::seeded_rng;

/// Offsets in a symmetric envelope (§9.1).
const KEY_ID_START: usize = 2;
const NONCE_START: usize = 18;
const BODY_START: usize = 74;

/// Offsets in an HPKE envelope (§9.2).
const HPKE_ENC_START: usize = 18;

const CASES: u32 = 24;

/// A small case count, and no regression files written into the source tree.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: CASES,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------------------------------------
// Random context fields
// ---------------------------------------------------------------------------------------------

/// A fixed-width context field: random values, the §8.4 byte layout, and a different value.
trait Field: Copy {
    fn random(rng: &mut ChaCha20Rng) -> Self;
    fn read(r: &mut Reader<'_>) -> Option<Self>;
    /// A value that differs from `self`.
    fn tweak(self) -> Self;
}

impl Field for u16 {
    fn random(rng: &mut ChaCha20Rng) -> Self {
        (rng.next_u32() & 0xffff) as u16
    }
    fn read(r: &mut Reader<'_>) -> Option<Self> {
        r.u16().ok()
    }
    fn tweak(self) -> Self {
        self ^ 1
    }
}

impl Field for u32 {
    fn random(rng: &mut ChaCha20Rng) -> Self {
        // Epochs and counters: mostly small, like real ones, sometimes anything.
        if rng.next_u32().is_multiple_of(4) {
            rng.next_u32()
        } else {
            rng.next_u32() % 8
        }
    }
    fn read(r: &mut Reader<'_>) -> Option<Self> {
        r.u32().ok()
    }
    fn tweak(self) -> Self {
        self.wrapping_add(1)
    }
}

impl Field for u64 {
    fn random(rng: &mut ChaCha20Rng) -> Self {
        rng.next_u64()
    }
    fn read(r: &mut Reader<'_>) -> Option<Self> {
        r.u64().ok()
    }
    fn tweak(self) -> Self {
        self ^ (1 << 40)
    }
}

impl<const N: usize> Field for [u8; N] {
    fn random(rng: &mut ChaCha20Rng) -> Self {
        let mut out = [0u8; N];
        rng.fill_bytes(&mut out);
        out
    }
    fn read(r: &mut Reader<'_>) -> Option<Self> {
        r.array::<N>().ok().copied()
    }
    fn tweak(mut self) -> Self {
        if let Some(last) = self.last_mut() {
            *last ^= 0x80;
        }
        self
    }
}

/// `kdf_id` in a context is only a `u16` in the AAD. The allowed id is 1; the tweak is a
/// test-only id no allow-list contains, which a reader would never build, but which must still
/// change the AAD.
impl Field for KdfId {
    fn random(_: &mut ChaCha20Rng) -> Self {
        KdfId::DEFAULT
    }
    fn read(r: &mut Reader<'_>) -> Option<Self> {
        match r.u16().ok()? {
            1 => Some(KdfId::DEFAULT),
            id => Some(KdfId::test_cheap(id, 1)),
        }
    }
    fn tweak(self) -> Self {
        KdfId::test_cheap(self.get() ^ 0x8000, 1)
    }
}

macro_rules! id_fields {
    ($($id:ident),+) => {$(
        impl Field for $id {
            fn random(rng: &mut ChaCha20Rng) -> Self {
                Self::from_bytes(Field::random(rng))
            }
            fn read(r: &mut Reader<'_>) -> Option<Self> {
                Some(Self::from_bytes(*r.array().ok()?))
            }
            fn tweak(self) -> Self {
                Self::from_bytes(self.to_bytes().tweak())
            }
        }
    )+};
}

id_fields!(
    AccountId, DeviceId, VaultId, ItemId, OpId, SnapshotId, ExportId, BackupId, LoginId
);

impl Field for PublicKeyId {
    fn random(rng: &mut ChaCha20Rng) -> Self {
        Self::from_bytes(Field::random(rng))
    }
    fn read(r: &mut Reader<'_>) -> Option<Self> {
        Some(Self::from_bytes(*r.array().ok()?))
    }
    fn tweak(self) -> Self {
        Self::from_bytes(self.as_bytes().tweak())
    }
}

// ---------------------------------------------------------------------------------------------
// Purposes under test
// ---------------------------------------------------------------------------------------------

/// Which table seals and opens a purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Table {
    Client,
    Server,
}

/// A symmetric purpose under test.
trait Case: Context + Copy + Debug + Sized {
    const TABLE: Table;
    fn random(rng: &mut ChaCha20Rng) -> Self;
    /// This purpose's context with the given `ctx` bytes, if the layout has that length.
    fn from_ctx(bytes: &[u8]) -> Option<Self>;
    /// Copies of `self` that each differ in one field.
    fn variants(&self) -> Vec<Self>;
    fn seal(rng: &mut ChaCha20Rng, key: &Key32, ctx: &Self, pt: &[u8]) -> Vec<u8>;
    fn open(key: &Key32, ctx: &Self, env: &[u8]) -> Result<SecretBytes, DecryptError>;
    /// Opens through the other table (client ↔ server).
    fn open_other_table(key: &Key32, ctx: &Self, env: &[u8]) -> Result<SecretBytes, DecryptError>;
}

macro_rules! case {
    ($table:ident $ty:ident { $($f:ident),+ $(,)? }) => {
        impl Case for $ty {
            const TABLE: Table = Table::$table;

            fn random(rng: &mut ChaCha20Rng) -> Self {
                Self { $($f: Field::random(rng)),+ }
            }

            fn from_ctx(bytes: &[u8]) -> Option<Self> {
                let mut r = Reader::new(bytes);
                // Struct literal fields are evaluated in source order: the §8.4 order.
                let ctx = Self { $($f: Field::read(&mut r)?),+ };
                r.finish().ok()?;
                Some(ctx)
            }

            fn variants(&self) -> Vec<Self> {
                vec![$(Self { $f: self.$f.tweak(), ..*self }),+]
            }

            fn seal(rng: &mut ChaCha20Rng, key: &Key32, ctx: &Self, pt: &[u8]) -> Vec<u8> {
                case!(@seal $table, rng, key, ctx, pt)
            }

            fn open(key: &Key32, ctx: &Self, env: &[u8]) -> Result<SecretBytes, DecryptError> {
                case!(@open $table, key, ctx, env)
            }

            fn open_other_table(
                key: &Key32,
                ctx: &Self,
                env: &[u8],
            ) -> Result<SecretBytes, DecryptError> {
                // Neither entry point accepts the other side's contexts at compile time, so
                // this goes through the other table's allow-list directly.
                let allow = match Self::TABLE {
                    Table::Client => Self::PURPOSE.server_decrypt_allow_list(),
                    Table::Server => Self::PURPOSE.client_decrypt_allow_list(),
                };
                assert!(allow.is_empty(), "{:?} is in both tables", Self::PURPOSE);
                parse::parse_for_purpose(env, allow)?;
                Self::open(key, ctx, env)
            }
        }
    };
    (@seal Client, $rng:ident, $key:ident, $ctx:ident, $pt:ident) => {
        seal($rng, $key, $ctx, $pt).expect("seal")
    };
    (@seal Server, $rng:ident, $key:ident, $ctx:ident, $pt:ident) => {
        server_seal($rng, $key, $ctx, $pt).expect("seal")
    };
    (@open Client, $key:ident, $ctx:ident, $env:ident) => {
        open($key, $ctx, $env)
    };
    (@open Server, $key:ident, $ctx:ident, $env:ident) => {
        server_open($key, $ctx, $env)
    };
}

case!(Client AccountKeyServerWrapCtx { account_id, account_key_epoch, password_epoch, kdf_id });
case!(Client AccountKeyLocalWrapCtx {
    account_id, device_id, account_key_epoch, password_epoch, kdf_id
});
case!(Client AccountKeyRecoveryWrapCtx { account_id, account_key_epoch, recovery_epoch });
case!(Client IdentitySecretKeysCtx { account_id, identity_epoch });
case!(Client DeviceSecretKeysCtx { account_id, device_id });
case!(Client RetiredSecretKeyCtx { account_id, retired_key_id });
case!(Client AccountSettingsCtx { account_id, settings_seq });
case!(Client VaultKeySelfGrantCtx { account_id, vault_id, account_key_epoch, vault_key_epoch });
case!(Client ItemKeyWrapCtx { vault_id, item_id, vault_key_epoch });
case!(Client ItemOpCtx {
    vault_id, item_id, item_schema_version, op_id, device_id, device_seq, hlc, op_header_hash
});
case!(Client ItemSnapshotCtx {
    vault_id, item_id, item_schema_version, snapshot_id, snapshot_header_hash
});
case!(Client ExportFileCtx { export_id, created_at_ms, kdf_id, export_salt });
case!(Server ServerTotpSecretCtx { account_id, totp_credential_seq });
case!(Server ServerLoginStateCtx { login_id, credential_identifier, expires_at_ms });
case!(Server ServerSecretsBackupCtx { backup_id, created_at_ms, kdf_id, backup_salt });

/// Opens `env` as purpose `C`, with `ctx_bytes` read as `C`'s context where the layouts have
/// the same length, and a random `C` context otherwise. Returns the result and how many `okm`
/// derivations and AEAD openings it took.
fn open_as<C: Case>(
    rng: &mut ChaCha20Rng,
    key: &Key32,
    ctx_bytes: &[u8],
    env: &[u8],
) -> (Purpose, Result<(), DecryptError>, usize, usize) {
    let ctx = C::from_ctx(ctx_bytes).unwrap_or_else(|| C::random(rng));
    let (result, okm, aead) = counted(|| C::open(key, &ctx, env).map(|_| ()));
    (C::PURPOSE, result, okm, aead)
}

type OpenAs =
    fn(&mut ChaCha20Rng, &Key32, &[u8], &[u8]) -> (Purpose, Result<(), DecryptError>, usize, usize);

/// Every implemented symmetric purpose, as an opener.
const ALL_SYMMETRIC: [OpenAs; 15] = [
    open_as::<AccountKeyServerWrapCtx>,
    open_as::<AccountKeyLocalWrapCtx>,
    open_as::<AccountKeyRecoveryWrapCtx>,
    open_as::<IdentitySecretKeysCtx>,
    open_as::<DeviceSecretKeysCtx>,
    open_as::<RetiredSecretKeyCtx>,
    open_as::<AccountSettingsCtx>,
    open_as::<VaultKeySelfGrantCtx>,
    open_as::<ItemKeyWrapCtx>,
    open_as::<ItemOpCtx>,
    open_as::<ItemSnapshotCtx>,
    open_as::<ExportFileCtx>,
    open_as::<ServerTotpSecretCtx>,
    open_as::<ServerLoginStateCtx>,
    open_as::<ServerSecretsBackupCtx>,
];

/// Runs `f`, counting `okm` derivations and AEAD openings on this thread.
fn counted<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    let (okm, aead) = (test_hooks::okm_derivations(), test_hooks::aead_opens());
    let out = f();
    (
        out,
        test_hooks::okm_derivations() - okm,
        test_hooks::aead_opens() - aead,
    )
}

fn hpke_counted<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = hpke::test_hooks::hpke_opens();
    let out = f();
    (out, hpke::test_hooks::hpke_opens() - before)
}

/// A plaintext that fits the purpose's rule: its fixed size, or `len` bytes.
fn plaintext(purpose: Purpose, len: usize, rng: &mut ChaCha20Rng) -> Vec<u8> {
    let len = match purpose.plaintext_rule() {
        PlaintextRule::Fixed(n) => n,
        _ => len,
    };
    let mut pt = vec![0u8; len];
    rng.fill_bytes(&mut pt);
    pt
}

/// Random mutation parameters for one case.
#[derive(Clone, Copy, Debug)]
struct Mutation {
    flip: usize,
    bit: u8,
    cut: usize,
    alg: u8,
    version: u8,
}

fn mutation() -> impl Strategy<Value = Mutation> {
    (
        any::<usize>(),
        0u8..8,
        any::<usize>(),
        any::<u8>(),
        any::<u8>(),
    )
        .prop_map(|(flip, bit, cut, alg, version)| Mutation {
            flip,
            bit,
            cut,
            alg,
            version,
        })
}

// ---------------------------------------------------------------------------------------------
// Symmetric properties
// ---------------------------------------------------------------------------------------------

/// Every property of the module doc for one symmetric purpose.
fn symmetric_properties<C: Case>(seed: u64, len: usize, m: Mutation) -> Result<(), TestCaseError> {
    let mut rng = seeded_rng(seed);
    let key = Key32::generate(&mut rng);
    let ctx = C::random(&mut rng);
    let pt = plaintext(C::PURPOSE, len, &mut rng);
    let env = C::seal(&mut rng, &key, &ctx, &pt);
    let rejected = |r: &Result<SecretBytes, DecryptError>| matches!(r, Err(DecryptError));

    // Round trip, and parse → serialise.
    let (opened, okm, aead) = counted(|| C::open(&key, &ctx, &env));
    let opened = opened.expect("opens");
    prop_assert_eq!(opened.expose_secret(), pt.as_slice());
    prop_assert_eq!((okm, aead), (1, 1));
    let parsed = parse::parse(&env).expect("parses");
    prop_assert_eq!(parsed.to_vec(), env.clone());
    prop_assert_eq!(parsed.alg_id(), AlgId::XChaCha20Poly1305Committed);

    // A single-bit flip anywhere.
    let i = m.flip % env.len();
    let mut flipped = env.clone();
    flipped[i] ^= 1 << m.bit;
    let (result, okm, aead) = counted(|| C::open(&key, &ctx, &flipped));
    prop_assert!(rejected(&result), "flip at {i}");
    // Header flips fail the version, allow-list or key-id check before any crypto; nonce and
    // commitment flips fail the commitment; only body flips reach the AEAD.
    prop_assert_eq!(okm, usize::from(i >= NONCE_START), "okm, flip at {}", i);
    prop_assert_eq!(aead, usize::from(i >= BODY_START), "aead, flip at {}", i);

    // Wrong context field or epoch: the commitment fails first.
    for wrong in ctx.variants() {
        let (result, okm, aead) = counted(|| C::open(&key, &wrong, &env));
        prop_assert!(rejected(&result), "{:?}", wrong);
        prop_assert_eq!((okm, aead), (1, 0), "{:?}", wrong);
    }

    // Wrong purpose: every other implemented purpose, with the same ctx bytes where they fit.
    let ctx_bytes = ctx.ctx_bytes();
    for open_as in ALL_SYMMETRIC {
        let (purpose, result, _, aead) = open_as(&mut rng, &key, &ctx_bytes, &env);
        if purpose == C::PURPOSE {
            continue;
        }
        prop_assert_eq!(result, Err(DecryptError), "as {:?}", purpose);
        prop_assert_eq!(aead, 0, "as {:?}", purpose);
    }

    // The other side's table rejects before any crypto.
    let (result, okm, aead) = counted(|| C::open_other_table(&key, &ctx, &env));
    prop_assert!(rejected(&result));
    prop_assert_eq!((okm, aead), (0, 0));

    // Wrong key: the key id differs, so nothing is derived. Relabelled with the wrong key's id,
    // the commitment (which covers the key) fails before the AEAD.
    let other = Key32::generate(&mut rng);
    let (result, okm, aead) = counted(|| C::open(&other, &ctx, &env));
    prop_assert!(rejected(&result));
    prop_assert_eq!((okm, aead), (0, 0));
    let mut relabelled = env.clone();
    relabelled[KEY_ID_START..NONCE_START].copy_from_slice(other.key_id().expect("id").as_bytes());
    let (result, okm, aead) = counted(|| C::open(&other, &ctx, &relabelled));
    prop_assert!(rejected(&result));
    prop_assert_eq!((okm, aead), (1, 0));

    // alg_id outside the allow-list and a wrong format_version: before any crypto.
    if m.alg != AlgId::XChaCha20Poly1305Committed.to_u8() {
        let mut bad = env.clone();
        bad[1] = m.alg;
        let (result, okm, aead) = counted(|| C::open(&key, &ctx, &bad));
        prop_assert!(rejected(&result), "alg {:#04x}", m.alg);
        prop_assert_eq!((okm, aead), (0, 0));
    }
    if m.version != 0x01 {
        let mut bad = env.clone();
        bad[0] = m.version;
        let (result, okm, aead) = counted(|| C::open(&key, &ctx, &bad));
        prop_assert!(rejected(&result));
        prop_assert_eq!((okm, aead), (0, 0));
    }

    // Truncation at a random length, and an extension: errors, never panics. Shorter than the
    // 90-byte overhead fails the length check; longer keeps an intact header, nonce and
    // commitment (which do not cover the ciphertext), so the AEAD tag check is what fails.
    let cut = m.cut % env.len();
    let (result, _, aead) = counted(|| C::open(&key, &ctx, &env[..cut]));
    prop_assert!(rejected(&result), "cut at {cut}");
    prop_assert_eq!(
        aead,
        usize::from(cut >= symmetric::OVERHEAD),
        "cut at {}",
        cut
    );
    let _ = parse::parse(&env[..cut]);
    let mut longer = env.clone();
    longer.push(0);
    prop_assert!(rejected(&C::open(&key, &ctx, &longer)));
    Ok(())
}

/// Deterministic sweeps for one envelope of the purpose: every truncation length, and every
/// single-bit flip.
fn symmetric_sweeps<C: Case>(seed: u64, len: usize) {
    let mut rng = seeded_rng(seed);
    let key = Key32::generate(&mut rng);
    let ctx = C::random(&mut rng);
    let pt = plaintext(C::PURPOSE, len, &mut rng);
    let env = C::seal(&mut rng, &key, &ctx, &pt);
    for n in 0..env.len() {
        assert_eq!(
            C::open(&key, &ctx, &env[..n]).map(|_| ()),
            Err(DecryptError),
            "{:?} cut at {n}",
            C::PURPOSE
        );
    }
    for i in 0..env.len() {
        for bit in 0..8 {
            let mut bad = env.clone();
            bad[i] ^= 1 << bit;
            let (result, _, aead) = counted(|| C::open(&key, &ctx, &bad).map(|_| ()));
            assert_eq!(result, Err(DecryptError), "{:?} flip {i}.{bit}", C::PURPOSE);
            assert_eq!(
                aead,
                usize::from(i >= BODY_START),
                "{:?} flip {i}",
                C::PURPOSE
            );
        }
    }
}

macro_rules! symmetric_tests {
    ($($name:ident: $ty:ty),+ $(,)?) => {
        proptest! {
            #![proptest_config(config())]
            $(
                #[test]
                fn $name(seed in any::<u64>(), len in 0usize..600, m in mutation()) {
                    symmetric_properties::<$ty>(seed, len, m)?;
                }
            )+
        }

        #[test]
        fn every_purpose_rejects_every_truncation_and_every_bit_flip() {
            $( symmetric_sweeps::<$ty>(0x5eed, 20); )+
        }

        /// The harness covers every symmetric purpose that has a context type in M1.
        #[test]
        fn the_harness_covers_every_implemented_symmetric_purpose() {
            let covered = [$(<$ty as Context>::PURPOSE),+];
            for p in Purpose::ALL {
                let implemented = p.spec().first_used == super::purpose::Milestone::M1
                    && p.encrypt_alg() == AlgId::XChaCha20Poly1305Committed;
                assert_eq!(covered.contains(&p), implemented, "{}", p.name());
            }
        }
    };
}

symmetric_tests!(
    account_key_server_wrap: AccountKeyServerWrapCtx,
    account_key_local_wrap: AccountKeyLocalWrapCtx,
    account_key_recovery_wrap: AccountKeyRecoveryWrapCtx,
    identity_secret_keys: IdentitySecretKeysCtx,
    device_secret_keys: DeviceSecretKeysCtx,
    retired_secret_key: RetiredSecretKeyCtx,
    account_settings: AccountSettingsCtx,
    vault_key_self_grant: VaultKeySelfGrantCtx,
    item_key_wrap: ItemKeyWrapCtx,
    item_op: ItemOpCtx,
    item_snapshot: ItemSnapshotCtx,
    export_file: ExportFileCtx,
    server_totp_secret: ServerTotpSecretCtx,
    server_login_state: ServerLoginStateCtx,
    server_secrets_backup: ServerSecretsBackupCtx,
);

// ---------------------------------------------------------------------------------------------
// HPKE PSK: ACCOUNT_KEY_DEVICE_GRANT
// ---------------------------------------------------------------------------------------------

struct Grant {
    recipient: HpkeSecretKey,
    previous: AccountKey,
    ctx: AccountKeyDeviceGrantCtx,
    pt: [u8; 32],
    env: Vec<u8>,
}

fn grant(rng: &mut ChaCha20Rng) -> Grant {
    let epoch = 1 + rng.next_u32() % 8;
    let ctx = AccountKeyDeviceGrantCtx {
        account_id: Field::random(rng),
        account_key_epoch: epoch,
        sender_device_id: Field::random(rng),
        recipient_device_id: Field::random(rng),
    };
    let recipient = HpkeSecretKey::generate_x25519(rng);
    let previous = AccountKey::generate(rng, epoch - 1);
    let psk = HpkePsk::device_grant(&previous, &ctx).expect("psk");
    let pt: [u8; 32] = Field::random(rng);
    let env = hpke::seal_psk(rng, recipient.public_key(), &psk, &ctx, &pt).expect("seal");
    Grant {
        recipient,
        previous,
        ctx,
        pt,
        env,
    }
}

fn open_grant(
    g: &Grant,
    recipient: &HpkeSecretKey,
    ctx: &AccountKeyDeviceGrantCtx,
    env: &[u8],
) -> (Result<(), DecryptError>, usize) {
    hpke_counted(|| {
        let psk = HpkePsk::device_grant(&g.previous, ctx).map_err(|_| DecryptError)?;
        hpke::open_psk(recipient, &psk, ctx, env).map(|_| ())
    })
}

fn device_grant_properties(seed: u64, m: Mutation) -> Result<(), TestCaseError> {
    let mut rng = seeded_rng(seed);
    let g = grant(&mut rng);

    let psk = HpkePsk::device_grant(&g.previous, &g.ctx).expect("psk");
    let opened = hpke::open_psk(&g.recipient, &psk, &g.ctx, &g.env).expect("opens");
    prop_assert_eq!(opened.expose_secret(), &g.pt[..]);
    let parsed = parse::parse(&g.env).expect("parses");
    prop_assert_eq!(parsed.to_vec(), g.env.clone());
    prop_assert_eq!(parsed.alg_id(), AlgId::HpkePskX25519);

    // A single-bit flip: header flips fail before any HPKE open.
    let i = m.flip % g.env.len();
    let mut flipped = g.env.clone();
    flipped[i] ^= 1 << m.bit;
    let (result, opens) = open_grant(&g, &g.recipient, &g.ctx, &flipped);
    prop_assert_eq!(result, Err(DecryptError), "flip at {}", i);
    prop_assert_eq!(opens, usize::from(i >= HPKE_ENC_START), "flip at {}", i);

    // Wrong context field or epoch. HPKE has no separate commitment (§9.2): the AEAD rejects
    // the rebuilt AAD (and a changed epoch or recipient also changes the PSK).
    for wrong in [
        AccountKeyDeviceGrantCtx {
            account_id: g.ctx.account_id.tweak(),
            ..g.ctx
        },
        AccountKeyDeviceGrantCtx {
            sender_device_id: g.ctx.sender_device_id.tweak(),
            ..g.ctx
        },
        AccountKeyDeviceGrantCtx {
            recipient_device_id: g.ctx.recipient_device_id.tweak(),
            ..g.ctx
        },
    ] {
        let (result, _) = open_grant(&g, &g.recipient, &wrong, &g.env);
        prop_assert_eq!(result, Err(DecryptError), "{:?}", wrong);
    }
    let later = AccountKeyDeviceGrantCtx {
        account_key_epoch: g.ctx.account_key_epoch + 1,
        ..g.ctx
    };
    let (result, opens) = hpke_counted(|| {
        // The previous key no longer fits the epoch: refused before any crypto.
        HpkePsk::device_grant(&g.previous, &later)
            .map_err(|_| DecryptError)
            .and_then(|psk| hpke::open_psk(&g.recipient, &psk, &later, &g.env).map(|_| ()))
    });
    prop_assert_eq!(result, Err(DecryptError));
    prop_assert_eq!(opens, 0);

    // Wrong recipient key: the key id differs, nothing is decapsulated.
    let other = HpkeSecretKey::generate_x25519(&mut rng);
    let (result, opens) = open_grant(&g, &other, &g.ctx, &g.env);
    prop_assert_eq!(result, Err(DecryptError));
    prop_assert_eq!(opens, 0);

    // Wrong PSK: another previous account key.
    let wrong_previous = AccountKey::generate(&mut rng, g.previous.epoch());
    let wrong_psk = HpkePsk::device_grant(&wrong_previous, &g.ctx).expect("psk");
    let (result, opens) =
        hpke_counted(|| hpke::open_psk(&g.recipient, &wrong_psk, &g.ctx, &g.env).map(|_| ()));
    prop_assert_eq!(result, Err(DecryptError));
    prop_assert_eq!(opens, 1);

    // Wrong purpose: no symmetric purpose accepts an HPKE algorithm (§9.5 rule 2), so every one
    // rejects it before any crypto.
    let key = Key32::generate(&mut rng);
    let ctx_bytes = g.ctx.ctx_bytes();
    for open_as in ALL_SYMMETRIC {
        let (purpose, result, okm, aead) = open_as(&mut rng, &key, &ctx_bytes, &g.env);
        prop_assert_eq!(result, Err(DecryptError), "as {:?}", purpose);
        prop_assert_eq!((okm, aead), (0, 0), "as {:?}", purpose);
    }

    // alg_id outside the allow-list (Base mode included) and a wrong version: no HPKE open.
    if m.alg != AlgId::HpkePskX25519.to_u8() {
        let mut bad = g.env.clone();
        bad[1] = m.alg;
        let (result, opens) = open_grant(&g, &g.recipient, &g.ctx, &bad);
        prop_assert_eq!(result, Err(DecryptError), "alg {:#04x}", m.alg);
        prop_assert_eq!(opens, 0);
    }
    if m.version != 0x01 {
        let mut bad = g.env.clone();
        bad[0] = m.version;
        let (result, opens) = open_grant(&g, &g.recipient, &g.ctx, &bad);
        prop_assert_eq!(result, Err(DecryptError));
        prop_assert_eq!(opens, 0);
    }

    // Truncation and extension: the fixed-size purpose rejects any other length before crypto.
    let cut = m.cut % g.env.len();
    let (result, opens) = open_grant(&g, &g.recipient, &g.ctx, &g.env[..cut]);
    prop_assert_eq!(result, Err(DecryptError));
    prop_assert_eq!(opens, 0);
    let mut longer = g.env.clone();
    longer.push(0);
    let (result, opens) = open_grant(&g, &g.recipient, &g.ctx, &longer);
    prop_assert_eq!(result, Err(DecryptError));
    prop_assert_eq!(opens, 0);
    Ok(())
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn account_key_device_grant(seed in any::<u64>(), m in mutation()) {
        device_grant_properties(seed, m)?;
    }

    /// Parse → serialise is the identity for every envelope the parser accepts, and the parser
    /// never panics.
    #[test]
    fn parse_serialise_identity_on_arbitrary_input(
        head in prop_oneof![Just(vec![0x01u8, 0x01]), Just(vec![0x01, 0x10]),
            Just(vec![0x01, 0x12]), proptest::collection::vec(any::<u8>(), 0..3)],
        body in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let mut env = head;
        env.extend_from_slice(&body);
        if let Ok(parsed) = parse::parse(&env) {
            prop_assert_eq!(parsed.to_vec(), env.clone());
            prop_assert_eq!(parsed.encoded_len(), env.len());
        }
    }
}

#[test]
fn device_grant_rejects_every_truncation_and_every_bit_flip() {
    let g = grant(&mut seeded_rng(0x5eed));
    for n in 0..g.env.len() {
        assert_eq!(
            open_grant(&g, &g.recipient, &g.ctx, &g.env[..n]).0,
            Err(DecryptError)
        );
    }
    for i in 0..g.env.len() {
        for bit in 0..8 {
            let mut bad = g.env.clone();
            bad[i] ^= 1 << bit;
            let (result, opens) = open_grant(&g, &g.recipient, &g.ctx, &bad);
            assert_eq!(result, Err(DecryptError), "flip {i}.{bit}");
            assert_eq!(opens, usize::from(i >= HPKE_ENC_START), "flip {i}");
        }
    }
}

/// `from_ctx` reads exactly the §8.4 layout that `write_ctx` writes.
#[test]
fn harness_ctx_reader_matches_the_writer() {
    fn check<C: Case + PartialEq>() {
        let mut rng = seeded_rng(7);
        for _ in 0..8 {
            let ctx = C::random(&mut rng);
            assert_eq!(C::from_ctx(&ctx.ctx_bytes()), Some(ctx));
            for v in ctx.variants() {
                assert_ne!(v.ctx_bytes(), ctx.ctx_bytes(), "{v:?}");
            }
        }
    }
    check::<AccountKeyServerWrapCtx>();
    check::<ItemOpCtx>();
    check::<ExportFileCtx>();
    check::<ServerLoginStateCtx>();
    assert_eq!(BODY_START + symmetric::TAG_LEN, symmetric::OVERHEAD);
}
