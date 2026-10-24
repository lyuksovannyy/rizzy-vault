// SPDX-License-Identifier: AGPL-3.0-only

//! Proptest-driven malicious-server mutation harness against the fake server's Fetch channel
//! (threat model §5, A2/A3; CRYPTO.md §15 item 5's malicious-server canary). It generalises the
//! hand-picked cases of `fetch_drops_forged_records`, `unlock_keeps_settings_the_server_leaves_out`
//! and `server_behind_and_restore_generations` into a combinatorial fuzzer over the same wire
//! types, following the convergence suite's PR/nightly split
//! (`rizzy_sync::convergence::generate`: `Seeds::Fixed` for PR, `Seeds::Fresh` for nightly).
//!
//! **Why a fixed fixture instead of a fresh one per case.** Every signup, login and local
//! unlock here runs one real 64 MiB Argon2id (module docs of the parent `tests` module). A
//! proptest loop that re-registers or re-logs-in per case is dead on arrival at PR budgets. So
//! [`build_fixture`] pays that cost exactly once per `#[test]` function, and each generated case
//! only re-derives a fresh [`VaultKey`] from the account's already-opened vault self-grant
//! (`AccountKey::unwrap_vault_key`, a single AEAD open: no KDF) and builds a brand-new
//! [`VaultSync`] reader around it. Cases are therefore independent and reproducible by seed
//! alone, as proptest shrinking requires, without sharing mutable state across cases.
//!
//! **What the generator covers, and which oracle each arm gets.** [`Mutation`] rewrites an
//! honest [`FetchResponse`]. Every arm is checked by [`assert_values_match`] ("never show
//! plaintext not honestly written to that item": G-1, INV-13); three arms get a second, more
//! specific check because the value oracle alone cannot see their failure mode:
//! - Bit flips in a signed statement, an `ITEM_OP` envelope or a carried key wrap (§5.2, §5.3,
//!   INV-9, INV-10, INV-13), and swaps of a body or a statement between two of the response's
//!   own op records, which in this fixture belong to different items and (for one pair)
//!   different devices (§5.3, §5.5): the value oracle alone, since a successful forgery would
//!   have to decrypt into *some* text, and this fixture gives every item a distinct one.
//! - `DropOp` (§5.6, withholding): also [`check_gap`] (INV-27) on the dropped op's own item
//!   *and* every later op of the same device, using [`Fixture::op_meta`] to know which is
//!   which. A dropped middle op always leaves its own item `Absent`, which the value oracle
//!   cannot fail on (it only inspects `Active` items); the real risk INV-27 names is a *later*
//!   op of the same device applying with its own, perfectly correct value despite the gap, and
//!   the value oracle is structurally blind to that "right value, wrong provenance" case. A
//!   deliberately broken `op_meta` (swapped entries) is `not_covered` below rather than built
//!   in, matching the task's distinction between the real oracle and a test of the test.
//! - `Reorder` (§5.6): also an exact-count check (`out.applied == 3`), since every record stays
//!   present and validly signed, so a pure reorder is the one arm where "the mutated result
//!   equals the honest one" should hold in full, not just "no wrong plaintext".
//! - `Truncate` (§5.9, re-paging) cuts the (3-op) response to a 1- or 2-op *prefix* and marks it
//!   incomplete; with only 3 ops it can only produce a shorter honest page, never a gap, so it
//!   is checked by the value oracle alone and documented here as prefix-only, not as gap
//!   coverage.
//!
//! The KDF-downgrade class (§5.1) and the rollback/fork class (§5.6, INV-25) are not
//! representable as a `FetchResponse` rewrite and get their own small harnesses below
//! ([`fuzz_login_refuses_non_allowed_kdf_ids`], [`rollback_after_sync_is_detected_as_server_behind`]).
//!
//! **What it does not cover, and why** (`not_covered` in the task's own terms):
//! - **Cross-vault and cross-account swaps.** M1 gives every account exactly one vault
//!   (threat model §9, ADR 0021 §9 "Revoked and kind-4 authors": "one vault per account in M1,
//!   per vault from M9"), so there is no second vault or account to swap a record *with* at this
//!   layer today. INV-13's AAD already has no account id for exactly this reason (M9 shared
//!   vaults), so a future per-vault test belongs with M9, not here.
//! - **Epoch swaps** (a record from before a key rotation served after one). Building a rotation
//!   is a substantial fixture on its own (`tests/rotation.rs`); out of scope for this pass.
//! - **Forged device registrations and public-key substitution** (§5.4, §5.5) at the
//!   certificate layer: already covered by dedicated hand-built tests
//!   (`unlock_requires_a_certificate_of_this_devices_keys`,
//!   `unlock_detects_rollback_fork_and_hidden_devices`) and by `rizzy-core`'s `sign::tests`
//!   (ETH class 3). Folding them into this generator would duplicate, not broaden, that
//!   coverage.
//! - **Snapshot/cover mutation** (ADR 0021 compaction, INV-26): the fixture never triggers
//!   compaction, so `FetchResponse::covers` is always empty here; `fake_server_refuses_forged_snapshots_and_serves_covers`
//!   already exercises that channel directly.
//! - **"Never sends a secret."** `apply_fetch` only ever reads a response; it issues no request
//!   for any mutation here to ride along on, so `Server::wire` (the INV-15/CRYPTO.md §15 item 5
//!   canary haystack, `tests/canary.rs`) would be empty in this harness and scanning it here
//!   would be theatre, not coverage. That property stays owned by `canary.rs`, which exercises
//!   every flow that *does* send requests.

use std::cell::RefCell;

use proptest::prelude::*;
use proptest::test_runner::{TestRng, TestRunner};

use rizzy_core::envelope::purpose::VaultKeySelfGrantCtx;
use rizzy_core::ids::VaultId;
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::VaultKey;
use rizzy_core::sign::AccountState;
use rizzy_proto::vault::FetchResponse;
use rizzy_proto::wire::List;

use crate::sync::FetchOutcome;

use super::*;

/// Where a batch's `(family-less)` cases come from, mirroring
/// `rizzy_sync::convergence::generate::Seeds`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seeds {
    /// Proptest's deterministic RNG: the same cases every run (never flaky in CI).
    Fixed,
    /// A fresh RNG: a different batch each run, for the `#[ignore]`d nightly jobs.
    Fresh,
}

fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn new_runner(seeds: Seeds, cases: u32) -> (TestRunner, ProptestConfig) {
    let cfg = config(cases);
    let runner = match seeds {
        Seeds::Fixed => {
            TestRunner::new_with_rng(cfg.clone(), TestRng::deterministic_rng(cfg.rng_algorithm))
        }
        Seeds::Fresh => TestRunner::new(cfg.clone()),
    };
    (runner, cfg)
}

// -------------------------------------------------------------------------------------------
// Fixture
// -------------------------------------------------------------------------------------------

/// A synced, three-device, three-item vault (see [`build_fixture`] for why it is three, not
/// two), plus the two `FetchResponse`s a fresh reader would get at two points in its history:
/// after device A's first two writes only (`early`, used as the stale/rolled-back state) and
/// after every write (`honest`, the mutation target).
struct Fixture {
    server: Server,
    authors: Authors,
    unlocked: UnlockedDevice,
    account_id: AccountId,
    state: AccountState,
    /// Item id -> the one value ever honestly written to it. Each item gets a distinct value
    /// so that a swapped-in foreign record is caught by a value mismatch, not masked by two
    /// items coincidentally holding the same plaintext.
    values: Vec<(ItemId, String)>,
    /// `(device_id, device_seq, item)` for every op in `honest`, in the same order, so
    /// `DropOp`'s INV-27 check can find "every later op of the same device" without parsing a
    /// signed statement: matched by statement byte-equality against the fake server's own
    /// records ([`build_fixture`]).
    op_meta: Vec<([u8; 16], u64, ItemId)>,
    early: FetchResponse,
    honest: FetchResponse,
}

/// Re-derives the vault's key from the account's self-grant (`AccountKey::unwrap_vault_key`):
/// one AEAD open, no KDF, safe to call once per generated case.
fn mint_vault_key(fixture: &Fixture) -> VaultKey {
    mint_vault_key_from(
        &fixture.server,
        fixture.account_id,
        &fixture.state,
        &fixture.unlocked,
    )
}

/// The building block [`mint_vault_key`] wraps; used directly inside [`build_fixture`], before
/// a `Fixture` exists to hand `mint_vault_key` itself.
fn mint_vault_key_from(
    server: &Server,
    account_id: AccountId,
    state: &AccountState,
    unlocked: &UnlockedDevice,
) -> VaultKey {
    let view = server.view();
    let grant = view.vault_self_grants.as_slice()[0].clone();
    let vault_id = VaultId::from_bytes(grant.vault_id.to_bytes());
    let ctx = VaultKeySelfGrantCtx {
        account_id,
        vault_id,
        account_key_epoch: state.account_key_epoch,
        vault_key_epoch: grant.vault_key_epoch,
    };
    unlocked
        .account_key
        .unwrap_vault_key(&ctx, grant.envelope.as_slice())
        .expect("the account's own self-grant must open under its own account key")
}

/// Decodes a field value as text, panicking on anything else (every value this fixture writes
/// is text).
fn decode_text(value: &Value) -> String {
    match ValueRef::decode(value.expose_secret()).expect("a value written by this fixture") {
        ValueRef::Text(t) => t.to_string(),
        other => panic!("expected Text, decoded {other:?}"),
    }
}

/// Logs in a device and enrols it, like [`login_and_enrol`] but without that helper's "exactly
/// the first additional device" assertion: used for the fixture's *third* device, enrolled
/// after a second (`B`) already exists.
fn login_and_enrol_more(
    server: &mut Server,
    rng: &mut ChaCha20Rng,
    sk: &str,
    now_ms: u64,
) -> crate::login::Enrolled {
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: "alice",
        secret_key: sk,
        password: PASSWORD,
    };
    let (started, request) = start_login(rng, &input).unwrap();
    let answer = server.login_start(&request);
    let (awaiting, finish) = started.finish(rng, &answer, None).unwrap();
    let response = server.login_finish(&finish).unwrap();
    let logged_in = awaiting.complete(response).unwrap();
    let (pending, enrol) = logged_in
        .enrol(rng, DeviceKind::DesktopCli, now_ms)
        .unwrap();
    server.enrol(&enrol);
    pending.finalize()
}

/// Builds the fixture with **three** devices, not two: `B` is the fuzz target's identity and
/// must never itself write anything, or a fresh `VaultSync` built around it (as every generated
/// case does) sees its own op served back and raises `own_history_ahead` (ADR 0026 §4 step 7) —
/// a real, but different and irrelevant, alarm that would drown out every mutation case. So `A`
/// and a third device `C` are the two writers whose ops end up in the pool; `B` only ever reads.
#[expect(
    clippy::too_many_lines,
    reason = "one story: two writers, three items, the early/honest snapshots and op_meta, in order"
)]
fn build_fixture() -> Fixture {
    let mut rng = ChaCha20Rng::seed_from_u64(0x6D75_7461_7465); // "mutate" in hex-ish, fixed.
    let mut server = Server::new(0xF0CA_CC1A);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let a_state = a.device.as_ref().unwrap();
    let account_id = a_state.account_id();
    let sk = secret_key_text(a_state);
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let state = b.account.state().clone();

    // Device A: two items, two distinct values, device_seq 1 and 2.
    let a_authors = server.authors();
    let mut a_vault = VaultSync::new(a.vault_key, &a.unlocked, 1).unwrap();
    a_vault
        .apply_fetch(
            &a_authors,
            &server.fetch(&a_vault.fetch_request().unwrap()),
            T0,
        )
        .unwrap();
    let key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
    let mut values = Vec::new();
    let v0 = Value::text("alpha").unwrap();
    let item0 = a_vault
        .create_item(
            &mut rng,
            &a.unlocked,
            ItemType::LOGIN,
            &[FieldEdit {
                key: &key,
                value: &v0,
            }],
            T0 + 1,
        )
        .unwrap();
    values.push((item0, "alpha".to_string()));
    let v1 = Value::text("bravo").unwrap();
    let item1 = a_vault
        .create_item(
            &mut rng,
            &a.unlocked,
            ItemType::LOGIN,
            &[FieldEdit {
                key: &key,
                value: &v1,
            }],
            T0 + 2,
        )
        .unwrap();
    values.push((item1, "bravo".to_string()));
    let up = a_vault
        .upload_request(&mut rng, &a.unlocked)
        .unwrap()
        .unwrap();
    server.upload(&up);

    // The early, strictly-behind snapshot: A's two writes only, nothing from C yet.
    let early_key = mint_vault_key_from(&server, account_id, &state, &b.unlocked);
    let early_vault = VaultSync::new(early_key, &b.unlocked, 1).unwrap();
    let early = server.fetch(&early_vault.fetch_request().unwrap());

    // Device C, a third device, enrols and adds a third item under its own device_seq 1: a
    // second author in the pool that is not the fuzz target's own identity.
    let c = login_and_enrol_more(&mut server, &mut rng, &sk, T0 + 2000);
    let c_authors = server.authors();
    let c_key = mint_vault_key_from(&server, account_id, &state, &c.unlocked);
    let mut c_vault = VaultSync::new(c_key, &c.unlocked, 1).unwrap();
    c_vault
        .apply_fetch(
            &c_authors,
            &server.fetch(&c_vault.fetch_request().unwrap()),
            T0 + 3,
        )
        .unwrap();
    let v2 = Value::text("charlie").unwrap();
    let item2 = c_vault
        .create_item(
            &mut rng,
            &c.unlocked,
            ItemType::LOGIN,
            &[FieldEdit {
                key: &key,
                value: &v2,
            }],
            T0 + 4,
        )
        .unwrap();
    values.push((item2, "charlie".to_string()));
    let up2 = c_vault
        .upload_request(&mut rng, &c.unlocked)
        .unwrap()
        .unwrap();
    server.upload(&up2);

    // The authors every later Fetch is verified against: A, B and C, all certified by now.
    let authors = server.authors();

    // The honest, fully-synced snapshot, from a fresh reader's first-ever Fetch.
    let final_key = mint_vault_key_from(&server, account_id, &state, &b.unlocked);
    let final_vault = VaultSync::new(final_key, &b.unlocked, 1).unwrap();
    let honest = server.fetch(&final_vault.fetch_request().unwrap());
    let op_meta = build_op_meta(&server, &honest);

    Fixture {
        server,
        authors,
        unlocked: b.unlocked,
        account_id,
        state,
        values,
        op_meta,
        early,
        honest,
    }
}

/// `(device_id, device_seq, item)` for every op in `honest`, matched against the fake server's
/// own records by statement byte-equality (opaque `Bytes<N>`, so `==` is exact and needs no
/// parsing). Panics if an op in `honest` cannot be found, which would mean `honest` was built
/// from a different server than `server`.
fn build_op_meta(server: &Server, honest: &FetchResponse) -> Vec<([u8; 16], u64, ItemId)> {
    honest
        .ops
        .as_slice()
        .iter()
        .map(|op| {
            for (device_id, chain) in &server.ops {
                for (seq, record) in chain {
                    if record.statement == op.statement {
                        let item = *server
                            .op_items
                            .get(&(*device_id, *seq))
                            .expect("every stored op is indexed by item");
                        return (*device_id, *seq, item);
                    }
                }
            }
            panic!("an op in `honest` was not found in the server's own store");
        })
        .collect()
}

// -------------------------------------------------------------------------------------------
// Mutations
// -------------------------------------------------------------------------------------------

/// One malicious-server rewrite of an honest [`FetchResponse`] (threat model §5.2, §5.3, §5.6;
/// CRYPTO.md §15 item 5). `op`/`a`/`b` index into the response's own op list modulo its length,
/// so every generated value is always in bounds; `byte` indexes a blob modulo its own length
/// for the same reason.
#[derive(Clone, Copy, Debug)]
enum Mutation {
    /// A bit flip anywhere in a signed `op` statement (header and signature bundled on the
    /// wire): INV-9 (the whole header is AAD), forged-signer and unbound-item territory.
    FlipStatement { op: usize, byte: u64, bit: u8 },
    /// A bit flip anywhere in the `ITEM_OP` envelope (version, algorithm id, key id, nonce or
    /// ciphertext are all opaque wire bytes here): INV-9, INV-10, §5.2.
    FlipBody { op: usize, byte: u64, bit: u8 },
    /// A bit flip in the op's carried item-key wrap: INV-13's key-wrap-to-item binding.
    FlipKeyWrap { op: usize, byte: u64, bit: u8 },
    /// Swaps the ciphertext body between two of the response's own ops: §5.3's "the server
    /// swaps ciphertext between items", without needing a second vault to draw a foreign body
    /// from.
    SwapBody { a: usize, b: usize },
    /// Swaps the signed statement (header + signature) between two ops: the mirror image of
    /// `SwapBody`, and (for the A/B op pair in this fixture) a different *device* too.
    SwapStatement { a: usize, b: usize },
    /// Clears a carried item-key wrap: §5.6's "withholds" at the per-record level (the
    /// hand-written precedent is `fetch_drops_forged_records`'s `ops[0].key_wrap = None`).
    WithholdKeyWrap { op: usize },
    /// Drops a whole op record from the response: withholding, and (when the dropped op is not
    /// the last of its device's chain) a gap.
    DropOp { op: usize },
    /// Deterministically reorders the op records: §5.6's "reorders".
    Reorder { seed: u64 },
    /// Cuts the response down to its first `at.max(1)` ops and marks it incomplete: §5.9's
    /// "re-pages" (a malicious or buggy paging split).
    Truncate { at: usize },
}

impl Mutation {
    /// Applies this rewrite to `response.ops` in place. A no-op silently does nothing (for
    /// example a swap of an index with itself), which is fine: the oracle only ever requires
    /// "no wrong plaintext", never "this exact case did damage".
    fn apply(self, response: &mut FetchResponse) {
        let mut ops = response.ops.as_slice().to_vec();
        if ops.is_empty() {
            return;
        }
        let len = ops.len();
        match self {
            Self::FlipStatement { op, byte, bit } => {
                let i = op % len;
                let mut raw = ops[i].statement.as_slice().to_vec();
                if !raw.is_empty() {
                    let idx = usize::try_from(byte).unwrap_or(0) % raw.len();
                    raw[idx] ^= 1 << (bit % 8);
                    ops[i].statement = bytes(&raw);
                }
            }
            Self::FlipBody { op, byte, bit } => {
                let i = op % len;
                if let Some(body) = ops[i].body.clone() {
                    let mut raw = body.as_slice().to_vec();
                    if !raw.is_empty() {
                        let idx = usize::try_from(byte).unwrap_or(0) % raw.len();
                        raw[idx] ^= 1 << (bit % 8);
                        ops[i].body = Some(bytes(&raw));
                    }
                }
            }
            Self::FlipKeyWrap { op, byte, bit } => {
                let i = op % len;
                if let Some(mut wrap) = ops[i].key_wrap.clone() {
                    let mut raw = wrap.envelope.as_slice().to_vec();
                    if !raw.is_empty() {
                        let idx = usize::try_from(byte).unwrap_or(0) % raw.len();
                        raw[idx] ^= 1 << (bit % 8);
                        wrap.envelope = bytes(&raw);
                        ops[i].key_wrap = Some(wrap);
                    }
                }
            }
            Self::SwapBody { a, b } => {
                let (ia, ib) = (a % len, b % len);
                if ia != ib {
                    let tmp = ops[ia].body.clone();
                    ops[ia].body = ops[ib].body.clone();
                    ops[ib].body = tmp;
                }
            }
            Self::SwapStatement { a, b } => {
                let (ia, ib) = (a % len, b % len);
                if ia != ib {
                    let tmp = ops[ia].statement.clone();
                    ops[ia].statement = ops[ib].statement.clone();
                    ops[ib].statement = tmp;
                }
            }
            Self::WithholdKeyWrap { op } => {
                ops[op % len].key_wrap = None;
            }
            Self::DropOp { op } => {
                ops.remove(op % len);
            }
            Self::Reorder { seed } => {
                // A deterministic Fisher-Yates pass keyed by `seed`: no `rand` dependency
                // needed for a pure index permutation.
                let mut s = seed | 1;
                for i in (1..len).rev() {
                    s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    let j = usize::try_from(s >> 33).unwrap_or(0) % (i + 1);
                    ops.swap(i, j);
                }
            }
            Self::Truncate { at } => {
                let cut = (at % len).max(1);
                ops.truncate(cut);
                response.complete = false;
            }
        }
        response.ops = List::new(ops).expect("within MAX_RECORDS: no record was added");
    }
}

/// The generator: every [`Mutation`] variant, weighted so the cheap, high-signal categories
/// (bit flips, swaps) dominate the budget.
fn mutation_strategy(num_ops: usize) -> impl Strategy<Value = Mutation> + Clone {
    let idx = 0..num_ops.max(1);
    prop_oneof![
        3 => (idx.clone(), any::<u64>(), 0u8..8)
            .prop_map(|(op, byte, bit)| Mutation::FlipStatement { op, byte, bit }),
        3 => (idx.clone(), any::<u64>(), 0u8..8)
            .prop_map(|(op, byte, bit)| Mutation::FlipBody { op, byte, bit }),
        2 => (idx.clone(), any::<u64>(), 0u8..8)
            .prop_map(|(op, byte, bit)| Mutation::FlipKeyWrap { op, byte, bit }),
        2 => (idx.clone(), idx.clone()).prop_map(|(a, b)| Mutation::SwapBody { a, b }),
        2 => (idx.clone(), idx.clone()).prop_map(|(a, b)| Mutation::SwapStatement { a, b }),
        1 => idx.clone().prop_map(|op| Mutation::WithholdKeyWrap { op }),
        1 => idx.clone().prop_map(|op| Mutation::DropOp { op }),
        1 => any::<u64>().prop_map(|seed| Mutation::Reorder { seed }),
        1 => idx.prop_map(|at| Mutation::Truncate { at }),
    ]
}

// -------------------------------------------------------------------------------------------
// Oracle
// -------------------------------------------------------------------------------------------

/// The security property (not a mirror of `VaultSync`'s own logic): whatever a mutated response
/// makes the client show, it is never plaintext that was not honestly written to that exact
/// item. A dropped, withheld or rejected record is always fine (that is `applied == 0` /
/// `dropped > 0`, not a failure); the only failure is an item that reads `Active` with a value
/// this fixture never wrote to it.
fn assert_values_match(reader: &VaultSync, values: &[(ItemId, String)]) -> Result<(), String> {
    for (id, expected) in values {
        if reader.item_lifecycle(*id) == ItemLifecycle::Active {
            let shown = reader
                .field_value(*id, LOGIN_PASSWORD)
                .ok_or_else(|| format!("item {id:?} is Active with no value"))?;
            let text = decode_text(&shown);
            if text != *expected {
                return Err(format!(
                    "item {id:?} shows {text:?}, expected {expected:?}: wrong plaintext accepted (threat model G-1, INV-13)"
                ));
            }
        }
    }
    Ok(())
}

/// INV-27 for [`Mutation::DropOp`]: dropping one op must leave its own item unapplied *and*
/// stop every later op of the same device from applying too ("nothing from that device past
/// the gap is applied"). The value oracle cannot see this failure mode: a later op applying
/// past the gap would show its own, perfectly correct value, which is exactly why this needs
/// [`Fixture::op_meta`] rather than another value comparison.
fn check_dropped_op_respects_the_gap(
    fixture: &Fixture,
    reader: &VaultSync,
    op: usize,
) -> Result<(), String> {
    let (device, seq, item) = fixture.op_meta[op % fixture.op_meta.len()];
    check_gap(reader.item_lifecycle(item))?;
    for &(later_device, later_seq, later_item) in &fixture.op_meta {
        if later_device == device && later_seq > seq {
            check_gap(reader.item_lifecycle(later_item))?;
        }
    }
    Ok(())
}

/// One case of the main fuzzer: a fresh reader, fed exactly the mutated response, nothing else.
fn run_one_case(fixture: &Fixture, mutation: Mutation) -> Result<(), String> {
    let mut response = fixture.honest.clone();
    mutation.apply(&mut response);
    let key = mint_vault_key(fixture);
    let mut reader =
        VaultSync::new(key, &fixture.unlocked, 1).map_err(|e| format!("VaultSync::new: {e:?}"))?;
    match reader.apply_fetch(&fixture.authors, &response, T0 + 1_000) {
        Err(_) => Ok(()), // an outright refusal is always a safe outcome.
        Ok(out) => {
            assert_values_match(&reader, &fixture.values)?;
            match mutation {
                Mutation::DropOp { op } => check_dropped_op_respects_the_gap(fixture, &reader, op),
                Mutation::Reorder { .. } if out.applied != fixture.values.len() => Err(format!(
                    "a pure reorder of otherwise-untouched, validly signed records changed what applied: {out:?}"
                )),
                _ => Ok(()),
            }
        }
    }
}

// -------------------------------------------------------------------------------------------
// PR and nightly entry points
// -------------------------------------------------------------------------------------------

/// Generated cases per PR run.
const PR_CASES: u32 = 500;

fn run_mutation_cases(cases: u32, seeds: Seeds) {
    let fixture = build_fixture();
    let num_ops = fixture.honest.ops.as_slice().len();
    assert_eq!(num_ops, 3, "the fixture always writes exactly 3 items");
    let (mut runner, cfg) = new_runner(seeds, cases);
    let result = runner.run(&mutation_strategy(num_ops), |mutation| {
        run_one_case(&fixture, mutation)
            .map_err(|e| TestCaseError::fail(format!("{mutation:?}: {e}")))
    });
    if let Err(e) = result {
        panic!("{e} (batch rng_seed {:?})", cfg.rng_seed);
    }
}

/// PR budget: [`PR_CASES`] generated [`Mutation`]s against the one fixed fixture, on proptest's
/// deterministic RNG (never flaky).
#[test]
fn fuzz_malicious_fetch_mutations() {
    run_mutation_cases(PR_CASES, Seeds::Fixed);
}

/// Nightly budget: 20x [`PR_CASES`] on fresh seeds. No CI job runs it yet
/// (`.github/workflows/` is the owner's to change, CLAUDE.md); the job it needs is
/// `cargo test --release -p rizzy-client -- --ignored`, on a schedule.
#[test]
#[ignore = "nightly budget: 20x the PR cases on fresh seeds"]
fn nightly_fuzz_malicious_fetch_mutations() {
    run_mutation_cases(PR_CASES * 20, Seeds::Fresh);
}

// -------------------------------------------------------------------------------------------
// §5.1 KDF parameter downgrade: a dedicated, cheap fuzzer over the whole `kdf_id` space
// -------------------------------------------------------------------------------------------

/// The only `kdf_id` this client currently allows. Excluded from the fuzzed space so every
/// generated case is refused *before* any Argon2id runs (CRYPTO.md §6.2; threat model INV-3):
/// the whole sweep below costs no KSF evaluations at all. Read from [`KdfId::DEFAULT`] itself,
/// not hand-copied, so a future second allowed id cannot silently turn a correct client into a
/// spurious red here.
const ALLOWED_KDF_ID: u16 = KdfId::DEFAULT.get();

/// Generated `kdf_id` values per PR run.
const KDF_PR_CASES: u32 = 500;

fn run_kdf_cases(cases: u32, seeds: Seeds) {
    let mut setup_rng = ChaCha20Rng::seed_from_u64(0xD00D);
    let mut server = Server::new(0xFEED);
    let a = signup(&mut server, &mut setup_rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(a.device.as_ref().unwrap());
    let server = RefCell::new(server);

    let (mut runner, cfg) = new_runner(seeds, cases);
    let strategy = any::<u16>().prop_filter("the one allowed kdf_id", |id| *id != ALLOWED_KDF_ID);
    let result = runner.run(&strategy, |kdf_id| {
        let mut rng = ChaCha20Rng::seed_from_u64(u64::from(kdf_id) | 1);
        let input = LoginInput {
            server_origin: ORIGIN,
            login_name: "alice",
            secret_key: &sk,
            password: PASSWORD,
        };
        let (started, request) = start_login(&mut rng, &input)
            .map_err(|e| TestCaseError::fail(format!("start_login: {e:?}")))?;
        let mut answer = server.borrow_mut().login_start(&request);
        answer.kdf_id = kdf_id;
        match started.finish(&mut rng, &answer, None) {
            Err(ClientError::KdfNotAllowed) => Ok(()),
            Err(other) => Err(TestCaseError::fail(format!(
                "kdf_id {kdf_id}: expected KdfNotAllowed, got {other:?}"
            ))),
            Ok(_) => Err(TestCaseError::fail(format!(
                "kdf_id {kdf_id}: a non-allowed kdf_id was accepted (threat model §5.1, INV-3)"
            ))),
        }
    });
    if let Err(e) = result {
        panic!("{e} (batch rng_seed {:?})", cfg.rng_seed);
    }
}

/// PR budget.
#[test]
fn fuzz_login_refuses_non_allowed_kdf_ids() {
    run_kdf_cases(KDF_PR_CASES, Seeds::Fixed);
}

/// Nightly budget: 20x on fresh seeds. Still costs no Argon2id (see [`ALLOWED_KDF_ID`]).
#[test]
#[ignore = "nightly budget: 20x the PR cases on fresh seeds"]
fn nightly_fuzz_login_refuses_non_allowed_kdf_ids() {
    run_kdf_cases(KDF_PR_CASES * 20, Seeds::Fresh);
}

// -------------------------------------------------------------------------------------------
// §5.6 rollback via Fetch's `heads` (INV-25's Fetch-layer form, ADR 0021 §9 "Server behind")
// -------------------------------------------------------------------------------------------

/// `FetchOutcome::server_behind` is the Fetch-layer signal of a rollback: the server claims a
/// head lower than one this device already accepted (ADR 0021 §9 "Server behind").
fn check_server_behind(outcome: &FetchOutcome) -> Result<(), String> {
    if outcome.server_behind {
        Ok(())
    } else {
        Err("a rollback was accepted without server_behind (threat model §5.6, INV-25; ADR 0021 §9 \"Server behind\")".into())
    }
}

/// Two rollback shapes: the server replays a whole earlier response, and the server replays
/// only the `heads` field while still (redundantly) serving every op the device already has.
/// Neither must let an already-synced item regress to the wrong value or disappear.
#[test]
fn rollback_after_sync_is_detected_as_server_behind() {
    let fixture = build_fixture();
    for scenario in 0..2u8 {
        let key = mint_vault_key(&fixture);
        let mut reader = VaultSync::new(key, &fixture.unlocked, 1).unwrap();
        let out = reader
            .apply_fetch(&fixture.authors, &fixture.honest, T0 + 10)
            .unwrap();
        assert_eq!(
            out.applied,
            fixture.values.len(),
            "scenario {scenario}: {out:?}"
        );
        assert_values_match(&reader, &fixture.values).unwrap();

        let rollback = if scenario == 0 {
            fixture.early.clone()
        } else {
            let mut spliced = fixture.honest.clone();
            spliced.heads = fixture.early.heads.clone();
            spliced
        };
        match reader.apply_fetch(&fixture.authors, &rollback, T0 + 11) {
            Err(_) => {} // an outright refusal is also a safe detection.
            Ok(out2) => {
                check_server_behind(&out2).unwrap_or_else(|e| panic!("scenario {scenario}: {e}"));
            }
        }
        assert_values_match(&reader, &fixture.values)
            .unwrap_or_else(|e| panic!("scenario {scenario}: {e}"));
    }
}

// -------------------------------------------------------------------------------------------
// §5.6 a withheld predecessor must stop its device's later ops too (INV-27)
// -------------------------------------------------------------------------------------------

/// The oracle `drops_past_a_device_gap_per_inv27` uses: an item that reads `Active` past a
/// withheld predecessor in its own device's chain is the gap-skipping violation INV-27 forbids.
fn check_gap(lifecycle: ItemLifecycle) -> Result<(), String> {
    if lifecycle == ItemLifecycle::Active {
        Err("an op applied past a withheld predecessor in its device's chain (threat model §5.6, INV-27)".into())
    } else {
        Ok(())
    }
}

/// A single-writer vault with two chained ops (`device_seq` 1, 2). Withholding the first must
/// stop the second from applying too: "a gap is reported as missing data, never skipped, and
/// nothing from that device past the gap is applied" (INV-27).
#[test]
fn drops_past_a_device_gap_per_inv27() {
    let mut rng = ChaCha20Rng::seed_from_u64(31_337);
    let mut server = Server::new(31_338);
    let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let sk = secret_key_text(a.device.as_ref().unwrap());
    let vault_id = a.vault_key.vault_id();
    let b = login_and_enrol(&mut server, &mut rng, &sk);
    let authors = Authors::from_account(&b.account).unwrap();
    let (_a_vault, _a_unlocked, items) = synced_writer(&mut server, &mut rng, a, &authors, 2);
    let mut b_account = b.account;
    let key = b_account.take_vault_key(vault_id).unwrap();
    let mut reader = VaultSync::new(key, &b.unlocked, 1).unwrap();

    let mut response = server.fetch(&reader.fetch_request().unwrap());
    let mut ops = response.ops.into_vec();
    assert_eq!(ops.len(), 2, "two chained ops from the one writer");
    ops.remove(0); // withhold device_seq 1, keep device_seq 2.
    response.ops = List::new(ops).unwrap();
    let out = reader.apply_fetch(&authors, &response, T0 + 5).unwrap();
    assert_eq!(out.applied, 0, "{out:?}");
    check_gap(reader.item_lifecycle(items[1])).unwrap();
    assert_eq!(reader.item_lifecycle(items[0]), ItemLifecycle::Absent);
}

// -------------------------------------------------------------------------------------------
// Positive controls: the oracle functions above, fed a deliberately planted bad case
// -------------------------------------------------------------------------------------------

#[test]
fn oracle_catches_a_planted_wrong_plaintext() {
    let fixture = build_fixture();
    let key = mint_vault_key(&fixture);
    let mut reader = VaultSync::new(key, &fixture.unlocked, 1).unwrap();
    reader
        .apply_fetch(&fixture.authors, &fixture.honest, T0 + 1)
        .unwrap();
    // The real values match.
    assert_values_match(&reader, &fixture.values).unwrap();
    // A deliberately wrong expectation must be flagged.
    let mut wrong = fixture.values.clone();
    wrong[0].1 = format!("{}-tampered", wrong[0].1);
    assert!(assert_values_match(&reader, &wrong).is_err());
}

#[test]
fn oracle_catches_a_planted_gap_skip() {
    assert!(check_gap(ItemLifecycle::Active).is_err());
    assert!(check_gap(ItemLifecycle::Absent).is_ok());
}

/// [`check_dropped_op_respects_the_gap`] end to end, without needing a real `DropOp` to go
/// wrong: a reader that honestly applied *everything* has every item `Active`, including
/// whichever one sits right after another op of the same device. Asking "does this look like a
/// gap-skip if op `idx` had been withheld" against that reader is exactly what a real
/// gap-skipping bug would produce, so it must be flagged.
#[test]
fn oracle_catches_a_planted_dropped_op_gap_skip() {
    let fixture = build_fixture();
    let idx = fixture
        .op_meta
        .iter()
        .position(|&(device, seq, _)| {
            fixture
                .op_meta
                .iter()
                .any(|&(d, s, _)| d == device && s > seq)
        })
        .expect("writer A has two chained ops in this fixture, so some index has a later sibling");
    let key = mint_vault_key(&fixture);
    let mut reader = VaultSync::new(key, &fixture.unlocked, 1).unwrap();
    reader
        .apply_fetch(&fixture.authors, &fixture.honest, T0 + 1)
        .unwrap();
    assert!(
        check_dropped_op_respects_the_gap(&fixture, &reader, idx).is_err(),
        "a reader with every item Active must look like a gap-skip when checked as if op {idx} had been withheld"
    );
}

#[test]
fn oracle_catches_a_planted_unflagged_rollback() {
    let bad = FetchOutcome::default(); // server_behind: false
    assert!(check_server_behind(&bad).is_err());
    let good = FetchOutcome {
        server_behind: true,
        ..FetchOutcome::default()
    };
    assert!(check_server_behind(&good).is_ok());
}
