//! Fuzzes `rizzy-domain-auth`'s pure rules (its `rules` module): the checks the server runs on
//! untrusted statements and state transitions before anything is stored (CRYPTO.md §5.10,
//! §10.2, §11; ADR 0012 §7). The statement parsers themselves are `rizzy-core`'s and have
//! their own target (`signed_statements`); this one drives the cross-object logic around them.
//!
//! For each input:
//!
//! - **Request-counter window** (§5.10: each counter at most once per session, within a sliding
//!   window of 64): the input read as a sequence of counters, accepted or refused exactly as a
//!   reference model of the rule decides.
//! - **State transitions** (`classify`): two `account-state` bodies built from the input (the
//!   rule is pure and runs after signature checks, so no signature is needed); nothing panics,
//!   and an accepted step is `state_seq + 1` with the rule's other invariants.
//! - **Bundle chains** (`verify_chain_from_start`, `extend_chain`): the input split into
//!   bundle wires, alone and appended to a valid three-bundle fixture chain (one silent step,
//!   one identity change); nothing panics, the fixture chain verifies, re-uploading the stored
//!   chain extends nothing, and an accepted extension continues the stored head one
//!   `bundle_seq` at a time.
//!
//! The fixture's RNG counts upward: deterministic, so a crash reproduces from its input alone,
//! and not a CSPRNG, which nothing here needs.
#![no_main]

use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};
use rizzy_core::ids::{AccountId, SymmetricKeyId};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::IdentityKeys;
use rizzy_core::sign::{AccountState, PublicKeyBundle, SyncMode, VerifiedBundle};
use rizzy_domain_auth::rules::{self, RequestWindow};

/// A deterministic byte counter, marked `CryptoRng` only so the key generators accept it.
struct CountingRng(u8);

impl TryRng for CountingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for b in dst {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

impl TryCryptoRng for CountingRng {}

/// A valid chain: bundle 1, a silent successor, and an identity change.
struct Fixture {
    wires: Vec<Vec<u8>>,
    chain: Vec<VerifiedBundle>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut rng = CountingRng(1);
        let account_id = AccountId::from_bytes([7; 16]);
        let first_keys = IdentityKeys::generate(&mut rng, 0);
        let second_keys = IdentityKeys::generate(&mut rng, 1);
        let bundle = |keys: &IdentityKeys, seq: u64, prev: [u8; 32]| PublicKeyBundle {
            account_id,
            identity_epoch: keys.epoch(),
            bundle_seq: seq,
            identity_ed25519: *keys.signing_key().verifying_key(),
            identity_x25519: keys.public_keys().x25519,
            mail_x25519: None,
            pq_required: seq == 2,
            created_at_ms: seq,
            prev_bundle_hash: prev,
        };
        let w1 = bundle(&first_keys, 1, [0; 32])
            .sign(first_keys.signing_key())
            .expect("bundle 1 signs");
        let b1 = PublicKeyBundle::verify_self_signed(&w1).expect("bundle 1 verifies");
        let w2 = bundle(&first_keys, 2, *b1.hash())
            .sign(first_keys.signing_key())
            .expect("bundle 2 signs");
        let (b2, _) = b1.verify_successor(&w2).expect("bundle 2 follows");
        let w3 = bundle(&second_keys, 3, *b2.hash())
            .sign_identity_change(&b2, second_keys.signing_key(), first_keys.signing_key())
            .expect("bundle 3 signs");
        let (b3, _) = b2.verify_successor(&w3).expect("bundle 3 follows");
        Fixture {
            wires: vec![w1, w2, w3],
            chain: vec![b1, b2, b3],
        }
    })
}

/// Reads fixed-size fields from the input, zero-padded past its end.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        let n = self.0.len().min(N);
        out[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        out
    }

    fn u8(&mut self) -> u8 {
        self.bytes::<1>()[0]
    }

    /// Small epochs, so neighbouring values (equal, +1, +2) are common.
    fn epoch(&mut self) -> u32 {
        u32::from(self.u8() % 4)
    }

    fn state(&mut self) -> AccountState {
        AccountState {
            account_id: AccountId::from_bytes([self.u8() % 2; 16]),
            state_seq: u64::from(self.u8() % 4) + 1,
            identity_epoch: self.epoch(),
            account_key_epoch: self.epoch(),
            account_key_id: SymmetricKeyId::from_bytes([self.u8() % 2; 16]),
            password_epoch: self.epoch(),
            kdf_id: KdfId::DEFAULT,
            recovery_epoch: self.epoch(),
            recovery_enabled: self.u8() % 2 == 1,
            sync_mode: SyncMode::Server,
            mail_key_epoch: self.epoch(),
            bundle_hash: [self.u8() % 2; 32],
            device_set_hash: [self.u8() % 2; 32],
            settings_seq: u64::from(self.u8() % 3),
            settings_hash: [self.u8() % 2; 32],
        }
    }
}

fn window(data: &[u8]) {
    let mut w = RequestWindow::default();
    let mut accepted: HashSet<u64> = HashSet::new();
    let mut max: Option<u64> = None;
    for chunk in data.chunks(8).take(512) {
        let mut b = [0u8; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        // Mostly near each other, sometimes anywhere in the u64 range.
        let raw = u64::from_be_bytes(b);
        let c = if raw >> 63 == 1 { raw } else { raw % 256 };
        let expect = !accepted.contains(&c) && max.is_none_or(|m| c > m || m - c < 64);
        match w.accept(c) {
            Some(next) => {
                assert!(expect, "accepted a counter the rule refuses");
                accepted.insert(c);
                max = Some(max.map_or(c, |m| m.max(c)));
                w = next;
            }
            None => assert!(!expect, "refused a counter the rule accepts"),
        }
    }
}

fn transition(data: &[u8]) {
    let mut r = Reader(data);
    let current = r.state();
    let new = r.state();
    if let Ok(step) = rules::classify(&current, &new) {
        assert_eq!(new.state_seq, current.state_seq + 1);
        assert_eq!(new.account_id, current.account_id);
        assert!(!step.identity_changed || step.account_key_rotated);
        assert_eq!(
            step.account_key_rotated,
            new.account_key_epoch != current.account_key_epoch
        );
        assert_eq!(
            step.device_set_changed,
            new.device_set_hash != current.device_set_hash
        );
    }
}

fn chains(data: &[u8]) {
    let f = fixture();
    let stored: Vec<&[u8]> = f.wires.iter().map(Vec::as_slice).collect();
    let verified = rules::verify_chain_from_start(&stored).expect("the fixture chain verifies");
    assert_eq!(verified.len(), 3);
    let again = rules::extend_chain(&f.chain, &stored).expect("the stored chain re-uploads");
    assert!(again.is_empty());

    // Split the input into at most four wires, each prefixed by a one-byte length.
    let mut pieces: Vec<&[u8]> = Vec::new();
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let n = usize::from(len).min(tail.len());
        pieces.push(&tail[..n]);
        rest = &tail[n..];
        if pieces.len() == 4 {
            break;
        }
    }
    let _ = rules::verify_chain_from_start(&pieces);
    for base in 1..=f.chain.len() {
        let mut wires: Vec<&[u8]> = stored[..base].to_vec();
        wires.extend(pieces.iter().copied());
        if let Ok(new) = rules::extend_chain(&f.chain[..base], &wires) {
            let mut seq = f.chain[base - 1].bundle_seq;
            for (bundle, _) in &new {
                seq += 1;
                assert_eq!(bundle.bundle_seq, seq, "an extension skipped a bundle_seq");
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    window(data);
    transition(data);
    chains(data);
});
