//! The auth domain's pure rules: checks on untrusted statements and on state transitions,
//! with no database and no clock of their own.
//!
//! Every function here takes bytes or values a client sent (or the server stored) and either
//! returns verified values or refuses. Signatures and statement layouts are checked by
//! `rizzy-core` only ([`rizzy_core::sign`]); this module adds the cross-object rules of the
//! flows: which statements must agree with which, and how a new `account-state` may differ from
//! the current one. Keeping them pure makes them testable without a database and fuzzable
//! (`fuzz/fuzz_targets/auth_rules.rs`).
//!
//! Nothing here panics or allocates in proportion to a length field: statement parsers are
//! `rizzy-core`'s bounded ones, and every list is bounded by its `rizzy-proto` type before it
//! gets here.

use rizzy_core::ids::AccountId;
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::device_set_hash;
use rizzy_core::sign::{
    AccountState, BundleChainError, BundleStep, DeviceCertificate, DeviceRevocation,
    PublicKeyBundle, SyncMode, Verified, VerifiedBundle,
};
use rizzy_proto::auth::RegisterFinishRequest;

use crate::config::REQUEST_WINDOW;
use crate::error::AuthError;

/// Maps any refusal of a client-supplied statement onto [`AuthError::InvalidRequest`], so no
/// answer says which check failed.
fn invalid<E>(_: E) -> AuthError {
    AuthError::InvalidRequest
}

/// Verifies a whole stored or uploaded bundle chain from `bundle_seq` 1: the first bundle is
/// self-signed with `bundle_seq = 1`, and each next one is its predecessor's successor
/// (CRYPTO.md §10.2 "Bundles are a chain", §10.3). Returns every bundle, oldest first.
///
/// # Errors
/// [`AuthError::InvalidRequest`] for an empty list or any broken link.
pub fn verify_chain_from_start(wires: &[&[u8]]) -> Result<Vec<VerifiedBundle>, AuthError> {
    let (first, rest) = wires.split_first().ok_or(AuthError::InvalidRequest)?;
    let first = PublicKeyBundle::verify_self_signed(first).map_err(invalid)?;
    if first.bundle_seq != 1 {
        return Err(AuthError::InvalidRequest);
    }
    let mut chain = Vec::with_capacity(wires.len());
    chain.push(first);
    for wire in rest {
        let (next, step) = chain
            .last()
            .ok_or(AuthError::InvalidRequest)?
            .verify_successor(wire)
            .map_err(invalid)?;
        if step == BundleStep::Unchanged {
            return Err(AuthError::InvalidRequest);
        }
        chain.push(next);
    }
    Ok(chain)
}

/// Why an uploaded chain does not extend the stored one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainExtendError {
    /// A bundle does not parse or verify, or does not link.
    Invalid,
    /// An uploaded bundle has a `bundle_seq` the server holds but a different hash, or links
    /// to another branch: two versions of the account's keys (CRYPTO.md §10.3 "Fork").
    Fork,
}

/// Checks uploaded bundles against the stored, verified chain `stored` (oldest first, never
/// empty) and returns the ones that extend it, oldest first, each with its wire form (ADR 0012 §7
/// healing step 1).
///
/// An uploaded bundle at or below the stored head must be byte-for-byte the stored one (the
/// same signed message hash); anything above must continue the chain from the stored head,
/// one `bundle_seq` at a time, with the identity-change rules of §10.2. Uploaded bundles must
/// be in ascending `bundle_seq` order.
///
/// # Errors
/// [`ChainExtendError`].
pub fn extend_chain<'a>(
    stored: &[VerifiedBundle],
    wires: &[&'a [u8]],
) -> Result<Vec<(VerifiedBundle, &'a [u8])>, ChainExtendError> {
    let mut head = stored.last().ok_or(ChainExtendError::Invalid)?.clone();
    let mut new = Vec::new();
    let mut last_seq = 0u64;
    for &wire in wires {
        let bundle =
            PublicKeyBundle::verify_self_signed(wire).map_err(|_| ChainExtendError::Invalid)?;
        if bundle.bundle_seq <= last_seq {
            return Err(ChainExtendError::Invalid);
        }
        last_seq = bundle.bundle_seq;
        if bundle.bundle_seq <= head.bundle_seq {
            let index =
                usize::try_from(bundle.bundle_seq - 1).map_err(|_| ChainExtendError::Invalid)?;
            let stored_bundle = stored.get(index).ok_or(ChainExtendError::Invalid)?;
            if stored_bundle.bundle_seq != bundle.bundle_seq
                || stored_bundle.hash() != bundle.hash()
            {
                return Err(ChainExtendError::Fork);
            }
            continue;
        }
        match head.verify_successor(wire) {
            Ok((next, BundleStep::Silent | BundleStep::IdentityChanged)) => {
                head = next.clone();
                new.push((next, wire));
            }
            Err(BundleChainError::Fork | BundleChainError::Rollback) => {
                return Err(ChainExtendError::Fork);
            }
            Ok((_, BundleStep::Unchanged)) | Err(_) => return Err(ChainExtendError::Invalid),
        }
    }
    Ok(new)
}

/// Finds the bundle a state commits to (`bundle_hash`) in a verified chain.
#[must_use]
pub fn bundle_for_state<'a>(
    chain: &'a [VerifiedBundle],
    state: &AccountState,
) -> Option<&'a VerifiedBundle> {
    chain.iter().rev().find(|b| state.matches_bundle(b))
}

/// Verifies an `account-state` wire against the head of a verified chain: under the head's
/// identity key and epoch, for `account_id`, committing to the head bundle (CRYPTO.md §10.2).
///
/// # Errors
/// [`AuthError::InvalidRequest`].
pub fn verify_state_at_head(
    wire: &[u8],
    head: &VerifiedBundle,
    account_id: AccountId,
) -> Result<Verified<AccountState>, AuthError> {
    let state =
        AccountState::verify(wire, &head.identity_ed25519, head.identity_epoch).map_err(invalid)?;
    if state.account_id != account_id || !state.matches_bundle(head) {
        return Err(AuthError::InvalidRequest);
    }
    Ok(state)
}

/// Verifies a `device-certificate` wire for `account_id` under the head of a verified chain
/// (CRYPTO.md §10.2: the identity key of that `identity_epoch`; after a full rotation only the
/// current key, INV-30).
///
/// # Errors
/// [`AuthError::InvalidRequest`].
pub fn verify_certificate(
    wire: &[u8],
    head: &VerifiedBundle,
    account_id: AccountId,
) -> Result<Verified<DeviceCertificate>, AuthError> {
    let cert = DeviceCertificate::verify(wire, &head.identity_ed25519, head.identity_epoch)
        .map_err(invalid)?;
    if cert.account_id != account_id {
        return Err(AuthError::InvalidRequest);
    }
    Ok(cert)
}

/// Verifies a `device-revocation` wire for `account_id` under the head's identity key.
///
/// # Errors
/// [`AuthError::InvalidRequest`].
pub fn verify_revocation(
    wire: &[u8],
    head: &VerifiedBundle,
    account_id: AccountId,
) -> Result<Verified<DeviceRevocation>, AuthError> {
    let revocation = DeviceRevocation::verify(wire, &head.identity_ed25519).map_err(invalid)?;
    if revocation.account_id != account_id {
        return Err(AuthError::InvalidRequest);
    }
    Ok(revocation)
}

/// `device_set_hash` over `certs` minus `revocations` (CRYPTO.md §10.2 "Device set").
///
/// # Errors
/// [`AuthError::InvalidRequest`] for a certificate or revocation of another account, or two
/// certificates of one device.
pub fn device_set(
    account_id: AccountId,
    certs: &[Verified<DeviceCertificate>],
    revocations: &[Verified<DeviceRevocation>],
) -> Result<[u8; 32], AuthError> {
    device_set_hash(account_id, certs.iter(), revocations.iter()).map_err(invalid)
}

/// Whether `new` is `current` with only `state_seq` advanced by one and `device_set_hash`
/// changed: the shape of an enrolment or a revocation's state (CRYPTO.md §11.2 step 7, §10.2
/// "the loser … where only `state_seq` and `device_set_hash` changed").
#[must_use]
pub fn only_device_set_advances(current: &AccountState, new: &AccountState) -> bool {
    let mut probe = new.clone();
    probe.state_seq = current.state_seq;
    probe.device_set_hash = current.device_set_hash;
    current.state_seq.checked_add(1) == Some(new.state_seq) && probe == *current
}

/// The verified objects of a signup commit (CRYPTO.md §11.1 step 8), after
/// [`check_signup`]. The OPAQUE upload and the envelopes stay opaque bytes; only their
/// locators are checked against the signed state.
#[derive(Debug)]
pub struct CheckedSignup {
    /// The account id the signed state names.
    pub account_id: AccountId,
    /// The first bundle.
    pub bundle: VerifiedBundle,
    /// The first `account-state`.
    pub state: Verified<AccountState>,
    /// The first device's certificate.
    pub certificate: Verified<DeviceCertificate>,
}

/// The cheap consistency checks of a signup commit (CRYPTO.md §11.1 steps 5 and 8: "checks the
/// bundle self-signature and the certificate chain"), plus every rule §11.1 step 5 gives the
/// first objects, so the server never stores a first state a client would refuse:
///
/// - the bundle is self-signed, `bundle_seq = 1`, `identity_epoch = 0`;
/// - the state verifies under the bundle's identity key, commits to the bundle, and has
///   `state_seq = 1`, every epoch 0 (`recovery_epoch` 1 with a recovery registration, else 0),
///   `recovery_enabled` exactly when a recovery registration is present, `sync_mode = 1`,
///   `settings_seq = 0`, and the `kdf_id` of a new M1 account ([`KdfId::DEFAULT`], §11.1 step
///   4);
/// - the certificate verifies under the bundle's identity key for the same account, and the
///   state's `device_set_hash` is over exactly it (the empty set for a kind-4 web signup), and
///   a kind-4 certificate has not expired at `now_ms`;
/// - every locator (`E_srv`, `E_id`, `E_rec`, the self-grant) names the state's epochs.
///
/// # Errors
/// [`AuthError::InvalidRequest`].
pub fn check_signup(req: &RegisterFinishRequest, now_ms: u64) -> Result<CheckedSignup, AuthError> {
    let bundle = PublicKeyBundle::verify_self_signed(req.bundle.as_slice()).map_err(invalid)?;
    if bundle.bundle_seq != 1 || bundle.identity_epoch != 0 {
        return Err(AuthError::InvalidRequest);
    }
    let state = AccountState::verify(req.account_state.as_slice(), &bundle.identity_ed25519, 0)
        .map_err(invalid)?;
    let account_id = state.account_id;
    let with_recovery = req.recovery.is_some();
    let state_ok = state.state_seq == 1
        && bundle.account_id == account_id
        && state.matches_bundle(&bundle)
        && state.account_key_epoch == 0
        && state.password_epoch == 0
        && state.kdf_id == KdfId::DEFAULT
        && state.recovery_enabled == with_recovery
        && state.recovery_epoch == u32::from(with_recovery)
        && state.sync_mode == SyncMode::Server
        && state.mail_key_epoch == 0
        && state.settings_seq == 0;
    if !state_ok {
        return Err(AuthError::InvalidRequest);
    }
    let certificate = verify_certificate(req.device_certificate.as_slice(), &bundle, account_id)?;
    if !certificate.in_device_set() && certificate.expires_at_ms <= now_ms {
        return Err(AuthError::InvalidRequest);
    }
    let set = device_set(account_id, core::slice::from_ref(&certificate), &[])?;
    if set != state.device_set_hash {
        return Err(AuthError::InvalidRequest);
    }
    let srv = &req.account_key_server_wrap;
    let id = &req.identity_secret_keys;
    let grant = &req.vault_self_grant;
    let locators_ok = srv.account_key_epoch == 0
        && srv.password_epoch == 0
        && srv.kdf_id == state.kdf_id.get()
        && id.identity_epoch == 0
        && grant.account_key_epoch == 0
        && grant.vault_key_epoch == 0
        && req.recovery.as_ref().is_none_or(|r| {
            r.recovery_wrap.account_key_epoch == 0
                && r.recovery_wrap.recovery_epoch == state.recovery_epoch
        });
    if !locators_ok {
        return Err(AuthError::InvalidRequest);
    }
    Ok(CheckedSignup {
        account_id,
        bundle,
        state,
        certificate,
    })
}

/// How `recovery_epoch` and `recovery_enabled` move in a new `account-state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryTransition {
    /// Both unchanged.
    Unchanged,
    /// `recovery_epoch + 1` with `recovery_enabled = 1`: a new recovery code, with a new
    /// `E_rec` and `H_rec` (CRYPTO.md §11 "Replacing credentials", §11.6 step 5, §11.9 step 5).
    NewCode,
    /// `recovery_enabled` from 1 to 0 at the same epoch: recovery switched off, `E_rec` and
    /// `H_rec` deleted.
    Disabled,
}

/// What a new `account-state` changes against the current one, after [`classify`] checked
/// that every change is one the flows of CRYPTO.md §11 can make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one flag per independent field group of the signed state (CRYPTO.md §10.2)"
)]
pub struct Transition {
    /// `password_epoch + 1`: the password or the Secret Key changed (§11.5).
    pub password_bumped: bool,
    /// `kdf_id` changed (a same-password re-registration under a newer `kdf_id`, §6.3).
    pub kdf_changed: bool,
    /// `account_key_epoch + 1` with a new `account_key_id`: a rotation (§11.6).
    pub account_key_rotated: bool,
    /// `identity_epoch + 1` with a new bundle: a full rotation (§11.6 step 7).
    pub identity_changed: bool,
    /// How recovery moves.
    pub recovery: RecoveryTransition,
    /// `settings_seq + 1`: a new `ACCOUNT_SETTINGS` (§10.2 "Settings freshness").
    pub settings_changed: bool,
    /// `device_set_hash` changed.
    pub device_set_changed: bool,
}

/// Classifies the step from the current verified state to a new verified one (both of the
/// same account; the caller has checked the signatures), refusing every step the flows of
/// CRYPTO.md §11 cannot produce:
///
/// - `state_seq + 1` exactly (the compare-and-swap itself runs under the account lock);
/// - `sync_mode` and `mail_key_epoch` unchanged (On-device mode is parked by ADR 0022; mail
///   keys are M6);
/// - `password_epoch` unchanged or `+1` (§11 "Replacing credentials");
/// - `account_key_epoch` unchanged with the same `account_key_id`, or `+1` with a different
///   one (§11.6);
/// - `identity_epoch` unchanged, or `+1` only together with an account-key rotation (a full
///   rotation is a standard one plus the identity keys, §11.6);
/// - `bundle_hash` unchanged unless the identity changes: no M1 flow publishes a bundle
///   without an identity change (a PQ key and the mail key are later milestones);
/// - recovery as in [`RecoveryTransition`];
/// - `settings_seq` unchanged with the same `settings_hash`, or `+1`; a rotation re-encrypts
///   existing settings, so with `settings_seq > 0` it must move them (§11.6 step 3).
///
/// # Errors
/// [`AuthError::InvalidRequest`].
pub fn classify(current: &AccountState, new: &AccountState) -> Result<Transition, AuthError> {
    let step = |a: u32, b: u32| -> Result<bool, AuthError> {
        if a == b {
            Ok(false)
        } else if a.checked_add(1) == Some(b) {
            Ok(true)
        } else {
            Err(AuthError::InvalidRequest)
        }
    };
    if current.state_seq.checked_add(1) != Some(new.state_seq)
        || current.account_id != new.account_id
        || current.sync_mode != new.sync_mode
        || current.mail_key_epoch != new.mail_key_epoch
    {
        return Err(AuthError::InvalidRequest);
    }
    let password_bumped = step(current.password_epoch, new.password_epoch)?;
    let account_key_rotated = step(current.account_key_epoch, new.account_key_epoch)?;
    if account_key_rotated == (current.account_key_id == new.account_key_id) {
        return Err(AuthError::InvalidRequest);
    }
    let identity_changed = step(current.identity_epoch, new.identity_epoch)?;
    if (identity_changed && !account_key_rotated)
        || (!identity_changed && current.bundle_hash != new.bundle_hash)
    {
        return Err(AuthError::InvalidRequest);
    }
    let recovery = match (
        step(current.recovery_epoch, new.recovery_epoch)?,
        current.recovery_enabled,
        new.recovery_enabled,
    ) {
        (true, _, true) => RecoveryTransition::NewCode,
        (false, a, b) if a == b => RecoveryTransition::Unchanged,
        (false, true, false) => RecoveryTransition::Disabled,
        _ => return Err(AuthError::InvalidRequest),
    };
    let settings_changed = if new.settings_seq == current.settings_seq {
        if new.settings_hash != current.settings_hash {
            return Err(AuthError::InvalidRequest);
        }
        false
    } else if current.settings_seq.checked_add(1) == Some(new.settings_seq) {
        true
    } else {
        return Err(AuthError::InvalidRequest);
    };
    if account_key_rotated && current.settings_seq > 0 && !settings_changed {
        return Err(AuthError::InvalidRequest);
    }
    Ok(Transition {
        password_bumped,
        kdf_changed: current.kdf_id != new.kdf_id,
        account_key_rotated,
        identity_changed,
        recovery,
        settings_changed,
        device_set_changed: current.device_set_hash != new.device_set_hash,
    })
}

/// Whether `reissue` is `original` re-issued under a new identity epoch: every field equal
/// except `identity_epoch` (CRYPTO.md §11.6 step 7: "identical except that `identity_epoch` is
/// the new epoch").
#[must_use]
pub fn is_reissue(original: &DeviceCertificate, reissue: &DeviceCertificate) -> bool {
    let mut probe = reissue.clone();
    probe.identity_epoch = original.identity_epoch;
    probe == *original && reissue.identity_epoch != original.identity_epoch
}

/// The request-counter window of a device-authenticated session (CRYPTO.md §5.10: "accepts
/// each `request_counter` at most once per session, within a sliding window of 64").
///
/// `max` is the highest counter accepted so far; bit `i` of `seen` says that `max - i` was
/// accepted (bit 0 is `max` itself). A counter above `max` slides the window forward; one
/// within the 64 below it is accepted once; one further back is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RequestWindow {
    /// The highest accepted counter, `None` before the first request.
    pub max: Option<u64>,
    /// The acceptance bitmap below and at `max`.
    pub seen: u64,
}

impl RequestWindow {
    /// The window after accepting `counter`, or `None` when `counter` is refused: already
    /// accepted, or 64 or more below the highest accepted counter.
    #[must_use]
    pub fn accept(self, counter: u64) -> Option<Self> {
        let Some(max) = self.max else {
            return Some(Self {
                max: Some(counter),
                seen: 1,
            });
        };
        if counter > max {
            let shift = counter - max;
            let seen = if shift >= REQUEST_WINDOW {
                0
            } else {
                self.seen << shift
            };
            return Some(Self {
                max: Some(counter),
                seen: seen | 1,
            });
        }
        let back = max - counter;
        if back >= REQUEST_WINDOW {
            return None;
        }
        let bit = 1u64 << back;
        if self.seen & bit != 0 {
            return None;
        }
        Some(Self {
            max: Some(max),
            seen: self.seen | bit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_accepts_each_counter_once() {
        let mut w = RequestWindow::default();
        for c in [5, 3, 7, 6, 4] {
            w = w.accept(c).unwrap();
        }
        for c in [3, 4, 5, 6, 7] {
            assert!(w.accept(c).is_none(), "replay of {c}");
        }
        assert_eq!(w.max, Some(7));
    }

    #[test]
    fn window_refuses_counters_64_or_more_behind() {
        let w = RequestWindow::default().accept(100).unwrap();
        assert!(w.accept(36).is_none());
        assert!(w.accept(37).is_some());
        let w = w.accept(1_000).unwrap();
        assert!(w.accept(100).is_none());
        assert_eq!(w.seen, 1);
    }

    #[test]
    fn window_survives_the_top_of_the_range() {
        let w = RequestWindow::default().accept(u64::MAX).unwrap();
        assert!(w.accept(u64::MAX).is_none());
        assert!(w.accept(u64::MAX - 63).is_some());
        assert!(w.accept(0).is_none());
    }

    #[test]
    fn window_matches_a_reference_set() {
        // A reference model: the set of accepted counters, with the same rule.
        let mut w = RequestWindow::default();
        let mut accepted: Vec<u64> = Vec::new();
        let mut x = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..5_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let c = 1_000 + (x % 300);
            let max = accepted.iter().copied().max();
            let expect = !accepted.contains(&c) && max.is_none_or(|m| c > m || m - c < 64);
            match w.accept(c) {
                Some(next) => {
                    assert!(expect, "accepted {c}");
                    accepted.push(c);
                    w = next;
                }
                None => assert!(!expect, "refused {c}"),
            }
        }
    }
}
