// SPDX-License-Identifier: AGPL-3.0-only

//! Device revocation on the client ([ADR 0091] §2–§3, §5): the server's advisory revocation
//! notice, the retry of a `revocation_pending` answer, and how a device learns that it was
//! revoked itself.
//!
//! # The revocation flow (§3; the host drives it, this crate builds the parts)
//!
//! The revoking device R (kinds 1–3):
//! 1. **Settle first**: a pending record is settled (CRYPTO.md §11, "On restart with a pending
//!    record") before anything else; a revocation never starts on top of another pending commit.
//! 2. **Choose** one or more devices and a reason: "lost or stolen" (preselected for a device
//!    not seen for 24 hours or more, [`LOST_DEVICE_IDLE_MS`]) or "wiped and handed over". Every
//!    durable certificate is listed with its enrolment time; those enrolled in the last 30 days
//!    ([`RECENT_ENROLMENT_MS`]) are marked.
//! 3. **Re-authenticate and suspend at once**: a fresh OPAQUE login bound to R, then
//!    `devices/suspend` for each chosen device in ascending `device_id` order. The first call
//!    opens the window; each returns H.
//! 4. **Secrets**: for "lost or stolen" the default also changes the Secret Key in the same
//!    commit (`credentials::start_credential_change` with `new_secret_key`, `rotate` and
//!    `full_rotation`, and the chosen devices in `revoke`), which issues a new recovery code
//!    where recovery is on. The opt-out keeps the Secret Key ([`crate::rotation::start_rotation`]).
//!    The kit is generated, rendered and confirmed here.
//! 5. **Renew, fetch, build**: re-authenticate if the session is no longer fresh; call
//!    `devices/suspend` again for the first chosen device (it renews the window) and check that
//!    its H equals step 3's ([`check_renewed_head`]); then fetch `account-state` (after this
//!    suspend, never before), upload and run a complete Fetch, and build the rotation with one
//!    revocation per chosen device ([`crate::rotation::RotationOptions::revoke`]).
//! 6. **Persist and commit**: the pending record and the exact request, then `account/commit`.
//! 7. **On `state_conflict`**: as ADR 0025 §2 step 5, with the renewing suspend of step 5 before
//!    each rebuild or restart.
//! 8. **Crash**: on restart the pending record is settled as usual. With no pending record but a
//!    non-empty [`RevocationNotice::suspended`], every durable device offers "Finish removing"
//!    (from step 3) and "Cancel" (`devices/unsuspend`).
//!
//! A device whose own revocation is in a verified state ([`own_revocation`]) deletes its
//! pending record without resending, stops syncing and offers to delete its local data.
//!
//! [ADR 0091]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0091-revoked-device-rotation-race.md

use rizzy_core::ids::DeviceId;
use rizzy_core::keys::AccountFingerprint;
use rizzy_proto::account::AccountView;

use crate::account::{Anchor, verify_public};
use crate::device::DeviceState;
use crate::error::ClientError;

/// What a host shows while a write is refused `revocation_pending` (§2 "What clients see").
pub const REVOCATION_PENDING_MESSAGE: &str =
    "Another of your devices is removing a device. Changes are paused for up to 10 minutes.";

/// The wait before the first retry of a `revocation_pending` answer, and between retries.
pub const REVOCATION_RETRY_MS: u64 = 15_000;

/// How long after the window's served `expires_at_ms` the retries go on.
pub const REVOCATION_RETRY_GRACE_MS: u64 = 5_000;

/// The most retries of one refused request.
pub const MAX_REVOCATION_RETRIES: u32 = 41;

/// A device not seen for this long is preselected "lost or stolen" (§3 step 2): 24 hours.
pub const LOST_DEVICE_IDLE_MS: u64 = 24 * 60 * 60 * 1000;

/// A device enrolled this recently is marked in the revocation list (§3 step 2): 30 days.
pub const RECENT_ENROLMENT_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// The server's advisory revocation state of an account (§2 "What clients see"): the
/// suspended, unrevoked devices and the open revocation window.
///
/// **Not verified.** Nothing signs it. A host uses it for display and to time the retry of a
/// `revocation_pending` answer, never for a security decision; a server that lies in it gains
/// only a delayed or a needless retry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevocationNotice {
    /// The suspended, unrevoked devices, ascending, as served.
    pub suspended: Vec<DeviceId>,
    /// The open window: its revoker and when it expires (the server's clock), as served.
    pub window: Option<(DeviceId, u64)>,
}

impl RevocationNotice {
    /// The notice of `view`, as served.
    #[must_use]
    pub fn of_view(view: &AccountView) -> Self {
        Self {
            suspended: view
                .suspended_devices
                .iter()
                .map(|id| DeviceId::from_bytes(id.to_bytes()))
                .collect(),
            window: view.revocation_window.map(|w| {
                (
                    DeviceId::from_bytes(w.revoker_device_id.to_bytes()),
                    w.expires_at_ms,
                )
            }),
        }
    }

    /// Whether the server says a removal is under way or was left half done: a window is open
    /// or a device is suspended.
    #[must_use]
    pub fn removal_in_progress(&self) -> bool {
        self.window.is_some() || !self.suspended.is_empty()
    }
}

/// When to retry a request the server refused `revocation_pending` (§2): `REVOCATION_RETRY_MS`
/// after `now_ms`, as long as fewer than [`MAX_REVOCATION_RETRIES`] retries were made and the
/// retry falls before the served window's `expires_at_ms + REVOCATION_RETRY_GRACE_MS`. Read
/// `window` from a fresh `account/state` ([`RevocationNotice::window`]); without one the
/// window closed, and the retry is still made (bounded by the count). `None`: stop retrying
/// and report the refusal.
#[must_use]
pub fn next_revocation_retry(
    retries_done: u32,
    now_ms: u64,
    window: Option<(DeviceId, u64)>,
) -> Option<u64> {
    if retries_done >= MAX_REVOCATION_RETRIES {
        return None;
    }
    let at = now_ms.saturating_add(REVOCATION_RETRY_MS);
    match window {
        Some((_, expires_at_ms))
            if retries_done > 0 && at > expires_at_ms.saturating_add(REVOCATION_RETRY_GRACE_MS) =>
        {
            None
        }
        _ => Some(at),
    }
}

/// Step 5's check of the renewing suspend (§3): H cannot move while every refused write is
/// frozen, so the H it returns must equal step 3's. A different H means a bug or a malicious
/// server: the host restarts at step 3 once, and stops and reports it on a second mismatch.
///
/// # Errors
/// [`ClientError::InvalidServerResponse`] when the two differ.
pub const fn check_renewed_head(first: u64, renewed: u64) -> Result<(), ClientError> {
    if first == renewed {
        Ok(())
    } else {
        Err(ClientError::InvalidServerResponse)
    }
}

/// Whether `view`, verified against this device's pin, holds a revocation of this device
/// (§3 "A revoked device with a pending commit"). `true`: the device deletes its pending record
/// without resending it, stops syncing and offers to delete its local data.
///
/// Only a verified revocation counts: the view must verify from the pin as an unlock's does,
/// with `confirmed` the fingerprint the user confirmed when the identity keys changed
/// ([`crate::unlock::identity_change_fingerprint`]).
///
/// # Errors
/// The public verification's errors: [`ClientError::InvalidServerResponse`],
/// [`ClientError::Rollback`], [`ClientError::Fork`], [`ClientError::IdentityChangeUnconfirmed`].
pub fn own_revocation(
    state: &DeviceState,
    view: &AccountView,
    confirmed: Option<&AccountFingerprint>,
) -> Result<bool, ClientError> {
    let public = verify_public(
        view,
        state.account_id,
        &Anchor::Enrolled {
            pin: &state.pin,
            confirmed,
        },
        None,
    )?;
    Ok(public
        .revocations
        .iter()
        .any(|r| r.revocation.device_id == state.device_id))
}
