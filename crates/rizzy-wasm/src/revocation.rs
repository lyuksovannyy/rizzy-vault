// SPDX-License-Identifier: AGPL-3.0-only

//! The server's revocation notice on a web or extension session ([ADR 0091] §2 "What clients
//! see"): the banner text, the suspended devices, the open window, and when to retry a write
//! the server refused `revocation_pending`.
//!
//! Every value here comes from `rizzy-client`'s [`rizzy_client::revocation`]: the notice is the
//! last verified account answer's (`VerifiedAccount::revocation_notice`), unsigned and advisory.
//! A host uses it to show the banner, the Devices pane's "Suspended" and to time the retry,
//! never for a security decision; a server that lies in it gains only a delayed or a needless
//! retry. Nothing here starts a revocation: ADR 0091 §8 step 7 gives the web vault and the
//! extension the banner and the suspended state only (kind 4 cannot revoke, CRYPTO.md §11's flow
//! table).
//!
//! A host that gets `server_revocation_pending` from a sync shows
//! [`revocation_pending_notice`] while reads go on, asks `revocationRetryAt` (on
//! [`crate::Session`] or [`crate::DeviceSession`]) when to sync again, and stops retrying and
//! reports the refusal once it answers `undefined`. A sync starts with `account/state`, so the
//! window a retry is timed by is that of a fresh answer.
//!
//! [ADR 0091]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0091-revoked-device-rotation-race.md

use rizzy_client::revocation::{
    REVOCATION_PENDING_MESSAGE, RevocationNotice, next_revocation_retry,
};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::items::hex;

/// What a host shows while a write is refused `revocation_pending` (ADR 0091 §2): "Another of
/// your devices is removing a device. Changes are paused for up to 10 minutes."
#[wasm_bindgen(js_name = revocationPendingNotice)]
#[must_use]
pub fn revocation_pending_notice() -> String {
    REVOCATION_PENDING_MESSAGE.to_owned()
}

/// The open window's revoking device, 32 hex digits, as served.
pub(crate) fn window_revoker(notice: &RevocationNotice) -> Option<String> {
    notice.window.map(|(revoker, _)| hex(revoker.as_bytes()))
}

/// When the open window expires, Unix milliseconds on the server's clock, as served.
pub(crate) fn window_expires_at_ms(notice: &RevocationNotice) -> Option<u64> {
    notice.window.map(|(_, expires_at_ms)| expires_at_ms)
}

/// Whether a device (`device_id`, 16 bytes) shows as suspended: not `revoked` by the verified
/// state, and listed as suspended by the notice.
pub(crate) fn is_suspended(notice: &RevocationNotice, revoked: bool, device_id: &[u8; 16]) -> bool {
    !revoked && notice.suspended.iter().any(|d| d.as_bytes() == device_id)
}

/// When to retry a request refused `revocation_pending`, after `retries_done` retries, timed by
/// the notice's window ([`next_revocation_retry`]); `None`: stop and report the refusal.
pub(crate) fn retry_at(notice: &RevocationNotice, retries_done: u32, now_ms: u64) -> Option<u64> {
    next_revocation_retry(retries_done, now_ms, notice.window)
}

#[cfg(test)]
mod tests {
    use rizzy_client::revocation::{MAX_REVOCATION_RETRIES, REVOCATION_RETRY_MS};
    use rizzy_client::rizzy_core::ids::DeviceId;

    use super::*;

    const A: [u8; 16] = [0xa1; 16];
    const B: [u8; 16] = [0xb2; 16];

    fn notice(window: Option<u64>) -> RevocationNotice {
        RevocationNotice {
            suspended: vec![DeviceId::from_bytes(A)],
            window: window.map(|at| (DeviceId::from_bytes(B), at)),
        }
    }

    #[test]
    fn the_banner_text_is_the_clients() {
        assert_eq!(revocation_pending_notice(), REVOCATION_PENDING_MESSAGE);
        assert_eq!(
            revocation_pending_notice(),
            "Another of your devices is removing a device. Changes are paused for up to 10 minutes."
        );
    }

    #[test]
    fn a_listed_unrevoked_device_is_suspended() {
        let n = notice(None);
        assert!(is_suspended(&n, false, &A));
        // The verified revocation wins over the notice: a revoked device is "Revoked".
        assert!(!is_suspended(&n, true, &A));
        assert!(!is_suspended(&n, false, &B));
        assert!(!is_suspended(&RevocationNotice::default(), false, &A));
    }

    #[test]
    fn the_window_is_served_as_is() {
        let n = notice(Some(1_000_000));
        assert_eq!(
            window_revoker(&n).as_deref(),
            Some("b2".repeat(16).as_str())
        );
        assert_eq!(window_expires_at_ms(&n), Some(1_000_000));
        assert_eq!(window_revoker(&notice(None)), None);
        assert_eq!(window_expires_at_ms(&notice(None)), None);
    }

    #[test]
    fn the_retry_follows_the_clients_rule() {
        let now = 10_000_000;
        // The first retry 15 s on, whatever the window says.
        assert_eq!(
            retry_at(&notice(Some(now)), 0, now),
            Some(now + REVOCATION_RETRY_MS)
        );
        // Later ones until the window's expiry plus 5 s.
        let expires = now + 20_000;
        assert_eq!(
            retry_at(&notice(Some(expires)), 1, now),
            Some(now + REVOCATION_RETRY_MS)
        );
        assert_eq!(retry_at(&notice(Some(expires)), 1, now + 10_001), None);
        // Without a window, bounded by the count only.
        assert_eq!(
            retry_at(&notice(None), MAX_REVOCATION_RETRIES - 1, now),
            Some(now + REVOCATION_RETRY_MS)
        );
        assert_eq!(retry_at(&notice(None), MAX_REVOCATION_RETRIES, now), None);
    }
}
