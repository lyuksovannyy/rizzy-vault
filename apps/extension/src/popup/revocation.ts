// SPDX-License-Identifier: AGPL-3.0-only

// A device removal under way on another device (ADR 0091 §2, §8 step 7: the extension shows
// the `revocation_pending` banner; it has no Devices pane). A sync the server refused
// `server_revocation_pending` shows packages/ui's `RevocationPendingBanner` with the core's
// sentence (`revocationPendingNotice`, through the long-lived context's `revocation_retry`
// answer) and is retried on the core's schedule while the popup is open (`RevocationRetry`);
// the change waits in the device's cache, and the next popup's sync sends it whatever happens.
// Reads (the item list, copy, autofill) go on. When the schedule ends, the refusal shows as the
// sync's message, `REVOCATION_REFUSED`.

/** The code of a sync refused while another device removes a device. */
export const REVOCATION_PENDING = "server_revocation_pending";

/** What the banner adds under the core's sentence. */
export const REVOCATION_RETRYING = "Your changes are kept on this device and are sent again automatically.";

/** The sync's message once the retries are over (the web vault's `errors.server_revocation_pending`). */
export const REVOCATION_REFUSED =
  "Another of your devices is removing a device, so the server did not save the latest change. Try again in a few minutes.";
