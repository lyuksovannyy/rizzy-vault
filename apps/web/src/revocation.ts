// SPDX-License-Identifier: AGPL-3.0-only

// A device removal under way on another device (ADR 0091 §2 "What clients see", §8 step 7: the
// web vault shows the `revocation_pending` banner and the suspended state, and nothing more;
// kind 4 cannot revoke, CRYPTO.md §11's flow table).
//
// - A sync the server refused `server_revocation_pending` shows the banner
//   (packages/ui `RevocationPendingBanner`) and is retried on the core's schedule
//   (`revocationRetryAt`, packages/ui `RevocationRetry`); reads go on, and the change waits in
//   the session's memory. The first sync that succeeds takes the banner away; when the schedule
//   ends, the refusal is reported like any sync error (`errors.server_revocation_pending`).
// - The Devices pane shows a suspended device as "Suspended".
//
// Both read the server's unsigned notice and decide nothing from it.
import type { DeviceView } from "@rizzy-vault/core";
import { t } from "@rizzy-vault/i18n";

/** The code of a write refused while another device removes a device. */
export const REVOCATION_PENDING = "server_revocation_pending";

/** A device's state in the Devices pane: a verified revocation first, then the server's word. */
export function deviceStateText(d: Pick<DeviceView, "revoked" | "suspended">): string {
  if (d.revoked) {
    return t("devices.stateRevoked");
  }
  return d.suspended ? t("devices.stateSuspended") : t("devices.stateActive");
}
