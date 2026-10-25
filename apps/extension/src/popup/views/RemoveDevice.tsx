// SPDX-License-Identifier: AGPL-3.0-only

// "Remove this device" (ADR 0026 §5 as ADR 0095 §D replaces it; `rv device forget`). On open it
// asks the long-lived context for the removal check: under alarm 1, 2 or 3 (or an alarm this
// build does not know) removal is refused and the alarm named, since the local data is its
// evidence; otherwise, while unlocked, the changes the server never acknowledged are uploaded
// first, byte for byte, and the view says how many are still not on the server and will be
// lost (while locked: that any such changes will be lost). Only after the user confirms is the
// local data deleted. The next use is a new enrolment; the old device is revoked from another
// device.
import { useEffect, useState } from "react";

import type { ExtensionClient, RemovalCheck } from "../../core/client.ts";
import { alarmDescription, isAlarmCode } from "../alarms.ts";

export interface RemoveDeviceViewProps {
  readonly client: ExtensionClient;
  /** Back to where the user came from, nothing removed. */
  readonly onCancel: () => void;
  /** The local data is gone. */
  readonly onRemoved: () => void;
}

/** What removal would lose, as `rv device forget` says it. */
function lossText(check: RemovalCheck): string {
  if (!check.unlocked) {
    return (
      "This device is locked, so changes made on it that never reached the server cannot be uploaded first: " +
      "any such changes will be lost. To upload them first, cancel and unlock."
    );
  }
  const ops = check.unsentChanges ?? 0;
  const snapshots = check.unsentSnapshots ?? 0;
  const prefix = check.uploaded === false ? "The changes the server never acknowledged could not be uploaded now. " : "";
  if (ops === 0 && snapshots === 0) {
    return `${prefix}Every change made on this device is on the server.`;
  }
  return `${prefix}${ops} changes and ${snapshots} snapshots made on this device are NOT on the server and will be lost.`;
}

export function RemoveDeviceView({ client, onCancel, onRemoved }: RemoveDeviceViewProps) {
  const [check, setCheck] = useState<RemovalCheck | undefined>(undefined);
  const [error, setError] = useState<string | undefined>(undefined);
  const [confirmed, setConfirmed] = useState(false);
  const [pending, setPending] = useState(false);

  useEffect(() => {
    let live = true;
    void client
      .removalCheck()
      .then((result) => {
        if (live) {
          setCheck(result);
        }
      })
      .catch((e: unknown) => {
        if (live) {
          setError(e instanceof Error ? e.message : "removal_check_failed");
        }
      });
    return () => {
      live = false;
    };
  }, [client]);

  return (
    <section aria-labelledby="remove-device-heading">
      <h2 id="remove-device-heading">Remove this device</h2>
      {check === undefined && error === undefined ? (
        <p role="status">Uploading any changes the server has not received yet…</p>
      ) : undefined}
      {check?.refusal !== undefined ? (
        <p role="alert">
          This device cannot be removed while an alarm is raised: {alarmDescription(check.refusal)}. Its local data
          is the evidence of it.
        </p>
      ) : undefined}
      {check !== undefined && check.refusal === undefined ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!confirmed) {
              return;
            }
            setPending(true);
            setError(undefined);
            void client
              .removeDevice()
              .then(onRemoved)
              .catch((err: unknown) => {
                const code = err instanceof Error ? err.message : "remove_device_failed";
                setError(
                  isAlarmCode(code)
                    ? `This device cannot be removed while an alarm is raised: ${alarmDescription(code)}.`
                    : code,
                );
              })
              .finally(() => setPending(false));
          }}
        >
          <p>{lossText(check)}</p>
          <p>
            This removes this device&apos;s keys and vault copy from this browser. To use the extension again, set it up
            anew with your Secret Key. Afterwards, revoke the old device from another device.
          </p>
          <label>
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
            Remove this device&apos;s local data
          </label>
          <button type="submit" disabled={!confirmed || pending}>
            Remove this device
          </button>
        </form>
      ) : undefined}
      {error !== undefined ? <p role="alert">{error}</p> : undefined}
      <button type="button" onClick={onCancel} disabled={pending}>
        Cancel
      </button>
    </section>
  );
}
