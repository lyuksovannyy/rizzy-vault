// The account's durable devices, as the login verified them (CRYPTO.md §11.8). The web vault
// itself is an ephemeral device and is not listed. Revocation needs a key rotation, which the
// web vault does not offer in M1; `rv devices revoke` does.
import type { DeviceView } from "@rizzy-vault/core";
import { useEffect, useState } from "react";

import { codeOf } from "../core-client.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText } from "./common.tsx";

/** Human names of the device kinds. */
const KINDS: Readonly<Record<string, string>> = {
  "desktop-cli": "Desktop or command line",
  extension: "Browser extension",
  mobile: "Mobile",
};

/** The device list (module docs). */
export function DevicesPane(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const [devices, setDevices] = useState<DeviceView[] | undefined>();
  const [error, setError] = useState<string | undefined>();

  useEffect(() => {
    let live = true;
    ctx.client.call("devices").then(
      (d) => live && setDevices(d),
      (e: unknown) => live && setError(codeOf(e)),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, ctx.revision]);

  return (
    <div className="panel">
      <h2>Devices</h2>
      <p className="muted">
        This browser session is device {ctx.session.deviceId.slice(0, 8)}…, a temporary web
        session that is not listed. To revoke a device, use <code>rv devices revoke</code>.
      </p>
      <ErrorText code={error} />
      {devices !== undefined &&
        (devices.length === 0 ? (
          <p className="muted">No enrolled devices.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th scope="col">Device</th>
                <th scope="col">Kind</th>
                <th scope="col">Enrolled</th>
                <th scope="col">State</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id}>
                  <td className="mono">{d.id.slice(0, 16)}…</td>
                  <td>{KINDS[d.kind] ?? d.kind}</td>
                  <td>{new Date(d.createdAtMs).toLocaleString()}</td>
                  <td>{d.revoked ? "Revoked" : "Active"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ))}
    </div>
  );
}
