// SPDX-License-Identifier: AGPL-3.0-only

// The Settings "What the server stores" group (ROADMAP §4.5): the static list and retention
// rules of `transparency.ts`, and the counts this browser already holds (that module's docs:
// no server-reported numbers, and why).
import { useEffect, useState } from "react";

import { codeOf } from "../core-client.ts";
import { type LocalCounts, RETENTION, STORED, countRows } from "../transparency.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText } from "./common.tsx";

/** What the server stores (module docs). */
export function TransparencyPane(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const [counts, setCounts] = useState<LocalCounts | undefined>();
  const [error, setError] = useState<string | undefined>();

  useEffect(() => {
    let live = true;
    Promise.all([ctx.client.call("items", false), ctx.client.call("items", true), ctx.client.call("devices")]).then(
      ([items, trashed, devices]) =>
        live && setCounts({ items: items.length, trashed: trashed.length, devices: devices.length }),
      (e: unknown) => live && setError(codeOf(e)),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, ctx.revision]);

  return (
    <section className="panel" aria-labelledby="transparency-heading">
      <h2 id="transparency-heading">What the server stores</h2>
      <p className="muted">
        Everything in your items is encrypted in this browser before it is sent. This is what the server holds
        for your account, and what it can see. It is only true of an honest server: a compromised one can keep
        more.
      </p>
      <table>
        <caption className="sr-only">Data the server stores for your account</caption>
        <thead>
          <tr>
            <th scope="col">Data</th>
            <th scope="col">How it is stored</th>
          </tr>
        </thead>
        <tbody>
          {STORED.map((row) => (
            <tr key={row.data}>
              <th scope="row">{row.data}</th>
              <td>{row.how}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h3>How long it is kept</h3>
      <ul>
        {RETENTION.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
      <h3>Your vault, as this browser received it</h3>
      <ErrorText code={error} />
      {counts !== undefined && (
        <table>
          <caption className="sr-only">Counts of your vault</caption>
          <tbody>
            {countRows(counts).map((row) => (
              <tr key={row.label}>
                <th scope="row">{row.label}</th>
                <td>{row.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="hint">
        Counted here from what the server sent, not reported by the server. The server cannot tell items in the
        Trash from other items.
      </p>
    </section>
  );
}
