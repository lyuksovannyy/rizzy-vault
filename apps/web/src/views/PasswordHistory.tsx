// An item's password history (gap 01; ADR 0012 §5 "Password history is the history of
// `login.password`"; ADR 0018 §7 for history imported from another manager), in a collapsed
// section of the item view.
//
// ADR 0013 §3 rule 3: the Worker sends the entries' sources, positions and dates only; one
// value crosses per Reveal or Copy, never the whole history. A revealed value is shown in the
// secret-field component (INV-68) and forgotten after the next sync, which may shift the
// entries (the rows are keyed by `revision`).
import type { HistoryEntry } from "@rizzy-vault/core";
import { SecretField } from "@rizzy-vault/ui";
import { useEffect, useState } from "react";

import { codeOf } from "../core-client.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** How a row is labelled: its date, and whether it was imported. */
export function historyLabel(entry: HistoryEntry): string {
  const date = entry.changedMs === undefined ? undefined : new Date(entry.changedMs).toLocaleString();
  if (entry.source === "imported") {
    return date === undefined ? "Imported" : `Imported, ${date}`;
  }
  return date === undefined ? "Replaced" : `Replaced ${date}`;
}

/** One former password: masked until revealed. */
function HistoryRow(props: { readonly ctx: VaultContext; readonly id: string; readonly entry: HistoryEntry }) {
  const { ctx, id, entry } = props;
  const [revealed, setRevealed] = useState<string | undefined>();
  const [copied, setCopied] = useState(false);
  const { error, run } = useAction();
  const label = historyLabel(entry);

  const value = (): Promise<string> => ctx.client.call("revealPasswordHistory", id, entry.source, entry.index);

  const copy = () =>
    void run(async () => {
      await ctx.clipboard.copy(await value());
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });

  return (
    <div className="field" data-history={`${entry.source}/${entry.index}`}>
      {revealed !== undefined ? (
        <SecretField label={label} name={`history-${entry.source}-${entry.index}`} value={revealed} initiallyRevealed />
      ) : (
        <>
          <span className="field-label">{label}</span>
          <span className="masked" aria-label={`${label}, hidden`}>
            ••••••••
          </span>
        </>
      )}
      <span className="field-actions">
        <button
          type="button"
          className="secondary small"
          onClick={() =>
            revealed !== undefined ? setRevealed(undefined) : void run(async () => setRevealed(await value()))
          }
        >
          {revealed !== undefined ? "Hide" : "Reveal"}
        </button>
        <button type="button" className="secondary small" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
      </span>
      <ErrorText code={error} />
    </div>
  );
}

/** The password-history section (module docs); nothing when the item has no history. */
export function PasswordHistory(props: { readonly ctx: VaultContext; readonly id: string }) {
  const { ctx, id } = props;
  const [entries, setEntries] = useState<HistoryEntry[] | undefined>();
  const [error, setError] = useState<string | undefined>();

  useEffect(() => {
    let live = true;
    ctx.client.call("passwordHistory", id).then(
      (h) => {
        if (live) {
          setEntries(h);
          setError(undefined);
        }
      },
      (e: unknown) => live && setError(codeOf(e)),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, id, ctx.revision]);

  if (error !== undefined) {
    return <ErrorText code={error} />;
  }
  if (entries === undefined || entries.length === 0) {
    return null;
  }
  return (
    <details className="password-history">
      <summary>
        Password history ({entries.length} older {entries.length === 1 ? "password" : "passwords"})
      </summary>
      <p className="muted small">Each stays hidden until you reveal or copy it.</p>
      {entries.map((e) => (
        <HistoryRow key={`${ctx.revision}:${e.source}:${e.index}`} ctx={ctx} id={id} entry={e} />
      ))}
    </details>
  );
}
