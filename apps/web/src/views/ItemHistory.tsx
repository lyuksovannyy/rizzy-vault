// SPDX-License-Identifier: AGPL-3.0-only

// An item's field history (ROADMAP §4.2 "Item revision history (restore old versions)", M3), in
// a collapsed section per field of the item view: `PasswordHistory.tsx` generalized to every
// field, not only `login.password` (that section stays for its own "imported" sub-list, ADR
// 0018 §7, which this one never carries).
//
// ADR 0013 §3 rule 3: the Worker sends each entry's position and date only; one value crosses
// per Reveal or Copy, never the whole history. Restoring writes the entry back as the field's
// current value, an ordinary edit (ADR 0018 §2 "Flow"): it syncs like any other write, and the
// value it displaces becomes history in turn.
//
// A sync can shift the entries, so a position read before it may name another entry after it.
// The same two guards as `PasswordHistory.tsx` keep a row from acting on the wrong identity:
// Reveal, Copy and Restore stay disabled until the list read after the latest sync has arrived
// (`canReveal`), and each call carries the row's own id, which the core checks against the
// entry it finds at that (field, position) pair (`unknown_item` when they differ).
import type { FieldHistory, HistoryEntry } from "@rizzy-vault/core";
import { SecretField } from "@rizzy-vault/ui";
import { useEffect, useState } from "react";

import { codeOf } from "../core-client.ts";
import { labelOf } from "../fields.ts";
import { historyLabel } from "./PasswordHistory.tsx";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** An item-history listing and the sync revision it was read at (`PasswordHistory.tsx`'s
 * `Listed`, generalized to every field). */
interface Listed {
  readonly revision: number;
  readonly fields: readonly FieldHistory[];
}

/** One field-history entry: masked until revealed, with Reveal, Copy and Restore. */
function FieldHistoryRow(props: {
  readonly ctx: VaultContext;
  readonly id: string;
  readonly fieldKey: string;
  readonly entry: HistoryEntry;
  readonly ready: boolean;
  readonly onRestore: (fieldKey: string, entry: HistoryEntry) => Promise<void>;
}) {
  const { ctx, id, fieldKey, entry } = props;
  const [revealed, setRevealed] = useState<string | undefined>();
  const [copied, setCopied] = useState(false);
  const { busy, error, run } = useAction();
  const label = historyLabel(entry);
  const disabled = !props.ready || busy;

  const value = (): Promise<string> =>
    ctx.client.call("revealFieldHistory", id, fieldKey, entry.index, entry.id);

  const copy = () =>
    void run(async () => {
      await ctx.clipboard.copy(await value());
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });

  const restore = () => void run(() => props.onRestore(fieldKey, entry));

  return (
    <div className="field" data-history={`${fieldKey}/${entry.index}`}>
      {revealed !== undefined ? (
        <SecretField
          label={label}
          name={`item-history-${fieldKey}-${entry.index}`}
          value={revealed}
          initiallyRevealed
        />
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
          disabled={revealed === undefined && disabled}
          onClick={() =>
            revealed !== undefined ? setRevealed(undefined) : void run(async () => setRevealed(await value()))
          }
        >
          {revealed !== undefined ? "Hide" : "Reveal"}
        </button>
        <button type="button" className="secondary small" disabled={disabled} onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
        <button type="button" className="secondary small" disabled={disabled} onClick={restore}>
          Restore
        </button>
      </span>
      <ErrorText code={error} />
    </div>
  );
}

/** One field's history section: nothing when it holds no entries. */
function FieldSection(props: {
  readonly ctx: VaultContext;
  readonly id: string;
  readonly field: FieldHistory;
  readonly ready: boolean;
  readonly onRestore: (fieldKey: string, entry: HistoryEntry) => Promise<void>;
}) {
  const { field } = props;
  const count = field.entries.length;
  if (count === 0) {
    return null;
  }
  return (
    <details className="field-history-section" data-field-history={field.key}>
      <summary>
        {labelOf(field.key)} history ({count} older {count === 1 ? "value" : "values"})
      </summary>
      <p className="muted small">Each stays hidden until you reveal or copy it.</p>
      {field.entries.map((e) => (
        <FieldHistoryRow
          key={`${field.key}:${e.index}`}
          ctx={props.ctx}
          id={props.id}
          fieldKey={field.key}
          entry={e}
          ready={props.ready}
          onRestore={props.onRestore}
        />
      ))}
    </details>
  );
}

/**
 * The item-history section (module docs): one collapsed sub-section per field that has
 * history, nothing when the item has none. `onRestore` is the host's write path (ItemView's
 * `act`, so a restore's error and busy state show the same way trash/purge do); it is called
 * only after this component has already checked the entry is still the one last listed.
 */
export function ItemHistory(props: {
  readonly ctx: VaultContext;
  readonly id: string;
  readonly onRestore: (fieldKey: string, entry: HistoryEntry) => Promise<void>;
}) {
  const { ctx, id } = props;
  const [listed, setListed] = useState<Listed | undefined>();
  const [error, setError] = useState<string | undefined>();

  useEffect(() => {
    let live = true;
    const revision = ctx.revision;
    ctx.client.call("itemHistory", id).then(
      (fields) => {
        if (live) {
          setListed({ revision, fields });
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
  if (listed === undefined || listed.fields.every((f) => f.entries.length === 0)) {
    return null;
  }
  // Whether the rows may reveal, copy or restore: only when the list was read at the latest
  // sync, so its positions are the Worker's (module docs; `PasswordHistory.tsx`'s `canReveal`).
  const ready = listed.revision === ctx.revision;
  return (
    <div className="item-history">
      {listed.fields.map((field) => (
        <FieldSection
          key={field.key}
          ctx={ctx}
          id={id}
          field={field}
          ready={ready}
          onRestore={props.onRestore}
        />
      ))}
    </div>
  );
}
