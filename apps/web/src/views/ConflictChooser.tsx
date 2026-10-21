// SPDX-License-Identifier: AGPL-3.0-only

// The conflict chooser of one field (ROADMAP §4.5 "edited on Phone and Laptop at the same time —
// keep both / pick one", M3; ADR 0012 §4 step 5, ADR 0018 §6): which devices edited the field at
// once, each distinct value with its device and date, "Use this value" on each ("pick one") and
// "Keep both" (the shown value stays; every other value becomes a new field or website). The
// wording and the rules are `conflicts.ts`'s.
//
// ADR 0013 §3 rule 3: the listing carries a value only when the field is shown by default; a
// concealed value (a password, a hidden field) stays masked until the user reveals that one
// value, which crosses from the Worker then and only then. Picking or keeping never needs the
// value on this side: the call names the value by its listed position and id, which the core
// checks against the listing it reads again (`unknown_item` when a sync has changed it), so a
// click can never resolve to a value the user did not see.
//
// A resolution is an ordinary edit: the item view refreshes after it (`onResolved`), and the
// view is keyed by the sync revision, so a sync remounts this chooser and drops what it revealed.
import type { ConflictValue, FieldView } from "@rizzy-vault/core";
import { SecretField } from "@rizzy-vault/ui";
import { useEffect, useState } from "react";

import {
  type DeviceNamer,
  canKeepBoth,
  conflictHeadline,
  conflictValueCaption,
  deviceNamer,
  keepBothLabel,
  keptValue,
} from "../conflicts.ts";
import { codeOf } from "../core-client.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** The error line of a resolution: a stale listing gets its own words. */
function ConflictError(props: { readonly code: string | undefined }) {
  if (props.code === "unknown_item") {
    return (
      <p className="error" role="alert" data-code={props.code}>
        This conflict has changed or was already resolved. Sync to see it again.
      </p>
    );
  }
  return <ErrorText code={props.code} />;
}

/** One conflicting value: masked until revealed when concealed, with "Use this value". */
function ConflictRow(props: {
  readonly ctx: VaultContext;
  readonly id: string;
  readonly field: FieldView;
  readonly value: ConflictValue;
  readonly name: DeviceNamer;
  readonly busy: boolean;
  readonly onPick: ((value: ConflictValue) => void) | undefined;
}) {
  const { ctx, id, field, value } = props;
  const [revealed, setRevealed] = useState<string | undefined>();
  const { busy, error, run } = useAction();
  const caption = conflictValueCaption(value, props.name);

  return (
    <li className="conflict-value" data-conflict-value={value.index}>
      <span className="field-label">{caption}</span>
      {value.cleared ? (
        <span className="muted">(cleared)</span>
      ) : value.concealed ? (
        revealed !== undefined ? (
          <SecretField
            label={caption}
            name={`conflict-${field.key}-${value.index}`}
            value={revealed}
            initiallyRevealed
          />
        ) : (
          <span className="masked" aria-label={`${caption}, hidden`}>
            ••••••••
          </span>
        )
      ) : (
        <span className="field-value">{value.value ?? ""}</span>
      )}
      <span className="field-actions">
        {value.concealed && !value.cleared && (
          <button
            type="button"
            className="secondary small"
            disabled={busy}
            onClick={() =>
              revealed !== undefined
                ? setRevealed(undefined)
                : void run(async () =>
                    setRevealed(
                      await ctx.client.call("revealConflictValue", id, field.key, value.index, value.id),
                    ),
                  )
            }
          >
            {revealed !== undefined ? "Hide" : "Reveal"}
          </button>
        )}
        {props.onPick !== undefined && (
          <button
            type="button"
            className="small"
            disabled={props.busy}
            onClick={() => props.onPick?.(value)}
          >
            {value.cleared ? "Keep it cleared" : "Use this value"}
          </button>
        )}
      </span>
      <ErrorText code={error} />
    </li>
  );
}

/**
 * The chooser for `field` (module docs). `label` is the field's display name, for the copies
 * "keep both" adds. `onResolved` runs after a resolution was written (the item view syncs and
 * refreshes); without it (read-only vault, trashed item) the chooser only shows the values.
 */
export function ConflictChooser(props: {
  readonly ctx: VaultContext;
  readonly id: string;
  readonly field: FieldView;
  readonly label: string;
  readonly onResolved: ((message: string) => Promise<void>) | undefined;
}) {
  const { ctx, id, field, onResolved } = props;
  const [values, setValues] = useState<readonly ConflictValue[] | undefined>();
  const [name, setName] = useState<DeviceNamer>(() => deviceNamer([], ctx.session.deviceId));
  const { busy, error, setError, run } = useAction();

  useEffect(() => {
    let live = true;
    ctx.client.call("fieldConflict", id, field.key).then(
      (v) => live && setValues(v),
      (e: unknown) => live && setError(codeOf(e)),
    );
    // The device list only names the devices; without it they show as "device <id>".
    ctx.client.call("devices").then(
      (d) => live && setName(() => deviceNamer(d, ctx.session.deviceId)),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [ctx.client, ctx.session.deviceId, id, field.key, setError]);

  if (values === undefined) {
    return <ConflictError code={error} />;
  }
  if (values.length === 0) {
    return null;
  }

  const pick =
    onResolved === undefined
      ? undefined
      : (value: ConflictValue) =>
          void run(async () => {
            await ctx.client.call("resolveConflictPick", id, field.key, value.index, value.id);
            await onResolved("Conflict resolved.");
          });
  const kept = keptValue(values);
  const keepBoth =
    onResolved === undefined || kept === undefined || !canKeepBoth(field, values)
      ? undefined
      : () =>
          void run(async () => {
            await ctx.client.call(
              "resolveConflictKeepBoth",
              id,
              field.key,
              kept.index,
              kept.id,
              keepBothLabel(props.label, values, name),
            );
            await onResolved(
              field.list === "uri" ? "Both kept: the other website was added." : "Both kept: the other value is a new field.",
            );
          });

  return (
    <section className="conflict-chooser" aria-label={`Conflict in ${props.label}`} data-conflict={field.key}>
      <p>{conflictHeadline(values, name)} Keep both, or pick the value to use.</p>
      <ul className="conflict-values">
        {values.map((v) => (
          <ConflictRow
            key={`${v.index}-${v.id}`}
            ctx={ctx}
            id={id}
            field={field}
            value={v}
            name={name}
            busy={busy}
            onPick={pick}
          />
        ))}
      </ul>
      {keepBoth !== undefined && (
        <button type="button" className="secondary small" disabled={busy} onClick={keepBoth}>
          Keep both
        </button>
      )}
      <ConflictError code={error} />
    </section>
  );
}
