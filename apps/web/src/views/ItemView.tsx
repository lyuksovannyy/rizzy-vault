// SPDX-License-Identifier: AGPL-3.0-only

// One item: its fields, masked where the core conceals them, with reveal and copy; its URIs as
// safe links (INV-42); its TOTP code; its encrypted attachments (`AttachmentsSection.tsx`, ADR
// 0054); its password history (`PasswordHistory.tsx`) and every
// field's history with restore (`ItemHistory.tsx`); edit, trash, restore and purge. A field two
// devices edited at once carries a "conflict" badge and a "Resolve conflict" chooser
// (`ConflictChooser.tsx`: keep both / pick one, ROADMAP §4.5), the name included.
//
// A concealed value crosses from the Worker only when the user asks (reveal or copy; ADR 0013
// §3 rule 3), and a revealed value is shown in the secret-field component (INV-68). The
// large-type password display (`LargeType.tsx`) reveals nothing beyond that same path: its
// "Large type" trigger below only renders a value `FieldValue` already fetched for Reveal/Copy.
//
// A Secure Note's notes, and only those, render from their Markdown (`NoteMarkdown.tsx`; ADR
// 0062 §2, INV-88). Every other item type's notes stay plain text, and Copy always copies the
// stored source (§12).
//
// A login's password offers "Check for breaches" (ADR 0053; `PasswordHealth.tsx`): the Worker
// reads the password inside the core and sends only a 5-character hash prefix, so the check
// needs no reveal and puts no value on this thread.
import type { FieldView, HistoryEntry, ItemSummary, TotpCode } from "@rizzy-vault/core";
import { ConfirmDialog, IconStarFilled, IconStarOutline, ItemIcon, SecretField, useToast } from "@rizzy-vault/ui";
import { type ReactNode, useEffect, useId, useState } from "react";

import { codeOf } from "../core-client.ts";
import {
  type Element,
  type Grouped,
  SSH_DEFAULT_PORT,
  canEditFields,
  displayValue,
  group,
  isMultiline,
  labelOf,
  matchModeLabel,
  orderFixed,
  typeLabel,
} from "../fields.ts";
import { SafeLink, SafeOpenButton } from "../SafeLink.tsx";
import { AttachmentsSection } from "./AttachmentsSection.tsx";
import { ConflictChooser } from "./ConflictChooser.tsx";
import { ItemHistory } from "./ItemHistory.tsx";
import { LargeType } from "./LargeType.tsx";
import { NoteMarkdown } from "./NoteMarkdown.tsx";
import { BreachCheckButton } from "./PasswordHealth.tsx";
import { PasswordHistory } from "./PasswordHistory.tsx";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** The value line of one field: plain, or masked with reveal and copy. `onLargeType`, when
 * given, adds a "Large type" button once the field is revealed, calling back with the already-
 * revealed value (never fetching it again: `LargeType.tsx`'s module docs). */
function FieldValue(props: {
  readonly ctx: VaultContext;
  readonly id: string;
  readonly field: FieldView;
  readonly label: string;
  readonly link?: boolean;
  /** Render the value from its Markdown (a Secure Note's `item.notes` only: ADR 0062 §2). */
  readonly markdown?: boolean;
  readonly onLargeType?: ((value: string) => void) | undefined;
  /** The refresh after a conflict resolution (`ConflictChooser.tsx`); `undefined` when the
   * item cannot be written (read-only vault, trashed item), so the chooser only shows. */
  readonly onResolved?: ((message: string) => Promise<void>) | undefined;
  /** Shown under the value: the password's breach check (`PasswordHealth.tsx`). */
  readonly extra?: ReactNode;
}) {
  const { ctx, id, field, label } = props;
  const [revealed, setRevealed] = useState<string | undefined>();
  const [choosing, setChoosing] = useState(false);
  const [copied, setCopied] = useState(false);
  const { error, run } = useAction();

  const value = async (): Promise<string> =>
    field.concealed ? ctx.client.call("reveal", id, field.key) : (field.value ?? "");

  const copy = () =>
    void run(async () => {
      await ctx.clipboard.copy(await value());
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });

  return (
    <div className="field" data-field={field.key}>
      {field.concealed ? (
        revealed !== undefined ? (
          <SecretField
            label={label}
            name={field.key}
            value={revealed}
            initiallyRevealed
            {...(isMultiline(field.key) ? { multiline: true } : {})}
          />
        ) : (
          <>
            <span className="field-label">{label}</span>
            <span className="masked" aria-label={`${label}, hidden`}>••••••••</span>
          </>
        )
      ) : (
        <>
          <span className="field-label">{label}</span>
          {props.markdown === true ? (
            <NoteMarkdown source={field.value ?? ""} />
          ) : (
            <span className="field-value">
              {props.link === true ? <SafeLink url={field.value ?? ""} /> : displayValue(field.key, field.value ?? "")}
            </span>
          )}
        </>
      )}
      {field.conflict && <span className="badge" title="Edited on two devices at once">conflict</span>}
      <span className="field-actions">
        {props.link === true && <SafeOpenButton url={field.value ?? ""} label={`Open ${label}`} />}
        {field.concealed && (
          <button
            type="button"
            className="secondary small"
            onClick={() =>
              revealed !== undefined
                ? setRevealed(undefined)
                : void run(async () => setRevealed(await value()))
            }
          >
            {revealed !== undefined ? "Hide" : "Reveal"}
          </button>
        )}
        {revealed !== undefined && props.onLargeType !== undefined && (
          <button type="button" className="secondary small" onClick={() => props.onLargeType?.(revealed)}>
            Large type
          </button>
        )}
        <button type="button" className="secondary small" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
        {field.conflict && (
          <button
            type="button"
            className="secondary small"
            aria-expanded={choosing}
            onClick={() => setChoosing((c) => !c)}
          >
            {choosing ? "Close conflict" : "Resolve conflict"}
          </button>
        )}
      </span>
      <ErrorText code={error} />
      {props.extra}
      {field.conflict && choosing && (
        <ConflictChooser ctx={ctx} id={id} field={field} label={label} onResolved={props.onResolved} />
      )}
    </div>
  );
}

/** The current TOTP code, refreshed when it runs out. */
function TotpLine(props: { readonly ctx: VaultContext; readonly id: string }) {
  const { ctx, id } = props;
  const [code, setCode] = useState<TotpCode | undefined>();
  const [left, setLeft] = useState(0);
  const [error, setError] = useState<string | undefined>();

  useEffect(() => {
    let live = true;
    let deadline = 0;
    const load = () =>
      ctx.client.call("totp", id).then(
        (c) => {
          if (live) {
            setCode(c);
            deadline = Date.now() + c.validForSeconds * 1000;
            setLeft(c.validForSeconds);
          }
        },
        (e: unknown) => live && setError(codeOf(e)),
      );
    void load();
    const timer = setInterval(() => {
      const remaining = Math.ceil((deadline - Date.now()) / 1000);
      if (remaining <= 0) {
        void load();
      } else {
        setLeft(remaining);
      }
    }, 1000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [ctx.client, id]);

  if (error !== undefined) {
    return <ErrorText code={error} />;
  }
  if (code === undefined) {
    return null;
  }
  // The countdown ring: an SVG circle whose stroke is `fraction` of the way drawn, fraction of
  // the current period remaining. SVG presentation attributes, not the banned `style` prop
  // (ADR 0014 §2; the eslint rule targets the JSX `style` attribute, not `stroke-dasharray`).
  const fraction = code.periodSeconds > 0 ? left / code.periodSeconds : 0;
  const radius = 9;
  const circumference = 2 * Math.PI * radius;
  return (
    <div className="field totp">
      <span className="field-label">One-time code</span>
      <span className="totp-ring" aria-hidden="true">
        <svg viewBox="0 0 22 22" width="22" height="22">
          <circle cx="11" cy="11" r={radius} className="totp-ring-track" />
          <circle
            cx="11"
            cy="11"
            r={radius}
            className="totp-ring-progress"
            strokeDasharray={circumference}
            strokeDashoffset={circumference * (1 - fraction)}
            transform="rotate(-90 11 11)"
          />
        </svg>
      </span>
      <span className="field-value mono" data-testid="totp-code">
        {code.code}
      </span>
      <span className="muted">{left}s</span>
      <span className="field-actions">
        <button type="button" className="secondary small" onClick={() => void ctx.clipboard.copy(code.code)}>
          Copy
        </button>
      </span>
    </div>
  );
}

/** One stored passkey's display row (ADR 0039 §1; task: "rp, user name, created; no private
 * key reveal"): `rp_id` and `created_ms` come straight off `rp_id`'s/`created_ms`'s own
 * `FieldView.value` (both have a text form, unlike the Bytes fields this item also carries —
 * `fields.ts`'s `Grouped.passkeys` doc); the "user name" shown alongside is this Login's own
 * `summary.username` (the ADR's field table has no separate per-passkey display name, module
 * doc in `apps/extension/src/core-host/bindings.ts`'s `StoredPasskey`). */
function PasskeyLine(props: {
  readonly element: Element;
  readonly username: string | undefined;
  readonly onDelete: () => void;
  readonly disabled: boolean;
}) {
  const { element, username } = props;
  const rpId = element.attributes.get("rp_id")?.value ?? "";
  const createdMsText = element.attributes.get("created_ms")?.value;
  const created = createdMsText !== undefined && createdMsText !== "" ? new Date(Number(createdMsText)) : undefined;
  return (
    <div className="field" data-passkey={element.element}>
      <span className="field-label">Passkey</span>
      <span className="field-value">
        {rpId}
        {username !== undefined && username !== "" ? ` (${username})` : ""}
      </span>
      {created !== undefined && <span className="muted small">Created {created.toLocaleDateString()}</span>}
      <span className="field-actions">
        <button type="button" className="secondary small" disabled={props.disabled} onClick={props.onDelete}>
          Delete
        </button>
      </span>
    </div>
  );
}

/** The item view (module docs). `onWritten(gone)` after a write; `gone` if it left this list. */
export function ItemView(props: {
  readonly ctx: VaultContext;
  readonly id: string;
  readonly onEdit: () => void;
  readonly onWritten: (gone: boolean) => Promise<void>;
}) {
  const { ctx, id } = props;
  const [summary, setSummary] = useState<ItemSummary | undefined>();
  const [grouped, setGrouped] = useState<Grouped | undefined>();
  const { busy, error, setError, run } = useAction();
  const { notify } = useToast();
  const titleId = useId();
  /** Which confirm dialog, if any, is open (module docs, item 2 of the redesign follow-up:
   * trash and purge both confirm, now through the accessible dialog rather than
   * `window.confirm`). `{ kind: "deletePasskey", element }` names which `passkey/<element>/…`
   * row a "Delete" click targets (ADR 0039's own write path has no other way to identify one). */
  const [confirming, setConfirming] = useState<{ readonly kind: "trash" | "purge" } | { readonly kind: "deletePasskey"; readonly element: string } | undefined>();
  /** The large-type overlay's value (module docs, `LargeType.tsx`), `undefined` while closed. */
  const [largeType, setLargeType] = useState<string | undefined>();

  useEffect(() => {
    let live = true;
    Promise.all([ctx.client.call("item", id), ctx.client.call("fields", id)]).then(
      ([s, f]) => {
        if (live) {
          setSummary(s);
          setGrouped(group(f));
        }
      },
      (e: unknown) => live && setError(codeOf(e)),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, id, setError]);

  if (summary === undefined || grouped === undefined) {
    return <ErrorText code={error} />;
  }

  const act = (f: () => Promise<void>, gone: boolean, successMessage?: string) =>
    void run(async () => {
      await f();
      await props.onWritten(gone);
      if (successMessage !== undefined) {
        notify("success", successMessage);
      }
    });

  const writable = !ctx.session.readOnly;

  /** Toggles favorite through the same `editItem` op the editor's checkbox writes (`fields.ts`
   * `item.favorite`): a one-op change over the existing write path, not a new one. */
  const toggleFavorite = () =>
    act(
      () =>
        ctx.client.call(
          "editItem",
          id,
          summary.favorite ? [{ op: "clear", key: "item.favorite" }] : [{ op: "set", key: "item.favorite", value: "true" }],
        ),
      false,
    );

  /** `ItemHistory`'s write path: restoring an entry is an ordinary edit (ROADMAP §4.2). Unlike
   * `act` (used for a button's own `onClick`), this returns a promise that settles when the
   * write has, so the row stays busy until then; a refused restore shows through `run`'s
   * shared error state (the one trash, purge and favorite use), not in the row. */
  const restoreHistoryEntry = (fieldKey: string, entry: HistoryEntry): Promise<void> =>
    run(async () => {
      await ctx.client.call("restoreFieldHistory", id, fieldKey, entry.index, entry.id);
      await props.onWritten(false);
      notify("success", "Value restored.");
    }).then(() => undefined);

  /** `ConflictChooser`'s refresh after a resolution, an ordinary edit (ROADMAP §4.5): like
   * `restoreHistoryEntry`, the view syncs and reloads; only a writable, active item gets it. */
  const resolved =
    writable && !summary.trashed
      ? async (message: string): Promise<void> => {
          await props.onWritten(false);
          notify("success", message);
        }
      : undefined;

  return (
    <article className="panel item" aria-labelledby="item-title">
      <div className="item-header">
        <span className="item-icon" aria-hidden="true">
          <ItemIcon icons={ctx.icons} websiteHost={summary.websiteHost} itemType={summary.itemType} size={28} />
        </span>
        <h2 id="item-title">{summary.title === "" ? "(untitled)" : summary.title}</h2>
        {writable && !summary.trashed && canEditFields(summary.itemType) && (
          <button
            type="button"
            className="secondary small icon-button favorite-toggle"
            aria-pressed={summary.favorite}
            disabled={busy}
            onClick={toggleFavorite}
          >
            {summary.favorite ? <IconStarFilled /> : <IconStarOutline />}
            <span className="sr-only">{summary.favorite ? "Remove from favorites" : "Add to favorites"}</span>
          </button>
        )}
      </div>
      <p className="muted">{typeLabel(summary.itemType)}</p>
      {orderFixed(summary.itemType, grouped.fixed)
        // The name is the title; it gets a row of its own only to resolve a conflict.
        .filter((f) => f.key !== "item.name" || f.conflict)
        .map((f) => (
          <FieldValue
            key={f.key}
            ctx={ctx}
            id={id}
            field={f}
            label={labelOf(f.key)}
            markdown={summary.itemType === "note" && f.key === "item.notes"}
            onLargeType={f.key === "login.password" ? setLargeType : undefined}
            onResolved={resolved}
            extra={
              f.key === "login.password" && f.concealed ? (
                <BreachCheckButton
                  check={() => ctx.client.call("breachCheckItem", id)}
                  testId="item-breach-result"
                />
              ) : undefined
            }
          />
        ))}
      {summary.itemType === "ssh-key" && !grouped.fixed.some((f) => f.key === "ssh.port") && (
        // ADR 0055 §1: no `ssh.port` means port 22, a display default that is never stored.
        <div className="field" data-field="ssh.port">
          <span className="field-label">{labelOf("ssh.port")}</span>
          <span className="field-value">{SSH_DEFAULT_PORT} (default)</span>
        </div>
      )}
      {summary.hasTotp && !summary.trashed && <TotpLine ctx={ctx} id={id} />}
      {grouped.uris.map((u) => {
        const v = u.attributes.get("value");
        if (v === undefined) {
          return null;
        }
        return (
          <div key={v.key}>
            <FieldValue ctx={ctx} id={id} field={v} label="Website" link onResolved={resolved} />
            <p className="muted small" data-field={`${v.key.replace(/\/value$/, "/match")}`}>
              Match: {matchModeLabel(u.attributes.get("match")?.value)}
            </p>
          </div>
        );
      })}
      {grouped.custom.map((c) => {
        const v = c.attributes.get("value");
        // ADR 0076 §2.4: a field without a Display Name shows as "Unnamed field".
        const savedLabel = c.attributes.get("label")?.value ?? "";
        const label = savedLabel.trim() === "" ? "Unnamed field" : savedLabel;
        return v === undefined ? null : (
          <FieldValue key={v.key} ctx={ctx} id={id} field={v} label={label} onResolved={resolved} />
        );
      })}
      {grouped.passkeys.map((p) => (
        <PasskeyLine
          key={p.element}
          element={p}
          username={summary.username}
          disabled={busy}
          onDelete={() => setConfirming({ kind: "deletePasskey", element: p.element })}
        />
      ))}
      {grouped.other.map((f) => (
        <FieldValue key={f.key} ctx={ctx} id={id} field={f} label={f.key} onResolved={resolved} />
      ))}
      <AttachmentsSection ctx={ctx} id={id} writable={writable && !summary.trashed} />
      <PasswordHistory ctx={ctx} id={id} />
      <ItemHistory ctx={ctx} id={id} onRestore={writable && !summary.trashed ? restoreHistoryEntry : undefined} />
      {grouped.tags.length > 0 && (
        <p className="tags">
          {grouped.tags.map((t) => (
            <span key={t} className="tag">
              {t}
            </span>
          ))}
        </p>
      )}
      <ErrorText code={error} />
      {writable && (
        <div className="actions">
          {summary.trashed ? (
            <>
              <button
                type="button"
                disabled={busy}
                onClick={() => act(() => ctx.client.call("restoreItem", id), true, "Item restored.")}
              >
                Restore
              </button>
              <button type="button" className="danger" disabled={busy} onClick={() => setConfirming({ kind: "purge" })}>
                Delete for good
              </button>
            </>
          ) : (
            <>
              {canEditFields(summary.itemType) && (
                // ADR 0018 §8: an unsupported type offers no field edits; trash still works.
                <button type="button" disabled={busy} onClick={props.onEdit}>
                  Edit
                </button>
              )}
              <button type="button" className="secondary" disabled={busy} onClick={() => setConfirming({ kind: "trash" })}>
                Move to trash
              </button>
            </>
          )}
        </div>
      )}
      <ConfirmDialog
        open={confirming?.kind === "trash"}
        titleId={`${titleId}-trash-title`}
        title="Move this item to trash?"
        description="You can restore it from the trash later, or delete it for good from there."
        confirmLabel="Move to trash"
        onConfirm={() => {
          setConfirming(undefined);
          act(() => ctx.client.call("trashItem", id), true, "Item moved to trash.");
        }}
        onCancel={() => setConfirming(undefined)}
      />
      <ConfirmDialog
        open={confirming?.kind === "purge"}
        titleId={`${titleId}-purge-title`}
        title="Delete this item for good?"
        description="This cannot be undone."
        confirmLabel="Delete for good"
        danger
        onConfirm={() => {
          setConfirming(undefined);
          act(() => ctx.client.call("purgeItem", id), true, "Item deleted for good.");
        }}
        onCancel={() => setConfirming(undefined)}
      />
      <ConfirmDialog
        open={confirming?.kind === "deletePasskey"}
        titleId={`${titleId}-delete-passkey-title`}
        title="Delete this passkey?"
        description="Signing in to this site with this passkey will no longer be possible. This cannot be undone."
        confirmLabel="Delete passkey"
        danger
        onConfirm={() => {
          const target = confirming;
          setConfirming(undefined);
          if (target?.kind !== "deletePasskey") {
            return;
          }
          act(
            () => ctx.client.call("editItem", id, [{ op: "removeElement", list: "passkey", element: target.element }]),
            false,
            "Passkey deleted.",
          );
        }}
        onCancel={() => setConfirming(undefined)}
      />
      <LargeType label="Password" value={largeType} onClose={() => setLargeType(undefined)} />
    </article>
  );
}
