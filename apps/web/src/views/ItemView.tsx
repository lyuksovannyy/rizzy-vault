// One item: its fields, masked where the core conceals them, with reveal and copy; its URIs as
// safe links (INV-42); its TOTP code; its password history (ADR 0018 §7), masked like any
// password; the "deleted on X while it was being edited on Y" notice (ADR 0012 §5); edit,
// trash, restore and purge.
//
// A concealed value crosses from the Worker only when the user asks (reveal or copy; ADR 0013
// §3 rule 3), and a revealed value is shown in the secret-field component (INV-68).
import type { DeviceView, FieldView, ItemSummary, PasswordHistoryEntry, TotpCode, TrashConflict } from "@rizzy-vault/core";
import { ConfirmDialog, IconStarFilled, IconStarOutline, SecretField, TypeIcon, useToast } from "@rizzy-vault/ui";
import { useEffect, useId, useState } from "react";

import { codeOf } from "../core-client.ts";
import { deviceName } from "../device-names.ts";
import { type Element, type Grouped, group, labelOf, matchModeLabel } from "../fields.ts";
import { SafeLink, SafeOpenButton } from "../SafeLink.tsx";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** The value line of one field: plain, or masked with reveal and copy. */
function FieldValue(props: {
  readonly ctx: VaultContext;
  readonly id: string;
  readonly field: FieldView;
  readonly label: string;
  readonly link?: boolean;
}) {
  const { ctx, id, field, label } = props;
  const [revealed, setRevealed] = useState<string | undefined>();
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
          <SecretField label={label} name={field.key} value={revealed} initiallyRevealed />
        ) : (
          <>
            <span className="field-label">{label}</span>
            <span className="masked" aria-label={`${label}, hidden`}>••••••••</span>
          </>
        )
      ) : (
        <>
          <span className="field-label">{label}</span>
          <span className="field-value">
            {props.link === true ? <SafeLink url={field.value ?? ""} /> : (field.value ?? "")}
          </span>
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
        <button type="button" className="secondary small" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
      </span>
      <ErrorText code={error} />
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

/** When a past password was written: its date and time, or that an imported one has none. */
function historyLabel(entry: PasswordHistoryEntry): string {
  const when = entry.atMs === undefined ? "date unknown" : new Date(entry.atMs).toLocaleString();
  return entry.source === "imported" ? `Imported, ${when}` : when;
}

/** One past password: masked, revealed or copied only on the user's request (ADR 0013 §3
 * rule 3), through the core's `revealPasswordHistory` by the entry's index. */
function HistoryLine(props: {
  readonly ctx: VaultContext;
  readonly id: string;
  readonly index: number;
  readonly entry: PasswordHistoryEntry;
}) {
  const { ctx, id, index, entry } = props;
  const [revealed, setRevealed] = useState<string | undefined>();
  const [copied, setCopied] = useState(false);
  const { error, run } = useAction();
  const label = historyLabel(entry);
  const value = () => ctx.client.call("revealPasswordHistory", id, index);

  return (
    <div className="field" data-history-entry={index}>
      {revealed !== undefined ? (
        <SecretField label={label} name={`history-${index}`} value={revealed} initiallyRevealed />
      ) : (
        <>
          <span className="field-label">{label}</span>
          <span className="masked" aria-label={`Password from ${label}, hidden`}>
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
        <button
          type="button"
          className="secondary small"
          onClick={() =>
            void run(async () => {
              await ctx.clipboard.copy(await value());
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            })
          }
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </span>
      <ErrorText code={error} />
    </div>
  );
}

/** The item's password history (ADR 0018 §7: the history of `login.password`, with history
 * imported from another manager), newest first, folded until the user opens it. Nothing shows
 * for an item without one. */
function PasswordHistory(props: { readonly ctx: VaultContext; readonly id: string }) {
  const { ctx, id } = props;
  const [entries, setEntries] = useState<PasswordHistoryEntry[] | undefined>();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const headingId = useId();

  useEffect(() => {
    let live = true;
    ctx.client.call("passwordHistory", id).then(
      (h) => live && setEntries(h),
      (e: unknown) => live && setError(codeOf(e)),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, ctx.revision, id]);

  if (error !== undefined) {
    return <ErrorText code={error} />;
  }
  if (entries === undefined || entries.length === 0) {
    return null;
  }
  return (
    <section className="password-history" aria-labelledby={headingId} data-testid="password-history">
      <div className="field">
        <h3 id={headingId} className="field-label">
          Password history
        </h3>
        <span className="field-value muted">{entries.length === 1 ? "1 earlier password" : `${entries.length} earlier passwords`}</span>
        <span className="field-actions">
          <button type="button" className="secondary small" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
            {open ? "Hide history" : "Show history"}
          </button>
        </span>
      </div>
      {open &&
        entries.map((entry, index) => (
          // The index is the entry's identity for the core's reveal call; the list is reloaded
          // whole after every sync.
          <HistoryLine key={`${ctx.revision}-${index}`} ctx={ctx} id={id} index={index} entry={entry} />
        ))}
    </section>
  );
}

/** "Deleted on X while it was being edited on Y" (ADR 0012 §5): an edit kept the item that
 * another device had moved to the trash at the same time. Nothing shows otherwise. */
function TrashConflictNotice(props: { readonly ctx: VaultContext; readonly id: string }) {
  const { ctx, id } = props;
  const [conflict, setConflict] = useState<{ conflict: TrashConflict; devices: DeviceView[] } | undefined>();

  useEffect(() => {
    let live = true;
    ctx.client.call("trashConflict", id).then(
      async (c) => {
        if (c === undefined) {
          if (live) {
            setConflict(undefined);
          }
          return;
        }
        // The device list only names the devices; the notice shows without it.
        const devices = await ctx.client.call("devices").catch(() => []);
        if (live) {
          setConflict({ conflict: c, devices });
        }
      },
      () => live && setConflict(undefined),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, ctx.revision, id]);

  if (conflict === undefined) {
    return null;
  }
  const own = ctx.session.deviceId;
  const { trashedBy, editedBy, trashedAtMs } = conflict.conflict;
  return (
    <p className="notice" role="status" data-testid="trash-conflict">
      Deleted on {deviceName(trashedBy, conflict.devices, own)} while it was being edited on{" "}
      {deviceName(editedBy, conflict.devices, own)}. The edit kept the item.{" "}
      <span className="muted">Moved to trash {new Date(trashedAtMs).toLocaleString()}.</span>
    </p>
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

  return (
    <article className="panel item" aria-labelledby="item-title">
      <div className="item-header">
        <span className="item-icon" aria-hidden="true">
          <TypeIcon type={summary.itemType} />
        </span>
        <h2 id="item-title">{summary.title === "" ? "(untitled)" : summary.title}</h2>
        {writable && !summary.trashed && (
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
      <p className="muted">{summary.itemType}</p>
      {!summary.trashed && <TrashConflictNotice ctx={ctx} id={id} />}
      {grouped.fixed
        .filter((f) => f.key !== "item.name")
        .map((f) => (
          <FieldValue key={f.key} ctx={ctx} id={id} field={f} label={labelOf(f.key)} />
        ))}
      {summary.hasTotp && !summary.trashed && <TotpLine ctx={ctx} id={id} />}
      {(summary.itemType === "login" || grouped.pwhist.length > 0) && <PasswordHistory ctx={ctx} id={id} />}
      {grouped.uris.map((u) => {
        const v = u.attributes.get("value");
        if (v === undefined) {
          return null;
        }
        return (
          <div key={v.key}>
            <FieldValue ctx={ctx} id={id} field={v} label="Website" link />
            <p className="muted small" data-field={`${v.key.replace(/\/value$/, "/match")}`}>
              Match: {matchModeLabel(u.attributes.get("match")?.value)}
            </p>
          </div>
        );
      })}
      {grouped.custom.map((c) => {
        const v = c.attributes.get("value");
        const label = c.attributes.get("label")?.value ?? "Field";
        return v === undefined ? null : <FieldValue key={v.key} ctx={ctx} id={id} field={v} label={label} />;
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
        <FieldValue key={f.key} ctx={ctx} id={id} field={f} label={f.key} />
      ))}
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
              <button type="button" disabled={busy} onClick={props.onEdit}>
                Edit
              </button>
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
    </article>
  );
}
