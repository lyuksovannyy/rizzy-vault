// One item: its fields, masked where the core conceals them, with reveal and copy; its URIs as
// safe links (INV-42); its TOTP code; edit, trash, restore and purge.
//
// A concealed value crosses from the Worker only when the user asks (reveal or copy; ADR 0013
// §3 rule 3), and a revealed value is shown in the secret-field component (INV-68).
import type { FieldView, ItemSummary, TotpCode } from "@rizzy-vault/core";
import { ConfirmDialog, IconStarFilled, IconStarOutline, SecretField, TypeIcon, useToast } from "@rizzy-vault/ui";
import { useEffect, useId, useState } from "react";

import { codeOf } from "../core-client.ts";
import { type Grouped, group, labelOf } from "../fields.ts";
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
   * `window.confirm`). */
  const [confirming, setConfirming] = useState<"trash" | "purge" | undefined>();

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
      {grouped.fixed
        .filter((f) => f.key !== "item.name")
        .map((f) => (
          <FieldValue key={f.key} ctx={ctx} id={id} field={f} label={labelOf(f.key)} />
        ))}
      {summary.hasTotp && !summary.trashed && <TotpLine ctx={ctx} id={id} />}
      {grouped.uris.map((u) => {
        const v = u.attributes.get("value");
        return v === undefined ? null : (
          <FieldValue key={v.key} ctx={ctx} id={id} field={v} label="Website" link />
        );
      })}
      {grouped.custom.map((c) => {
        const v = c.attributes.get("value");
        const label = c.attributes.get("label")?.value ?? "Field";
        return v === undefined ? null : <FieldValue key={v.key} ctx={ctx} id={id} field={v} label={label} />;
      })}
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
              <button type="button" className="danger" disabled={busy} onClick={() => setConfirming("purge")}>
                Delete for good
              </button>
            </>
          ) : (
            <>
              <button type="button" disabled={busy} onClick={props.onEdit}>
                Edit
              </button>
              <button type="button" className="secondary" disabled={busy} onClick={() => setConfirming("trash")}>
                Move to trash
              </button>
            </>
          )}
        </div>
      )}
      <ConfirmDialog
        open={confirming === "trash"}
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
        open={confirming === "purge"}
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
    </article>
  );
}
