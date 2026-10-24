// SPDX-License-Identifier: AGPL-3.0-only

// The vault dialogs (ADR 0081 §A4–§A6): move or copy an item to another vault, rename a vault,
// delete a vault.
//
// - Move and copy list only the other vaults this session can write to; the Personal vault is
//   preselected when it is one of them (§A8: no "last used" memory).
// - Delete offers two choices, the first preselected (owner answer 5): "Move its N items to
//   Personal, then delete" or "Delete the vault and its N items". Both need the vault's name
//   typed as confirmation. The server needs a fresh login for a delete (§A5): on
//   `server_fresh_session_required` the dialog asks for the Secret Key and master password,
//   switches this browser to the new login (`refreshSession`, as ending sessions does) and
//   tries again.
// - Each dialog is a `role="dialog"` with `aria-modal`, a label, Tab kept inside, Escape to
//   cancel, and focus back on the opener when it closes; it registers as open so the vault's
//   keyboard shortcuts stay quiet meanwhile.
import type { VaultInfo } from "@rizzy-vault/core";
import { t } from "@rizzy-vault/i18n";
import { SecretField, setModalOpen, trapTab, useToast } from "@rizzy-vault/ui";
import { type FormEvent, type ReactNode, useEffect, useId, useRef, useState } from "react";

import { codeOf, secretBytes } from "../core-client.ts";
import { MAX_VAULT_NAME_CHARS } from "../vault-limits.ts";
import { defaultVault, vaultLabel, writableVaults } from "../vaults.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, takeSecret, useAction } from "./common.tsx";

/** A modal dialog frame (module docs). */
export function Modal(props: {
  readonly titleId: string;
  readonly onCancel: () => void;
  readonly children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const previous = document.activeElement;
    setModalOpen(true);
    // Focus starts inside the dialog: on its `autoFocus` control, else on the first control.
    const dialog = ref.current;
    if (dialog !== null && !dialog.contains(document.activeElement)) {
      dialog.querySelector<HTMLElement>("input, select, textarea, button")?.focus();
    }
    return () => {
      setModalOpen(false);
      if (previous instanceof HTMLElement) {
        previous.focus();
      }
    };
  }, []);
  return (
    <div className="overlay">
      <div
        ref={ref}
        className="panel dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={props.titleId}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            props.onCancel();
            return;
          }
          trapTab(e, ref.current);
        }}
      >
        {props.children}
      </div>
    </div>
  );
}

/** "Move to…" or "Copy to…" an item (§A6). `onDone` gets the new item's reference. */
export function VaultPickDialog(props: {
  readonly ctx: VaultContext;
  readonly mode: "move" | "copy";
  readonly itemId: string;
  readonly sourceVaultId: string;
  readonly onDone: (newId: string) => void;
  readonly onCancel: () => void;
}) {
  const { ctx } = props;
  const titleId = useId();
  const selectId = useId();
  const targets = writableVaults(ctx.vaults).filter((v) => v.id !== props.sourceVaultId);
  const [target, setTarget] = useState<string | undefined>(() => defaultVault(targets, ctx.personalVaultId));
  const { busy, error, run } = useAction();
  const { notify } = useToast();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const chosen = targets.find((v) => v.id === target);
    if (chosen === undefined) {
      return;
    }
    void run(async () => {
      const newId = await ctx.client.call(props.mode === "move" ? "moveItem" : "copyItem", props.itemId, chosen.id);
      await ctx.afterWrite();
      notify("success", t(props.mode === "move" ? "vaults.moved" : "vaults.copied", { name: vaultLabel(chosen) }));
      props.onDone(newId);
    });
  };
  return (
    <Modal titleId={titleId} onCancel={props.onCancel}>
      <form onSubmit={submit}>
        <h2 id={titleId}>{t(props.mode === "move" ? "vaults.moveTitle" : "vaults.copyTitle")}</h2>
        {targets.length === 0 ? (
          <p>{t("vaults.noOther")}</p>
        ) : (
          <>
            <label htmlFor={selectId}>{t("vaults.target")}</label>
            <select
              id={selectId}
              name="target-vault"
              value={target ?? ""}
              autoFocus
              onChange={(e) => setTarget(e.currentTarget.value)}
            >
              {targets.map((v) => (
                <option key={v.id} value={v.id}>
                  {vaultLabel(v)}
                </option>
              ))}
            </select>
          </>
        )}
        <ErrorText code={error} />
        <div className="actions">
          {targets.length > 0 && (
            <button type="submit" disabled={busy || target === undefined}>
              {busy ? t("vaults.working") : t(props.mode === "move" ? "vaults.moveSubmit" : "vaults.copySubmit")}
            </button>
          )}
          <button type="button" className="secondary" disabled={busy} onClick={props.onCancel}>
            {t("vaults.cancel")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Renames an owned vault (§A4). */
export function RenameVaultDialog(props: {
  readonly ctx: VaultContext;
  readonly vault: VaultInfo;
  readonly onDone: () => void;
  readonly onCancel: () => void;
}) {
  const { ctx, vault } = props;
  const titleId = useId();
  const inputId = useId();
  const [name, setName] = useState(vault.name ?? "");
  const { busy, error, run } = useAction();
  const { notify } = useToast();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await ctx.client.call("renameVault", vault.id, name);
      await ctx.afterWrite();
      notify("success", t("vaults.renamed"));
      props.onDone();
    });
  };
  return (
    <Modal titleId={titleId} onCancel={props.onCancel}>
      <form onSubmit={submit}>
        <h2 id={titleId}>{t("vaults.renameTitle")}</h2>
        <label htmlFor={inputId}>{t("vaults.name")}</label>
        <input
          id={inputId}
          name="vault-name"
          autoComplete="off"
          maxLength={MAX_VAULT_NAME_CHARS}
          required
          autoFocus
          value={name}
          onChange={(e) => setName(e.currentTarget.value)}
        />
        <ErrorText code={error} />
        <div className="actions">
          <button type="submit" disabled={busy || name.trim() === ""}>
            {busy ? t("vaults.working") : t("vaults.renameSubmit")}
          </button>
          <button type="button" className="secondary" disabled={busy} onClick={props.onCancel}>
            {t("vaults.cancel")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Deletes an owned vault (§A5; module docs). */
export function DeleteVaultDialog(props: {
  readonly ctx: VaultContext;
  readonly vault: VaultInfo;
  readonly onDone: () => void;
  readonly onCancel: () => void;
}) {
  const { ctx, vault } = props;
  const titleId = useId();
  const typedId = useId();
  const label = vaultLabel(vault);
  const count = vault.itemCount;
  const [choice, setChoice] = useState<"move" | "delete">("move");
  const [typed, setTyped] = useState("");
  const [reauth, setReauth] = useState(false);
  const secretKey = useRef<HTMLInputElement>(null);
  const password = useRef<HTMLInputElement>(null);
  const { busy, error, setError, run } = useAction();
  const { notify } = useToast();

  const remove = () =>
    run(async () => {
      try {
        await ctx.client.call("deleteVault", vault.id, count > 0 && choice === "move");
      } catch (e) {
        if (codeOf(e) === "server_fresh_session_required") {
          setReauth(true);
          return;
        }
        throw e;
      }
      await ctx.afterWrite();
      notify("success", t("vaults.deleted"));
      props.onDone();
    });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (typed !== label) {
      return;
    }
    void remove();
  };

  const submitReauth = (e: FormEvent) => {
    e.preventDefault();
    const sk = secretBytes(takeSecret(secretKey.current));
    const pw = secretBytes(takeSecret(password.current));
    void run(async () => {
      await ctx.client.call("refreshSession", sk, pw);
      setReauth(false);
    }).then((ok) => {
      if (ok) {
        setError(undefined);
        void remove();
      }
    });
  };

  return (
    <Modal titleId={titleId} onCancel={props.onCancel}>
      {reauth ? (
        <form onSubmit={submitReauth}>
          <h2 id={titleId}>{t("vaults.reauthTitle")}</h2>
          <p>{t("vaults.reauthText")}</p>
          <SecretField label="Secret Key" name="vault-delete-secret-key" inputRef={secretKey} required />
          <SecretField label="Master password" name="vault-delete-master-password" inputRef={password} required />
          <ErrorText code={error} />
          <div className="actions">
            <button type="submit" disabled={busy}>
              {busy ? t("vaults.working") : t("vaults.reauthSubmit")}
            </button>
            <button type="button" className="secondary" disabled={busy} onClick={props.onCancel}>
              {t("vaults.cancel")}
            </button>
          </div>
        </form>
      ) : (
        <form onSubmit={submit}>
          <h2 id={titleId}>{t("vaults.deleteTitle", { name: label })}</h2>
          {count > 0 && (
            <fieldset>
              <legend>{t("vaults.deleteChoice")}</legend>
              <label className="check">
                <input
                  type="radio"
                  name="vault-delete-choice"
                  value="move"
                  checked={choice === "move"}
                  onChange={() => setChoice("move")}
                />
                {t("vaults.deleteMove", { count: String(count) })}
              </label>
              <label className="check">
                <input
                  type="radio"
                  name="vault-delete-choice"
                  value="delete"
                  checked={choice === "delete"}
                  onChange={() => setChoice("delete")}
                />
                {t("vaults.deleteWithItems", { count: String(count) })}
              </label>
            </fieldset>
          )}
          <label htmlFor={typedId}>{t("vaults.deleteConfirm")}</label>
          <input
            id={typedId}
            name="vault-delete-confirm"
            autoComplete="off"
            spellCheck={false}
            required
            value={typed}
            onChange={(e) => setTyped(e.currentTarget.value)}
          />
          <ErrorText code={error} />
          <div className="actions">
            <button type="submit" className="danger" disabled={busy || typed !== label}>
              {busy ? t("vaults.working") : t("vaults.deleteSubmit")}
            </button>
            <button type="button" className="secondary" disabled={busy} onClick={props.onCancel}>
              {t("vaults.cancel")}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
