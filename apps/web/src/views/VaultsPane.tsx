// SPDX-License-Identifier: AGPL-3.0-only

// The vault management screen (ADR 0081 §A3–§A5, §A8): every vault of the account, a form to
// create one, and Rename / Delete on each owned vault. The Personal vault is listed first, as
// "Personal", with no action: it cannot be renamed or deleted (§A1, owner answer 3). A vault
// this build cannot open says so ("This vault needs a newer rizzy-vault", §A12; a withheld
// vault stays read-only, §A2), and the completeness check's alarms are shown on top (INV-102).
import type { VaultAlarm, VaultInfo } from "@rizzy-vault/core";
import { t } from "@rizzy-vault/i18n";
import { useToast } from "@rizzy-vault/ui";
import { type FormEvent, useId, useState } from "react";

import { MAX_VAULT_NAME_CHARS } from "../vault-limits.ts";
import { vaultLabel, vaultStatusText } from "../vaults.ts";
import type { VaultContext } from "./VaultView.tsx";
import { DeleteVaultDialog, RenameVaultDialog } from "./VaultDialogs.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** The text of an alarm. */
export function alarmText(alarm: VaultAlarm): string {
  switch (alarm.kind) {
    case "withheld":
      return t("vaults.alarmWithheld");
    case "unlisted":
      return t("vaults.alarmUnlisted");
    case "no_directory":
      return t("vaults.alarmNoDirectory");
  }
}

/** The vault alarms, as one alert (nothing when there is none). */
export function VaultAlarms(props: { readonly alarms: readonly VaultAlarm[] }) {
  if (props.alarms.length === 0) {
    return null;
  }
  return (
    <div className="error" role="alert">
      {props.alarms.map((a, i) => (
        <p key={`${a.kind}-${a.vaultId ?? i}`}>{alarmText(a)}</p>
      ))}
    </div>
  );
}

/** Whether a vault offers Rename and Delete here. */
function manageable(vault: VaultInfo): boolean {
  return vault.kind === "owned" && vault.status === "open" && !vault.readOnly;
}

/** The vault management screen (module docs). */
export function VaultsPane(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const nameId = useId();
  const [name, setName] = useState("");
  const [dialog, setDialog] = useState<{ readonly kind: "rename" | "delete"; readonly vault: VaultInfo } | undefined>();
  const { busy, error, run } = useAction();
  const { notify } = useToast();

  const create = (e: FormEvent) => {
    e.preventDefault();
    const chosen = name;
    void run(async () => {
      await ctx.client.call("createVault", chosen);
      setName("");
      await ctx.afterWrite();
      notify("success", t("vaults.created", { name: chosen.trim() }));
    });
  };

  return (
    <section className="panel vaults-pane" aria-labelledby="vaults-title">
      <h1 id="vaults-title">{t("vaults.title")}</h1>
      <p className="muted">{t("vaults.intro")}</p>
      <VaultAlarms alarms={ctx.vaultAlarms} />
      <table aria-labelledby="vaults-title">
        <thead>
          <tr>
            <th scope="col">{t("vaults.name")}</th>
            <th scope="col">{t("vaults.itemsColumn")}</th>
            <th scope="col">{t("vaults.actions")}</th>
          </tr>
        </thead>
        <tbody>
          {ctx.vaults.map((v) => {
            const status = vaultStatusText(v);
            return (
              <tr key={v.id} data-vault-kind={v.kind}>
                <td>
                  <span className="vault-name">{vaultLabel(v)}</span>
                  {status !== undefined && <span className="muted vault-status"> — {status}</span>}
                </td>
                <td>{v.itemCount}</td>
                <td>
                  {manageable(v) && (
                    <div className="actions">
                      <button
                        type="button"
                        className="secondary small"
                        aria-label={`${t("vaults.rename")} ${vaultLabel(v)}`}
                        onClick={() => setDialog({ kind: "rename", vault: v })}
                      >
                        {t("vaults.rename")}
                      </button>
                      <button
                        type="button"
                        className="danger small"
                        aria-label={`${t("vaults.delete")} ${vaultLabel(v)}`}
                        onClick={() => setDialog({ kind: "delete", vault: v })}
                      >
                        {t("vaults.delete")}
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <form onSubmit={create} aria-labelledby="vaults-create-title">
        <h2 id="vaults-create-title">{t("vaults.create")}</h2>
        <label htmlFor={nameId}>{t("vaults.name")}</label>
        <input
          id={nameId}
          name="new-vault-name"
          autoComplete="off"
          maxLength={MAX_VAULT_NAME_CHARS}
          required
          value={name}
          onChange={(e) => setName(e.currentTarget.value)}
        />
        <ErrorText code={error} />
        <div className="actions">
          <button type="submit" disabled={busy || name.trim() === ""}>
            {busy ? t("vaults.working") : t("vaults.createSubmit")}
          </button>
        </div>
      </form>
      {dialog?.kind === "rename" && (
        <RenameVaultDialog
          ctx={ctx}
          vault={dialog.vault}
          onDone={() => setDialog(undefined)}
          onCancel={() => setDialog(undefined)}
        />
      )}
      {dialog?.kind === "delete" && (
        <DeleteVaultDialog
          ctx={ctx}
          vault={dialog.vault}
          onDone={() => setDialog(undefined)}
          onCancel={() => setDialog(undefined)}
        />
      )}
    </section>
  );
}
