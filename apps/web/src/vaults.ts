// SPDX-License-Identifier: AGPL-3.0-only

// Vault labels and filters of the web vault (ADR 0081 Part A, §A1, §A8).
//
// - The Personal vault is always labelled "Personal" (localised); it has no name of its own and
//   any `vault.name` in it is ignored (the core already leaves it out, §A1).
// - An owned vault without a name yet is "Untitled vault" (§A3 step 3).
// - Every picker (new item, import, export, save prompts) preselects the Personal vault every
//   time: there is no "last used" memory (owner answer 4).
// - Items are named by their reference, `<vault hex>:<item hex>` (INV-103); `vaultOf` reads the
//   vault part only for display and filtering, never to look an item up.
import type { ItemSummary, VaultInfo } from "@rizzy-vault/core";
import { t } from "@rizzy-vault/i18n";

/** The label of a vault. */
export function vaultLabel(vault: VaultInfo): string {
  if (vault.kind === "personal") {
    return t("vaults.personal");
  }
  return vault.name ?? t("vaults.untitled");
}

/** The label of the vault `vaultId` among `vaults` ("Untitled vault" for one not listed). */
export function vaultLabelOf(vaults: readonly VaultInfo[], vaultId: string): string {
  const vault = vaults.find((v) => v.id === vaultId);
  return vault === undefined ? t("vaults.untitled") : vaultLabel(vault);
}

/** The vaults a new item, an import, a copy or a move may go to: open and writable. */
export function writableVaults(vaults: readonly VaultInfo[]): VaultInfo[] {
  return vaults.filter((v) => v.status === "open" && !v.readOnly);
}

/** The vault every picker starts on: the Personal vault, else the first writable one. */
export function defaultVault(vaults: readonly VaultInfo[], personalVaultId: string | undefined): string | undefined {
  const writable = writableVaults(vaults);
  return writable.find((v) => v.id === personalVaultId)?.id ?? writable[0]?.id;
}

/** Whether `item` passes the vault filter (`undefined`: "All vaults"). */
export function inVault(item: ItemSummary, vaultFilter: string | undefined): boolean {
  return vaultFilter === undefined || item.vaultId === vaultFilter;
}

/** The text of a vault's status, or `undefined` for an open vault. */
export function vaultStatusText(vault: VaultInfo): string | undefined {
  switch (vault.status) {
    case "needs_update":
      return t("vaults.needsUpdate");
    case "withheld":
      return t("vaults.withheld");
    default:
      return undefined;
  }
}
