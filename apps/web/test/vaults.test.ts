// SPDX-License-Identifier: AGPL-3.0-only

// The web vault's vault labels, pickers and filter (ADR 0081 §A1, §A8).
import type { ItemSummary, VaultInfo } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import { defaultVault, inVault, vaultLabel, vaultLabelOf, vaultStatusText, writableVaults } from "../src/vaults.ts";

const PERSONAL = "1".repeat(32);
const WORK = "2".repeat(32);

function vault(over: Partial<VaultInfo>): VaultInfo {
  return {
    id: WORK,
    kind: "owned",
    name: "Work",
    status: "open",
    readOnly: false,
    itemCount: 0,
    bytesUsed: undefined,
    ...over,
  };
}

const VAULTS: readonly VaultInfo[] = [
  vault({ id: PERSONAL, kind: "personal", name: undefined }),
  vault({}),
  vault({ id: "3".repeat(32), name: undefined }),
  vault({ id: "4".repeat(32), kind: "unknown", name: undefined, status: "needs_update", readOnly: true }),
];

describe("vault labels", () => {
  it("names the Personal vault Personal and an unnamed vault Untitled vault", () => {
    expect(VAULTS.map(vaultLabel)).toEqual(["Personal", "Work", "Untitled vault", "Untitled vault"]);
    // A name inside the Personal vault is never shown (§A1).
    expect(vaultLabel(vault({ kind: "personal", name: "Mine" }))).toBe("Personal");
    expect(vaultLabelOf(VAULTS, WORK)).toBe("Work");
    expect(vaultLabelOf(VAULTS, "f".repeat(32))).toBe("Untitled vault");
  });

  it("says when a vault needs a newer rizzy-vault", () => {
    expect(vaultStatusText(VAULTS[3] as VaultInfo)).toBe("This vault needs a newer rizzy-vault");
    expect(vaultStatusText(VAULTS[0] as VaultInfo)).toBeUndefined();
  });
});

describe("pickers", () => {
  it("preselect the Personal vault every time and offer only writable vaults", () => {
    expect(defaultVault(VAULTS, PERSONAL)).toBe(PERSONAL);
    expect(writableVaults(VAULTS).map((v) => v.id)).toEqual([PERSONAL, WORK, "3".repeat(32)]);
    // Without a Personal vault to name (an alarm), the first writable vault.
    expect(defaultVault(VAULTS.slice(1), undefined)).toBe(WORK);
    expect(defaultVault([], PERSONAL)).toBeUndefined();
  });
});

describe("the vault filter", () => {
  it("keeps every item for All vaults and one vault's items otherwise", () => {
    const item = { id: `${WORK}:${"9".repeat(32)}`, vaultId: WORK } as ItemSummary;
    expect(inVault(item, undefined)).toBe(true);
    expect(inVault(item, WORK)).toBe(true);
    expect(inVault(item, PERSONAL)).toBe(false);
  });
});
