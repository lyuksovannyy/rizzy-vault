// SPDX-License-Identifier: AGPL-3.0-only

// The late-edit and trash notices' wording (gap 02; ADR 0018 §3, ADR 0012 §5) and the
// password-history row labels (gap 01).
import type { DeviceView, Notice } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import { DEVICE_KINDS, deviceLabel, joinNames, mergeNotices, noticeKey, noticeText } from "../src/notices.ts";
import { canReveal, historyLabel } from "../src/views/PasswordHistory.tsx";

const OWN = "00".repeat(16);
const LAPTOP = "ab".repeat(16);
const PHONE = "cd".repeat(16);
const UNLISTED = "ef".repeat(16);

const DEVICES: readonly DeviceView[] = [
  { id: LAPTOP, kind: "desktop-cli", createdAtMs: 0, revoked: false },
  { id: PHONE, kind: "mobile", createdAtMs: 0, revoked: false },
];

const label = (id: string) => deviceLabel(id, DEVICES, OWN);

describe("device labels", () => {
  it("names this browser, a listed device by kind and id, and any other by id", () => {
    expect(label(OWN)).toBe("this browser");
    expect(label(LAPTOP)).toBe(`${DEVICE_KINDS["desktop-cli"]} abababababababab`);
    expect(label(PHONE)).toBe("Mobile cdcdcdcdcdcdcdcd");
    expect(label(UNLISTED)).toBe("device efefefefefefefef");
    expect(deviceLabel(LAPTOP, [], OWN)).toBe("device abababababababab");
  });

  it("joins names in prose", () => {
    expect(joinNames([])).toBe("");
    expect(joinNames(["a"])).toBe("a");
    expect(joinNames(["a", "b"])).toBe("a and b");
    expect(joinNames(["a", "b", "c"])).toBe("a, b and c");
  });
});

describe("notice text", () => {
  it("words a late edit with the ADR's question", () => {
    const late: Notice = {
      kind: "late-edit",
      item: "11".repeat(16),
      devices: [LAPTOP, PHONE],
      conflictId: undefined,
      movedTo: undefined,
    };
    expect(noticeText(late, label, "")).toBe(
      `An edit from ${DEVICE_KINDS["desktop-cli"]} abababababababab and Mobile cdcdcdcdcdcdcdcd arrived for an item you deleted permanently. Restore it as a new item?`,
    );
  });

  // ADR 0081 §A6 step 2: the prompt names the target vault when this device recorded the move.
  it("names the vault a moved item went to", () => {
    const work = "77".repeat(16);
    const late: Notice = {
      kind: "late-edit",
      item: "11".repeat(16),
      devices: [LAPTOP],
      conflictId: undefined,
      movedTo: work,
    };
    const vault = (id: string) => (id === work ? "Work" : "?");
    expect(noticeText(late, label, "", vault)).toBe(
      `An edit from ${DEVICE_KINDS["desktop-cli"]} abababababababab arrived for an item you moved to the vault “Work”. Restore it as a new item?`,
    );
    // Without a way to name vaults, the plain question still reads.
    expect(noticeText(late, label, "")).toMatch(/an item you deleted permanently/);
  });

  it("words a concurrent trash as deleted on X while edited on Y", () => {
    const trash: Notice = {
      kind: "concurrent-trash",
      item: "22".repeat(16),
      devices: [OWN, LAPTOP],
      conflictId: "dot-a:dot-b",
      movedTo: undefined,
    };
    expect(noticeText(trash, label, "Mail")).toBe(
      `“Mail” was deleted on this browser while it was being edited on ${DEVICE_KINDS["desktop-cli"]} abababababababab. The edit kept it.`,
    );
    expect(noticeText(trash, label, "")).toMatch(/^An item was deleted on this browser/);
  });
});

describe("held notices", () => {
  const a: Notice = {
    kind: "late-edit",
    item: "11".repeat(16),
    devices: [LAPTOP],
    conflictId: undefined,
    movedTo: undefined,
  };
  const b: Notice = {
    kind: "concurrent-trash",
    item: "11".repeat(16),
    devices: [OWN, LAPTOP],
    conflictId: "dot-a:dot-b",
    movedTo: undefined,
  };

  it("appends fresh notices once, keyed by kind, item and devices", () => {
    expect(mergeNotices([], [])).toEqual([]);
    expect(mergeNotices([a], [a, b])).toEqual([a, b]);
    expect(noticeKey(a)).not.toBe(noticeKey(b));
    const laterEdit: Notice = { ...a, devices: [LAPTOP, PHONE] };
    expect(mergeNotices([a], [laterEdit])).toEqual([a, laterEdit]);
  });

  // Finding 3b (re-review of finding 3): the Rust layer now re-emits a second, genuinely
  // distinct concurrent-trash conflict between the same device pair on the same item (its own
  // dots differ), but the old key -- kind, item and devices only -- made it collide with a
  // conflict already held, so the web vault silently dropped it. `conflictId` fixes that.
  it("keeps a second, genuinely distinct conflict between the same device pair (finding 3b)", () => {
    const raceOne: Notice = { ...b, conflictId: "dot-a1:dot-b1" };
    const raceTwo: Notice = { ...b, conflictId: "dot-a2:dot-b2" };
    expect(noticeKey(raceOne)).not.toBe(noticeKey(raceTwo));
    // Both held: the second race is not mistaken for a repeat of the first.
    expect(mergeNotices([raceOne], [raceTwo])).toEqual([raceOne, raceTwo]);
    // The exact same conflict, synced again, is still a duplicate.
    expect(mergeNotices([raceOne], [{ ...raceOne }])).toEqual([raceOne]);
    // late-edit has no conflictId: two late-edit notices for the same devices are still one.
    expect(mergeNotices([a], [{ ...a }])).toEqual([a]);
  });
});

describe("password-history labels", () => {
  it("dates merge entries and marks imported ones", () => {
    const at = Date.UTC(2026, 0, 2, 3, 4, 5);
    const when = new Date(at).toLocaleString();
    expect(historyLabel({ source: "merge", index: 0, changedMs: at, id: "a" })).toBe(`Replaced ${when}`);
    expect(historyLabel({ source: "imported", index: 3, changedMs: at, id: "b" })).toBe(
      `Imported, ${when}`,
    );
    expect(historyLabel({ source: "imported", index: 0, changedMs: undefined, id: "c" })).toBe(
      "Imported",
    );
    expect(historyLabel({ source: "merge", index: 0, changedMs: undefined, id: "d" })).toBe("Replaced");
  });
});

describe("password-history reveal gate", () => {
  const entries = [{ source: "merge" as const, index: 0, changedMs: 1, id: "a" }];

  it("allows reveal only for a list read at the latest sync", () => {
    // Not loaded yet: nothing to reveal.
    expect(canReveal(undefined, 0)).toBe(false);
    // Read at the current revision: positions match the Worker's.
    expect(canReveal({ revision: 3, entries }, 3)).toBe(true);
    // A sync happened since (revision 4): the old positions may name other entries.
    expect(canReveal({ revision: 3, entries }, 4)).toBe(false);
    // An empty fresh list is still fresh.
    expect(canReveal({ revision: 4, entries: [] }, 4)).toBe(true);
  });
});
