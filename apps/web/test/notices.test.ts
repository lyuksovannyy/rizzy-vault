// The late-edit and trash notices' wording (gap 02; ADR 0018 §3, ADR 0012 §5) and the
// password-history row labels (gap 01).
import type { DeviceView, Notice } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import { DEVICE_KINDS, deviceLabel, joinNames, mergeNotices, noticeKey, noticeText } from "../src/notices.ts";
import { historyLabel } from "../src/views/PasswordHistory.tsx";

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
    expect(label(LAPTOP)).toBe(`${DEVICE_KINDS["desktop-cli"]} abababab`);
    expect(label(PHONE)).toBe("Mobile cdcdcdcd");
    expect(label(UNLISTED)).toBe("device efefefef");
    expect(deviceLabel(LAPTOP, [], OWN)).toBe("device abababab");
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
    const late: Notice = { kind: "late-edit", item: "11".repeat(16), devices: [LAPTOP, PHONE] };
    expect(noticeText(late, label, "")).toBe(
      `An edit from ${DEVICE_KINDS["desktop-cli"]} abababab and Mobile cdcdcdcd arrived for an item you deleted permanently. Restore it as a new item?`,
    );
  });

  it("words a concurrent trash as deleted on X while edited on Y", () => {
    const trash: Notice = { kind: "concurrent-trash", item: "22".repeat(16), devices: [OWN, LAPTOP] };
    expect(noticeText(trash, label, "Mail")).toBe(
      `“Mail” was deleted on this browser while it was being edited on ${DEVICE_KINDS["desktop-cli"]} abababab. The edit kept it.`,
    );
    expect(noticeText(trash, label, "")).toMatch(/^An item was deleted on this browser/);
  });
});

describe("held notices", () => {
  const a: Notice = { kind: "late-edit", item: "11".repeat(16), devices: [LAPTOP] };
  const b: Notice = { kind: "concurrent-trash", item: "11".repeat(16), devices: [OWN, LAPTOP] };

  it("appends fresh notices once, keyed by kind, item and devices", () => {
    expect(mergeNotices([], [])).toEqual([]);
    expect(mergeNotices([a], [a, b])).toEqual([a, b]);
    expect(noticeKey(a)).not.toBe(noticeKey(b));
    const laterEdit: Notice = { ...a, devices: [LAPTOP, PHONE] };
    expect(mergeNotices([a], [laterEdit])).toEqual([a, laterEdit]);
  });
});

describe("password-history labels", () => {
  it("dates merge entries and marks imported ones", () => {
    const at = Date.UTC(2026, 0, 2, 3, 4, 5);
    const when = new Date(at).toLocaleString();
    expect(historyLabel({ source: "merge", index: 0, changedMs: at })).toBe(`Replaced ${when}`);
    expect(historyLabel({ source: "imported", index: 3, changedMs: at })).toBe(`Imported, ${when}`);
    expect(historyLabel({ source: "imported", index: 0, changedMs: undefined })).toBe("Imported");
    expect(historyLabel({ source: "merge", index: 0, changedMs: undefined })).toBe("Replaced");
  });
});
