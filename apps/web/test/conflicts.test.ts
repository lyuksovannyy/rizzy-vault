// SPDX-License-Identifier: AGPL-3.0-only

// The conflict chooser's pure rules (`conflicts.ts`): its wording, when it offers "keep both",
// which value "keep both" keeps, and the label of the copies.
import type { ConflictValue, DeviceView, FieldView } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import {
  canKeepBoth,
  conflictHeadline,
  conflictValueCaption,
  deviceNamer,
  keepBothLabel,
  keptValue,
} from "../src/conflicts.ts";

const OWN = "a".repeat(32);
const OTHER = "b".repeat(32);
const DEVICES: DeviceView[] = [{ id: OTHER, kind: "desktop-cli", createdAtMs: 0, revoked: false }];
const name = deviceNamer(DEVICES, OWN);

function value(over: Partial<ConflictValue>): ConflictValue {
  return {
    index: 0,
    id: "00",
    device: OWN,
    writtenMs: 0,
    displayed: false,
    cleared: false,
    kind: "text",
    concealed: true,
    value: undefined,
    ...over,
  };
}

function field(over: Partial<FieldView>): FieldView {
  return {
    key: "login.password",
    list: undefined,
    element: undefined,
    attribute: undefined,
    tag: undefined,
    kind: "text",
    concealed: true,
    value: undefined,
    conflict: true,
    ...over,
  };
}

const shown = value({ index: 0, id: "01", device: OWN, displayed: true });
const other = value({ index: 1, id: "02", device: OTHER });

describe("conflictHeadline", () => {
  it("names each device once, this session as this browser", () => {
    expect(conflictHeadline([shown, other], name)).toBe(
      `Edited on this browser and Desktop or command line ${OTHER.slice(0, 16)} at the same time.`,
    );
  });
  it("falls back when one device wrote both values", () => {
    expect(conflictHeadline([shown, value({ device: OWN })], name)).toBe("Edited in two places at the same time.");
  });
});

describe("conflictValueCaption", () => {
  it("says edited or cleared, where, and which value shows now", () => {
    expect(conflictValueCaption(shown, name)).toMatch(/^Edited on this browser, .+ \(shown now\)$/);
    expect(conflictValueCaption(value({ device: OTHER, cleared: true }), name)).toMatch(
      /^Cleared on Desktop or command line b{16}, /,
    );
    // Never the value itself, even when the listing carries it.
    expect(conflictValueCaption(value({ concealed: false, value: "secret" }), name)).not.toContain("secret");
  });
});

describe("canKeepBoth", () => {
  it("offers keep both for two text values", () => {
    expect(canKeepBoth(field({}), [shown, other])).toBe(true);
  });
  it("not for a field that is not text, or for one value besides a cleared one", () => {
    expect(canKeepBoth(field({ kind: "bool" }), [shown, other])).toBe(false);
    expect(canKeepBoth(field({}), [shown, value({ cleared: true })])).toBe(false);
    expect(canKeepBoth(field({}), [shown, value({ kind: "unknown" })])).toBe(false);
  });
});

describe("keptValue", () => {
  it("keeps the value shown now", () => {
    expect(keptValue([other, shown])).toBe(shown);
    expect(keptValue([value({ displayed: true, cleared: true })])).toBeUndefined();
  });
});

describe("keepBothLabel", () => {
  it("names the one device the moved value came from", () => {
    expect(keepBothLabel("Password", [shown, other], name)).toBe(
      `Password (from Desktop or command line ${OTHER.slice(0, 16)})`,
    );
  });
  it("is generic when several values move, and ignores cleared ones", () => {
    expect(keepBothLabel("Password", [shown, other, value({ id: "03" })], name)).toBe("Password (other version)");
    expect(keepBothLabel("Notes", [shown, other, value({ cleared: true })], name)).toBe(
      `Notes (from Desktop or command line ${OTHER.slice(0, 16)})`,
    );
  });
});
