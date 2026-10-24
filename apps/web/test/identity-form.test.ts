// SPDX-License-Identifier: AGPL-3.0-only

// The "New identity" form's pure logic (`identity-form.ts`, ADR 0079 §10): who owns a field
// (a typed value survives picker changes and Regenerate all, only its own Regenerate replaces
// it), Start blank, the announcements, the age picker's modes and checks, and the starting
// country and defaults.
import { describe, expect, it } from "vitest";

import { AGE_PRESETS, DEFAULT_IDENTITY_DEFAULTS, GENERATED_KEYS } from "../src/identity-constants.ts";
import {
  AGE_BOUNDS_ERROR,
  AGE_CUSTOM,
  AGE_EXACT,
  AGE_ORDER_ERROR,
  ITEM_NAME,
  ageChoiceFor,
  ageRangeOf,
  announcement,
  defaultCountry,
  drawnSex,
  formFromDraft,
  isEdited,
  mergeDraft,
  optionsOf,
  parseAge,
  selectAge,
  startBlank,
  startingDefaults,
  typed,
} from "../src/identity-form.ts";

/** A draw whose every value carries `tag`, so the test sees which draw a value came from. */
function draw(tag: string, over: Record<string, string> = {}): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const key of GENERATED_KEYS) {
    fields[key] = `${key}:${tag}`;
  }
  fields["identity.first_name"] = `Ann${tag}`;
  fields["identity.last_name"] = `Lee${tag}`;
  return { ...fields, ...over };
}

describe("formFromDraft", () => {
  it("fills every generated key and the item name, all generated", () => {
    const form = formFromDraft(draw("1"), "Ann1 Lee1");
    expect(form.values[ITEM_NAME]).toBe("Ann1 Lee1");
    for (const key of GENERATED_KEYS) {
      expect(form.origin[key]).toBe("generated");
    }
  });

  it("keeps a key the draw left out empty (no domain: no email; no phone range)", () => {
    const fields = draw("1");
    delete fields["identity.email"];
    delete fields["identity.phone"];
    const form = formFromDraft(fields, "x");
    expect(form.values["identity.email"]).toBe("");
    expect(form.values["identity.phone"]).toBe("");
  });
});

describe("mergeDraft", () => {
  const start = formFromDraft(draw("1"), "Ann1 Lee1");

  it("a picker change writes the untouched fields only", () => {
    const edited = typed(start, "identity.city", "My town");
    const { form, written } = mergeDraft(edited, draw("2"), { kind: "picker" });
    expect(form.values["identity.city"]).toBe("My town");
    expect(isEdited(form, "identity.city")).toBe(true);
    expect(form.values["identity.postal_code"]).toBe("identity.postal_code:2");
    expect(written).not.toContain("identity.city");
    expect(written).toContain("identity.postal_code");
  });

  it("lists only the keys whose value changed", () => {
    const { written } = mergeDraft(start, draw("1", { "identity.birthday": "2000-01-01" }), { kind: "picker" });
    expect(written).toEqual(["identity.birthday"]);
  });

  it("Regenerate all keeps every edited field and refills blank ones", () => {
    let form = typed(start, "identity.first_name", "Bob");
    form = startBlank(form);
    expect(form.values["identity.first_name"]).toBe("Bob");
    expect(form.values["identity.city"]).toBe("");
    const merged = mergeDraft(form, draw("3"), { kind: "all" });
    expect(merged.form.values["identity.first_name"]).toBe("Bob");
    expect(merged.form.values["identity.city"]).toBe("identity.city:3");
    expect(merged.form.origin["identity.city"]).toBe("generated");
  });

  it("a picker change leaves Start blank's fields empty", () => {
    const blank = startBlank(start);
    const { form, written } = mergeDraft(blank, draw("2"), { kind: "picker" });
    for (const key of GENERATED_KEYS) {
      expect(form.values[key]).toBe("");
    }
    expect(written).toEqual([]);
  });

  it("a field's own Regenerate overwrites it even when edited, and it counts as generated again", () => {
    const edited = typed(start, "identity.first_name", "Bob");
    const { form, written } = mergeDraft(edited, draw("2"), { kind: "field", key: "identity.first_name" });
    expect(form.values["identity.first_name"]).toBe("Ann2");
    expect(isEdited(form, "identity.first_name")).toBe(false);
    expect(written).toContain("identity.first_name");
    // Its own Regenerate is announced even if the draw repeated the value.
    const same = mergeDraft(form, draw("2"), { kind: "field", key: "identity.first_name" });
    expect(same.written).toEqual(["identity.first_name"]);
  });

  it("a field's own Regenerate leaves other edited fields alone", () => {
    const edited = typed(start, "identity.email", "me@example.org");
    const { form } = mergeDraft(edited, draw("2"), { kind: "field", key: "identity.first_name" });
    expect(form.values["identity.email"]).toBe("me@example.org");
  });

  it("the item name follows the names until the user types one", () => {
    const { form } = mergeDraft(start, draw("2"), { kind: "field", key: "identity.last_name" });
    expect(form.values[ITEM_NAME]).toBe("Ann2 Lee2");
    const named = typed(form, ITEM_NAME, "Shopping persona");
    const after = mergeDraft(named, draw("3"), { kind: "all" });
    expect(after.form.values[ITEM_NAME]).toBe("Shopping persona");
    // Typing a name updates an untouched item name.
    expect(typed(start, "identity.first_name", "Bob").values[ITEM_NAME]).toBe("Bob Lee1");
  });
});

describe("startBlank", () => {
  it("clears every generated value and the item name, keeping typed values", () => {
    const form = startBlank(typed(formFromDraft(draw("1"), "Ann1 Lee1"), "identity.phone", "555"));
    expect(form.values[ITEM_NAME]).toBe("");
    expect(form.values["identity.phone"]).toBe("555");
    for (const key of GENERATED_KEYS.filter((k) => k !== "identity.phone")) {
      expect(form.values[key]).toBe("");
      expect(form.origin[key]).toBe("blank");
    }
  });
});

describe("announcement", () => {
  it("names the field, the redrawn fields, or Regenerate all", () => {
    expect(announcement({ kind: "field", key: "identity.first_name" }, ["identity.first_name"])).toBe(
      "First name regenerated",
    );
    expect(announcement({ kind: "picker" }, ["identity.birthday", "identity.email"])).toBe(
      "Birthday and email regenerated",
    );
    expect(announcement({ kind: "picker" }, ["identity.first_name", "identity.title", "identity.email"])).toBe(
      "First name, title and email regenerated",
    );
    expect(announcement({ kind: "picker" }, [])).toMatch(/^No field regenerated/u);
    expect(announcement({ kind: "all" }, [])).toMatch(/^All generated fields regenerated/u);
  });
});

describe("the age picker", () => {
  it("opens on the first preset with the bounds, else Exact age, else Custom range", () => {
    expect(ageChoiceFor({ min: 18, max: 27 }).select).toBe("18-27");
    expect(ageChoiceFor({ min: 21, max: 65 }).select).toBe("any");
    expect(ageChoiceFor({ min: 28, max: 65 }).select).toBe("28-65");
    expect(ageChoiceFor({ min: 30, max: 30 })).toMatchObject({ select: AGE_EXACT, exact: "30" });
    expect(ageChoiceFor({ min: 30, max: 44 })).toMatchObject({ select: AGE_CUSTOM, min: "30", max: "44" });
    for (const p of AGE_PRESETS) {
      expect(ageChoiceFor(p).select).toBe(p.id);
    }
  });

  it("reads whole ages from 18 to 99 only", () => {
    expect(parseAge("18")).toBe(18);
    expect(parseAge(" 99 ")).toBe(99);
    for (const bad of ["17", "100", "", "2.5", "-20", "1e1", "abc", "020"]) {
      expect(parseAge(bad)).toBeUndefined();
    }
  });

  it("gives each mode its range, or each invalid input its error", () => {
    expect(ageRangeOf({ select: "31-35", min: "", max: "", exact: "" })).toEqual({ ok: true, range: { min: 31, max: 35 } });
    expect(ageRangeOf({ select: AGE_EXACT, min: "", max: "", exact: "40" })).toEqual({
      ok: true,
      range: { min: 40, max: 40 },
    });
    expect(ageRangeOf({ select: AGE_EXACT, min: "", max: "", exact: "12" })).toEqual({
      ok: false,
      problems: { exact: AGE_BOUNDS_ERROR },
    });
    expect(ageRangeOf({ select: AGE_CUSTOM, min: "30", max: "40", exact: "" })).toEqual({
      ok: true,
      range: { min: 30, max: 40 },
    });
    expect(ageRangeOf({ select: AGE_CUSTOM, min: "50", max: "40", exact: "" })).toEqual({
      ok: false,
      problems: { max: AGE_ORDER_ERROR },
    });
    expect(ageRangeOf({ select: AGE_CUSTOM, min: "10", max: "120", exact: "" })).toEqual({
      ok: false,
      problems: { min: AGE_BOUNDS_ERROR, max: AGE_BOUNDS_ERROR },
    });
  });

  it("starts a custom mode from the last valid range", () => {
    const choice = ageChoiceFor({ min: 18, max: 27 });
    expect(selectAge(choice, AGE_CUSTOM, { min: 18, max: 27 })).toMatchObject({ select: AGE_CUSTOM, min: "18", max: "27" });
    expect(selectAge(choice, AGE_EXACT, { min: 18, max: 27 })).toMatchObject({ select: AGE_EXACT, exact: "18" });
    expect(selectAge(choice, "41-45", { min: 18, max: 27 }).select).toBe("41-45");
  });
});

describe("starting options", () => {
  const codes = ["AT", "AU", "CA", "CH", "DE", "ES", "FR", "GB", "IE", "IT", "NL", "SE", "US"];

  it("takes the synced country, else the browser language's region, else US", () => {
    expect(defaultCountry("FR", ["en-GB"], codes)).toBe("FR");
    expect(defaultCountry(null, ["en-GB"], codes)).toBe("GB");
    expect(defaultCountry(null, ["pt-BR", "de-AT"], codes)).toBe("AT");
    expect(defaultCountry(null, ["de"], codes)).toBe("DE");
    expect(defaultCountry(null, ["ja-JP"], codes)).toBe("US");
    expect(defaultCountry("ZZ", ["not a tag!"], codes)).toBe("US");
    expect(defaultCountry(null, [], ["SE"])).toBe("SE");
  });

  it("lays this session's last-used range over the synced or first-time defaults", () => {
    expect(startingDefaults(null, undefined)).toEqual(DEFAULT_IDENTITY_DEFAULTS);
    const synced = { ...DEFAULT_IDENTITY_DEFAULTS, ageMin: 30, ageMax: 30, emailDomain: "example.com" };
    expect(startingDefaults(synced, undefined)).toEqual(synced);
    expect(startingDefaults(synced, { min: 40, max: 50 })).toEqual({ ...synced, ageMin: 40, ageMax: 50 });
  });

  it("builds the core's options and reads a drawn sex", () => {
    expect(
      optionsOf({ sex: "male", country: "DE", age: { min: 21, max: 25 }, emailStyle: "nickname", emailDomain: null }),
    ).toEqual({ sex: "male", country: "DE", ageMin: 21, ageMax: 25, emailStyle: "nickname", emailDomain: null });
    expect(drawnSex("female")).toBe("female");
    expect(drawnSex("Female")).toBeUndefined();
  });
});
