// SPDX-License-Identifier: AGPL-3.0-only

// `identity-constants.ts` copies values out of `@rizzy-vault/core` (its module docs say why).
// This checks the copy against the real core and Rust's own answers (ADR 0079 §3, §12 "Preset
// list test"), like `generator-constants.test.ts`.
import {
  DEFAULT_IDENTITY_DEFAULTS as CORE_DEFAULTS,
  IDENTITY_ERROR_MESSAGES as CORE_MESSAGES,
  IDENTITY_MAX_AGE as CORE_MAX,
  IDENTITY_MIN_AGE as CORE_MIN,
  agePresets,
  checkAgeRange,
  generateIdentity,
  identityCountries,
} from "@rizzy-vault/core";
import { beforeAll, describe, expect, it } from "vitest";

import {
  AGE_PRESETS,
  DEFAULT_IDENTITY_DEFAULTS,
  GENERATED_KEYS,
  IDENTITY_ERROR_MESSAGES,
  IDENTITY_MAX_AGE,
  IDENTITY_MIN_AGE,
  identityErrorMessage,
} from "../src/identity-constants.ts";
import { FIXED_FIELDS } from "../src/fields.ts";
import { messageFor } from "../src/messages.ts";
import { loadCore } from "./load-core.ts";

beforeAll(() => {
  loadCore();
});

describe("identity-constants", () => {
  it("lists Rust's twelve presets in its order, with the client's labels", () => {
    expect(AGE_PRESETS.map((p) => ({ id: p.id, min: p.min, max: p.max }))).toEqual(agePresets());
    expect(AGE_PRESETS.map((p) => p.label)).toEqual([
      "18–27",
      "28+",
      "21–25",
      "26–30",
      "31–35",
      "36–40",
      "41–45",
      "46–50",
      "51–55",
      "56–60",
      "61–65",
      "Any (21–65)",
    ]);
    for (const p of AGE_PRESETS) {
      expect(() => checkAgeRange(p.min, p.max)).not.toThrow();
    }
  });

  it("matches the core's bounds, defaults and messages", () => {
    expect(IDENTITY_MIN_AGE).toBe(CORE_MIN);
    expect(IDENTITY_MAX_AGE).toBe(CORE_MAX);
    expect(DEFAULT_IDENTITY_DEFAULTS).toEqual(CORE_DEFAULTS);
    expect(IDENTITY_ERROR_MESSAGES).toEqual(CORE_MESSAGES);
    expect(identityErrorMessage("identity_data")).toBe("The identity could not be generated.");
    // Every `ErrorText` shows the core's sentence for an `identity_*` code.
    expect(messageFor("identity_age_range")).toBe(CORE_MESSAGES["identity_age_range"]);
    expect(messageFor("identity_rng_failure")).toBe("The identity could not be generated.");
  });

  it("names every key the core fills, and each is a field of the identity form", () => {
    const keys = new Set<string>();
    for (const c of identityCountries()) {
      for (const sex of ["male", "female"] as const) {
        const draft = generateIdentity({
          sex,
          country: c.code,
          ageMin: 18,
          ageMax: 27,
          emailStyle: "name",
          emailDomain: "example.com",
        });
        for (const k of Object.keys(draft.fields)) {
          keys.add(k);
        }
        draft.free();
      }
    }
    expect([...keys].sort()).toEqual([...GENERATED_KEYS].sort());
    const form = new Set((FIXED_FIELDS.identity ?? []).map((f) => f.key));
    for (const k of GENERATED_KEYS) {
      expect(form.has(k)).toBe(true);
    }
  });
});
