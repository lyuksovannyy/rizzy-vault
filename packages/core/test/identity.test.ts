// SPDX-License-Identifier: AGPL-3.0-only

// The identity generator through packages/core (ADR 0079 §3, §4, §8): the presets and the
// bundled countries, a draw's fields under each option, the email only with a domain, a redraw
// that changes only the field and its dependents, the age bounds and the domain check, each
// refusal's stable code.
import { beforeAll, describe, expect, it } from "vitest";

import {
  CoreError,
  DEFAULT_IDENTITY_DEFAULTS,
  type IdentityGeneratorOptions,
  agePresets,
  checkAgeRange,
  generateIdentity,
  identityCountries,
  identityErrorMessage,
  normalizeEmailDomain,
} from "../src/index.js";
import { loadCore } from "./load.js";

beforeAll(() => {
  loadCore();
});

/** The code a call throws, or `undefined`. */
function codeOf(f: () => unknown): string | undefined {
  try {
    f();
    return undefined;
  } catch (e) {
    return e instanceof CoreError ? e.code : "not a CoreError";
  }
}

const TODAY = new Date(2026, 9, 23);

/** Options with `over` changed, today fixed. */
function options(over: Partial<IdentityGeneratorOptions> = {}): IdentityGeneratorOptions {
  return { sex: "random", country: "US", ageMin: 18, ageMax: 27, emailStyle: "name", today: TODAY, ...over };
}

/** The completed age on 2026-10-23 of a `YYYY-MM-DD` birthday. */
function ageOn2026_10_23(birthday: string): number {
  const [y, m, d] = birthday.split("-").map(Number);
  const before = (m ?? 0) > 10 || ((m ?? 0) === 10 && (d ?? 0) > 23);
  return 2026 - (y ?? 0) - (before ? 1 : 0);
}

describe("identity generator", () => {
  it("lists twelve presets and the bundled countries", () => {
    const presets = agePresets();
    expect(presets).toHaveLength(12);
    expect(presets[0]).toEqual({ id: "18-27", min: 18, max: 27 });
    expect(presets[1]).toEqual({ id: "28-65", min: 28, max: 65 });
    expect(presets[11]).toEqual({ id: "any", min: 21, max: 65 });
    const countries = identityCountries();
    expect(countries.map((c) => c.code)).toContain("US");
    for (const c of countries) {
      expect(c.code).toMatch(/^[A-Z]{2}$/u);
      expect(c.name.length).toBeGreaterThan(0);
    }
    expect(countries.find((c) => c.code === "DE")?.name).toBe("Germany");
  });

  it("draws every field with the chosen sex, country and age, and no email without a domain", () => {
    for (const sex of ["male", "female"] as const) {
      const draft = generateIdentity(options({ sex }));
      try {
        expect(draft.fields["identity.sex"]).toBe(sex);
        expect(draft.fields["identity.country"]).toBe("US");
        const birthday = draft.fields["identity.birthday"] ?? "";
        expect(birthday).toMatch(/^\d{4}-\d{2}-\d{2}$/u);
        expect(ageOn2026_10_23(birthday)).toBeGreaterThanOrEqual(18);
        expect(ageOn2026_10_23(birthday)).toBeLessThanOrEqual(27);
        expect(draft.fields["identity.email"]).toBeUndefined();
        expect(draft.fields["identity.username"]).toMatch(/^[a-z]+\d{2}$/u);
        expect(draft.itemName).toBe(`${draft.fields["identity.first_name"]} ${draft.fields["identity.last_name"]}`);
        for (const never of ["identity.ssn", "identity.passport_number", "identity.drivers_license"]) {
          expect(draft.fields[never]).toBeUndefined();
        }
      } finally {
        draft.free();
      }
    }
  });

  it("builds the email on the user's domain in either style", () => {
    const named = generateIdentity(options({ emailDomain: "Example.COM" }));
    expect(named.fields["identity.email"]).toMatch(/^[a-z0-9._-]+@example\.com$/u);
    named.free();
    const nick = generateIdentity(options({ emailStyle: "nickname", emailDomain: "example.com" }));
    expect(nick.fields["identity.email"]).toBe(`${nick.fields["identity.username"]}@example.com`);
    nick.free();
  });

  it("an exact age is that age; a redraw of the birthday keeps the address and names", () => {
    const draft = generateIdentity(options({ ageMin: 40, ageMax: 40, emailDomain: "example.com" }));
    expect(ageOn2026_10_23(draft.fields["identity.birthday"] ?? "")).toBe(40);
    const next = draft.regenerate("identity.birthday", options({ ageMin: 61, ageMax: 65, emailDomain: "example.com" }));
    draft.free();
    try {
      const age = ageOn2026_10_23(next.fields["identity.birthday"] ?? "");
      expect(age).toBeGreaterThanOrEqual(61);
      expect(age).toBeLessThanOrEqual(65);
      for (const key of ["identity.first_name", "identity.last_name", "identity.address1", "identity.city", "identity.username"]) {
        expect(next.fields[key]).toBe(draft.fields[key]);
      }
    } finally {
      next.free();
    }
  });

  it("a country redraw keeps the birthday and the username", () => {
    const draft = generateIdentity(options());
    const next = draft.regenerate("identity.country", options({ country: "DE" }));
    draft.free();
    expect(next.fields["identity.country"]).toBe("DE");
    expect(next.fields["identity.birthday"]).toBe(draft.fields["identity.birthday"]);
    expect(next.fields["identity.username"]).toBe(draft.fields["identity.username"]);
    next.free();
  });

  it("refuses bad options with stable codes", () => {
    expect(codeOf(() => checkAgeRange(17, 30))).toBe("identity_age_range");
    expect(codeOf(() => checkAgeRange(40, 30))).toBe("identity_age_range");
    expect(codeOf(() => checkAgeRange(18, 100))).toBe("identity_age_range");
    expect(codeOf(() => checkAgeRange(18.5, 30))).toBe("identity_age_range");
    expect(codeOf(() => checkAgeRange(18, 99))).toBeUndefined();
    expect(codeOf(() => generateIdentity(options({ country: "ZZ" })))).toBe("identity_unsupported_country");
    expect(codeOf(() => generateIdentity(options({ emailDomain: "not a domain" })))).toBe("identity_email_domain");
    const draft = generateIdentity(options());
    expect(codeOf(() => draft.regenerate("identity.ssn", options()))).toBe("identity_unknown_field");
    draft.free();
    expect(normalizeEmailDomain("Mail.Example.COM")).toBe("mail.example.com");
    expect(codeOf(() => normalizeEmailDomain("localhost"))).toBe("identity_email_domain");
    expect(codeOf(() => normalizeEmailDomain("bücher.example"))).toBe("identity_email_domain_not_ascii");
    expect(identityErrorMessage("identity_email_domain")).toBe("Enter a domain name such as example.com.");
    expect(DEFAULT_IDENTITY_DEFAULTS).toMatchObject({ sex: "random", ageMin: 18, ageMax: 27, emailDomain: null });
  });
});
