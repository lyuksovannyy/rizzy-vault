// `generator-flow.ts`'s mapping from UI options to the core's calls, apart from React
// (`export-flow.test.ts`'s pattern): a normal option change reaches the real core and comes
// back as a value of the shape asked for; an impossible combination is refused with exactly
// the core's own message, not a UI-invented one; and the editor's fill is a pure DOM write.
import { CoreError, DEFAULT_PASSPHRASE_OPTIONS, DEFAULT_PASSWORD_OPTIONS } from "@rizzy-vault/core";
import type { PassphraseOptions, PasswordOptions } from "@rizzy-vault/core";
import { beforeAll, describe, expect, it } from "vitest";

import { type Caller, checkEntropy, fillGenerated, generateValue } from "../src/generator-flow.ts";
import { messageFor } from "../src/messages.ts";
import { loadCore } from "./load-core.ts";

beforeAll(() => {
  loadCore();
});

/** A `Caller` that runs the real core calls this module uses, nothing else. */
const realCore: Caller = {
  call: (async (method: string, ...args: unknown[]) => {
    const core = await import("@rizzy-vault/core");
    switch (method) {
      case "generatePasswordWithOptions":
        return core.generatePasswordWithOptions(args[0] as Partial<PasswordOptions>);
      case "generatePassphraseWithOptions":
        return core.generatePassphraseWithOptions(args[0] as Partial<PassphraseOptions>);
      case "passwordEntropy":
        return core.passwordEntropy(args[0] as Partial<PasswordOptions>);
      case "passphraseEntropy":
        return core.passphraseEntropy(args[0] as Partial<PassphraseOptions>);
      default:
        throw new Error(`unexpected call: ${method}`);
    }
  }) as Caller["call"],
};

describe("generateValue / checkEntropy: option mapping", () => {
  it("sends password mode's options to generatePasswordWithOptions, not the passphrase ones", async () => {
    const options: PasswordOptions = {
      ...DEFAULT_PASSWORD_OPTIONS,
      length: 40,
      excludeAmbiguous: true,
      exclude: "abc",
      symbolSet: "#!",
    };
    const value = await generateValue(realCore, "password", options, DEFAULT_PASSPHRASE_OPTIONS);
    expect(value.value).toHaveLength(40);
    expect(value.value).not.toMatch(/[abc]/);
    expect([...value.value].every((c) => !/[^\w]/.test(c) || c === "#" || c === "!")).toBe(true);

    const bits = await checkEntropy(realCore, "password", options, DEFAULT_PASSPHRASE_OPTIONS);
    expect(bits).toBeCloseTo(value.entropyBits, 9);
  });

  it("sends passphrase mode's options to generatePassphraseWithOptions, not the password ones", async () => {
    const options: PassphraseOptions = { ...DEFAULT_PASSPHRASE_OPTIONS, words: 4, separator: "_" };
    const value = await generateValue(realCore, "passphrase", DEFAULT_PASSWORD_OPTIONS, options);
    expect(value.value.split("_")).toHaveLength(4);

    const bits = await checkEntropy(realCore, "passphrase", DEFAULT_PASSWORD_OPTIONS, options);
    expect(bits).toBeCloseTo(value.entropyBits, 9);
  });
});

describe("an impossible combination", () => {
  it("is refused with exactly the core's own message, both for generating and for the live check", async () => {
    const everyClassExcluded: PasswordOptions = {
      ...DEFAULT_PASSWORD_OPTIONS,
      lowercase: "excluded",
      uppercase: "excluded",
      digits: "excluded",
      symbols: "excluded",
    };
    await expect(
      generateValue(realCore, "password", everyClassExcluded, DEFAULT_PASSPHRASE_OPTIONS),
    ).rejects.toSatisfy((e: unknown) => e instanceof CoreError && e.code === "generator_no_classes");

    let code: string | undefined;
    try {
      await checkEntropy(realCore, "password", everyClassExcluded, DEFAULT_PASSPHRASE_OPTIONS);
    } catch (e) {
      code = e instanceof CoreError ? e.code : undefined;
    }
    expect(code).toBe("generator_no_classes");
    expect(messageFor(code ?? "")).toBe("Turn on at least one kind of character.");
  });
});

describe("fillGenerated: the editor's fill", () => {
  it("writes the generated value into the input and nothing else", () => {
    const input = { value: "" };
    fillGenerated(input, { value: "s3cr3t!", entropyBits: 42 });
    expect(input).toEqual({ value: "s3cr3t!" });
  });

  it("is a no-op when the target input no longer exists", () => {
    expect(() => fillGenerated(null, { value: "x", entropyBits: 1 })).not.toThrow();
  });
});
