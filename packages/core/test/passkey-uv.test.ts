// SPDX-License-Identifier: AGPL-3.0-only

// Passkey user verification through packages/core (ADR 0110 §5, §6, §7 point 4), without a
// server: the requirement mapping and UV_FRESH_MS (Rust's), and what DurableSession's wrappers
// hand the Rust session for the decision (a stub records it; the decision itself and its table
// are rizzy-client's tests, the real session round trip e2e.test.ts's).
import { beforeAll, describe, expect, it } from "vitest";

import {
  type CacheStore,
  CoreError,
  DEFAULT_LOCK_SETTINGS,
  DurableSession,
  type Transport,
  UV_FRESH_MS,
  UV_REQUIRED,
  parseUvRequirement,
  uvFreshMs,
} from "../src/index.js";
import { loadCore } from "./load.js";

beforeAll(() => {
  loadCore();
});

const unreachable: Transport = () => {
  throw new Error("no request should be sent");
};

const noStore: CacheStore = {
  get: async () => undefined,
  put: async () => {},
  delete: async () => {},
  list: async () => [],
};

/** The code a call throws, or `undefined`. */
function codeOf(f: () => unknown): string | undefined {
  try {
    f();
    return undefined;
  } catch (e) {
    return e instanceof CoreError ? e.code : String(e);
  }
}

/** What the stub's Rust calls received; the settings are read while the call runs (they are
 * freed after it). */
interface Seen {
  call: string;
  requirement: string | undefined;
  settings?: { autoLock: boolean; idleMinutes: number; lockOnSleep: boolean };
  now: bigint;
  password?: Uint8Array;
}

interface StubSettings {
  autoLock: boolean;
  idleMinutes: number;
  lockOnSleep: boolean;
}

function settingsOf(s: StubSettings): StubSettings {
  return { autoLock: s.autoLock, idleMinutes: s.idleMinutes, lockOnSleep: s.lockOnSleep };
}

/** A DurableSession over a stub of the Rust session that records each UV call. */
function stubSession(clockMs: number): { session: DurableSession; seen: Seen[] } {
  const seen: Seen[] = [];
  const created = {
    privateKey: new Uint8Array(32),
    credentialId: new Uint8Array(32),
    publicKeyCose: new Uint8Array(77),
    clientDataJson: new Uint8Array(1),
    attestationObject: new Uint8Array(1),
    free: () => {},
  };
  const assertion = {
    credentialId: new Uint8Array(1),
    userHandle: new Uint8Array(1),
    clientDataJson: new Uint8Array(1),
    authenticatorData: new Uint8Array(37),
    signatureDer: new Uint8Array(1),
    free: () => {},
  };
  const inner = {
    unlockedByMasterPassword: true,
    passkeyAssertion: (
      _id: string,
      _passkeyId: string,
      _origin: string,
      _rpId: string,
      _challenge: Uint8Array,
      requirement: string | undefined,
      settings: StubSettings,
      now: bigint,
    ) => {
      seen.push({ call: "passkeyAssertion", requirement, settings: settingsOf(settings), now });
      return assertion;
    },
    createPasskey: (
      _origin: string,
      _rpId: string,
      _challenge: Uint8Array,
      requirement: string | undefined,
      settings: StubSettings,
      now: bigint,
    ) => {
      seen.push({ call: "createPasskey", requirement, settings: settingsOf(settings), now });
      return created;
    },
    passkeyUvDecision: (requirement: string | undefined, settings: StubSettings, now: bigint) => {
      seen.push({ call: "passkeyUvDecision", requirement, settings: settingsOf(settings), now });
      return UV_REQUIRED;
    },
    reverify: (password: Uint8Array, now: bigint) => {
      seen.push({ call: "reverify", requirement: undefined, now, password: password.slice() });
    },
  } as unknown as ConstructorParameters<typeof DurableSession>[0];
  return { session: new DurableSession(inner, unreachable, noStore, () => clockMs), seen };
}

describe("passkey user verification", () => {
  it("UV_FRESH_MS is Rust's", () => {
    expect(uvFreshMs()).toBe(UV_FRESH_MS);
    expect(UV_FRESH_MS).toBe(300_000);
  });

  it("maps the requirement as ADR 0110 §5 point 2 says", () => {
    expect(parseUvRequirement("required")).toBe("required");
    expect(parseUvRequirement("discouraged")).toBe("discouraged");
    expect(parseUvRequirement("preferred")).toBe("preferred");
    for (const other of ["REQUIRED", "Required", " required", "", "x", undefined, null, 1, {}]) {
      expect(parseUvRequirement(other)).toBe("preferred");
    }
  });

  it("hands the raw requirement, the current settings and the clock to Rust at signing", () => {
    const { session, seen } = stubSession(1_000);
    const loose = { autoLock: true, idleMinutes: 60, lockOnSleep: false };
    session.passkeyAssertion("item", "pk", "https://example.com", "example.com", new Uint8Array([1]), {
      userVerification: "required",
      lockSettings: loose,
    });
    const created = session.createPasskey("https://example.com", "example.com", new Uint8Array([1]), {
      userVerification: undefined,
      lockSettings: DEFAULT_LOCK_SETTINGS,
      nowMs: 2_500.9,
    });
    expect(created.credentialId).toHaveLength(32);
    expect(session.passkeyUvDecision({ userVerification: "REQUIRED", lockSettings: loose, nowMs: 7 })).toBe(
      UV_REQUIRED,
    );
    expect(seen).toEqual([
      { call: "passkeyAssertion", requirement: "required", settings: loose, now: 1_000n },
      {
        call: "createPasskey",
        requirement: undefined,
        settings: { autoLock: true, idleMinutes: 5, lockOnSleep: true },
        now: 2_500n,
      },
      // The raw value goes to Rust, which maps it; "REQUIRED" is not mapped here.
      { call: "passkeyUvDecision", requirement: "REQUIRED", settings: loose, now: 7n },
    ]);
    expect(session.unlockedByMasterPassword).toBe(true);
  });

  it("drops a non-string requirement and refuses a bad clock or idle time before Rust", () => {
    const { session, seen } = stubSession(1_000);
    const bad = { userVerification: 5 as unknown as string, lockSettings: DEFAULT_LOCK_SETTINGS };
    session.passkeyUvDecision(bad);
    expect(seen[0]?.requirement).toBeUndefined();
    const decide = (nowMs: number) =>
      codeOf(() => session.passkeyUvDecision({ userVerification: "required", lockSettings: DEFAULT_LOCK_SETTINGS, nowMs }));
    expect(decide(Number.NaN)).toBe("invalid_input");
    expect(decide(-1)).toBe("invalid_input");
    expect(decide(Number.POSITIVE_INFINITY)).toBe("invalid_input");
    expect(
      codeOf(() =>
        session.passkeyUvDecision({
          userVerification: "required",
          lockSettings: { autoLock: true, idleMinutes: 3, lockOnSleep: true },
        }),
      ),
    ).toBe("invalid_input");
    expect(seen).toHaveLength(1);
  });

  it("re-verifies with the password's bytes, then zeroes them", () => {
    const { session, seen } = stubSession(9_000);
    const password = new TextEncoder().encode("hunter2");
    session.reverify(password);
    session.reverify("hunter2", 12_000);
    expect(seen.map((s) => [s.call, s.now])).toEqual([
      ["reverify", 9_000n],
      ["reverify", 12_000n],
    ]);
    expect(new TextDecoder().decode(seen[0]?.password)).toBe("hunter2");
    expect(new TextDecoder().decode(seen[1]?.password)).toBe("hunter2");
    expect(password.every((b) => b === 0)).toBe(true);
    expect(codeOf(() => session.reverify("x", Number.NaN))).toBe("invalid_input");
  });
});
