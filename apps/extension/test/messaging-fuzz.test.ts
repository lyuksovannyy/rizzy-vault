// SPDX-License-Identifier: AGPL-3.0-only

// Bulk fuzzing of every message-shape boundary the page/content-script side can reach (ADR 0036
// §4, ADR 0040, INV-40, THREAT_MODEL.md attacker class A7 "malicious page scripts"): the
// content-script-to-background contract (`parseFromContentScript`), the two extension-origin
// `postMessage` protocols (`inline-menu/protocol.ts`, `content/passkey-protocol.ts`), and the
// direct-to-background messages a compromised content script might try to forge or replay
// (`isInlineMenuFillRequestMessage`, `isPasskeyCeremonyMessage`, `isApplyFillMessage`, etc. —
// `messaging/contract.ts`'s own doc on why these are checked independently of sender identity).
//
// Every payload this generator builds is JSON-safe (string/number/boolean/null/array/plain
// object only): the realistic shape an attacker-controlled page can actually deliver through
// `postMessage`/`chrome.runtime.sendMessage`, both of which structured-clone their argument
// before a listener ever sees it. A hand-crafted getter trap, a `Proxy`, or a real prototype
// change via `{__proto__: x}` object-literal syntax never survives that clone (the receiver gets
// a plain data value, or the browser never delivers the message at all) — fuzzing those is
// testing this file's own call convention, not anything THREAT_MODEL A7 can reach, so the
// generator does not build them. A `"__proto__"` *own property* (only reachable via
// `JSON.parse('{"__proto__":...}')`, never via `{__proto__: x}` literal or `obj["__proto__"] =
// x`, both of which just set the real prototype through `Object.prototype`'s accessor instead of
// creating an own key — the exact distinction this file's own mutation catalogue relies on) *can*
// survive structured clone as an ordinary same-named property, so that one is in scope and is
// fuzzed on every case.
//
// Oracle (never the implementation mirrored, always the stated invariant):
//   1. No validator ever throws anything the caller does not expect: the boolean `is*` checks
//      must never throw at all (a compromised content script's handcrafted message must never
//      crash the background's dispatch loop); `parseFromContentScript` may throw only
//      `MessageRejected` (INV-40: untrusted input is parsed without panics).
//   2. A `"__proto__"` own key never survives any validator call, accepted or refused
//      (`Object.prototype` gains no new property).
//   3. Byte/field/array-length budgets exported from `contract.ts` are never exceeded by
//      anything a validator accepts (INV-40's size limits), checked against those exported
//      constants directly, never against `validate.ts`'s own per-field branches.
//   4. ADR 0036 §4's own named rule — "never includes the field's current value for a password
//      field" — holds for every accepted `fields_detected` message.
// Positive controls (below) prove this oracle fails closed on a planted violation before any
// fuzz case runs, the same requirement `clickjacking-fuzz.spec.ts` meets for the other channel.
//
// Budgets: `PR_CASES` runs by default, deterministically, well under a minute (pure sync JS, no
// browser/network). The nightly budget is gated behind `RIZZY_FUZZ_NIGHTLY=1` (optionally
// `RIZZY_FUZZ_SEED_START`/`RIZZY_FUZZ_CASES`), mirroring the `clickjacking-fuzz.spec.ts`/
// `rizzy-sync` convergence-harness `Seeds::Fixed`/`Seeds::Fresh` split (CLAUDE.md harness
// convention). Each case's RNG is seeded independently via `deriveSeed(runSeed, caseIndex)`, so a
// failing case index reproduces in isolation for minimisation, the same way a failing seed does
// in the clickjacking harness.
//
// Not covered by this file (see the task's own `not_covered` writeup): sender-identity trust
// (`messaging/sender.ts`'s `isInlineMenuSender`) — already covered by hand-written cases in
// `test/sender.test.ts`, not fuzzed here, since this file's job is message *shape*, not origin
// trust; and replay/token-reuse races, which live in the stateful layer above these pure
// functions (`core-host/content-handler.ts`, `core-host/listener.ts`, `core-host/
// passkey-ceremony.ts`) and need a stateful harness this file does not build.
import { describe, expect, it } from "vitest";

import {
  type FromContentScript,
  MAX_ALGS,
  MAX_ALLOW_CREDENTIALS,
  MAX_CANDIDATES,
  MAX_FIELDS_PER_REPORT,
  MAX_FIELD_VALUE_LEN,
  MAX_HOST_LEN,
  MAX_MESSAGE_BYTES,
  MAX_PASSKEY_BYTES_B64,
  MAX_TITLE_LEN,
  MAX_URL_LEN,
  MESSAGE_TYPES,
  isApplyFillMessage,
  isApplyPasskeyResultMessage,
  isInlineMenuFillRequestMessage,
  isInlineMenuGeneratePasswordRequestMessage,
  isPasskeyCeremonyMessage,
  isRelayApplyFillMessage,
  isRelayPasskeyResultMessage,
} from "../src/messaging/contract.ts";
import { isPasskeyRequestFromPage, isPasskeyResponseToPage } from "../src/content/passkey-protocol.ts";
import { isInlineMenuPickMessage, isInlineMenuShowMessage } from "../src/inline-menu/protocol.ts";
import { MessageRejected, parseFromContentScript } from "../src/messaging/validate.ts";
import { type Rng, chance, deriveSeed, intBetween, mulberry32, pick } from "../e2e/support/prng.ts";

// --- Mutation machinery --------------------------------------------------------------------

const GARBAGE_STRINGS = ["", " ", "\u0000", "🙂".repeat(50), "‮‭​", "<script>", "../../etc/passwd", "null", "undefined"];
const GARBAGE_SCALARS: readonly unknown[] = [0, -1, 1.5, true, false, null, [], {}, [1, 2, 3], { a: 1 }];

function randomGarbageString(rng: Rng): string {
  if (chance(rng, 0.3)) {
    return "x".repeat(intBetween(rng, 1, 70_000));
  }
  return pick(rng, GARBAGE_STRINGS);
}

function randomGarbageValue(rng: Rng): unknown {
  if (chance(rng, 0.25)) {
    return randomGarbageString(rng);
  }
  return pick(rng, GARBAGE_SCALARS);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Adds an own `"__proto__"` key to a JSON-safe plain object, reachable only via `JSON.parse`
 * (see this file's header doc on why `{__proto__: x}` object-literal syntax would not test the
 * same thing). Handles the empty-object case explicitly: splicing a key into `"{}"` by replacing
 * its leading brace would otherwise leave a trailing comma (`{"__proto__":{...},}`), invalid
 * JSON. */
function injectProtoPollution(obj: Record<string, unknown>): Record<string, unknown> {
  const serialized = JSON.stringify(obj);
  const spliced = serialized === "{}" ? '{"__proto__":{"polluted":true}}' : serialized.replace(/^\{/, '{"__proto__":{"polluted":true},');
  return JSON.parse(spliced) as Record<string, unknown>;
}

/** One mutation pass, drawn from a fixed catalogue so repeated rounds explore the space
 * combinatorially rather than retracing a short hand-picked list. */
function mutateOnce(rng: Rng, value: unknown): unknown {
  if (Array.isArray(value)) {
    const arr = value.slice();
    switch (intBetween(rng, 0, 3)) {
      case 0:
        arr.push(randomGarbageValue(rng));
        return arr;
      case 1:
        if (arr.length > 0) {
          arr.splice(intBetween(rng, 0, arr.length - 1), 1);
        }
        return arr;
      case 2:
        return randomGarbageValue(rng);
      default:
        for (let i = 0; i < arr.length; i += 1) {
          if (chance(rng, 0.3)) {
            arr[i] = randomGarbageValue(rng);
          }
        }
        return arr;
    }
  }
  if (!isPlainRecord(value)) {
    return randomGarbageValue(rng);
  }
  const obj: Record<string, unknown> = { ...value };
  const keys = Object.keys(obj);
  switch (intBetween(rng, 0, 7)) {
    case 0:
      if (keys.length > 0) {
        delete obj[pick(rng, keys)];
      }
      return obj;
    case 1:
      if (keys.length > 0) {
        obj[pick(rng, keys)] = randomGarbageValue(rng);
      }
      return obj;
    case 2:
      for (const k of keys) {
        if (typeof obj[k] === "string") {
          obj[k] = randomGarbageString(rng);
          break;
        }
      }
      return obj;
    case 3:
      if ("type" in obj) {
        obj["type"] = pick(rng, [...MESSAGE_TYPES, "", "unknown_type_xyz", "rizzy-inline-menu-show", "rizzy-passkey-request"] as const);
      }
      return obj;
    case 4:
      obj[`garbage_${intBetween(rng, 0, 1_000_000)}`] = randomGarbageValue(rng);
      return obj;
    case 5:
      if (keys.length > 0) {
        const k = pick(rng, keys);
        obj[k] = chance(rng, 0.5) ? [obj[k]] : { nested: obj[k] };
      }
      return obj;
    case 6:
      return injectProtoPollution(obj);
    default:
      if (keys.length > 0) {
        const k = pick(rng, keys);
        obj[`${k} `] = obj[k];
      }
      return obj;
  }
}

function mutate(rng: Rng, base: unknown, rounds: number): unknown {
  // JSON round trip doubles as the deep clone and as the "attacker-reachable payload" filter:
  // structured clone strips exactly the same exotic values (functions, getters, symbols, cycles)
  // this removes, for the same reason (see header doc).
  let current: unknown = JSON.parse(JSON.stringify(base));
  for (let i = 0; i < rounds; i += 1) {
    current = mutateOnce(rng, current);
  }
  return current;
}

// --- Seed messages, one per message shape in scope -----------------------------------------

const SEEDS: Readonly<Record<string, () => unknown>> = {
  fieldsDetected: () => ({
    type: "fields_detected",
    pageUrl: "https://example.com/login",
    isTopFrame: true,
    fields: [
      { fieldId: "f1", kind: "username", visible: true, currentValue: "alice" },
      { fieldId: "f2", kind: "password", visible: true },
    ],
  }),
  credentialsSubmitted: () => ({
    type: "credentials_submitted",
    pageUrl: "https://example.com/login",
    usernameValue: "alice",
    passwordValue: "s3cret",
  }),
  savePromptResolved: () => ({ type: "save_prompt_resolved", token: "tok-1", action: "save" }),
  checkSavePrompt: () => ({ type: "check_save_prompt", pageUrl: "https://example.com/dashboard" }),
  passkeyCreateRequest: () => ({
    type: "passkey_create_request",
    pageUrl: "https://example.com/",
    rpName: "Example",
    userIdB64: "AAAA",
    userName: "alice",
    userDisplayName: "Alice",
    challengeB64: "AAAA",
    algs: [-7],
  }),
  passkeyGetRequest: () => ({
    type: "passkey_get_request",
    pageUrl: "https://example.com/",
    challengeB64: "AAAA",
    allowCredentialIdsB64: ["AAAA"],
  }),
  registerIframeInstance: () => ({ type: "register_iframe_instance", instanceToken: "3b241101-e2bb-4255-8caf-4136c566a962" }),
  revokeIframeInstance: () => ({ type: "revoke_iframe_instance", instanceToken: "3b241101-e2bb-4255-8caf-4136c566a962" }),
  inlineMenuFillRequest: () => ({ type: "inline_menu_fill_chosen", instanceToken: "3b241101-e2bb-4255-8caf-4136c566a962", itemId: "item-1", confirmedEquivalence: false }),
  inlineMenuGeneratePasswordRequest: () => ({ type: "inline_menu_generate_password_chosen", instanceToken: "3b241101-e2bb-4255-8caf-4136c566a962" }),
  passkeyCeremonyApproved: () => ({ type: "passkey_ceremony_approved", instanceToken: "3b241101-e2bb-4255-8caf-4136c566a962", ceremonyToken: "ct-1", chosenPasskeyRef: "ref-1" }),
  passkeyCeremonyDeclined: () => ({ type: "passkey_ceremony_declined", instanceToken: "3b241101-e2bb-4255-8caf-4136c566a962", ceremonyToken: "ct-1" }),
  applyFill: () => ({ type: "apply_fill", values: { username: "alice", password: "s3cret" } }),
  relayApplyFill: () => ({ type: "relay_apply_fill", tabId: 7, values: { password: "s3cret" } }),
  applyPasskeyResultOk: () => ({
    type: "apply_passkey_result",
    ceremonyToken: "ct-1",
    outcome: "ok",
    result: { credentialIdB64: "AAAA", clientDataJsonB64: "AAAA" },
  }),
  relayPasskeyResultFallback: () => ({ type: "relay_passkey_result", tabId: 7, ceremonyToken: "ct-1", outcome: "fallback" }),
  inlineMenuShow: () => ({
    type: "rizzy-inline-menu-show",
    pageOrigin: "https://example.com",
    instanceToken: "3b241101-e2bb-4255-8caf-4136c566a962",
    pageHost: "example.com",
    candidates: [{ itemId: "i1", title: "Example", username: "alice", needsWarning: false, savedHost: "example.com" }],
  }),
  inlineMenuPick: () => ({ type: "rizzy-inline-menu-pick", itemId: "i1" }),
  passkeyPageRequestCreate: () => ({
    type: "rizzy-passkey-request",
    nonce: "n1",
    kind: "create",
    rpName: "Example",
    userIdB64: "AAAA",
    userName: "alice",
    userDisplayName: "Alice",
    challengeB64: "AAAA",
    algs: [-7],
  }),
  passkeyPageRequestGet: () => ({
    type: "rizzy-passkey-request",
    nonce: "n1",
    kind: "get",
    challengeB64: "AAAA",
    allowCredentialIdsB64: ["AAAA"],
  }),
  passkeyPageResponseOk: () => ({
    type: "rizzy-passkey-response",
    nonce: "n1",
    outcome: "ok",
    result: { credentialIdB64: "AAAA", clientDataJsonB64: "AAAA" },
  }),
};

// --- The boolean validators under fuzz, run against every mutated payload (cross-channel
// confusion included: a payload shaped for one message type fed to a validator for another) ---

interface BooleanValidator {
  readonly name: string;
  readonly check: (value: unknown) => boolean;
}

const BOOLEAN_VALIDATORS: readonly BooleanValidator[] = [
  { name: "isInlineMenuFillRequestMessage", check: isInlineMenuFillRequestMessage },
  { name: "isInlineMenuGeneratePasswordRequestMessage", check: isInlineMenuGeneratePasswordRequestMessage },
  { name: "isPasskeyCeremonyMessage", check: isPasskeyCeremonyMessage },
  { name: "isApplyFillMessage", check: isApplyFillMessage },
  { name: "isRelayApplyFillMessage", check: isRelayApplyFillMessage },
  { name: "isApplyPasskeyResultMessage", check: isApplyPasskeyResultMessage },
  { name: "isRelayPasskeyResultMessage", check: isRelayPasskeyResultMessage },
  { name: "isInlineMenuShowMessage", check: isInlineMenuShowMessage },
  { name: "isInlineMenuPickMessage", check: isInlineMenuPickMessage },
  { name: "isPasskeyRequestFromPage", check: isPasskeyRequestFromPage },
  { name: "isPasskeyResponseToPage", check: isPasskeyResponseToPage },
];

function assertNoPrototypePollution(label: string): void {
  expect((({}) as Record<string, unknown>)["polluted"], label).toBeUndefined();
  expect(Object.prototype.hasOwnProperty.call(Object.prototype, "polluted"), label).toBe(false);
}

/** Re-verifies an accepted boolean-validator result against `contract.ts`'s own exported
 * budgets — never against `validate.ts`'s/the protocol file's internal branches — so this stays
 * an independent oracle, not a mirror of the implementation it is fuzzing. Throws (a test
 * failure) on violation; the "oracle self-check" test below proves it does. */
/** ADR 0043's instance-token shape, written out independently of `contract.ts`'s own pattern:
 * 36 characters, 8-4-4-4-12 lowercase hex groups, version nibble 4, variant 8/9/a/b. */
function isCanonicalV4(token: unknown): boolean {
  if (typeof token !== "string" || token.length !== 36) {
    return false;
  }
  const groups = token.split("-");
  const hex = (s: string) => [...s].every((ch) => "0123456789abcdef".includes(ch));
  return (
    groups.length === 5 &&
    groups.map((g) => g.length).join(",") === "8,4,4,4,12" &&
    groups.every(hex) &&
    token[14] === "4" &&
    "89ab".includes(token[19] ?? "")
  );
}

function checkAcceptedInvariant(name: string, value: unknown): void {
  const v = value as Record<string, unknown>;
  if (
    (name === "isInlineMenuFillRequestMessage" ||
      name === "isInlineMenuGeneratePasswordRequestMessage" ||
      name === "isPasskeyCeremonyMessage" ||
      name === "isInlineMenuShowMessage") &&
    !isCanonicalV4(v["instanceToken"])
  ) {
    throw new Error(`${name}: accepted an instanceToken that is not a canonical v4 UUID (ADR 0043)`);
  }
  switch (name) {
    case "isInlineMenuFillRequestMessage":
      if (typeof v["itemId"] !== "string" || v["itemId"].length > 256) {
        throw new Error(`${name}: accepted itemId out of bound`);
      }
      break;
    case "isPasskeyCeremonyMessage": {
      const token = v["ceremonyToken"];
      if (typeof token !== "string" || token.length > 256) {
        throw new Error(`${name}: accepted ceremonyToken out of bound`);
      }
      // `chosenPasskeyRef` is only part of the "approved" variant's shape (`contract.ts`'s
      // `PasskeyCeremonyApprovedMessage`); a "declined" message carries no such field, and the
      // real validator correctly never looks at it once `type` reads "declined" — checking it
      // unconditionally here was a harness bug (a benign extra key on a declined message is not
      // a violation of anything the contract promises).
      if (v["type"] === "passkey_ceremony_approved") {
        const ref = v["chosenPasskeyRef"];
        if (ref !== undefined && (typeof ref !== "string" || ref.length > 256)) {
          throw new Error(`${name}: accepted chosenPasskeyRef out of bound`);
        }
      }
      break;
    }
    case "isApplyFillMessage":
    case "isRelayApplyFillMessage": {
      const values = v["values"] as Record<string, unknown>;
      const password = values["password"];
      if (typeof password !== "string" || password.length > MAX_FIELD_VALUE_LEN) {
        throw new Error(`${name}: accepted password out of bound`);
      }
      const username = values["username"];
      if (username !== undefined && (typeof username !== "string" || username.length > MAX_FIELD_VALUE_LEN)) {
        throw new Error(`${name}: accepted username out of bound`);
      }
      if (name === "isRelayApplyFillMessage" && typeof v["tabId"] !== "number") {
        throw new Error(`${name}: accepted tabId not a number`);
      }
      break;
    }
    case "isApplyPasskeyResultMessage":
    case "isRelayPasskeyResultMessage": {
      const token = v["ceremonyToken"];
      if (typeof token !== "string" || token.length > 256) {
        throw new Error(`${name}: accepted ceremonyToken out of bound`);
      }
      if (v["outcome"] === "ok") {
        const r = v["result"] as Record<string, unknown>;
        const cred = r["credentialIdB64"];
        if (typeof cred !== "string" || cred.length > MAX_PASSKEY_BYTES_B64) {
          throw new Error(`${name}: accepted credentialIdB64 out of bound`);
        }
      } else if (v["result"] !== undefined) {
        throw new Error(`${name}: accepted a "fallback" outcome carrying a result`);
      }
      if (name === "isRelayPasskeyResultMessage" && typeof v["tabId"] !== "number") {
        throw new Error(`${name}: accepted tabId not a number`);
      }
      break;
    }
    case "isInlineMenuShowMessage": {
      const pageHost = v["pageHost"];
      if (typeof pageHost !== "string" || pageHost.length > MAX_HOST_LEN) {
        throw new Error(`${name}: accepted pageHost out of bound`);
      }
      const candidates = v["candidates"] as unknown[];
      if (!Array.isArray(candidates) || candidates.length > MAX_CANDIDATES) {
        throw new Error(`${name}: accepted candidates array out of bound`);
      }
      for (const c of candidates) {
        const cc = c as Record<string, unknown>;
        const title = cc["title"];
        const savedHost = cc["savedHost"];
        if (typeof title !== "string" || title.length > MAX_TITLE_LEN) {
          throw new Error(`${name}: accepted candidate title out of bound`);
        }
        if (typeof savedHost !== "string" || savedHost.length > MAX_HOST_LEN) {
          throw new Error(`${name}: accepted candidate savedHost out of bound`);
        }
      }
      break;
    }
    case "isInlineMenuPickMessage":
      if (typeof v["itemId"] !== "string" || v["itemId"].length > 256) {
        throw new Error(`${name}: accepted itemId out of bound`);
      }
      break;
    case "isPasskeyRequestFromPage": {
      const nonce = v["nonce"];
      if (typeof nonce !== "string" || nonce.length > 256) {
        throw new Error(`${name}: accepted nonce out of bound`);
      }
      if (v["kind"] === "create") {
        const userId = v["userIdB64"];
        const algs = v["algs"] as unknown[];
        if (typeof userId !== "string" || userId.length > MAX_PASSKEY_BYTES_B64) {
          throw new Error(`${name}: accepted userIdB64 out of bound`);
        }
        if (!Array.isArray(algs) || algs.length > MAX_ALGS) {
          throw new Error(`${name}: accepted algs array out of bound`);
        }
      } else if (v["kind"] === "get") {
        const allow = v["allowCredentialIdsB64"] as unknown[];
        if (!Array.isArray(allow) || allow.length > MAX_ALLOW_CREDENTIALS) {
          throw new Error(`${name}: accepted allowCredentialIdsB64 out of bound`);
        }
      } else {
        throw new Error(`${name}: accepted a message with neither kind "create" nor "get"`);
      }
      break;
    }
    case "isPasskeyResponseToPage": {
      const nonce = v["nonce"];
      if (typeof nonce !== "string" || nonce.length > 256) {
        throw new Error(`${name}: accepted nonce out of bound`);
      }
      break;
    }
    case "isInlineMenuGeneratePasswordRequestMessage":
      break; // no fields beyond `type` and `instanceToken` (checked above) to bound.
    default:
      throw new Error(`fuzz harness: no accepted-invariant wired for ${name} — add one before trusting its fuzz coverage`);
  }
}

/** Re-verifies an accepted `parseFromContentScript` result the same independent way. */
function checkParsedInvariant(value: FromContentScript): void {
  if (!(MESSAGE_TYPES as readonly string[]).includes(value.type)) {
    throw new Error(`parseFromContentScript: accepted an unknown type ${String(value.type)}`);
  }
  const approxSize = JSON.stringify(value).length;
  if (approxSize > MAX_MESSAGE_BYTES) {
    throw new Error(`parseFromContentScript: accepted a message over MAX_MESSAGE_BYTES (INV-40)`);
  }
  if ((value.type === "register_iframe_instance" || value.type === "revoke_iframe_instance") && !isCanonicalV4(value.instanceToken)) {
    throw new Error(`parseFromContentScript: accepted an instanceToken that is not a canonical v4 UUID (ADR 0043)`);
  }
  if ("pageUrl" in value && (typeof value.pageUrl !== "string" || value.pageUrl.length > MAX_URL_LEN)) {
    throw new Error(`parseFromContentScript: accepted pageUrl out of bound`);
  }
  if (value.type === "fields_detected") {
    if (value.fields.length > MAX_FIELDS_PER_REPORT) {
      throw new Error(`parseFromContentScript: accepted too many fields`);
    }
    for (const f of value.fields) {
      if (f.kind === "password" && f.currentValue !== undefined) {
        throw new Error(`parseFromContentScript: accepted a password field's currentValue (ADR 0036 §4)`);
      }
      if (f.currentValue !== undefined && f.currentValue.length > MAX_FIELD_VALUE_LEN) {
        throw new Error(`parseFromContentScript: accepted currentValue out of bound`);
      }
    }
  }
}

// --- The sweep ---------------------------------------------------------------------------

function runFuzzSweep(runSeed: number, caseCount: number): void {
  const seedBuilders = Object.values(SEEDS);
  for (let i = 0; i < caseCount; i += 1) {
    const rng = mulberry32(deriveSeed(runSeed, i));
    const builder = pick(rng, seedBuilders);
    const rounds = intBetween(rng, 1, 4);
    const mutated = mutate(rng, builder(), rounds);
    const describeCase = (): string => `case ${i} (runSeed=${runSeed}): ${JSON.stringify(mutated).slice(0, 300)}`;

    let parsed: FromContentScript | undefined;
    try {
      parsed = parseFromContentScript(mutated);
    } catch (err) {
      if (!(err instanceof MessageRejected)) {
        throw new Error(`parseFromContentScript threw a non-MessageRejected error on ${describeCase()}: ${String(err)}`);
      }
    }
    if (parsed !== undefined) {
      checkParsedInvariant(parsed);
    }
    assertNoPrototypePollution(`parseFromContentScript ${describeCase()}`);

    for (const validator of BOOLEAN_VALIDATORS) {
      let accepted: boolean;
      try {
        accepted = validator.check(mutated);
      } catch (err) {
        throw new Error(`${validator.name} threw (must only ever return a boolean) on ${describeCase()}: ${String(err)}`);
      }
      if (accepted) {
        try {
          checkAcceptedInvariant(validator.name, mutated);
        } catch (err) {
          throw new Error(`${(err as Error).message} on ${describeCase()}`);
        }
      }
    }
    assertNoPrototypePollution(`boolean validators ${describeCase()}`);
  }
}

const PR_SEED = 20261011;
const PR_CASES = 3000;

const NIGHTLY_ENABLED = process.env["RIZZY_FUZZ_NIGHTLY"] === "1";
const NIGHTLY_SEED_START = Number(process.env["RIZZY_FUZZ_SEED_START"] ?? "900000000");
const NIGHTLY_CASES = Number(process.env["RIZZY_FUZZ_CASES"] ?? String(PR_CASES * 25));

describe("messaging fuzz: PR budget (fixed seed, small N)", () => {
  it(`runs ${PR_CASES} mutated cases across every message-shape validator`, () => {
    runFuzzSweep(PR_SEED, PR_CASES);
  });
});

describe("messaging fuzz: nightly budget (fresh seeds, large N)", () => {
  it.skipIf(!NIGHTLY_ENABLED)(
    `runs ${NIGHTLY_CASES} mutated cases (set RIZZY_FUZZ_NIGHTLY=1, optionally RIZZY_FUZZ_SEED_START/RIZZY_FUZZ_CASES)`,
    { timeout: 480_000 }, // a large local scale run (CLAUDE.md harness convention) outruns vitest's 5s default.
    () => {
      runFuzzSweep(NIGHTLY_SEED_START, NIGHTLY_CASES);
    },
  );
});

// --- Positive controls: prove the oracle itself fails closed, without touching any production
// file, before trusting a clean fuzz run above (mirrors `clickjacking-fuzz.spec.ts`'s own
// positive-control requirement for the other channel). ---------------------------------------

describe("oracle self-check (positive control)", () => {
  it("an oversized fields_detected payload is rejected, not silently truncated", () => {
    const huge = {
      type: "fields_detected",
      pageUrl: "https://example.com/",
      isTopFrame: true,
      fields: Array.from({ length: MAX_FIELDS_PER_REPORT + 1 }, (_, i) => ({ fieldId: `f${i}`, kind: "other", visible: true })),
    };
    expect(() => parseFromContentScript(huge)).toThrow(MessageRejected);
  });

  it("a password field reporting currentValue is rejected (ADR 0036 §4)", () => {
    const bad = {
      type: "fields_detected",
      pageUrl: "https://example.com/",
      isTopFrame: true,
      fields: [{ fieldId: "f1", kind: "password", visible: true, currentValue: "leaked" }],
    };
    expect(() => parseFromContentScript(bad)).toThrow(MessageRejected);
  });

  it("a message over MAX_MESSAGE_BYTES is rejected even when otherwise well-shaped (INV-40)", () => {
    const big = { type: "check_save_prompt", pageUrl: `https://example.com/${"a".repeat(MAX_MESSAGE_BYTES)}` };
    expect(() => parseFromContentScript(big)).toThrow(MessageRejected);
  });

  it("checkAcceptedInvariant itself fails closed on a fabricated out-of-bound accepted value", () => {
    const bogus = { itemId: "x".repeat(300), confirmedEquivalence: true };
    expect(() => checkAcceptedInvariant("isInlineMenuFillRequestMessage", bogus)).toThrow();
  });

  it("checkParsedInvariant itself fails closed on a fabricated over-budget parsed value", () => {
    const bogus: FromContentScript = {
      type: "fields_detected",
      pageUrl: "https://example.com/",
      isTopFrame: true,
      fields: Array.from({ length: MAX_FIELDS_PER_REPORT + 1 }, (_, i) => ({ fieldId: `f${i}`, kind: "other" as const, visible: true })),
    };
    expect(() => checkParsedInvariant(bogus)).toThrow();
  });
});

describe("prototype pollution: an own \"__proto__\" key never survives any validator", () => {
  it("every seed message, polluted and run through every validator, leaves Object.prototype untouched", () => {
    for (const [name, builder] of Object.entries(SEEDS)) {
      const base = builder() as Record<string, unknown>;
      const polluted = injectProtoPollution(base);
      try {
        parseFromContentScript(polluted);
      } catch {
        // MessageRejected or any other refusal is fine; only the pollution check below matters.
      }
      for (const validator of BOOLEAN_VALIDATORS) {
        validator.check(polluted);
      }
      assertNoPrototypePollution(`seed ${name}`);
    }
  });
});
