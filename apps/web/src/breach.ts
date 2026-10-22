// SPDX-License-Identifier: AGPL-3.0-only

// The breach check's words and the vault-wide report (ADR 0053; CRYPTO.md §11.16; ROADMAP §4.5
// "Watchtower-style health: … breached passwords via HIBP k-anonymity"). Pure: no wasm, no DOM.
//
// - **What is sent.** The Worker's core sends the first five characters of the SHA-1 hash of a
//   password to this server's `icons` role, which asks Have I Been Pwned for every hash with that
//   prefix; the core compares the rest locally. No password, no full hash, no account or item id
//   leaves the browser. The UI says so where it offers the check (`PRIVACY_NOTE`).
// - **What a result means.** "Found" is the upstream's word relayed by a server the threat model
//   does not trust: advice to change a password, never proof either way (`FOUND_CAVEAT`).
// - **Failures.** `server_not_found` (the operator left the breach check off, or the role is
//   not routed), `server_internal` (the upstream was unreachable) and a bad answer read as
//   "unavailable", a state rather than an error (ADR 0053 Risks). `server_rate_limited` is a
//   pause: the report waits and retries the same item.
// - **The report** checks the active Login items one by one through `check`, waiting
//   `RATE_LIMIT_WAIT_MS` after a rate limit (the role allows 30 checks a minute, 10 at once);
//   items that share a hash prefix cost one request (packages/core keeps answers by prefix
//   until lock). It stops on the first "unavailable" answer, since every later item would get
//   the same, and when the caller cancels.

/** A breach-check result, as packages/core returns it. */
export interface BreachResult {
  readonly found: boolean;
  readonly count: number;
}

/** What the check sends, worded for the UI. */
export const PRIVACY_NOTE =
  "Only the first 5 characters of a hash of the password leave this browser, sent to this server, which asks Have I Been Pwned for every hash that starts with them. The password itself never leaves.";

/** What a "found" result does and does not mean. */
export const FOUND_CAVEAT =
  "This is the breach database's answer, relayed by your server. Change the password on the website, then update it here.";

/** How long the report waits after a rate limit before it retries the same item. */
export const RATE_LIMIT_WAIT_MS = 2_500;

/** The most rate-limit waits in a row before the report gives up. */
export const MAX_RATE_LIMIT_RETRIES = 30;

/** Whether a failure code means the breach check is not available (module docs). */
export function isUnavailable(code: string): boolean {
  return code !== "server_rate_limited" && code !== "locked" && code !== "session_ended";
}

/** The sentence for one result. */
export function resultText(result: BreachResult): string {
  if (!result.found) {
    return "Not found in known data breaches.";
  }
  const times = result.count === 1 ? "once" : `${result.count.toLocaleString("en")} times`;
  return `Found in known data breaches (seen ${times}). Change this password.`;
}

/** The sentence for a failed check. */
export function failureText(code: string): string {
  if (code === "server_not_found") {
    return "Breach checking is not enabled on this server.";
  }
  if (code === "server_rate_limited") {
    return "Too many checks right now. Try again in a moment.";
  }
  return "Breach checking is unavailable right now. Try again later.";
}

/** One item of the report. */
export interface ReportItem {
  readonly id: string;
  readonly title: string;
}

/** One breached item of the report. */
export interface ReportHit extends ReportItem {
  readonly count: number;
}

/** The report's progress and outcome. */
export interface ReportState {
  /** Items checked so far (with or without a password). */
  readonly checked: number;
  /** Items to check. */
  readonly total: number;
  /** Items that have a password and were checked. */
  readonly withPassword: number;
  /** Breached items, in check order. */
  readonly hits: readonly ReportHit[];
  /** "running", "done", "cancelled", or the failure code that stopped it. */
  readonly status: "running" | "done" | "cancelled" | { readonly failed: string };
}

/** The failure code of a thrown value: a `{ code }` object's code, or `internal`. */
function codeOfError(e: unknown): string {
  if (typeof e === "object" && e !== null && typeof (e as { code?: unknown }).code === "string") {
    return (e as { code: string }).code;
  }
  return "internal";
}

/**
 * Runs the report over `items` (module docs). `check` is the Worker call (`null` for an item
 * without a password), `sleep` waits, `cancelled` is polled before each item, and `progress`
 * receives every state. Returns the last state.
 */
export async function runReport(
  items: readonly ReportItem[],
  check: (id: string) => Promise<BreachResult | null>,
  sleep: (ms: number) => Promise<void>,
  cancelled: () => boolean,
  progress: (state: ReportState) => void,
): Promise<ReportState> {
  let state: ReportState = { checked: 0, total: items.length, withPassword: 0, hits: [], status: "running" };
  progress(state);
  for (const item of items) {
    let retries = 0;
    for (;;) {
      if (cancelled()) {
        state = { ...state, status: "cancelled" };
        progress(state);
        return state;
      }
      try {
        const result = await check(item.id);
        state = {
          ...state,
          checked: state.checked + 1,
          withPassword: state.withPassword + (result === null ? 0 : 1),
          hits:
            result?.found === true
              ? [...state.hits, { id: item.id, title: item.title, count: result.count }]
              : state.hits,
        };
        progress(state);
        break;
      } catch (e) {
        const code = codeOfError(e);
        if (code === "server_rate_limited" && retries < MAX_RATE_LIMIT_RETRIES) {
          retries += 1;
          await sleep(RATE_LIMIT_WAIT_MS);
          continue;
        }
        state = { ...state, status: { failed: code } };
        progress(state);
        return state;
      }
    }
  }
  state = { ...state, status: "done" };
  progress(state);
  return state;
}
