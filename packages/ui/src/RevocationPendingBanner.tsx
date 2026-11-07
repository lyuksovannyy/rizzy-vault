// SPDX-License-Identifier: AGPL-3.0-only

// The `revocation_pending` banner of ADR 0091 §2 ("What clients see"; §8 step 7: the web vault
// and the extension), shared by both surfaces so they show it the same way, and the retry it
// stands for (`RevocationRetry`).
//
// While another of the user's devices removes a device, the server refuses every write of
// every other device with `409 revocation_pending` for up to 10 minutes (the revocation
// window). A host whose sync is refused so shows this banner, keeps the change it could not
// send, retries the same sync on ADR 0091's schedule, and lets every read go on. The banner
// goes with the first sync that succeeds, or when the schedule ends; the host then reports the
// refusal as an ordinary sync error (`errors.server_revocation_pending`).
//
// What the schedule is timed by is the server's unsigned `revocation_window`: a host never
// decides anything else from it (a lying server gains only a delayed or a needless retry). The
// schedule itself is the core's (`revocationRetryAt`, `rizzy-client`'s
// `next_revocation_retry`); `RevocationRetry` only holds the count and the one timer.
//
// The words are the host's: the web vault's catalogue (`revocation.pending`) and the core's
// `revocationPendingNotice` hold the same sentence.
import { useId } from "react";

/** Timers, injected for tests (`itemIcons.ts`'s `IconTimers` shape). */
export interface RevocationTimers {
  set(f: () => void, ms: number): unknown;
  clear(handle: unknown): void;
}

const browserTimers: RevocationTimers = {
  set: (f, ms) => setTimeout(f, ms),
  clear: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

/**
 * The retry of a sync the server refused `revocation_pending` (module docs): at most one timer,
 * and the count of retries made, which the core's schedule takes.
 */
export class RevocationRetry {
  readonly #timers: RevocationTimers;
  readonly #onChange: (paused: boolean) => void;
  #retries = 0;
  #timer: { readonly handle: unknown } | undefined;
  #paused = false;

  /** `onChange` hears when the banner should appear (`true`) or go (`false`). */
  constructor(onChange: (paused: boolean) => void, timers: RevocationTimers = browserTimers) {
    this.#onChange = onChange;
    this.#timers = timers;
  }

  /** The retries made since the last successful sync: what the core's schedule takes next. */
  get retriesDone(): number {
    return this.#retries;
  }

  /** Whether a retry is waiting. */
  get scheduled(): boolean {
    return this.#timer !== undefined;
  }

  /** Whether the banner shows. */
  get paused(): boolean {
    return this.#paused;
  }

  /**
   * A sync was refused `revocation_pending`. `retryAtMs`: the core's answer to
   * `revocationRetryAt(retriesDone)`, Unix milliseconds, or `undefined` when the schedule is
   * over. With a retry already waiting (another sync was refused meanwhile, such as one after a
   * write) nothing changes. Returns whether a retry waits: `false` means stop and report.
   */
  refused(retryAtMs: number | undefined, nowMs: number, retry: () => void): boolean {
    if (this.#timer !== undefined) {
      return true;
    }
    if (retryAtMs === undefined) {
      this.ended();
      return false;
    }
    this.#retries += 1;
    const timer = {
      handle: this.#timers.set(
        () => {
          if (this.#timer === timer) {
            this.#timer = undefined;
            retry();
          }
        },
        Math.max(0, retryAtMs - nowMs),
      ),
    };
    this.#timer = timer;
    this.#set(true);
    return true;
  }

  /** A sync succeeded, the schedule ended, or the vault locked: no retry, no banner. */
  ended(): void {
    if (this.#timer !== undefined) {
      this.#timers.clear(this.#timer.handle);
      this.#timer = undefined;
    }
    this.#retries = 0;
    this.#set(false);
  }

  #set(paused: boolean): void {
    if (this.#paused !== paused) {
      this.#paused = paused;
      this.#onChange(paused);
    }
  }
}

export interface RevocationPendingBannerProps {
  /** The sentence of ADR 0091 §2 (module docs). */
  readonly message: string;
  /** What happens to the change meanwhile, in the host's words. */
  readonly detail?: string | undefined;
}

/** The banner (module docs). A status, not an alert: nothing failed for good, and it has no
 * control, so the keyboard walks past it. */
export function RevocationPendingBanner(props: RevocationPendingBannerProps) {
  const titleId = useId();
  return (
    <section className="revocation-banner" role="status" aria-labelledby={titleId} data-testid="revocation-banner">
      <p>
        <strong id={titleId}>{props.message}</strong>
      </p>
      {props.detail !== undefined && <p>{props.detail}</p>}
    </section>
  );
}
