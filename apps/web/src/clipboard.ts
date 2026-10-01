// Copying a value to the clipboard, and clearing it after a timeout (THREAT_MODEL A14, NG-1:
// "The clipboard is cleared after a timeout, but only if it still holds our value").
//
// - The value is cleared after `CLEAR_AFTER_MS` (30 s, the default ADR 0019 §5 sets for the
//   native clients), on lock, and when the page is hidden for good (`pagehide`).
// - The clipboard is read back before clearing only when the page already holds the
//   clipboard-read permission (`readGranted`). The vault never asks for that permission
//   itself: a read would open a browser prompt (Chromium) or a "Paste" popup (Firefox), and
//   a vault that keeps asking teaches users to grant clipboard-read to its origin, which any
//   script injected into that origin would then inherit. When it can read, it clears only if
//   the clipboard still holds the copied value, so a value the user copied since is left alone.
// - When it cannot read (no permission, Firefox, a read that fails), it cannot tell whose
//   value is there, and clears anyway: leaving a password on the clipboard is the worse
//   failure. That is this module's reading of A14, reported to the owner.
// - A clear that fails is kept, not dropped. Browsers refuse clipboard writes from a page
//   without focus ("Document is not focused"), which is the usual state 30 s after a copy: the
//   user switched to another app to paste. The clear is then retried whenever the page gets
//   focus back or becomes visible (`retrySignals`), and dropped only after a write succeeded,
//   or after a read-back showed another value. The guard keeps listening after the vault
//   locks, since a lock is one of the moments it clears.
// - Nothing in the vault awaits a clear before doing something more important: a lock never
//   waits on the clipboard (`VaultView.tsx`).
// - A newer copy replaces the pending clear of an older one.
//
// Honest limits: browsers have no "sensitive" clipboard flag for web pages, so clipboard
// history and cross-device clipboard sync can keep the value (AR-16); and a clear due when the
// page closes (`pagehide`) without focus fails with no later chance to retry.

/** How long a copied secret stays on the clipboard. */
export const CLEAR_AFTER_MS = 30_000;

/** The clipboard calls this module uses (the async Clipboard API). */
export interface ClipboardPort {
  writeText(text: string): Promise<void>;
  readText(): Promise<string>;
  /** Whether a `readText` would answer without asking the user (module docs). */
  readGranted(): Promise<boolean>;
}

/** Timer functions, injectable for tests. */
export interface Timers {
  set(f: () => void, ms: number): unknown;
  clear(handle: unknown): void;
}

/**
 * When to retry a clear that failed: `subscribe` calls `retry` on every such moment, and
 * returns the function that stops it.
 */
export interface RetrySignals {
  subscribe(retry: () => void): () => void;
}

const browserTimers: Timers = {
  set: (f, ms) => setTimeout(f, ms),
  clear: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

/** The page got focus back, or became visible. */
export const browserRetrySignals: RetrySignals = {
  subscribe(retry) {
    const onVisible = () => {
      if (document.visibilityState === "visible") {
        retry();
      }
    };
    window.addEventListener("focus", retry);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.removeEventListener("focus", retry);
      document.removeEventListener("visibilitychange", onVisible);
    };
  },
};

/** The browser's clipboard (`navigator.clipboard`) with the permission check of the module docs. */
export const browserClipboard: ClipboardPort = {
  writeText: (t) => navigator.clipboard.writeText(t),
  readText: () => navigator.clipboard.readText(),
  async readGranted() {
    try {
      // `clipboard-read` is not in every browser's permission registry (Firefox throws).
      const status = await navigator.permissions.query({ name: "clipboard-read" as PermissionName });
      return status.state === "granted";
    } catch {
      return false;
    }
  },
};

/** A copied value waiting to be cleared. */
interface Pending {
  readonly value: string;
  /** The timeout's handle, until it fires or the clear is due. */
  timer: unknown;
  /** Whether the clear is due (the timeout fired, or `clearNow` asked). */
  due: boolean;
}

/** Copies values and clears them again (module docs). */
export class ClipboardGuard {
  readonly #clipboard: ClipboardPort;
  readonly #timers: Timers;
  readonly #signals: RetrySignals;
  #pending: Pending | undefined;
  /** Stops listening for retry moments; set while a due clear has failed. */
  #unsubscribe: (() => void) | undefined;
  /** Whether a clear attempt is running, so that two do not overlap. */
  #attempting = false;

  constructor(
    clipboard: ClipboardPort,
    timers: Timers = browserTimers,
    signals: RetrySignals = browserRetrySignals,
  ) {
    this.#clipboard = clipboard;
    this.#timers = timers;
    this.#signals = signals;
  }

  /** Copies `value` and schedules its clearing. Rejects if the browser refuses the write. */
  async copy(value: string): Promise<void> {
    await this.#clipboard.writeText(value);
    if (this.#pending !== undefined) {
      // The new value overwrote the old one, so the old clear (and its retries) is moot.
      this.#timers.clear(this.#pending.timer);
      this.#stopRetrying();
    }
    const pending: Pending = { value, timer: undefined, due: false };
    pending.timer = this.#timers.set(() => {
      pending.due = true;
      void this.#attempt();
    }, CLEAR_AFTER_MS);
    this.#pending = pending;
  }

  /** Whether a copied value is waiting to be cleared. */
  get pending(): boolean {
    return this.#pending !== undefined;
  }

  /**
   * Clears the copied value now if the clipboard still holds it (module docs). Resolves after
   * this attempt; a failed attempt stays pending and is retried on the next focus. Never
   * rejects, and never waits on the user: callers may still choose not to await it.
   */
  async clearNow(): Promise<void> {
    const pending = this.#pending;
    if (pending === undefined) {
      return;
    }
    pending.due = true;
    this.#timers.clear(pending.timer);
    await this.#attempt();
  }

  /** One attempt at the due clear (module docs). */
  async #attempt(): Promise<void> {
    const pending = this.#pending;
    if (pending === undefined || !pending.due || this.#attempting) {
      return;
    }
    this.#attempting = true;
    let done = false;
    try {
      let current: string | undefined;
      if (await this.#clipboard.readGranted().catch(() => false)) {
        try {
          current = await this.#clipboard.readText();
        } catch {
          current = undefined;
        }
      }
      if (this.#pending !== pending) {
        // A newer copy replaced this one while we waited: writing now would clear the newer
        // value before its own timeout. Its own clear handles it (below).
      } else if (current !== undefined && current !== pending.value) {
        done = true;
      } else {
        try {
          await this.#clipboard.writeText("");
          done = true;
        } catch {
          // No focus, or no permission: retried on the next focus (module docs).
        }
      }
    } finally {
      this.#attempting = false;
    }
    if (this.#pending !== pending) {
      // The newer value's timeout may have fired while this attempt ran, and was skipped.
      void this.#attempt();
      return;
    }
    if (done) {
      this.#pending = undefined;
      this.#stopRetrying();
    } else if (this.#unsubscribe === undefined) {
      this.#unsubscribe = this.#signals.subscribe(() => void this.#attempt());
    }
  }

  /** Stops listening for retry moments. */
  #stopRetrying(): void {
    this.#unsubscribe?.();
    this.#unsubscribe = undefined;
  }
}
