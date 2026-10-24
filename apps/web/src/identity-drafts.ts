// SPDX-License-Identifier: AGPL-3.0-only

// The Worker's identity drafts (ADR 0079 §3, §10), by handle. An `IdentityDraft` of
// packages/core wraps a wasm object, which cannot cross `postMessage`: the Worker keeps it here
// and hands the UI a number plus the draft's plain values (`protocol.ts`'s `identityGenerate`,
// `identityRegenerate`, `identityRelease`). A redraw replaces its draft, freeing the old one; a
// lock frees them all (`core-worker.ts`). At most {@link MAX_IDENTITY_DRAFTS} live at once, the
// oldest freed first, so a UI that forgets a release cannot grow the Worker's memory.
//
// Pure bookkeeping over anything with `free()`; no wasm here, so it is unit-tested in Node.

/** The most drafts kept at once (one open editor needs one). */
export const MAX_IDENTITY_DRAFTS = 8;

/** What the registry frees. */
export interface Freeable {
  free(): void;
}

/** Drafts by handle (module docs). */
export class DraftRegistry<T extends Freeable> {
  readonly #drafts = new Map<number, T>();
  readonly #limit: number;
  #next = 1;

  constructor(limit: number = MAX_IDENTITY_DRAFTS) {
    this.#limit = Math.max(1, limit);
  }

  /** How many drafts are live. */
  get size(): number {
    return this.#drafts.size;
  }

  /** Keeps `draft` and returns its new handle; the oldest is freed past the limit. */
  add(draft: T): number {
    while (this.#drafts.size >= this.#limit) {
      const oldest = this.#drafts.keys().next();
      if (oldest.done === true) {
        break;
      }
      this.release(oldest.value);
    }
    const handle = this.#next;
    this.#next += 1;
    this.#drafts.set(handle, draft);
    return handle;
  }

  /** The draft of `handle`, or `undefined` (released, replaced, or freed by a lock). */
  get(handle: number): T | undefined {
    return this.#drafts.get(handle);
  }

  /** Frees `handle`'s draft and keeps `next` under a new handle. */
  replace(handle: number, next: T): number {
    this.release(handle);
    return this.add(next);
  }

  /** Frees `handle`'s draft; an unknown handle is a no-op. */
  release(handle: number): void {
    const draft = this.#drafts.get(handle);
    if (draft !== undefined) {
      this.#drafts.delete(handle);
      draft.free();
    }
  }

  /** Frees every draft. */
  clear(): void {
    for (const handle of [...this.#drafts.keys()]) {
      this.release(handle);
    }
  }
}
