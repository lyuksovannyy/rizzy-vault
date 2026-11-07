// SPDX-License-Identifier: AGPL-3.0-only

// The lock messages between the service worker and the offscreen document (ADR 0111 §3.1), and
// the storage keys of the lock settings (ADR 0110 §3). On Chromium the offscreen document, which
// holds the core, has neither `chrome.idle` nor `chrome.storage`; the service worker has both and
// holds nothing secret, so it relays the OS idle state and the settings record's text.
//
// This module never imports `@rizzy-vault/core` (the service worker imports it, and the service
// worker never loads the core, ADR 0036 §2). The record is parsed by Rust's `lock_settings` in the
// long-lived context only; {@link idleDetectionSeconds} is the one value the service worker needs
// from it, and it reads the defaults' value whenever the record is not exactly well-formed.
//
// No version field (ADR 0111 §3.1 item 7): these messages pass only between contexts of one
// installed build. None of these types is on the content-script message list, so the
// content-script relay refuses all of them before any handler runs.

/** `rizzy.lock_settings`, ADR 0110 §3 point 2 (also `LOCK_SETTINGS_LIMITS.storageKey`). */
export const LOCK_SETTINGS_KEY = "rizzy.lock_settings";

/** `rizzy.auto_lock_minutes`, the code-only key migrated once (ADR 0110 §3 point 5). */
export const LEGACY_AUTO_LOCK_KEY = "rizzy.auto_lock_minutes";

/** How often the offscreen document asks for the idle state while unlocked (ADR 0111 §3). */
export const IDLE_POLL_MS = 30_000;

/** The idle times of ADR 0110 §1, in minutes. */
const IDLE_MINUTES: readonly number[] = [1, 2, 5, 10, 15, 30, 60, 240];
const DEFAULT_IDLE_MINUTES = 5;
const MAX_RECORD_BYTES = 256;

/** Service worker → offscreen document: the OS reported `"idle"` or `"locked"` (§3.1 item 1). */
export interface IdleStateMessage {
  readonly type: "idle_state";
  readonly state: "idle" | "locked";
}

/** Service worker → offscreen document: the record changed (§3.1 item 4). `null`: removed. */
export interface LockSettingsPush {
  readonly type: "lock_settings";
  readonly settings: string | null;
}

/** Offscreen document → service worker (§3.1 item 3). */
export interface IdleStatusQuery {
  readonly type: "idle_status_query";
}

/** The service worker's answer to {@link IdleStatusQuery}: the OS idle state and the record's
 * text (`null` when absent). `legacy` is the old `rizzy.auto_lock_minutes` value, sent only while
 * the record is absent, so the long-lived context can migrate it (ADR 0110 §3 point 5). */
export interface IdleStatusAnswer {
  readonly type: "idle_status";
  readonly state: string;
  readonly settings: string | null;
  readonly legacy?: number;
}

/** Offscreen document → service worker: the migrated record to write, once (ADR 0110 §3 point
 * 5). Written only while `rizzy.lock_settings` is still absent; the old key is then removed. */
export interface LockSettingsMigrate {
  readonly type: "lock_settings_migrate";
  readonly settings: string;
}

function typeOf(value: unknown): unknown {
  return typeof value === "object" && value !== null ? (value as { type?: unknown }).type : undefined;
}

export function isIdleStateMessage(value: unknown): value is IdleStateMessage {
  if (typeOf(value) !== "idle_state") {
    return false;
  }
  const state = (value as { state?: unknown }).state;
  return state === "idle" || state === "locked";
}

export function isLockSettingsPush(value: unknown): value is LockSettingsPush {
  if (typeOf(value) !== "lock_settings") {
    return false;
  }
  const settings = (value as { settings?: unknown }).settings;
  return settings === null || typeof settings === "string";
}

export function isIdleStatusQuery(value: unknown): value is IdleStatusQuery {
  return typeOf(value) === "idle_status_query";
}

/** A well-formed answer, or `undefined` (ignored, never a lock: §3.1 item 6). */
export function idleStatusAnswerOf(value: unknown): IdleStatusAnswer | undefined {
  if (typeOf(value) !== "idle_status") {
    return undefined;
  }
  const { state, settings, legacy } = value as { state?: unknown; settings?: unknown; legacy?: unknown };
  if (typeof state !== "string" || (settings !== null && typeof settings !== "string")) {
    return undefined;
  }
  if (legacy !== undefined && typeof legacy !== "number") {
    return undefined;
  }
  return { type: "idle_status", state, settings, ...(legacy !== undefined ? { legacy } : {}) };
}

export function isLockSettingsMigrate(value: unknown): value is LockSettingsMigrate {
  return typeOf(value) === "lock_settings_migrate" && typeof (value as { settings?: unknown }).settings === "string";
}

/** A stored value as the record's text: a string, or `null` for anything else. */
export function recordTextOf(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/** A stored legacy value worth sending: a finite number (Rust decides whether it is usable). */
export function legacyMinutesOf(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/**
 * `idle_minutes * 60` of a well-formed v1 record, else the defaults' 300 s: the service worker's
 * `setDetectionInterval` and `queryState` argument (ADR 0111 §3, `idleIntervalSeconds`). It checks
 * every rule of ADR 0110 §3 point 3 that Rust's parser checks (length, a JSON object, `v` exactly
 * 1, each field's type, the idle list), so it can only disagree with Rust by reading the defaults'
 * interval for a record Rust also reads as the defaults. The lock decision itself is Rust's, in
 * the long-lived context. A legacy value is not read here: until the long-lived context has
 * migrated it (which writes the record, and the write reaches this function through
 * `storage.onChanged`), the interval is the defaults' 5 minutes. That lasts until the long-lived
 * context's first query after it starts (ADR 0111 §3.1 item 3), before any unlock.
 */
export function idleDetectionSeconds(record: string | null | undefined): number {
  const fallback = DEFAULT_IDLE_MINUTES * 60;
  if (typeof record !== "string" || new TextEncoder().encode(record).length > MAX_RECORD_BYTES) {
    return fallback;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(record);
  } catch {
    return fallback;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return fallback;
  }
  const r = parsed as Record<string, unknown>;
  const minutes = r["idle_minutes"];
  const wellFormed =
    r["v"] === 1 &&
    typeof r["auto_lock"] === "boolean" &&
    typeof r["lock_on_restart"] === "boolean" &&
    typeof r["lock_on_sleep"] === "boolean" &&
    typeof minutes === "number" &&
    IDLE_MINUTES.includes(minutes);
  return wellFormed ? (minutes as number) * 60 : fallback;
}
