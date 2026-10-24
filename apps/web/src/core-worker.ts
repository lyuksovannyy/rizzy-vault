// SPDX-License-Identifier: AGPL-3.0-only

// The core Worker: the one context of the web vault that holds the wasm instance, every handle
// and every key (ADR 0013 §4 "Where the core lives"). It runs the KDF, does the HTTP transport
// to its own origin (`/api/v1`, ADR 0028) through packages/core's `fetchTransport`, and answers
// the UI thread's calls (`protocol.ts`) with summaries and requested values only.
//
// Calls run one at a time, in arrival order: the core refuses an edit while a sync runs
// (`wrong_state`), and one queue keeps the UI from interleaving them. `lock` jumps the queue,
// so that the user can lock while a sync waits on the network: it locks the session and aborts
// every request in flight, so the queued call fails at once (`transport_failed`) and the queue
// drains. Every request also has a deadline (`bounded-fetch.ts`), so a stalled server cannot
// hold the queue, and the login after a lock, for longer than that.
//
// A session the server ended (another session ended it, ADR 0075 §6) answers `401`: the Worker
// locks it at once and answers the call `session_ended`. A lock also ends the session on the
// server (`sessions/current/end`), best effort.
//
// A trap (a Rust panic under `panic = "abort"`) leaves the instance in an unknown state: every
// later call answers `core_crashed`, and the UI asks for a reload.
import {
  CoreError,
  type IdentityDraft,
  type IdentityGeneratorOptions,
  Signup,
  type Transport,
  type VaultSession,
  checkPasswordBreach,
  checkServer,
  cxfExportWarning,
  detectImportFormat,
  fetchItemIcon,
  fetchTransport,
  generatePassphraseWithOptions,
  generatePasswordWithOptions,
  generateIdentity,
  generatorLimits,
  identityCountries,
  init,
  login,
  newElementId,
  normalizeEmailDomain,
  othersEndedNotice,
  passphraseEntropy,
  passwordEntropy,
  plaintextExportPhrase,
  plaintextExportWarning,
  sessionEndedByYouNotice,
  sessionEndedNotice,
  version,
} from "@rizzy-vault/core";

import { BoundedTransport } from "./bounded-fetch.ts";
import { DraftRegistry } from "./identity-drafts.ts";
import {
  BAD_MESSAGE,
  CORE_CRASHED,
  type CallMessage,
  type IdentityDraftMessage,
  SESSION_ENDED,
  type CoreApi,
  type FromWorker,
  type KitMessage,
  type SessionInfo,
  TOTP_CANCELLED,
  isIdentityOptions,
  isSettingsChange,
  isToWorker,
  transferables,
} from "./protocol.ts";

/** The part of the dedicated-worker scope this module uses (the DOM lib types the rest). */
interface WorkerScope {
  readonly location: { readonly origin: string };
  postMessage(message: FromWorker, transfer: Transferable[]): void;
  addEventListener(type: "message", listener: (event: MessageEvent<unknown>) => void): void;
}

const scope = globalThis as unknown as WorkerScope;

/** The vault's origin: the Worker is served from it, and the API lives under it. */
const origin = scope.location.origin;
/** Requests with a deadline, aborted on lock (`bounded-fetch.ts`). */
const bounded = new BoundedTransport(
  (fetchImpl) => fetchTransport(origin, fetchImpl),
  globalThis.fetch.bind(globalThis),
);
const transport: Transport = bounded.transport;

let session: VaultSession | undefined;
let signup: Signup | undefined;
let crashed = false;
/** The identity drafts of open "New identity" forms (`identity-drafts.ts`); freed on lock. */
const drafts = new DraftRegistry<IdentityDraft>();
/** Counts locks, so that a login that finishes after a lock does not unlock. */
let lockEpoch = 0;

/** Pending second-factor prompts, by call id. */
const totpWaiters = new Map<number, (code: string | null) => void>();

/** Asks the UI for the second factor of call `id`. */
function askTotp(id: number): () => Promise<string> {
  return () =>
    new Promise<string>((resolve, reject) => {
      totpWaiters.set(id, (code) => {
        totpWaiters.delete(id);
        if (code === null) {
          reject(new CoreError(TOTP_CANCELLED));
        } else {
          resolve(code);
        }
      });
      scope.postMessage({ kind: "ask-totp", id }, []);
    });
}

/** The current session, or `locked`. */
function current(): VaultSession {
  if (session === undefined || session.locked) {
    throw new CoreError("locked");
  }
  return session;
}

/**
 * Locks: every request in flight is aborted first, then the session locks, which also ends it
 * on the server (`sessions/current/end`, ADR 0075 §6), best effort and unawaited, so that the
 * abort does not cancel that request.
 */
function lockSession(): void {
  lockEpoch += 1;
  bounded.abortAll();
  drafts.clear();
  session?.lock();
  session = undefined;
}

/** Identity options from the UI, rebuilt from their checked fields (no `today`: the Worker's
 * clock), or `invalid_input`. */
function identityOptions(v: unknown): IdentityGeneratorOptions {
  if (!isIdentityOptions(v)) {
    throw new CoreError("invalid_input");
  }
  return {
    sex: v.sex,
    country: v.country,
    ageMin: v.ageMin,
    ageMax: v.ageMax,
    emailStyle: v.emailStyle,
    emailDomain: v.emailDomain ?? null,
  };
}

/** A draft kept under `handle`, as it crosses to the UI. */
function draftMessage(handle: number, draft: IdentityDraft): IdentityDraftMessage {
  return { handle, fields: { ...draft.fields }, itemName: draft.itemName };
}

/** The current signup, or `wrong_state`. */
function currentSignup(): Signup {
  if (signup === undefined) {
    throw new CoreError("wrong_state");
  }
  return signup;
}

/** The state the UI shows. */
function info(s: VaultSession): SessionInfo {
  return {
    locked: s.locked,
    accountId: s.accountId,
    deviceId: s.deviceId,
    readOnly: s.readOnly,
    unsentChanges: s.unsentChanges,
    storageUsage: s.storageUsage,
  };
}

/**
 * Replaces the session, locking the one before. A login that started before the latest lock
 * (`epoch`) is locked at once instead: the user locked while it ran.
 */
function setSession(next: VaultSession, epoch: number): SessionInfo {
  if (epoch !== lockEpoch) {
    next.lock();
    throw new CoreError("locked");
  }
  session?.lock();
  session = next;
  return info(next);
}

/** An argument of the expected type, or `invalid_input`. */
function str(v: unknown): string {
  if (typeof v !== "string") {
    throw new CoreError("invalid_input");
  }
  return v;
}

/** A byte-array argument, or `invalid_input`. */
function bytes(v: unknown): Uint8Array {
  if (!(v instanceof Uint8Array)) {
    throw new CoreError("invalid_input");
  }
  return v;
}

/** A boolean argument, or `invalid_input`. */
function bool(v: unknown): boolean {
  if (typeof v !== "boolean") {
    throw new CoreError("invalid_input");
  }
  return v;
}

/** A non-negative safe-integer argument (a list position), or `invalid_input`. */
function index(v: unknown): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
    throw new CoreError("invalid_input");
  }
  return v;
}

/** Zeroes every byte array among `args`, whatever the call did with them. */
function wipe(args: readonly unknown[]): void {
  for (const a of args) {
    if (a instanceof Uint8Array) {
      a.fill(0);
    }
  }
}

/**
 * Runs one call. The argument checks are shape checks only; the core checks every value.
 * Item changes and item types are passed as the core takes them, which refuses anything else
 * (`invalid_input`, `invalid_edit`).
 */
async function run(m: CallMessage): Promise<unknown> {
  const a = m.args;
  const epoch = lockEpoch;
  const api = {
    start: async () => {
      await init();
      await checkServer(transport);
      return { version: version() };
    },
    login: async () => {
      const s = await login(
        transport,
        { origin, loginName: str(a[0]), secretKey: bytes(a[1]), password: bytes(a[2]) },
        askTotp(m.id),
      );
      return setSession(s, epoch);
    },
    signupStart: async () => {
      signup?.cancel();
      signup = undefined;
      const invite = a[2] === undefined ? undefined : str(a[2]);
      signup = await Signup.start(transport, {
        origin,
        loginName: str(a[0]),
        password: bytes(a[1]),
        ...(invite === undefined || invite === "" ? {} : { invite }),
        issueRecoveryCode: bool(a[3]),
      });
    },
    signupKit: (): KitMessage => {
      const kit = currentSignup().emergencyKit();
      return {
        serverOrigin: kit.serverOrigin,
        loginName: kit.loginName,
        secretKey: kit.secretKey,
        recoveryCode: kit.recoveryCode,
      };
    },
    signupConfirm: () => currentSignup().confirm(str(a[0])),
    signupRetryCommit: () => currentSignup().retryCommit(),
    signupLogin: async () => {
      const flow = currentSignup();
      signup = undefined;
      return setSession(await flow.login(askTotp(m.id)), epoch);
    },
    signupCancel: () => {
      signup?.cancel();
      signup = undefined;
    },
    status: () => (session === undefined || session.locked ? undefined : info(session)),
    lock: () => {
      lockSession();
    },
    sync: async () => {
      const s = current();
      await s.sync();
      return info(s);
    },
    items: () => current().items(bool(a[0])),
    item: () => current().item(str(a[0])),
    fields: () => current().fields(str(a[0])),
    customFieldAutofill: () => current().customFieldAutofill(str(a[0])),
    reveal: () => current().reveal(str(a[0]), str(a[1])),
    createItem: () => current().createItem(str(a[0]) as never, a[1] as never),
    editItem: () => current().editItem(str(a[0]), a[1] as never),
    trashItem: () => current().trashItem(str(a[0])),
    restoreItem: () => current().restoreItem(str(a[0])),
    // ADR 0054 §7: the item's attachments go from the server first, or they would stay behind.
    purgeItem: async () => {
      const s = current();
      await s.deleteAttachmentsOf(str(a[0]));
      s.purgeItem(str(a[0]));
    },
    // Dates only; one value per reveal (ADR 0013 §3 rule 3): the history is never sent whole.
    passwordHistory: () => current().passwordHistory(str(a[0])),
    revealPasswordHistory: () =>
      current().revealPasswordHistory(str(a[0]), str(a[1]) as never, index(a[2]), str(a[3])),
    // ROADMAP §4.2: the same dates-only/one-value-per-reveal rule, generalized to every field.
    itemHistory: () => current().itemHistory(str(a[0])),
    revealFieldHistory: () =>
      current().revealFieldHistory(str(a[0]), str(a[1]), index(a[2]), str(a[3])),
    restoreFieldHistory: () =>
      current().restoreFieldHistory(str(a[0]), str(a[1]), index(a[2]), str(a[3])),
    // ROADMAP §4.5 "keep both / pick one": the listing withholds concealed values; one value
    // crosses per reveal; a resolution names the value by its listed index and id.
    fieldConflict: () => current().fieldConflict(str(a[0]), str(a[1])),
    revealConflictValue: () =>
      current().revealConflictValue(str(a[0]), str(a[1]), index(a[2]), str(a[3])),
    resolveConflictPick: () =>
      current().resolveConflictPick(str(a[0]), str(a[1]), index(a[2]), str(a[3])),
    resolveConflictKeepBoth: () =>
      current().resolveConflictKeepBoth(
        str(a[0]),
        str(a[1]),
        index(a[2]),
        str(a[3]),
        a[4] === undefined ? undefined : str(a[4]),
      ),
    takeNotices: () => current().takeNotices(),
    restoreLateAsNew: () => current().restoreLateAsNew(str(a[0]), str(a[1]) as never),
    totp: () => current().totp(str(a[0])),
    breachCheckItem: async () => (await current().checkItemBreach(str(a[0]))) ?? null,
    itemIcon: async () => {
      current();
      return (await fetchItemIcon(transport, str(a[0]))) ?? null;
    },
    breachCheckPassword: () => {
      current();
      return checkPasswordBreach(transport, bytes(a[0]));
    },
    exportEncrypted: () => current().exportEncrypted(bytes(a[0])),
    exportBlockers: () => current().exportBlockers(),
    csvExportWarning: () => current().csvExportWarning(),
    reauthenticate: () => current().reauthenticate(bytes(a[0]), bytes(a[1]), askTotp(m.id)),
    reauthFresh: () => current().reauthFresh(),
    plaintextWarningShown: () => current().plaintextWarningShown(),
    exportPlaintext: () => {
      const format = str(a[0]);
      if (format !== "json" && format !== "csv") {
        throw new CoreError("unknown_format");
      }
      return current().exportPlaintext(format, str(a[1]));
    },
    // Recognition needs no session: the file is read here and never leaves the Worker.
    detectImportFormat: () => detectImportFormat(bytes(a[0])),
    importFile: () => current().importFile(str(a[0]) as never, bytes(a[1])),
    attachments: () => current().attachments(str(a[0])),
    addAttachment: () => current().addAttachment(str(a[0]), str(a[1]), str(a[2]), bytes(a[3])),
    downloadAttachment: () => current().downloadAttachment(str(a[0]), str(a[1])),
    deleteAttachment: () => current().deleteAttachment(str(a[0]), str(a[1])),
    importEncrypted: () => current().importEncrypted(bytes(a[0]), bytes(a[1])),
    cxfExportPasskeys: () => current().cxfExportPasskeys(),
    exportCxf: () => current().exportCxf(str(a[0]), bytes(a[1])),
    importCxfEncrypted: () => current().importCxfEncrypted(bytes(a[0]), bytes(a[1])),
    devices: () => current().devices(),
    sessions: () => current().sessions(),
    endSession: () => current().endSession(str(a[0])),
    endOtherSessions: () => current().endOtherSessions(),
    refreshSession: () => current().refreshSession(bytes(a[0]), bytes(a[1]), askTotp(m.id)),
    sessionNotices: () => ({
      ended: sessionEndedNotice(),
      othersEnded: othersEndedNotice(),
      oneEnded: sessionEndedByYouNotice(),
    }),
    enableTwoFactor: () => current().enableTwoFactor(),
    confirmTwoFactor: () => current().confirmTwoFactor(str(a[0])),
    disableTwoFactor: () => current().disableTwoFactor(str(a[0])),
    matchSettings: () => current().matchSettings(),
    matchCandidates: () => current().matchCandidates(str(a[0])),
    changeMatchSettings: async () => {
      if (!isSettingsChange(a[0])) {
        throw new CoreError("invalid_input");
      }
      await current().changeMatchSettings(a[0]);
    },
    generatePasswordWithOptions: () => generatePasswordWithOptions(a[0] as never),
    generatePassphraseWithOptions: () => generatePassphraseWithOptions(a[0] as never),
    passwordEntropy: () => passwordEntropy(a[0] as never),
    passphraseEntropy: () => passphraseEntropy(a[0] as never),
    generatorLimits: () => generatorLimits(),
    newElementId: () => newElementId(),
    plaintextExportWarning: () => plaintextExportWarning(),
    plaintextExportPhrase: () => plaintextExportPhrase(),
    cxfExportWarning: () => cxfExportWarning(),
      identityCountries: () => identityCountries(),
      identityDefaults: () => current().identityDefaults(),
      normalizeEmailDomain: () => normalizeEmailDomain(str(a[0])),
      identityGenerate: () => {
        const draft = generateIdentity(identityOptions(a[0]));
        return draftMessage(drafts.add(draft), draft);
      },
      identityRegenerate: () => {
        const handle = index(a[0]);
        const old = drafts.get(handle);
        if (old === undefined) {
          throw new CoreError("wrong_state");
        }
        const draft = old.regenerate(str(a[1]), identityOptions(a[2]));
        return draftMessage(drafts.replace(handle, draft), draft);
      },
      identityRelease: () => {
        drafts.release(index(a[0]));
      },
    } satisfies { [K in keyof CoreApi]: () => unknown };
  try {
    return await api[m.method]();
  } finally {
    wipe(a);
  }
}

/** Sends the outcome of call `id`. */
function answer(id: number, outcome: { value: unknown } | { code: string }): void {
  if ("code" in outcome) {
    scope.postMessage({ kind: "result", id, ok: false, code: outcome.code }, []);
  } else {
    scope.postMessage(
      { kind: "result", id, ok: true, value: outcome.value },
      transferables([outcome.value]),
    );
  }
}

/** Runs a call and answers it; a non-`CoreError` throw marks the instance as crashed. */
/**
 * Whether the server ended the current session (ADR 0075 §6: a `401` on a request other than
 * `login/*`, `recovery/*` and the sign-out); if so, it is locked here, which clears its keys
 * and decrypted items as a lock does, and the call answers `session_ended`.
 */
function endedNow(): boolean {
  if (session === undefined || !session.ended) {
    return false;
  }
  lockSession();
  return true;
}

async function serve(m: CallMessage): Promise<void> {
  if (crashed) {
    wipe(m.args);
    answer(m.id, { code: CORE_CRASHED });
    return;
  }
  try {
    const value = await run(m);
    answer(m.id, endedNow() ? { code: SESSION_ENDED } : { value });
  } catch (e) {
    if (e instanceof CoreError) {
      answer(m.id, { code: endedNow() ? SESSION_ENDED : e.code });
    } else {
      // A trap, or a bug in this module: nothing about it is sent (it could hold anything).
      crashed = true;
      session = undefined;
      signup = undefined;
      answer(m.id, { code: CORE_CRASHED });
    }
  }
}

let queue: Promise<void> = Promise.resolve();

scope.addEventListener("message", (event) => {
  const m = event.data;
  if (!isToWorker(m)) {
    const id = (m as { id?: unknown } | null)?.id;
    if (typeof id === "number") {
      answer(id, { code: BAD_MESSAGE });
    }
    return;
  }
  if (m.kind === "totp") {
    totpWaiters.get(m.id)?.(m.code);
    return;
  }
  // An icon fetch touches no session state and may wait on a slow site (the role's budget is
  // 10 s), so it runs beside the queue instead of holding every user action behind it. A lock
  // still aborts it (`bounded.abortAll`), and it refuses to start while locked.
  if (m.method === "lock" || m.method === "itemIcon") {
    void serve(m);
    return;
  }
  queue = queue.then(() => serve(m));
});
