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
// A trap (a Rust panic under `panic = "abort"`) leaves the instance in an unknown state: every
// later call answers `core_crashed`, and the UI asks for a reload.
import {
  CoreError,
  Signup,
  type Transport,
  type VaultSession,
  checkServer,
  detectImportFormat,
  fetchTransport,
  generatePassphraseWithOptions,
  generatePasswordWithOptions,
  generatorLimits,
  init,
  login,
  newElementId,
  passphraseEntropy,
  passwordEntropy,
  plaintextExportPhrase,
  plaintextExportWarning,
  version,
} from "@rizzy-vault/core";

import { BoundedTransport } from "./bounded-fetch.ts";
import {
  BAD_MESSAGE,
  CORE_CRASHED,
  type CallMessage,
  type CoreApi,
  type FromWorker,
  type KitMessage,
  type SessionInfo,
  TOTP_CANCELLED,
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
      lockEpoch += 1;
      session?.lock();
      session = undefined;
      bounded.abortAll();
    },
    sync: async () => {
      const s = current();
      await s.sync();
      return info(s);
    },
    items: () => current().items(bool(a[0])),
    item: () => current().item(str(a[0])),
    fields: () => current().fields(str(a[0])),
    reveal: () => current().reveal(str(a[0]), str(a[1])),
    createItem: () => current().createItem(str(a[0]) as never, a[1] as never),
    editItem: () => current().editItem(str(a[0]), a[1] as never),
    trashItem: () => current().trashItem(str(a[0])),
    restoreItem: () => current().restoreItem(str(a[0])),
    purgeItem: () => current().purgeItem(str(a[0])),
    totp: () => current().totp(str(a[0])),
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
    importEncrypted: () => current().importEncrypted(bytes(a[0]), bytes(a[1])),
    devices: () => current().devices(),
    enableTwoFactor: () => current().enableTwoFactor(),
    confirmTwoFactor: () => current().confirmTwoFactor(str(a[0])),
    disableTwoFactor: () => current().disableTwoFactor(str(a[0])),
    generatePasswordWithOptions: () => generatePasswordWithOptions(a[0] as never),
    generatePassphraseWithOptions: () => generatePassphraseWithOptions(a[0] as never),
    passwordEntropy: () => passwordEntropy(a[0] as never),
    passphraseEntropy: () => passphraseEntropy(a[0] as never),
    generatorLimits: () => generatorLimits(),
    newElementId: () => newElementId(),
    plaintextExportWarning: () => plaintextExportWarning(),
    plaintextExportPhrase: () => plaintextExportPhrase(),
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
async function serve(m: CallMessage): Promise<void> {
  if (crashed) {
    wipe(m.args);
    answer(m.id, { code: CORE_CRASHED });
    return;
  }
  try {
    answer(m.id, { value: await run(m) });
  } catch (e) {
    if (e instanceof CoreError) {
      answer(m.id, { code: e.code });
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
  if (m.method === "lock") {
    void serve(m);
    return;
  }
  queue = queue.then(() => serve(m));
});
