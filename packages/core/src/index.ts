// @rizzy-vault/core — the only way UI code reaches the Rust core (ADR 0013 §4 "One entry point
// for UI code"; ADR 0014 §2, §4). This file is the set to review when the boundary changes.
//
// What it does:
// - loads the wasm module generated from `crates/rizzy-wasm` (`cargo xtask build-wasm`); the
//   generated files are reachable only through this module (the package's `exports` field does
//   not export them);
// - performs the HTTP transport for the core, which is sans-I/O: Rust builds every request and
//   verifies every answer, this module only carries bytes (`fetchTransport`);
// - turns the generated classes into plain objects and frees them at once, so no handle but
//   the session's outlives a call;
// - turns the core's thrown `CoreError` objects into `CoreError` instances of this module, with
//   the same stable code.
//
// Where it runs: in the web vault, inside one dedicated Worker that holds the only wasm
// instance with keys (ADR 0013 §4 "Where the core lives"). The UI thread exchanges summaries and
// revealed values with that Worker by message; it never imports this module itself.
//
// Honest limit (ADR 0013 §4): JavaScript strings cannot be wiped. Secrets the user types go
// in, and the Emergency Kit's secrets come out, as byte arrays that are zeroed after use
// (`SecretInput`; ADR 0019 §3), but a string the UI held before stays in the JS heap until
// garbage-collected, as do revealed values and plaintext exports.

import initWasm, {
  CoreError as WasmCoreError,
  HttpRequest,
  ItemDraft,
  LoginFlow,
  Session,
  SignupFlow,
  TwoFactorEnrolment,
  checkMeta,
  coreVersion,
  expectNoContent,
  generatePassphrase as wasmGeneratePassphrase,
  generatePassword as wasmGeneratePassword,
  initSync,
  metaRequest,
  plaintextExportPhrase as wasmPlaintextExportPhrase,
  plaintextExportWarning as wasmPlaintextExportWarning,
} from "../generated/rizzy_core.js";

// ---------------------------------------------------------------------------------------------
// Errors

/** A failed core call: a stable code and nothing else (ADR 0013 §3 rule 4). */
export class CoreError extends Error {
  /** The stable code, such as `wrong_password_or_secret_key` or `server_rate_limited`. */
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "CoreError";
    this.code = code;
  }
}

/** Codes this module adds to the core's. */
export const TRANSPORT_FAILED = "transport_failed";
export const NOT_INITIALISED = "not_initialised";

/** Runs a core call, translating what it throws into a {@link CoreError}. */
function call<T>(f: () => T): T {
  try {
    return f();
  } catch (e) {
    throw toCoreError(e);
  }
}

/** The {@link CoreError} of anything a core call threw. */
function toCoreError(e: unknown): unknown {
  if (e instanceof WasmCoreError) {
    const code = e.code;
    e.free();
    return new CoreError(code);
  }
  // A trap (`RuntimeError: unreachable`) after a panic, which `panic = "abort"` turns into an
  // abort: the instance may be in any state. It is not translated; the host reloads.
  return e;
}

// ---------------------------------------------------------------------------------------------
// Loading the module

let ready = false;

/**
 * Loads the wasm module. In a browser or Worker, with no argument, it fetches the module next
 * to the generated JavaScript; tests and hosts that already have the bytes pass them.
 */
export async function init(module?: BufferSource | WebAssembly.Module | URL): Promise<void> {
  if (ready) {
    return;
  }
  if (module === undefined) {
    await initWasm();
  } else {
    await initWasm({ module_or_path: module });
  }
  ready = true;
}

/** Loads the wasm module synchronously from its bytes (Node tests, a Worker with the bytes). */
export function initFromBytes(bytes: BufferSource | WebAssembly.Module): void {
  if (ready) {
    return;
  }
  initSync({ module: bytes });
  ready = true;
}

/** Throws unless {@link init} or {@link initFromBytes} ran. */
function ensureReady(): void {
  if (!ready) {
    throw new CoreError(NOT_INITIALISED);
  }
}

/** The core's version, as the `Rizzy-Client` header carries it. */
export function version(): string {
  ensureReady();
  return coreVersion();
}

// ---------------------------------------------------------------------------------------------
// Secrets as bytes

/**
 * A secret the user typed: the master password, the Secret Key, an export password. The core
 * takes it only as UTF-8 bytes, never as a string (CRYPTO.md §12.2; ADR 0019 §3 "Secrets cross
 * as bytes"). A string is encoded into an array this module zeroes after the call; a
 * `Uint8Array` is the caller's, and holds zeroes when the call returns, whatever its outcome
 * (the core wipes it, and this module zeroes it again). The string itself cannot be wiped;
 * a host that never holds one passes the bytes.
 */
export type SecretInput = string | Uint8Array;

/** Runs `f` on the secrets as byte arrays, and zeroes every array afterwards. */
function withSecrets<T>(secrets: readonly SecretInput[], f: (bytes: Uint8Array[]) => T): T {
  const encoder = new TextEncoder();
  const bytes = secrets.map((s) => (typeof s === "string" ? encoder.encode(s) : s));
  try {
    return f(bytes);
  } finally {
    for (const b of bytes) {
      b.fill(0);
    }
  }
}

/** The array at `i`, which {@link withSecrets} always provides. */
function at(bytes: readonly Uint8Array[], i: number): Uint8Array {
  const b = bytes[i];
  if (b === undefined) {
    throw new CoreError("invalid_input");
  }
  return b;
}

// ---------------------------------------------------------------------------------------------
// Transport

/** A request the core built: everything the host sends, nothing it may change. */
export interface CoreRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array | undefined;
}

/** The answer the host hands back: the status and the body bytes. */
export interface CoreResponse {
  readonly status: number;
  readonly body: Uint8Array;
}

/** Carries one request to the server and returns its answer. */
export type Transport = (request: CoreRequest) => Promise<CoreResponse>;

/**
 * The largest body read: the largest body `/api/v1` sizes anything for (ADR 0028 item 7). The
 * core checks it again.
 */
export const MAX_RESPONSE_BYTES = 256 * 1024 * 1024;

/** Copies a generated request into a plain object and frees it. */
function takeRequest(request: HttpRequest): CoreRequest {
  try {
    const headers: Record<string, string> = {
      [HttpRequest.clientHeaderName()]: request.client,
    };
    const authorization = request.authorization;
    if (authorization !== undefined) {
      headers["Authorization"] = authorization;
    }
    const contentType = request.contentType;
    if (contentType !== undefined) {
      headers["Content-Type"] = contentType;
    }
    return { method: request.method, path: request.path, headers, body: request.body };
  } finally {
    request.free();
  }
}

/**
 * Reads a response body, refusing more than `max` bytes (`response_too_large`). A body that
 * breaks off mid-read is a `transport_failed` {@link CoreError}.
 */
async function readLimited(response: Response, max: number): Promise<Uint8Array> {
  const declared = response.headers.get("Content-Length");
  if (declared !== null && Number(declared) > max) {
    await response.body?.cancel();
    throw new CoreError("response_too_large");
  }
  if (response.body === null) {
    return new Uint8Array(0);
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    let chunk: ReadableStreamReadResult<Uint8Array>;
    try {
      chunk = await reader.read();
    } catch {
      throw new CoreError(TRANSPORT_FAILED);
    }
    const { done, value } = chunk;
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new CoreError("response_too_large");
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of chunks) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

/**
 * The transport over `fetch` to `origin` (the vault's own origin, `location.origin`): no
 * redirects, no cookies, no cache (ADR 0028 items 1, 4; INV-52). A network failure is a
 * `transport_failed` {@link CoreError}.
 */
export function fetchTransport(
  origin: string,
  fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
): Transport {
  return async (request) => {
    let response: Response;
    try {
      const init: RequestInit = {
        method: request.method,
        headers: request.headers,
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
      };
      if (request.body !== undefined) {
        init.body = request.body as Uint8Array<ArrayBuffer>;
      }
      response = await fetchImpl(origin + request.path, init);
    } catch {
      throw new CoreError(TRANSPORT_FAILED);
    }
    return { status: response.status, body: await readLimited(response, MAX_RESPONSE_BYTES) };
  };
}

/** The host's clock, as the core takes it. */
export type Clock = () => number;

/** `Date.now()` as a `bigint`. */
function nowOf(clock: Clock): bigint {
  return BigInt(Math.trunc(clock()));
}

/** `GET /api/meta`: whether the server speaks `v1`, checked before anything secret is typed. */
export async function checkServer(transport: Transport): Promise<void> {
  ensureReady();
  const answer = await transport(takeRequest(metaRequest()));
  call(() => checkMeta(answer.status, answer.body));
}

// ---------------------------------------------------------------------------------------------
// Signup and login

/** What the user types to log in. */
export interface LoginInput {
  readonly origin: string;
  readonly loginName: string;
  readonly secretKey: SecretInput;
  readonly password: SecretInput;
  /** The second factor, if the host already has it. */
  readonly totp?: string;
}

/** Asks the user for the second factor when the server wants one. */
export type AskTotp = () => Promise<string>;

/** Drives a login flow to `"done"` or `"needs_totp"`. */
async function drive(
  flow: LoginFlow,
  transport: Transport,
  clock: Clock,
  askTotp: AskTotp | undefined,
): Promise<void> {
  for (;;) {
    const state = flow.state;
    if (state === "request") {
      const answer = await transport(takeRequest(call(() => flow.request())));
      call(() => flow.respond(answer.status, answer.body, nowOf(clock)));
    } else if (state === "needs_totp") {
      if (askTotp === undefined) {
        throw new CoreError("server_second_factor_required");
      }
      const code = await askTotp();
      call(() => flow.provideTotp(code));
    } else {
      return;
    }
  }
}

/**
 * Logs in (CRYPTO.md §11.4: every web-vault session is an OPAQUE login) and returns the
 * session. `askTotp` is called if the account has 2FA and `input.totp` is missing.
 */
export async function login(
  transport: Transport,
  input: LoginInput,
  askTotp?: AskTotp,
  clock: Clock = Date.now,
): Promise<VaultSession> {
  // `ensureReady` inside, so that byte secrets are zeroed even before the module is loaded.
  const flow = withSecrets([input.secretKey, input.password], (b) => {
    ensureReady();
    return call(() =>
      LoginFlow.start(input.origin, input.loginName, at(b, 0), at(b, 1), input.totp),
    );
  });
  try {
    await drive(flow, transport, clock, askTotp);
  } catch (e) {
    flow.free();
    throw e;
  }
  return new VaultSession(call(() => flow.finish()), transport, clock);
}

/** What the user types to sign up. */
export interface SignupInput {
  readonly origin: string;
  readonly loginName: string;
  readonly password: SecretInput;
  readonly invite?: string;
  /** Whether to issue a recovery code; the UI's default is yes (CRYPTO.md §11.9). */
  readonly issueRecoveryCode: boolean;
}

/**
 * The Emergency Kit: shown once, then forgotten (ADR 0013 §3 rule 2). The Secret Key and the
 * recovery code are UTF-8 bytes (ADR 0019 §3), so the host can zero them (`fill(0)`) once the
 * kit is rendered; `TextDecoder` turns them into text for display.
 */
export interface EmergencyKit {
  readonly serverOrigin: string;
  readonly loginName: string;
  readonly secretKey: Uint8Array;
  readonly recoveryCode: Uint8Array | undefined;
}

/**
 * A signup in the order of "Secrets before commit" (CRYPTO.md §11): `start` registers and
 * builds everything; `emergencyKit` hands the kit out once; `confirm` checks the re-typed last
 * group of the Secret Key and sends the commit; `login` opens the first session.
 */
export class Signup {
  #flow: SignupFlow | undefined;
  readonly #transport: Transport;
  readonly #clock: Clock;

  private constructor(flow: SignupFlow, transport: Transport, clock: Clock) {
    this.#flow = flow;
    this.#transport = transport;
    this.#clock = clock;
  }

  /** Starts the signup and runs the registration (one Argon2id run). */
  static async start(
    transport: Transport,
    input: SignupInput,
    clock: Clock = Date.now,
  ): Promise<Signup> {
    // `ensureReady` inside, so that a byte password is zeroed even before the module is loaded.
    const flow = withSecrets([input.password], (b) => {
      ensureReady();
      return call(() =>
        SignupFlow.start(
          input.origin,
          input.loginName,
          at(b, 0),
          input.invite,
          input.issueRecoveryCode,
          nowOf(clock),
        ),
      );
    });
    const signup = new Signup(flow, transport, clock);
    try {
      await signup.#send();
    } catch (e) {
      signup.#dispose();
      throw e;
    }
    return signup;
  }

  /** The flow, or `wrong_state` once it was consumed. */
  #current(): SignupFlow {
    if (this.#flow === undefined) {
      throw new CoreError("wrong_state");
    }
    return this.#flow;
  }

  /** Sends the outstanding request and passes the answer in. */
  async #send(): Promise<void> {
    const flow = this.#current();
    const answer = await this.#transport(takeRequest(call(() => flow.request())));
    call(() => flow.respond(answer.status, answer.body));
  }

  /** Frees the flow. */
  #dispose(): void {
    this.#flow?.free();
    this.#flow = undefined;
  }

  /** The Emergency Kit, once. */
  emergencyKit(): EmergencyKit {
    const kit = call(() => this.#current().emergencyKit());
    try {
      return {
        serverOrigin: kit.serverOrigin,
        loginName: kit.loginName,
        secretKey: kit.secretKey,
        recoveryCode: kit.recoveryCode,
      };
    } finally {
      kit.free();
    }
  }

  /**
   * Confirms the kit with the last group of the Secret Key and sends the commit. On an error
   * answer the commit stays outstanding; `retryCommit` sends the same bytes again.
   */
  async confirm(lastGroup: string): Promise<void> {
    const flow = this.#current();
    call(() => flow.confirmKit(lastGroup));
    await this.#send();
  }

  /** Sends the commit again after an unknown outcome (ADR 0028 "Register finish"). */
  async retryCommit(): Promise<void> {
    await this.#send();
  }

  /** The first session, after the commit was acknowledged. Consumes the signup. */
  async login(askTotp?: AskTotp): Promise<VaultSession> {
    const flow = this.#current();
    this.#flow = undefined;
    const loginFlow = call(() => flow.login());
    try {
      await drive(loginFlow, this.#transport, this.#clock, askTotp);
    } catch (e) {
      loginFlow.free();
      throw e;
    }
    return new VaultSession(call(() => loginFlow.finish()), this.#transport, this.#clock);
  }

  /** Abandons the signup and wipes what it holds. */
  cancel(): void {
    this.#dispose();
  }
}

// ---------------------------------------------------------------------------------------------
// Items

/** One change of an item edit; a list of them is written as one op. */
export type ItemChange =
  | { readonly op: "set"; readonly key: string; readonly value: string }
  | { readonly op: "clear"; readonly key: string }
  | { readonly op: "tag"; readonly name: string }
  | { readonly op: "untag"; readonly name: string }
  | { readonly op: "addUri"; readonly uri: string }
  | {
      readonly op: "addCustomField";
      readonly label: string;
      readonly kind: "text" | "hidden" | "boolean";
      readonly value: string;
    }
  | { readonly op: "removeElement"; readonly list: string; readonly element: string };

/** The item types the core names. */
export type ItemType =
  | "login"
  | "note"
  | "card"
  | "identity"
  | "ssh-key"
  | "api-credential"
  | "software-license"
  | "wifi"
  | "bank-account"
  | "passkey";

/** One row of an item list: no concealed value. */
export interface ItemSummary {
  readonly id: string;
  readonly itemType: ItemType | "unknown";
  readonly title: string;
  readonly username: string | undefined;
  readonly favorite: boolean;
  readonly hasTotp: boolean;
  readonly trashed: boolean;
}

/** One displayed field. `value` is absent while `concealed`; reveal it with `reveal`. */
export interface FieldView {
  readonly key: string;
  readonly list: string | undefined;
  readonly element: string | undefined;
  readonly attribute: string | undefined;
  readonly tag: string | undefined;
  readonly kind: "text" | "bool" | "number" | "enum" | "bytes" | "sort_key" | "unknown";
  readonly concealed: boolean;
  readonly value: string | undefined;
  readonly conflict: boolean;
}

/** A current TOTP code. */
export interface TotpCode {
  readonly code: string;
  readonly validForSeconds: number;
  readonly periodSeconds: number;
}

/** An encrypted export: ciphertext to save as a download. */
export interface EncryptedExport {
  readonly file: Uint8Array;
  readonly items: number;
  readonly unresolved: number;
}

/** What an import did, as counts. */
export interface ImportReport {
  readonly imported: number;
  readonly skipped: number;
  readonly warnings: number;
  readonly collapsedConflicts: number;
  readonly historyNotCarried: number;
  readonly fieldsNotCarried: number;
}

/** The import formats of other products, and our own plaintext JSON. */
export type ImportFormat =
  | "bitwarden-json"
  | "1pux"
  | "keepass-xml"
  | "csv"
  | "chrome-csv"
  | "firefox-csv"
  | "rizzy-json";

/** One durable device of the account. */
export interface DeviceView {
  readonly id: string;
  readonly kind: string;
  readonly createdAtMs: number;
  readonly revoked: boolean;
}

/** A started 2FA enrolment, to show once. */
export interface TwoFactorSetup {
  readonly otpauthUri: string;
  readonly secret: string;
}

/** Builds the core's draft from a change list. */
function draftOf(changes: readonly ItemChange[]): ItemDraft {
  const draft = new ItemDraft();
  try {
    for (const change of changes) {
      call(() => {
        switch (change.op) {
          case "set":
            draft.set(change.key, change.value);
            break;
          case "clear":
            draft.clear(change.key);
            break;
          case "tag":
            draft.tag(change.name);
            break;
          case "untag":
            draft.untag(change.name);
            break;
          case "addUri":
            draft.addUri(change.uri);
            break;
          case "addCustomField":
            draft.addCustomField(change.label, change.kind, change.value);
            break;
          case "removeElement":
            draft.removeElement(change.list, change.element);
            break;
        }
      });
    }
    return draft;
  } catch (e) {
    draft.free();
    throw e;
  }
}

/** Frees each element of a generated array after mapping it. */
function mapFree<T extends { free(): void }, U>(items: T[], f: (item: T) => U): U[] {
  try {
    return items.map(f);
  } finally {
    for (const item of items) {
      item.free();
    }
  }
}

/** Maps one generated value and frees it. */
function mapOne<T extends { free(): void }, U>(item: T, f: (item: T) => U): U {
  try {
    return f(item);
  } finally {
    item.free();
  }
}

// ---------------------------------------------------------------------------------------------
// The session

/**
 * An unlocked session. The keys live in the core's memory behind this handle; `lock` wipes
 * them. One call per user action (ADR 0013 §3 rule 6). Writes go to memory first; `sync`
 * uploads them.
 */
export class VaultSession {
  #session: Session | undefined;
  readonly #transport: Transport;
  readonly #clock: Clock;
  #enrolment: TwoFactorEnrolment | undefined;

  /** @internal Use {@link login} or {@link Signup.login}. */
  constructor(session: Session, transport: Transport, clock: Clock) {
    this.#session = session;
    this.#transport = transport;
    this.#clock = clock;
  }

  /** The session, or `locked`. */
  #s(): Session {
    if (this.#session === undefined) {
      throw new CoreError("locked");
    }
    return this.#session;
  }

  /** The clock as the core takes it. */
  #now(): bigint {
    return nowOf(this.#clock);
  }

  /** Whether the session was locked. */
  get locked(): boolean {
    return this.#session === undefined;
  }

  /** The account id (hex). */
  get accountId(): string {
    return call(() => this.#s().accountId);
  }

  /** The ephemeral device's id (hex). */
  get deviceId(): string {
    return call(() => this.#s().deviceId);
  }

  /** Whether writes are refused. */
  get readOnly(): boolean {
    return call(() => this.#s().readOnly);
  }

  /** Own changes the server has not acknowledged: what `lock` would lose. */
  get unsentChanges(): number {
    return call(() => this.#s().unsentChanges);
  }

  /** Locks: wipes every key and decrypted item; unsent changes are lost. */
  lock(): void {
    this.#enrolment?.free();
    this.#enrolment = undefined;
    this.#session?.lock();
    this.#session?.free();
    this.#session = undefined;
  }

  /**
   * Fetches, heals if needed, uploads, and fetches again (the core's sync driver). An error
   * from the core ends the sync there. When the transport throws (`transport_failed`,
   * `response_too_large`, a broken-off body), the sync is aborted in the core before the error
   * is rethrown: the outcome of that request is unknown, the unsent changes stay queued, and
   * the next `sync()` sends them again (ADR 0028 "Retry after an unknown outcome"). Writes are
   * accepted again at once.
   */
  async sync(): Promise<void> {
    const s = this.#s();
    call(() => s.syncStart());
    for (;;) {
      const request = call(() => s.syncRequest());
      if (request === undefined) {
        return;
      }
      let answer: CoreResponse;
      try {
        answer = await this.#transport(takeRequest(request));
      } catch (e) {
        // A lock while the request was out already ended the sync (and freed `s`).
        if (this.#session === s) {
          call(() => s.syncAbort());
        }
        throw e;
      }
      if (this.#session !== s) {
        throw new CoreError("locked");
      }
      call(() => s.syncRespond(answer.status, answer.body, this.#now()));
    }
  }

  /** The active items, or the trashed ones. */
  items(trash = false): ItemSummary[] {
    return mapFree(
      call(() => this.#s().items(trash)),
      (i) => ({
        id: i.id,
        itemType: i.itemType as ItemType | "unknown",
        title: i.title,
        username: i.username,
        favorite: i.favorite,
        hasTotp: i.hasTotp,
        trashed: i.trashed,
      }),
    );
  }

  /** One item's summary. */
  item(id: string): ItemSummary {
    return mapOne(
      call(() => this.#s().item(id)),
      (i) => ({
        id: i.id,
        itemType: i.itemType as ItemType | "unknown",
        title: i.title,
        username: i.username,
        favorite: i.favorite,
        hasTotp: i.hasTotp,
        trashed: i.trashed,
      }),
    );
  }

  /** One item's fields; concealed values are absent. */
  fields(id: string): FieldView[] {
    return mapFree(
      call(() => this.#s().itemFields(id)),
      (f) => ({
        key: f.key,
        list: f.list,
        element: f.element,
        attribute: f.attribute,
        tag: f.tag,
        kind: f.kind as FieldView["kind"],
        concealed: f.concealed,
        value: f.value,
        conflict: f.conflict,
      }),
    );
  }

  /** One field's value, on the user's request only. */
  reveal(id: string, key: string): string {
    return call(() => this.#s().revealField(id, key));
  }

  /** Creates an item; returns its id. */
  createItem(itemType: ItemType, changes: readonly ItemChange[]): string {
    const draft = draftOf(changes);
    try {
      return call(() => this.#s().createItem(itemType, draft, this.#now()));
    } finally {
      draft.free();
    }
  }

  /** Edits an active item as one op. */
  editItem(id: string, changes: readonly ItemChange[]): void {
    const draft = draftOf(changes);
    try {
      call(() => this.#s().editItem(id, draft, this.#now()));
    } finally {
      draft.free();
    }
  }

  /** Moves an item to the trash. */
  trashItem(id: string): void {
    call(() => this.#s().trashItem(id, this.#now()));
  }

  /** Restores a trashed item. */
  restoreItem(id: string): void {
    call(() => this.#s().restoreItem(id, this.#now()));
  }

  /** Purges a trashed item for good. */
  purgeItem(id: string): void {
    call(() => this.#s().purgeItem(id, this.#now()));
  }

  /** The item's current TOTP code. */
  totp(id: string): TotpCode {
    return mapOne(
      call(() => this.#s().totp(id, this.#now())),
      (t) => ({ code: t.code, validForSeconds: t.validForSeconds, periodSeconds: t.periodSeconds }),
    );
  }

  /** The vault as an encrypted export file under a new export password. */
  exportEncrypted(exportPassword: SecretInput): EncryptedExport {
    const s = this.#s();
    return mapOne(
      withSecrets([exportPassword], (b) => call(() => s.exportEncrypted(at(b, 0), this.#now()))),
      (e) => ({ file: e.file, items: e.items, unresolved: e.unresolved }),
    );
  }

  /** The ids of the items too large to export. */
  exportBlockers(): string[] {
    return call(() => this.#s().exportBlockers());
  }

  /** The warning to add before a CSV export. */
  csvExportWarning(): string {
    return call(() => this.#s().csvExportWarning());
  }

  /**
   * Re-authenticates (an OPAQUE login of this account) for one plaintext export within five
   * minutes.
   */
  async reauthenticate(
    secretKey: SecretInput,
    password: SecretInput,
    askTotp?: AskTotp,
    totp?: string,
  ): Promise<void> {
    const s = this.#s();
    const flow = withSecrets([secretKey, password], (b) =>
      call(() => s.reauth(at(b, 0), at(b, 1), totp)),
    );
    try {
      await drive(flow, this.#transport, this.#clock, askTotp);
      call(() => s.confirmReauth(flow, this.#now()));
    } finally {
      flow.free();
    }
  }

  /**
   * The plaintext export, after {@link plaintextExportWarning} was shown and the user typed
   * {@link plaintextExportPhrase}, within five minutes of {@link reauthenticate}.
   */
  exportPlaintext(format: "json" | "csv", typedPhrase: string): Uint8Array {
    return call(() => this.#s().exportPlaintext(format, typedPhrase, this.#now()));
  }

  /** Imports another product's file, or our own plaintext JSON, as new items. */
  importFile(format: ImportFormat, file: Uint8Array): ImportReport {
    return mapOne(call(() => this.#s().importFile(format, file, this.#now())), report);
  }

  /** Imports our own encrypted export as new items. */
  importEncrypted(file: Uint8Array, exportPassword: SecretInput): ImportReport {
    const s = this.#s();
    return mapOne(
      withSecrets([exportPassword], (b) =>
        call(() => s.importEncrypted(file, at(b, 0), this.#now())),
      ),
      report,
    );
  }

  /** The account's durable devices, as the login verified them. */
  devices(): DeviceView[] {
    return mapFree(
      call(() => this.#s().devices()),
      (d) => ({ id: d.id, kind: d.kind, createdAtMs: Number(d.createdAtMs), revoked: d.revoked }),
    );
  }

  /** Starts a 2FA enrolment: the server's secret, to show once (QR or Base32). */
  async enableTwoFactor(): Promise<TwoFactorSetup> {
    const s = this.#s();
    const answer = await this.#transport(takeRequest(call(() => s.twoFactorEnrolRequest())));
    const enrolment = call(() => s.twoFactorEnrolResponse(answer.status, answer.body));
    this.#enrolment?.free();
    this.#enrolment = enrolment;
    return { otpauthUri: enrolment.otpauthUri, secret: enrolment.secret };
  }

  /** Confirms the started enrolment with the authenticator's current code. */
  async confirmTwoFactor(code: string): Promise<void> {
    const s = this.#s();
    const enrolment = this.#enrolment;
    if (enrolment === undefined) {
      throw new CoreError("wrong_state");
    }
    const answer = await this.#transport(
      takeRequest(call(() => s.twoFactorConfirmRequest(enrolment, code))),
    );
    call(() => expectNoContent(answer.status, answer.body));
    enrolment.free();
    this.#enrolment = undefined;
  }

  /** Removes 2FA with a current code. */
  async disableTwoFactor(code: string): Promise<void> {
    const s = this.#s();
    const answer = await this.#transport(takeRequest(call(() => s.twoFactorDisableRequest(code))));
    call(() => expectNoContent(answer.status, answer.body));
  }
}

/** An import report as a plain object. */
function report(r: {
  imported: number;
  skipped: number;
  warnings: number;
  collapsedConflicts: number;
  historyNotCarried: number;
  fieldsNotCarried: number;
}): ImportReport {
  return {
    imported: r.imported,
    skipped: r.skipped,
    warnings: r.warnings,
    collapsedConflicts: r.collapsedConflicts,
    historyNotCarried: r.historyNotCarried,
    fieldsNotCarried: r.fieldsNotCarried,
  };
}

// ---------------------------------------------------------------------------------------------
// The generator and the frozen texts

/** A generated password or passphrase. */
export interface Generated {
  readonly value: string;
  readonly entropyBits: number;
}

/** A password: lowercase, uppercase and digits required; symbols required or left out. */
export function generatePassword(
  length: number,
  symbols = true,
  excludeAmbiguous = false,
): Generated {
  ensureReady();
  return mapOne(
    call(() => wasmGeneratePassword(length, symbols, excludeAmbiguous)),
    (g) => ({ value: g.value, entropyBits: g.entropyBits }),
  );
}

/** A passphrase of `words` words. */
export function generatePassphrase(words: number): Generated {
  ensureReady();
  return mapOne(
    call(() => wasmGeneratePassphrase(words)),
    (g) => ({ value: g.value, entropyBits: g.entropyBits }),
  );
}

/** The frozen warning before a plaintext export (ADR 0027 §5). */
export function plaintextExportWarning(): string {
  ensureReady();
  return wasmPlaintextExportWarning();
}

/** The phrase the user types to allow a plaintext export (ADR 0027 §5). */
export function plaintextExportPhrase(): string {
  ensureReady();
  return wasmPlaintextExportPhrase();
}
