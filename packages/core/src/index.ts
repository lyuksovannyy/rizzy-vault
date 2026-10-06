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
  detectImportFormat as wasmDetectImportFormat,
  expectNoContent,
  generateElementId,
  generatePassphraseWithOptions as wasmGeneratePassphraseWithOptions,
  generatePasswordWithOptions as wasmGeneratePasswordWithOptions,
  generatorLimits as wasmGeneratorLimits,
  initSync,
  metaRequest,
  passphraseEntropy as wasmPassphraseEntropy,
  passwordEntropy as wasmPasswordEntropy,
  plaintextExportHoldMs as wasmPlaintextExportHoldMs,
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

/**
 * A fresh element id (32 lowercase hex digits) for a new website or custom field row. Mint it
 * once, immediately when the row is added to the editor, and reuse it in the `addUri` or
 * `addCustomField` change sent on every attempt to save that row.
 */
export function newElementId(): string {
  ensureReady();
  return call(() => generateElementId());
}

/** Where {@link ItemChange} `op: "move"` puts an element. */
export type ListPlace =
  | { readonly at: "first" | "last" }
  | { readonly at: "before" | "after"; readonly element: string };

/**
 * One change of an item edit; a list of them is written as one op.
 *
 * `addUri` and `addCustomField` carry `element`: the id {@link generateElementId} minted for
 * this row. Mint it once, when the row is added to the form, and send the same id on every
 * attempt to save the row — the first and any retry — so a retry after an unclear outcome
 * writes the same element again instead of creating a second one.
 */
export type ItemChange =
  | { readonly op: "set"; readonly key: string; readonly value: string }
  | { readonly op: "clear"; readonly key: string }
  | { readonly op: "tag"; readonly name: string }
  | { readonly op: "untag"; readonly name: string }
  | { readonly op: "addUri"; readonly element: string; readonly uri: string }
  | {
      readonly op: "addCustomField";
      readonly element: string;
      readonly label: string;
      readonly kind: "text" | "hidden" | "boolean";
      readonly value: string;
    }
  | { readonly op: "removeElement"; readonly list: string; readonly element: string }
  | {
      readonly op: "move";
      readonly list: string;
      readonly element: string;
      readonly place: ListPlace;
    };

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
  /** The item's tag names, display order. */
  readonly tags: readonly string[];
  /** The host of the item's first website, or `undefined`. Never the full URI. */
  readonly websiteHost: string | undefined;
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
  | "rizzy-json"
  | "aliasvault-csv"
  | "aliasvault-avux";

/**
 * What {@link detectImportFormat} recognised: an {@link ImportFormat}, our encrypted export
 * (`rizzy-encrypted`, opened with the file's own password), our plaintext CSV export
 * (`rizzy-csv`, which cannot be imported), or `unknown` (ask the user to name the format).
 */
export type DetectedImportFormat = ImportFormat | "rizzy-encrypted" | "rizzy-csv" | "unknown";

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
            draft.addUri(change.element, change.uri);
            break;
          case "addCustomField":
            draft.addCustomField(change.element, change.label, change.kind, change.value);
            break;
          case "removeElement":
            draft.removeElement(change.list, change.element);
            break;
          case "move": {
            const { place } = change;
            if (place.at === "before" || place.at === "after") {
              draft.moveElement(change.list, change.element, place.at, place.element);
            } else {
              draft.moveElement(change.list, change.element, place.at);
            }
            break;
          }
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
        tags: i.tags,
        websiteHost: i.websiteHost,
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
        tags: i.tags,
        websiteHost: i.websiteHost,
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

  /**
   * The vault as an encrypted export file under a new password for that file, which is needed
   * to import it. Needs {@link reauthenticate} within five minutes, and spends it
   * (`reauth_required` otherwise).
   */
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
   * Re-authenticates (an OPAQUE login of this account, with the Secret Key and master
   * password typed again) for one export, encrypted or plaintext, within five minutes.
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

  /** Whether an unspent {@link reauthenticate} still allows an export. */
  reauthFresh(): boolean {
    return call(() => this.#s().reauthFresh(this.#now()));
  }

  /**
   * Records that {@link plaintextExportWarning} is shown now: the hold starts, or starts over
   * when the dialog is shown again. Returns the hold in milliseconds, for the countdown.
   */
  plaintextWarningShown(): number {
    return call(() => this.#s().plaintextWarningShown(this.#now()));
  }

  /** How much of the hold after the plaintext warning is left, in milliseconds. */
  plaintextHoldRemainingMs(): number {
    return call(() => this.#s().plaintextHoldRemainingMs(this.#now()));
  }

  /**
   * The plaintext export, after {@link plaintextExportWarning} was shown
   * ({@link plaintextWarningShown}), its hold of {@link plaintextExportHoldMs} ended, and the
   * user typed {@link plaintextExportPhrase}, within five minutes of {@link reauthenticate}.
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
// The generator with every option (CRYPTO.md §12.1)
//
// There is one generator API, not two: every caller (the generator page, the editor's generate
// slot, `rv generate`) builds a `PasswordOptions` or `PassphraseOptions` and calls
// `generate*WithOptions`. `DEFAULT_PASSWORD_OPTIONS` / `DEFAULT_PASSPHRASE_OPTIONS` give the
// historic plain defaults (20 required-everything characters; six `.`-separated words) for a
// caller that wants no options UI at all.
//
/** A generated password or passphrase. */
export interface Generated {
  readonly value: string;
  readonly entropyBits: number;
}

// The options below are those of `rizzy-core`'s generator. Rust checks them and computes the
// entropy; this module only translates names and refuses values Rust could not even receive
// (a non-integer length, an unknown rule name), with the same `generator_*` codes. Options are
// not secrets; a generated value is.

/** How a character class takes part in a password. */
export type ClassRule = "excluded" | "included" | "required";

/** Character-mode options. */
export interface PasswordOptions {
  /** Number of characters, {@link GENERATOR_LIMITS} `minLength`..`maxLength`. */
  readonly length: number;
  /** `a`–`z`. */
  readonly lowercase: ClassRule;
  /** `A`–`Z`. */
  readonly uppercase: ClassRule;
  /** `0`–`9`. */
  readonly digits: ClassRule;
  /** The symbols: all 32 ASCII punctuation characters, or {@link PasswordOptions.symbolSet}. */
  readonly symbols: ClassRule;
  /** Leave out look-alike characters ({@link GENERATOR_LIMITS} `ambiguous`). */
  readonly excludeAmbiguous: boolean;
  /**
   * Characters never used, whatever their class; order and repeats do not matter. Printable
   * ASCII without spaces, at most `maxSetTextLength` bytes; `""` excludes nothing.
   */
  readonly exclude: string;
  /**
   * The symbols to draw from instead of all 32: a subset of {@link GENERATOR_LIMITS}
   * `symbols`. `null` means all 32. Checked even while symbols are excluded.
   */
  readonly symbolSet: string | null;
}

/** Passphrase-mode options. */
export interface PassphraseOptions {
  /** Number of words, {@link GENERATOR_LIMITS} `minWords`..`maxWords`. */
  readonly words: number;
  /** One printable ASCII character between words: not a letter and not `-`. */
  readonly separator: string;
  /** Capitalise the first letter of every word (adds no entropy). */
  readonly capitalize: boolean;
  /**
   * Append one random digit to one random word. Adds `log2(words) + log2(10)` bits: the digit
   * goes right after the word's last letter, before the separator.
   */
  readonly includeNumber: boolean;
}

/** The defaults of `rizzy-core`: 20 characters, every class required, nothing excluded. */
export const DEFAULT_PASSWORD_OPTIONS: Readonly<PasswordOptions> = Object.freeze({
  length: 20,
  lowercase: "required",
  uppercase: "required",
  digits: "required",
  symbols: "required",
  excludeAmbiguous: false,
  exclude: "",
  symbolSet: null,
});

/** The defaults of `rizzy-core`: six words separated by `.`, not capitalised, no number. */
export const DEFAULT_PASSPHRASE_OPTIONS: Readonly<PassphraseOptions> = Object.freeze({
  words: 6,
  separator: ".",
  capitalize: false,
  includeNumber: false,
});

/** The generator's bounds and character sets. */
export interface GeneratorLimits {
  readonly minLength: number;
  readonly maxLength: number;
  readonly minWords: number;
  readonly maxWords: number;
  /** The 32 default symbols; a custom symbol set is a subset of them. */
  readonly symbols: string;
  /** The characters `excludeAmbiguous` leaves out. */
  readonly ambiguous: string;
  /** The longest `exclude` or `symbolSet` text, in bytes. */
  readonly maxSetTextLength: number;
}

/**
 * The generator's bounds, as constants so a UI can lay out its controls before the module
 * loads. A test checks them against {@link generatorLimits}, which reads them from Rust.
 */
export const GENERATOR_LIMITS: GeneratorLimits = Object.freeze({
  minLength: 4,
  maxLength: 256,
  minWords: 3,
  maxWords: 20,
  symbols: "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
  ambiguous: "lIo0O1|",
  maxSetTextLength: 256,
});

/** The generator's bounds and character sets, read from Rust. */
export function generatorLimits(): GeneratorLimits {
  ensureReady();
  return mapOne(wasmGeneratorLimits(), (l) => ({
    minLength: l.minLength,
    maxLength: l.maxLength,
    minWords: l.minWords,
    maxWords: l.maxWords,
    symbols: l.symbols,
    ambiguous: l.ambiguous,
    maxSetTextLength: l.maxSetTextLength,
  }));
}

/**
 * The `generator_*` codes the generator throws, each with a sentence a UI can show as is.
 * Codes never change meaning; new ones are only added.
 */
export const GENERATOR_ERROR_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  generator_invalid_length: `Length must be between ${GENERATOR_LIMITS.minLength} and ${GENERATOR_LIMITS.maxLength} characters.`,
  generator_no_classes: "Turn on at least one kind of character.",
  generator_too_many_required: "The password is shorter than the number of required kinds of character.",
  generator_empty_alphabet: "Every character is excluded. Exclude fewer characters.",
  generator_required_lowercase_empty: "Lowercase letters are required, but all of them are excluded.",
  generator_required_uppercase_empty: "Uppercase letters are required, but all of them are excluded.",
  generator_required_digits_empty: "Digits are required, but all of them are excluded.",
  generator_required_symbols_empty: "Symbols are required, but none is left to use.",
  generator_requirements_too_strict:
    "So few characters are left that a password would rarely contain every required kind. Exclude fewer characters, require fewer kinds, or make it longer.",
  generator_invalid_character_set: `Use printable ASCII characters only, without spaces, at most ${GENERATOR_LIMITS.maxSetTextLength}.`,
  generator_invalid_symbol_set: "Custom symbols must be ASCII punctuation characters.",
  generator_invalid_word_count: `A passphrase has between ${GENERATOR_LIMITS.minWords} and ${GENERATOR_LIMITS.maxWords} words.`,
  generator_invalid_separator: "The separator must be one printable ASCII character that is not a letter or a hyphen.",
  generator_invalid_rule: "Each kind of character is excluded, included or required.",
  generator_rng_failure: "The random number generator failed. Reload the page.",
  generator_invalid_options: "These generator options are not valid.",
});

/** The sentence for a `generator_*` code; a generic one for any other code. */
export function generatorErrorMessage(code: string): string {
  return GENERATOR_ERROR_MESSAGES[code] ?? "These generator options are not valid.";
}

/** The result of checking options: their entropy, or the code and sentence of the refusal. */
export type GeneratorCheck =
  | { readonly ok: true; readonly entropyBits: number }
  | { readonly ok: false; readonly code: string; readonly message: string };

/** Largest value a `usize` argument of the wasm module takes (wasm32). */
const MAX_USIZE = 0xffff_ffff;

/** `n` as a count Rust can receive, or the code `code` thrown as a {@link CoreError}. */
function count(n: unknown, code: string): number {
  if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > MAX_USIZE) {
    throw new CoreError(code);
  }
  return n;
}

/** A rule's number on the wasm boundary: 0 excluded, 1 included, 2 required. */
function ruleNumber(rule: unknown): number {
  switch (rule) {
    case "excluded":
      return 0;
    case "included":
      return 1;
    case "required":
      return 2;
    default:
      throw new CoreError("generator_invalid_rule");
  }
}

/** A text option, refused unless it is a string. */
function text(value: unknown, code: string): string {
  if (typeof value !== "string") {
    throw new CoreError(code);
  }
  return value;
}

/** The arguments of the wasm password calls, from options over the defaults. */
function passwordArgs(
  options: Partial<PasswordOptions>,
): [number, number, number, number, number, boolean, string, string | undefined] {
  const o = { ...DEFAULT_PASSWORD_OPTIONS, ...options };
  const symbolSet = o.symbolSet === null ? undefined : text(o.symbolSet, "generator_invalid_character_set");
  return [
    count(o.length, "generator_invalid_length"),
    ruleNumber(o.lowercase),
    ruleNumber(o.uppercase),
    ruleNumber(o.digits),
    ruleNumber(o.symbols),
    o.excludeAmbiguous === true,
    text(o.exclude, "generator_invalid_character_set"),
    symbolSet,
  ];
}

/** The arguments of the wasm passphrase calls, from options over the defaults. */
function passphraseArgs(options: Partial<PassphraseOptions>): [number, string, boolean, boolean] {
  const o = { ...DEFAULT_PASSPHRASE_OPTIONS, ...options };
  return [
    count(o.words, "generator_invalid_word_count"),
    text(o.separator, "generator_invalid_separator"),
    o.capitalize === true,
    o.includeNumber === true,
  ];
}

/**
 * A password with every option; missing options take {@link DEFAULT_PASSWORD_OPTIONS}.
 * Throws a {@link CoreError} with a `generator_*` code ({@link GENERATOR_ERROR_MESSAGES}) for
 * options the generator refuses.
 */
export function generatePasswordWithOptions(options: Partial<PasswordOptions> = {}): Generated {
  ensureReady();
  const args = passwordArgs(options);
  return mapOne(
    call(() => wasmGeneratePasswordWithOptions(...args)),
    (g) => ({ value: g.value, entropyBits: g.entropyBits }),
  );
}

/**
 * A passphrase with every option; missing options take {@link DEFAULT_PASSPHRASE_OPTIONS}.
 * Throws a {@link CoreError} with a `generator_*` code for options the generator refuses.
 */
export function generatePassphraseWithOptions(options: Partial<PassphraseOptions> = {}): Generated {
  ensureReady();
  const args = passphraseArgs(options);
  return mapOne(
    call(() => wasmGeneratePassphraseWithOptions(...args)),
    (g) => ({ value: g.value, entropyBits: g.entropyBits }),
  );
}

/** The entropy, in bits, of a password with these options; throws as the generator would. */
export function passwordEntropy(options: Partial<PasswordOptions> = {}): number {
  ensureReady();
  const args = passwordArgs(options);
  return call(() => wasmPasswordEntropy(...args));
}

/** The entropy, in bits, of a passphrase with these options; throws as the generator would. */
export function passphraseEntropy(options: Partial<PassphraseOptions> = {}): number {
  ensureReady();
  const args = passphraseArgs(options);
  return call(() => wasmPassphraseEntropy(...args));
}

/** Runs a check, turning a `generator_*` refusal into a {@link GeneratorCheck}. */
function check(f: () => number): GeneratorCheck {
  try {
    return { ok: true, entropyBits: f() };
  } catch (e) {
    if (e instanceof CoreError) {
      return { ok: false, code: e.code, message: generatorErrorMessage(e.code) };
    }
    throw e;
  }
}

/** Checks password options without generating, for a live display: entropy or refusal. */
export function checkPasswordOptions(options: Partial<PasswordOptions> = {}): GeneratorCheck {
  return check(() => passwordEntropy(options));
}

/** Checks passphrase options without generating, for a live display: entropy or refusal. */
export function checkPassphraseOptions(options: Partial<PassphraseOptions> = {}): GeneratorCheck {
  return check(() => passphraseEntropy(options));
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

/** How long the host holds the user after the plaintext-export warning, in milliseconds. */
export function plaintextExportHoldMs(): number {
  ensureReady();
  return wasmPlaintextExportHoldMs();
}

/**
 * The format of an import file, recognised from its bytes; a kind only, never a byte of the
 * file. The reader the answer picks still checks the whole file.
 */
export function detectImportFormat(file: Uint8Array): DetectedImportFormat {
  ensureReady();
  const found = wasmDetectImportFormat(file);
  switch (found) {
    case "bitwarden-json":
    case "1pux":
    case "keepass-xml":
    case "csv":
    case "chrome-csv":
    case "firefox-csv":
    case "rizzy-json":
    case "aliasvault-csv":
    case "aliasvault-avux":
    case "rizzy-encrypted":
    case "rizzy-csv":
      return found;
    default:
      return "unknown";
  }
}
