// SPDX-License-Identifier: AGPL-3.0-only

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
  CacheDelta,
  CacheKey,
  CoreError as WasmCoreError,
  DeviceSession as WasmDeviceSession,
  EnrolFlow,
  type EquivalenceGroupView as WasmEquivalenceGroupView,
  GlobalEquivalence,
  HttpRequest,
  ItemDraft,
  KvRow,
  LoginFlow,
  type MatchDecision as WasmMatchDecision,
  type MatchSettingsView as WasmMatchSettingsView,
  PasskeyAssertion as WasmPasskeyAssertion,
  PasskeyCandidate as WasmPasskeyCandidate,
  Session,
  SignupFlow,
  TwoFactorEnrolment,
  UriInput,
  checkMeta,
  coreVersion,
  cacheStoreNames as wasmCacheStoreNames,
  createPasskey as wasmCreatePasskey,
  decideMatchCandidates as wasmDecideMatchCandidates,
  detectImportFormat as wasmDetectImportFormat,
  endsSessionOnUnauthorized,
  expectNoContent,
  generateElementId,
  generatePassphraseWithOptions as wasmGeneratePassphraseWithOptions,
  generatePasswordWithOptions as wasmGeneratePasswordWithOptions,
  generatorLimits as wasmGeneratorLimits,
  initSync,
  metaRequest,
  normalizePageUrl as wasmNormalizePageUrl,
  passphraseEntropy as wasmPassphraseEntropy,
  passwordEntropy as wasmPasswordEntropy,
  plaintextExportHoldMs as wasmPlaintextExportHoldMs,
  plaintextExportPhrase as wasmPlaintextExportPhrase,
  plaintextExportWarning as wasmPlaintextExportWarning,
  othersEndedNotice as wasmOthersEndedNotice,
  sessionEndedByYouNotice as wasmSessionEndedByYouNotice,
  sessionEndedNotice as wasmSessionEndedNotice,
  registrableDomainOf as wasmRegistrableDomainOf,
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

/** The request headers of a signed request (ADR 0028 item 5; CRYPTO.md §5.10): the `u64`
 * counter in decimal and the signature container's base64url form, the client's own request
 * builder names them identically on every platform (`rizzy_proto::http`'s own constants). */
const REQUEST_COUNTER_HEADER = "Rizzy-Request-Counter";
const REQUEST_SIGNATURE_HEADER = "Rizzy-Request-Signature";

/** The two requests whose `401` may be a wrong TOTP code rather than an ended session. */
const TOTP_CODE_PATHS: ReadonlySet<string> = new Set([
  "/api/v1/totp/enrol/confirm",
  "/api/v1/totp/disable",
]);

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
    const requestCounter = request.requestCounter;
    const requestSignature = request.requestSignature;
    if (requestCounter !== undefined && requestSignature !== undefined) {
      headers[REQUEST_COUNTER_HEADER] = requestCounter.toString();
      headers[REQUEST_SIGNATURE_HEADER] = requestSignature;
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

/**
 * The shape every request/response flow of the core shares (module docs, "The shape of every
 * flow"): `LoginFlow` and `EnrolFlow` both satisfy this structurally, so {@link drive} drives
 * either without the core needing to export a common base class (`wasm-bindgen` classes cannot
 * share one anyway).
 */
interface RequestResponseFlow {
  readonly state: string;
  request(): HttpRequest;
  respond(status: number, body: Uint8Array, now_ms: bigint): void;
  provideTotp(code: string): void;
}

/** Drives a login or enrolment flow to `"done"` or `"needs_totp"`. */
async function drive(
  flow: RequestResponseFlow,
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
    }
  | {
      /** Adds a new passkey (ADR 0039 §1): the write path for {@link createPasskey}'s result.
       * `element` is {@link newElementId}'s id, minted once, same convention as `addUri`.
       * `privateKey` and `userHandle` are the host's own copy of
       * {@link CreatedPasskey.privateKey}/the relying party's user handle — this module zeroes
       * neither after the call (unlike {@link SecretInput}'s bytes, class docs): the caller
       * must drop its own reference once this resolves. `alg` is `1` for ES256, `2` for
       * `EdDSA` (ADR 0039 §1). */
      readonly op: "addPasskey";
      readonly element: string;
      readonly rpId: string;
      readonly userHandle: Uint8Array;
      readonly credentialId: Uint8Array;
      readonly privateKey: Uint8Array;
      readonly publicKeyCose: Uint8Array;
      readonly alg: number;
      readonly discoverable: boolean;
      readonly createdMs: number;
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

/**
 * One password-history entry, without its value (ADR 0013 §3 rule 3): `merge` is the history
 * of `login.password` (ADR 0012 §5), `imported` came from another manager (`pwhist`, ADR 0018
 * §7). `index` is its position within its source, for display only; `changedMs` the date it
 * stopped being current (`merge`) or the other manager's date (`imported`, when it gave one),
 * also display only, since two entries can share one date. `id` is the entry's own identity
 * (never shared, never absent): pass it to {@link VaultSession.revealPasswordHistory}, not
 * `index` or `changedMs`, to bind a reveal to the exact entry this listing showed.
 */
export interface HistoryEntry {
  readonly source: "merge" | "imported";
  readonly index: number;
  readonly changedMs: number | undefined;
  readonly id: string;
}

/**
 * One field's history, without values (ADR 0013 §3 rule 3; ROADMAP §4.2 "Item revision history
 * (restore old versions)", M3): generalizes {@link HistoryEntry} to every field, not only
 * `login.password`. `key` is the field's final key ({@link FieldView.key}); `entries` is
 * newest first, each `source` always `"merge"` (imported `login.password` history stays
 * {@link VaultSession.passwordHistory}-only and is never part of this listing). Pass an
 * entry's own `id`, scoped to `key`, to {@link VaultSession.revealFieldHistory} or
 * {@link VaultSession.restoreFieldHistory}: the same dot can appear in two different fields'
 * histories when one edit wrote both, so an id from one field's listing is never read or
 * restored under another field's name.
 */
export interface FieldHistory {
  readonly key: string;
  readonly entries: readonly HistoryEntry[];
}

/**
 * One distinct value of a conflicting field (ROADMAP §4.5 "edited on Phone and Laptop at the
 * same time — keep both / pick one"; ADR 0012 §4 step 5, ADR 0018 §6), as
 * {@link VaultSession.fieldConflict} lists them: the displayed value first. `device` wrote it
 * ("edited on X"; name it from {@link VaultSession.devices}), at `writtenMs` (display only).
 * `cleared` is "cleared on X". `value` is absent while `concealed` (ADR 0013 §3 rule 3): reveal
 * it with {@link VaultSession.revealConflictValue}. Pass `index` and `id` back as listed to
 * reveal or resolve: when a sync has since changed the listing, the core refuses
 * (`unknown_item`) instead of acting on another value.
 */
export interface ConflictValue {
  readonly index: number;
  readonly id: string;
  readonly device: string;
  readonly writtenMs: number;
  readonly displayed: boolean;
  readonly cleared: boolean;
  readonly kind: FieldView["kind"];
  readonly concealed: boolean;
  readonly value: string | undefined;
}

/**
 * A notice of {@link VaultSession.takeNotices}: ids only. `late-edit`: "An edit from
 * `<devices>` arrived for an item you deleted permanently. Restore it as a new item?" (ADR 0018
 * §3). `concurrent-trash`: "deleted on `devices[0]` while it was being edited on `devices[1]`"
 * (ADR 0012 §5). Name the devices from {@link VaultSession.devices}. `conflictId` is this one
 * conflict's own identity for `concurrent-trash` (`undefined` for `late-edit`, which has none):
 * fold it into a host-side dedup key alongside `item` and `devices`, so a second, genuinely
 * distinct race between the same two devices on the same item is not dropped as a repeat of
 * the first.
 */
export interface Notice {
  readonly kind: "late-edit" | "concurrent-trash";
  readonly item: string;
  readonly devices: readonly string[];
  readonly conflictId: string | undefined;
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

/**
 * One session of the account, as `sessions/list` reports it (ADR 0075 §9). The server's word,
 * for display only (AR-9): never proof that nothing else is open.
 */
export interface SessionRowView {
  /** The `session_id`, 32 hex digits: what {@link VaultSession.endSession} takes. */
  readonly id: string;
  /**
   * `password-login` (a web or password login), `password-recheck` (a password re-check on a
   * device), `device`, `recovery` (an account recovery in progress) or `unknown`.
   */
  readonly kind: string;
  /** The device of a device session or a password re-check, 32 hex digits. */
  readonly deviceId: string | undefined;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  /** This browser's own session. */
  readonly current: boolean;
  /** Whether "End" is offered: never on a device row (ADR 0075 §5) or the current one. */
  readonly endable: boolean;
}

/** The account's sessions: the rows, newest first, and whether the server cut the list. */
/**
 * One attachment an item lists (ADR 0054 §4): its id, file name, declared media type and size
 * in bytes. Item data, for display.
 */
export interface AttachmentInfo {
  readonly id: string;
  readonly name: string;
  readonly mime: string;
  readonly size: number;
}

/** The largest attachment, in bytes: 25 MiB (ADR 0054 §2). Checked in the core too. */
export const MAX_ATTACHMENT_BYTES = 26_214_400;

export interface SessionListView {
  readonly sessions: readonly SessionRowView[];
  readonly truncated: boolean;
}

/** What the web vault shows when its session was ended elsewhere (ADR 0075 §6). */
export function sessionEndedNotice(): string {
  return wasmSessionEndedNotice();
}

/** The confirmation after ending other sessions (ADR 0075 §8). */
export function othersEndedNotice(): string {
  return wasmOthersEndedNotice();
}

/** The confirmation after ending one session (ADR 0075 §8). */
export function sessionEndedByYouNotice(): string {
  return wasmSessionEndedByYouNotice();
}

/** A started 2FA enrolment, to show once. */
export interface TwoFactorSetup {
  readonly otpauthUri: string;
  readonly secret: string;
}

// ---------------------------------------------------------------------------------------------
// Passkeys (ADR 0039)

/**
 * One `navigator.credentials.create()` ceremony's result (ADR 0039 §1, §2, §4). `privateKey`
 * is the fresh credential's raw 32-byte scalar — the one place besides the master
 * password/Secret Key/export password/2FA code/Emergency Kit that a key crosses this boundary
 * (`Session`/`DurableSession` class docs' own "Keys stay in Rust" exceptions list). The host's
 * one job with it is an immediate {@link ItemChange} `op: "addPasskey"` through
 * {@link VaultSession.createItem}/{@link DurableSession.createItem} (or `editItem`, for a second
 * passkey on an existing Login) — never log it, never store it outside that one encrypted
 * field, never hold it longer than that one call needs.
 */
export interface CreatedPasskey {
  readonly privateKey: Uint8Array;
  readonly credentialId: Uint8Array;
  readonly publicKeyCose: Uint8Array;
  readonly clientDataJson: Uint8Array;
  readonly attestationObject: Uint8Array;
}

/**
 * The `addPasskey` `alg` value for an ES256 credential, in this item schema's own small-enum
 * convention (`1`, never the real COSE id `-7`) — `rizzy-core::item::schema::PASSKEY_ALG_ES256`.
 * {@link createPasskey} only ever produces ES256 credentials today, so this is the only value
 * an `addPasskey` change needs until `EdDSA` support lands.
 */
export const PASSKEY_ALG_ES256 = 1;

/** One `navigator.credentials.get()` ceremony's result (ADR 0039 §2): everything the page's
 * `PublicKeyCredential` response needs, never the private key that signed it. `userHandle` is
 * empty only when the stored passkey somehow has none (`PasskeyAssertion`'s own doc on why that
 * should not happen in practice); gap 35(a) in the M2 gap audit added this field — it used to be
 * missing from every assertion, so a relying party doing username-less discoverable sign-in
 * could not identify the user from the response alone. */
export interface PasskeyAssertionResult {
  readonly credentialId: Uint8Array;
  readonly userHandle: Uint8Array;
  readonly clientDataJson: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly signatureDer: Uint8Array;
}

/** One stored passkey's non-secret metadata (ADR 0039 §1), for the host to list
 * `navigator.credentials.get()`/`.create()` candidates (gaps 35(a)/(b) in the M2 gap audit) —
 * never the private key, which stays behind the wasm boundary. */
export interface PasskeyCandidateResult {
  readonly elementId: string;
  readonly rpId: string;
  readonly userHandle: Uint8Array;
  readonly credentialId: Uint8Array;
  readonly alg: number;
  readonly createdMs: number;
}

/**
 * Runs a `WebAuthn` registration ceremony for one new ES256 passkey (ADR 0039 §1, §2, §4):
 * checks INV-64, generates a fresh key, and assembles every byte structure the page's
 * `create()` promise resolves with. No session needed — a pure, stateless call
 * (`crates/rizzy-wasm/src/passkey.rs`'s own module docs) — so it works before enrolment/unlock
 * too, though the result is only useful once there is a session to {@link CreatedPasskey}
 * write it through.
 *
 * `origin` must be the browser-verified origin, never a page-supplied value: the extension's
 * background takes it from the browser's own sender information (ADR 0039 §2), never from an
 * intercepted call's relayed payload.
 *
 * Throws a {@link CoreError} with code `rp_id_rejected` (INV-64) or `invalid_input`.
 */
export function createPasskey(origin: string, rpId: string, challenge: Uint8Array): CreatedPasskey {
  ensureReady();
  return mapOne(
    call(() => wasmCreatePasskey(origin, rpId, challenge)),
    (c) => ({
      privateKey: c.privateKey,
      credentialId: c.credentialId,
      publicKeyCose: c.publicKeyCose,
      clientDataJson: c.clientDataJson,
      attestationObject: c.attestationObject,
    }),
  );
}

/** Maps a generated {@link WasmPasskeyAssertion} and frees it — shared by
 * {@link VaultSession.passkeyAssertion} and {@link DurableSession.passkeyAssertion}. */
function mapPasskeyAssertion(assertion: WasmPasskeyAssertion): PasskeyAssertionResult {
  return mapOne(assertion, (a) => ({
    credentialId: a.credentialId,
    userHandle: a.userHandle,
    clientDataJson: a.clientDataJson,
    authenticatorData: a.authenticatorData,
    signatureDer: a.signatureDer,
  }));
}

/** Maps every generated {@link WasmPasskeyCandidate} and frees them — shared by
 * {@link VaultSession.passkeyCandidates} and {@link DurableSession.passkeyCandidates}.
 * `createdMs` narrows from the generated `bigint` to `number`, the same convention
 * `StoredPasskey`/`mapOne`'s other `U64` fields already use for a local-display timestamp. */
function mapPasskeyCandidates(candidates: WasmPasskeyCandidate[]): PasskeyCandidateResult[] {
  return mapFree(candidates, (c) => ({
    elementId: c.elementId,
    rpId: c.rpId,
    userHandle: c.userHandle,
    credentialId: c.credentialId,
    alg: c.alg,
    createdMs: Number(c.createdMs),
  }));
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
          case "addPasskey":
            draft.addPasskey(
              change.element,
              change.rpId,
              change.userHandle,
              change.credentialId,
              change.privateKey,
              change.publicKeyCose,
              change.alg,
              change.discoverable,
              BigInt(change.createdMs),
            );
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
 * The account's storage usage as the server reports it (ADR 0048 §5): unsigned, so the
 * server's word, shown for information only.
 */
export interface StorageUsage {
  /** The account's counted bytes on the server. */
  readonly bytesUsed: number;
  /** The instance's per-account quota (`RIZZY_ACCOUNT_QUOTA_BYTES`). */
  readonly quotaBytes: number;
}

/**
 * An unlocked session. The keys live in the core's memory behind this handle; `lock` wipes
 * them. One call per user action (ADR 0013 §3 rule 6). Writes go to memory first; `sync`
 * uploads them.
 */
export class VaultSession {
  #session: Session | undefined;
  readonly #transport: Transport;
  /** The transport as given, without the ended-session watch (for the sign-out). */
  readonly #plainTransport: Transport;
  readonly #clock: Clock;
  #enrolment: TwoFactorEnrolment | undefined;
  /** Set once a request answered `401` that means the session ended (ADR 0075 §6). */
  #ended = false;

  /** @internal Use {@link login} or {@link Signup.login}. */
  constructor(session: Session, transport: Transport, clock: Clock) {
    this.#session = session;
    this.#plainTransport = transport;
    // ADR 0075 §6: a `401` on any request but `login/*`, `recovery/*` and the sign-out means
    // the session has ended. TOTP confirmation and removal also answer `401` for a wrong code,
    // so for those two the session is asked once more (`#confirmEnded`).
    this.#transport = async (request) => {
      const answer = await transport(request);
      if (
        answer.status === 401 &&
        !TOTP_CODE_PATHS.has(request.path) &&
        endsSessionOnUnauthorized(request.path)
      ) {
        this.#ended = true;
      }
      return answer;
    };
    this.#clock = clock;
  }

  /**
   * Whether the server ended this session (ADR 0075 §6): a request answered `401` that only an
   * ended or unknown session gets. The host locks and shows {@link sessionEndedNotice}.
   */
  get ended(): boolean {
    return this.#ended;
  }

  /** After a `401` on a TOTP code check: whether the session itself ended (a list answers `401`
   * too) or only the code was wrong. */
  async #confirmEnded(): Promise<void> {
    const s = this.#s();
    await this.#transport(takeRequest(call(() => s.sessionsListRequest())));
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

  /**
   * The account's storage usage the server reported with its last account answer (ADR 0048
   * §5): its counted bytes and the instance's quota, `undefined` when it reported none. The
   * server's word, unverified: for display only.
   */
  get storageUsage(): StorageUsage | undefined {
    return call(() => {
      const s = this.#s();
      const used = s.storageBytesUsed;
      const quota = s.storageQuotaBytes;
      return used === undefined || quota === undefined
        ? undefined
        : { bytesUsed: Number(used), quotaBytes: Number(quota) };
    });
  }

  /**
   * Locks: wipes every key and decrypted item; unsent changes are lost. The session is also
   * ended on the server (`sessions/current/end`, ADR 0075 §6), best effort: the request is
   * sent and not awaited, a failure is ignored and not retried, and the token then lapses at
   * its TTL. Not sent for a session the server already ended.
   */
  lock(): void {
    this.#enrolment?.free();
    this.#enrolment = undefined;
    const s = this.#session;
    if (s !== undefined && !s.locked && !this.#ended) {
      try {
        const signOut = takeRequest(s.signOutRequest());
        this.#plainTransport(signOut).catch(() => undefined);
      } catch {
        // Best effort (module docs of lock).
      }
    }
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
   *
   * Once the fetch/upload driver settles, this also runs the client-side trash auto-purge
   * (gap 00; ADR 0012 §5, ADR 0018 §9, §11): a pass over every trashed item whose retention
   * period has elapsed, run only here, after a successful sync, while unlocked — never by the
   * server (ADR 0022).
   */
  async sync(): Promise<void> {
    const s = this.#s();
    call(() => s.syncStart());
    for (;;) {
      const request = call(() => s.syncRequest());
      if (request === undefined) {
        break;
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
    call(() => this.#s().autoPurge(this.#now()));
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

  /**
   * The item's password history, without values (ADR 0013 §3 rule 3): one entry per former
   * password, `merge` entries newest first, then `imported` ones. List it again after every
   * sync: a sync can shift the entries.
   */
  passwordHistory(id: string): HistoryEntry[] {
    return mapFree(
      call(() => this.#s().passwordHistory(id)),
      (h) => ({
        source: h.source as HistoryEntry["source"],
        index: h.index,
        changedMs: h.changedMs === undefined ? undefined : Number(h.changedMs),
        id: h.id,
      }),
    );
  }

  /**
   * One password-history entry's value, as {@link passwordHistory} listed it, on the user's
   * request only. Pass the entry's `id` as listed: when a sync has since moved another entry
   * to that position, the core refuses (`unknown_item`) instead of revealing it.
   */
  revealPasswordHistory(
    id: string,
    source: HistoryEntry["source"],
    index: number,
    entryId: string,
  ): string {
    return call(() => this.#s().revealPasswordHistory(id, source, index, entryId));
  }

  /**
   * Every field's history, without values ({@link FieldHistory}'s own doc; ROADMAP §4.2 "Item
   * revision history (restore old versions)", M3): generalizes {@link passwordHistory} to
   * every field. List it again after every sync: a sync can shift the entries.
   */
  itemHistory(id: string): FieldHistory[] {
    return mapFree(call(() => this.#s().itemHistory(id)), (field) => ({
      key: field.key,
      entries: mapFree(field.entries, (h) => ({
        source: h.source as HistoryEntry["source"],
        index: h.index,
        changedMs: h.changedMs === undefined ? undefined : Number(h.changedMs),
        id: h.id,
      })),
    }));
  }

  /**
   * One field-history entry's value, as {@link itemHistory} listed it, on the user's request
   * only. `key` scopes `index`/`entryId` ({@link FieldHistory}'s own doc): when a sync has
   * since moved another entry to that position, or the id was listed under a different field,
   * the core refuses (`unknown_item`) instead of revealing it.
   */
  revealFieldHistory(id: string, key: string, index: number, entryId: string): string {
    return call(() => this.#s().revealFieldHistory(id, key, index, entryId));
  }

  /**
   * Restores one field-history entry as the field's current value (ROADMAP §4.2): an ordinary
   * edit, which syncs and merges like any other. `key`, `index` and `entryId` name the entry
   * exactly as {@link itemHistory} listed it, checked the same way {@link revealFieldHistory}
   * is.
   */
  restoreFieldHistory(id: string, key: string, index: number, entryId: string): void {
    call(() => this.#s().restoreFieldHistory(id, key, index, entryId, this.#now()));
  }

  /**
   * A conflicting field's distinct values ({@link ConflictValue}'s own doc), the displayed one
   * first, concealed values withheld. Empty when the field does not conflict. List it again
   * after every sync: a sync can resolve the conflict or add a value.
   */
  fieldConflict(id: string, key: string): ConflictValue[] {
    return mapFree(call(() => this.#s().fieldConflict(id, key)), (v) => ({
      index: v.index,
      id: v.id,
      device: v.device,
      writtenMs: Number(v.writtenMs),
      displayed: v.displayed,
      cleared: v.cleared,
      kind: v.kind as FieldView["kind"],
      concealed: v.concealed,
      value: v.value,
    }));
  }

  /** One conflicting value, as {@link fieldConflict} listed it, on the user's request only. */
  revealConflictValue(id: string, key: string, index: number, valueId: string): string {
    return call(() => this.#s().revealConflictValue(id, key, index, valueId));
  }

  /**
   * "Pick one": writes the named value back to the field, an ordinary edit whose context
   * covers every conflicting value, so the conflict ends on every device once it syncs.
   */
  resolveConflictPick(id: string, key: string, index: number, valueId: string): void {
    call(() => this.#s().resolveConflictPick(id, key, index, valueId, this.#now()));
  }

  /**
   * "Keep both": keeps the named value in the field and moves every other non-empty value into
   * a new website (for a website) or a new custom field, hidden when the field is concealed,
   * labelled `label` (required for a fixed field such as the password; a custom field's copies
   * take its own label without one). Returns the new elements' ids. A field that is not text,
   * or has no second value to keep, is refused (`invalid_edit`): "pick one" resolves it.
   */
  resolveConflictKeepBoth(
    id: string,
    key: string,
    index: number,
    valueId: string,
    label: string | undefined,
  ): string[] {
    return call(() =>
      this.#s().resolveConflictKeepBoth(id, key, index, valueId, label, this.#now()),
    );
  }

  /**
   * The notices not yet handed over in this session, each handed over once (gap 02): an edit
   * that arrived for an item deleted permanently (offer {@link restoreLateAsNew}), and an item
   * deleted on one device while it was being edited on another. Call it after each `sync`.
   * The "handed over" marks live in the core's memory only and end with the session.
   */
  takeNotices(): Notice[] {
    return mapFree(
      call(() => this.#s().takeNotices()),
      (n) => ({
        kind: n.kind as Notice["kind"],
        item: n.item,
        devices: n.devices,
        conflictId: n.conflictId,
      }),
    );
  }

  /**
   * Restores the late edits of an item deleted permanently as a new item of `itemType`, the
   * type the user picked; returns the new item's id. The deleted item stays deleted.
   */
  restoreLateAsNew(id: string, itemType: ItemType): string {
    return call(() => this.#s().restoreLateAsNew(id, itemType, this.#now()));
  }

  /** The item's current TOTP code. */
  totp(id: string): TotpCode {
    return mapOne(
      call(() => this.#s().totp(id, this.#now())),
      (t) => ({ code: t.code, validForSeconds: t.validForSeconds, periodSeconds: t.periodSeconds }),
    );
  }

  /**
   * Signs a WebAuthn assertion with a passkey already stored on this item (ADR 0039 §2). The
   * private key never leaves the wasm boundary; only the signed assertion comes back.
   */
  passkeyAssertion(id: string, passkeyId: string, origin: string, rpId: string, challenge: Uint8Array): PasskeyAssertionResult {
    return mapPasskeyAssertion(call(() => this.#s().passkeyAssertion(id, passkeyId, origin, rpId, challenge)));
  }

  /**
   * Every stored passkey's non-secret metadata on one item (ADR 0039 §1), for the host to pick
   * which credential to run {@link passkeyAssertion} with — in particular, to filter against
   * the page's `allowCredentials` before picking one (gap 35(b) in the M2 gap audit).
   */
  passkeyCandidates(id: string): PasskeyCandidateResult[] {
    return mapPasskeyCandidates(call(() => this.#s().passkeyCandidates(id)));
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

  /** The account's live sessions (`sessions/list`, ADR 0075 R1), newest first. */
  async sessions(): Promise<SessionListView> {
    const s = this.#s();
    const answer = await this.#transport(takeRequest(call(() => s.sessionsListRequest())));
    const rows = mapFree(
      call(() => s.sessionsListResponse(answer.status, answer.body)),
      (r) => ({
        id: r.id,
        kind: r.kind,
        deviceId: r.deviceId,
        createdAtMs: Number(r.createdAtMs),
        expiresAtMs: Number(r.expiresAtMs),
        current: r.current,
        endable: r.endable,
      }),
    );
    return { sessions: rows, truncated: call(() => s.sessionsTruncated()) };
  }

  /**
   * Ends one other session of the last {@link sessions} list (`sessions/end`, R3). Needs a
   * fresh login (`server_fresh_session_required` otherwise: call {@link refreshSession} and try
   * again).
   */
  async endSession(id: string): Promise<void> {
    const s = this.#s();
    const answer = await this.#transport(takeRequest(call(() => s.endSessionRequest(id))));
    call(() => expectNoContent(answer.status, answer.body));
  }

  /** The attachments of an item, in list order (ADR 0054 §4). */
  attachments(itemId: string): AttachmentInfo[] {
    return mapFree(call(() => this.#s().attachments(itemId)), (a) => ({
      id: a.id,
      name: a.name,
      mime: a.mime,
      size: Number(a.size),
    }));
  }

  /**
   * Adds a file to an item as an encrypted attachment (ADR 0054): the core writes the item op
   * naming it first (§7), seals every chunk, and this sends `attachments/create` and each
   * `upload-chunk` in turn. Then syncs, so the op reaches the server. Returns the attachment id.
   * Codes: `attachment_too_large` over 25 MiB, `server_quota_exceeded` past the account's quota.
   */
  async addAttachment(itemId: string, name: string, mime: string, data: Uint8Array): Promise<string> {
    const s = this.#s();
    const id = call(() => s.addAttachment(itemId, name, mime, data, this.#now()));
    try {
      const created = await this.#transport(takeRequest(call(() => s.attachmentCreateRequest(id))));
      call(() => expectNoContent(created.status, created.body));
      const count = call(() => s.attachmentChunkCount(id));
      for (let i = 0; i < count; i++) {
        const answer = await this.#transport(
          takeRequest(call(() => s.attachmentUploadChunkRequest(id, i))),
        );
        call(() => expectNoContent(answer.status, answer.body));
      }
    } finally {
      if (!this.locked) {
        call(() => s.attachmentUploadDone(id));
      }
    }
    await this.sync();
    return id;
  }

  /**
   * Downloads and verifies an attachment: the chunk count comes from the item's own size, every
   * chunk is opened where it was asked for, and the file is returned only when all of them
   * opened (INV-79). Codes: `server_not_found` (the server lacks it), `attachment_incomplete`.
   */
  async downloadAttachment(itemId: string, attachmentId: string): Promise<Uint8Array> {
    const s = this.#s();
    const count = call(() => s.attachmentDownloadStart(itemId, attachmentId));
    try {
      const wrap = await this.#transport(takeRequest(call(() => s.attachmentGetRequest(attachmentId))));
      call(() => s.attachmentGetResponse(attachmentId, wrap.status, wrap.body));
      for (let i = 0; i < count; i++) {
        const answer = await this.#transport(
          takeRequest(call(() => s.attachmentDownloadChunkRequest(attachmentId, i))),
        );
        call(() => s.attachmentDownloadChunkResponse(attachmentId, i, answer.status, answer.body));
      }
      return call(() => s.attachmentDownloadFinish(attachmentId));
    } catch (e) {
      if (!this.locked) {
        call(() => s.attachmentDownloadAbort(attachmentId));
      }
      throw e;
    }
  }

  /**
   * Deletes an attachment: `attachments/delete` first (a `server_not_found` answer means it is
   * gone already), then the item's fields are cleared and synced, so a failure leaves a
   * reference that heals rather than a blob that keeps counting against the quota.
   */
  async deleteAttachment(itemId: string, attachmentId: string): Promise<void> {
    const s = this.#s();
    const answer = await this.#transport(takeRequest(call(() => s.attachmentDeleteRequest(attachmentId))));
    try {
      call(() => expectNoContent(answer.status, answer.body));
    } catch (e) {
      if (!(e instanceof CoreError) || e.code !== "server_not_found") {
        throw e;
      }
    }
    call(() => s.removeAttachment(itemId, attachmentId, this.#now()));
    await this.sync();
  }

  /**
   * Deletes every attachment an item names from the server (`attachments/delete`; a
   * `server_not_found` answer counts as deleted), leaving the item's fields as they are. For an
   * item about to be deleted for good: the server cannot tell which attachments an item names
   * (ADR 0054 §7), so without this they would stay and keep counting against the quota.
   */
  async deleteAttachmentsOf(itemId: string): Promise<void> {
    const s = this.#s();
    for (const a of this.attachments(itemId)) {
      const answer = await this.#transport(takeRequest(call(() => s.attachmentDeleteRequest(a.id))));
      try {
        call(() => expectNoContent(answer.status, answer.body));
      } catch (e) {
        if (!(e instanceof CoreError) || e.code !== "server_not_found") {
          throw e;
        }
      }
    }
  }

  /**
   * Ends every other password and recovery session (`sessions/others/end`, R4); device sessions
   * stay. Needs a fresh login, as {@link endSession}.
   */
  async endOtherSessions(): Promise<void> {
    const s = this.#s();
    const answer = await this.#transport(takeRequest(call(() => s.endOtherSessionsRequest())));
    call(() => expectNoContent(answer.status, answer.body));
  }

  /**
   * Logs in again (Secret Key and master password typed again) and switches this vault to the
   * new, fresh session; the old one is ended on the server, best effort (ADR 0075 §9: "It
   * switches to the new session and ends the old one").
   */
  async refreshSession(
    secretKey: SecretInput,
    password: SecretInput,
    askTotp?: AskTotp,
  ): Promise<void> {
    const s = this.#s();
    const flow = withSecrets([secretKey, password], (b) =>
      call(() => s.refresh(at(b, 0), at(b, 1), undefined)),
    );
    try {
      await drive(flow, this.#transport, this.#clock, askTotp);
      const signOut = takeRequest(call(() => s.adoptRefresh(flow)));
      this.#plainTransport(signOut).catch(() => undefined);
    } finally {
      flow.free();
    }
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
    if (answer.status === 401) {
      await this.#confirmEnded();
    }
    call(() => expectNoContent(answer.status, answer.body));
    enrolment.free();
    this.#enrolment = undefined;
  }

  /** Removes 2FA with a current code. */
  async disableTwoFactor(code: string): Promise<void> {
    const s = this.#s();
    const answer = await this.#transport(takeRequest(call(() => s.twoFactorDisableRequest(code))));
    if (answer.status === 401) {
      await this.#confirmEnded();
    }
    call(() => expectNoContent(answer.status, answer.body));
  }

  /** The account's matching settings (ADR 0037 §6–§7, ADR 0042): `settings_update_required` when a
   * newer rizzy-vault wrote them, `invalid_server_response` when they do not read. */
  matchSettings(): MatchSettings {
    const s = this.#s();
    return matchSettingsOf(call(() => s.matchSettings()));
  }

  /** What the extension would offer on `pageUrl` (a top frame) among this vault's items, under
   * the account's settings: the settings screen's "check a website". */
  matchCandidates(pageUrl: string): MatchDecisionResult {
    const s = this.#s();
    return decisionOf(call(() => s.matchCandidates(pageUrl)));
  }

  /**
   * Changes the account's matching settings: one `account/commit` of a new signed account state
   * and the whole new settings record (ADR 0042 §5). When another device changed the account
   * first (`server_state_conflict`), this syncs, which verifies the newer state, and retries the
   * same change on top of it, once. The server takes the commit only within five minutes of the
   * login (`server_fresh_session_required` afterwards: log in again).
   */
  async changeMatchSettings(change: SettingsChange): Promise<void> {
    const s = this.#s();
    let request = takeRequest(call(() => settingsRequest(s, change)));
    for (let attempt = 0; ; attempt++) {
      const answer = await this.#transport(request);
      try {
        call(() => s.settingsRespond(answer.status, answer.body));
        return;
      } catch (e) {
        if (!(e instanceof CoreError) || e.code !== "server_state_conflict" || attempt > 0) {
          throw e;
        }
      }
      await this.sync();
      request = takeRequest(call(() => s.settingsRetryRequest()));
    }
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

// ---------------------------------------------------------------------------------------------
// Durable device (the browser extension, M2; ADR 0036). Not wired into `apps/web` (that app
// uses `VaultSession`/`login` above, the ephemeral kind-4 device of CRYPTO.md §11.4) and not
// the same type as `VaultSession`: a durable device additionally persists a device-state
// record and a cache (ADR 0026), which this section's `CacheRow` carries as opaque bytes, and
// separates the local unlock from the online device authentication (§5.10), which
// {@link DurableSession.authStart}/{@link DurableSession.authRespond} drive as their own
// request/response loop. Items and sync are exposed through the same `rizzy_client::sync`/
// `items` calls `VaultSession` above uses, over a cache-backed `VaultSync` (not new Rust
// logic); every mutating call here is `async`, unlike `VaultSession`'s, because it persists
// through {@link CacheStore} before it resolves (ADR 0026 §4's write order), where
// `VaultSession`'s ephemeral device persists nothing.

/**
 * One row of the byte-blob cache (ADR 0026 §3; `crates/rizzy-wasm/src/store.rs`'s module
 * docs): an `IndexedDB` object store's name, key and value, every one opaque bytes. A host
 * creates one `IndexedDB` object store per name in {@link cacheStoreNames}, once, and this
 * module never parses a row's `value` (ADR 0036 §6: the adapter "parses nothing").
 */
export interface CacheRow {
  readonly store: string;
  readonly key: Uint8Array;
  readonly value: Uint8Array;
}

/** [ADR 0026] §3's eight logical stores, verbatim: the `IndexedDB` object stores a host
 * creates once, before any {@link enrolDevice} or {@link unlockDurableDevice} call. */
export function cacheStoreNames(): readonly string[] {
  ensureReady();
  return wasmCacheStoreNames();
}

/**
 * The host-provided byte-blob cache store (ADR 0026 §3; ADR 0036 §6 "parses nothing"): get,
 * put and delete of one row, and list of a whole store, keyed exactly as {@link cacheStoreNames}
 * names them. An `IndexedDB` adapter (`cache/idb.ts`-shaped) maps onto this one call per method,
 * since every value here is already the opaque bytes a `put`/`get` needs — this module never
 * decides what belongs in which `IndexedDB` key path, only moves the bytes `rizzy-wasm`'s
 * `store` bindings already encoded.
 */
export interface CacheStore {
  get(store: string, key: Uint8Array): Promise<Uint8Array | undefined>;
  put(store: string, key: Uint8Array, value: Uint8Array): Promise<void>;
  delete(store: string, key: Uint8Array): Promise<void>;
  list(store: string): Promise<readonly CacheRow[]>;
}

/** Every row of every store, for the one-time full load {@link unlockDurableDevice} needs. */
async function readCacheStore(store: CacheStore): Promise<CacheRow[]> {
  const rows: CacheRow[] = [];
  for (const name of cacheStoreNames()) {
    rows.push(...(await store.list(name)));
  }
  return rows;
}

/** Persists every row of `rows` into `store` (ADR 0026 §4's one-transaction write order; a
 * host's `IndexedDB` adapter runs these in one transaction across their stores). */
async function writeCacheRows(store: CacheStore, rows: readonly CacheRow[]): Promise<void> {
  for (const row of rows) {
    await store.put(row.store, row.key, row.value);
  }
}

/** Persists one drain's `puts` then `deletes` into `store` (module docs, {@link CacheDelta}'s
 * generated docs: "never one without the other"). */
async function writeCacheDelta(
  store: CacheStore,
  puts: readonly CacheRow[],
  deletes: readonly { store: string; key: Uint8Array }[],
): Promise<void> {
  for (const row of puts) {
    await store.put(row.store, row.key, row.value);
  }
  for (const key of deletes) {
    await store.delete(key.store, key.key);
  }
}

/** Copies a generated `KvRow` into a plain object and frees it. */
function takeCacheRow(row: KvRow): CacheRow {
  try {
    return { store: row.store, key: row.key, value: row.value };
  } finally {
    row.free();
  }
}

/** Copies every row of a generated `KvRow[]` and frees each one, even if one throws. */
function takeCacheRows(rows: KvRow[]): CacheRow[] {
  try {
    return rows.map((row) => takeCacheRow(row));
  } finally {
    for (const row of rows) {
      // `takeCacheRow` already freed every row up to a thrown one; freeing an already-freed
      // handle is a no-op in the generated glue, so a second pass here is safe and simple.
      try {
        row.free();
      } catch {
        // Already freed.
      }
    }
  }
}

/** What the user types to enrol this device (CRYPTO.md §11.2). `device_kind` is always
 * `Extension` (ADR 0036 §1); this call never takes one in. */
export interface EnrolInput {
  readonly origin: string;
  readonly loginName: string;
  readonly secretKey: SecretInput;
  readonly password: SecretInput;
  readonly totp?: string;
}

/**
 * Enrols this device as a durable device (CRYPTO.md §11.2; ADR 0036 §1). `askTotp` is called
 * if the account has 2FA and `input.totp` is missing. The cache rows the enrolment produces
 * are persisted into `cacheStore` before this resolves (ADR 0026 §4 step 1, "secrets before
 * commit"): the returned {@link DurableSession} is never usable before its own cache row is on
 * disk.
 */
export async function enrolDevice(
  transport: Transport,
  input: EnrolInput,
  cacheStore: CacheStore,
  askTotp?: AskTotp,
  clock: Clock = Date.now,
): Promise<DurableSession> {
  const flow = withSecrets([input.secretKey, input.password], (b) => {
    ensureReady();
    return call(() =>
      EnrolFlow.start(input.origin, input.loginName, at(b, 0), at(b, 1), input.totp),
    );
  });
  try {
    await drive(flow, transport, clock, askTotp);
  } catch (e) {
    flow.free();
    throw e;
  }
  const result = call(() => flow.finish());
  let session: WasmDeviceSession;
  try {
    const rows = takeCacheRows(result.cacheRows);
    await writeCacheRows(cacheStore, rows);
    session = call(() => result.session());
  } finally {
    result.free();
  }
  return new DurableSession(session, transport, cacheStore, clock);
}

/**
 * Unlocks a persisted durable device by reading every row of `cacheStore` back (ADR 0026 §4
 * step 5): the offline unlock, then the local verify against the cache's own account objects.
 * No network beyond `cacheStore`'s own reads. The session returned is not yet
 * device-authenticated ({@link DurableSession.isAuthenticated} is `false`); call
 * {@link DurableSession.authStart}/`authRespond` before signing a request.
 */
export async function unlockDurableDevice(
  transport: Transport,
  cacheStore: CacheStore,
  password: SecretInput,
  clock: Clock = Date.now,
): Promise<DurableSession> {
  const cacheRows = await readCacheStore(cacheStore);
  const inner = withSecrets([password], (b) => {
    ensureReady();
    const rows = cacheRows.map((r) => new KvRow(r.store, r.key, r.value));
    return call(() => WasmDeviceSession.unlock(rows, at(b, 0), nowOf(clock)));
  });
  return DurableSession.started(inner, transport, cacheStore, clock);
}

/**
 * The values of one signed request (CRYPTO.md §5.10 "Request signing"): the `Authorization`
 * header value and the `device-request` counter and signature (ADR 0028 item 5's
 * `Rizzy-Request-Counter`/`Rizzy-Request-Signature`). {@link DurableSession.sync} already
 * attaches these to every request it sends; a host only needs this directly for a signed call
 * {@link DurableSession.sync} does not make.
 */
export interface SignedRequestValues {
  readonly bearer: string;
  readonly requestCounter: bigint;
  readonly signature: string;
}

/** Copies a generated `CacheKey` into a plain object and frees it. */
function takeCacheKey(key: CacheKey): { store: string; key: Uint8Array } {
  try {
    return { store: key.store, key: key.key };
  } finally {
    key.free();
  }
}

/** Copies a generated `CacheDelta` into plain `puts`/`deletes` and frees it and every row and
 * key it held. */
function takeCacheDelta(delta: CacheDelta): {
  puts: CacheRow[];
  deletes: { store: string; key: Uint8Array }[];
} {
  try {
    return { puts: takeCacheRows(delta.puts), deletes: mapFree(delta.deletes, takeCacheKey) };
  } finally {
    delta.free();
  }
}

/**
 * A durable device, unlocked. Returned by {@link enrolDevice} and {@link unlockDurableDevice};
 * {@link DurableSession.lock} drops every handle it holds (ADR 0013 §3 rule 1), as does letting
 * it be garbage-collected after `lock`, though a host should not rely on GC timing for a
 * secret handle.
 *
 * Every mutating call ({@link DurableSession.sync}, {@link DurableSession.createItem}, …) is
 * `async`: it drains the core's cache writes (`drainCacheWrites`) and persists them through the
 * {@link CacheStore} given at construction before it resolves, so a caller that `await`s the
 * call already has its result on disk (ADR 0026 §4's write order; `VaultSession`'s matching
 * calls need no such wait, since the ephemeral web vault persists nothing).
 */
export class DurableSession {
  readonly #inner: WasmDeviceSession;
  readonly #transport: Transport;
  readonly #cacheStore: CacheStore;
  readonly #clock: Clock;
  #locked = false;

  /** @internal use {@link enrolDevice} or {@link unlockDurableDevice}. */
  constructor(inner: WasmDeviceSession, transport: Transport, cacheStore: CacheStore, clock: Clock) {
    this.#inner = inner;
    this.#transport = transport;
    this.#cacheStore = cacheStore;
    this.#clock = clock;
  }

  /** The clock as the core takes it. */
  #now(): bigint {
    return nowOf(this.#clock);
  }

  /**
   * The session {@link unlockDurableDevice} returns, with the writes of its start already
   * persisted: a cache-format migration of the rows it was unlocked from (ADR 0026 §5) and a
   * raised `highest_equivalence_list_version` once a newer global equivalence list verified
   * (ADR 0051 §1–§4), committed as part of the load, before any other step. If persisting
   * fails, the session is locked and the error thrown; the next unlock simply migrates and
   * verifies again (INV-75). Internal to this package.
   *
   * @internal
   */
  static async started(
    inner: WasmDeviceSession,
    transport: Transport,
    cacheStore: CacheStore,
    clock: Clock,
  ): Promise<DurableSession> {
    const session = new DurableSession(inner, transport, cacheStore, clock);
    try {
      await session.#drain();
    } catch (e) {
      session.lock();
      throw e;
    }
    return session;
  }

  /** Drains the core's cache writes since the last drain and persists them (class docs). */
  async #drain(): Promise<void> {
    const delta = takeCacheDelta(call(() => this.#inner.drainCacheWrites()));
    await writeCacheDelta(this.#cacheStore, delta.puts, delta.deletes);
  }

  /** The account, hex. */
  get accountId(): string {
    return call(() => this.#inner.accountId);
  }

  /** This device, hex. */
  get deviceId(): string {
    return call(() => this.#inner.deviceId);
  }

  /** Whether {@link signRequest} would succeed right now. */
  isAuthenticated(): boolean {
    return call(() => this.#inner.isAuthenticated());
  }

  /**
   * Runs device authentication (§5.10) to `"done"`, so {@link signRequest} can be called.
   * Idempotent: a call while already authenticated does nothing.
   */
  async authenticate(): Promise<void> {
    if (this.isAuthenticated()) {
      return;
    }
    call(() => this.#inner.authStart());
    for (;;) {
      const state = call(() => this.#inner.authState);
      if (state !== "request") {
        break;
      }
      const request = takeRequest(call(() => this.#inner.authRequest()));
      const answer = await this.#transport(request);
      call(() => this.#inner.authRespond(answer.status, answer.body));
    }
  }

  /** Signs one request with the device key, after {@link authenticate}. */
  signRequest(method: string, pathAndQuery: string, body: Uint8Array): SignedRequestValues {
    const signed = call(() => this.#inner.signRequest(method, pathAndQuery, body));
    try {
      return {
        bearer: signed.bearer,
        requestCounter: signed.requestCounter,
        signature: signed.signature,
      };
    } finally {
      signed.free();
    }
  }

  /** Whether writes are refused. */
  get readOnly(): boolean {
    return call(() => this.#inner.readOnly);
  }

  /** Own changes the server has not acknowledged: what a lock now would lose (the cache keeps
   * them, unlike {@link VaultSession}'s ephemeral device; a later unlock resends them). */
  get unsentChanges(): number {
    return call(() => this.#inner.unsentChanges);
  }

  /** Whether a sync is running. */
  get syncing(): boolean {
    return this.#inner.syncing;
  }

  /**
   * Fetches, heals if needed, uploads, and fetches again (as {@link VaultSession.sync}), every
   * request signed with this device's key ({@link authenticate} first). After each answer,
   * drains and persists the step's cache writes (class docs) before the next request is
   * released (ADR 0026 §4's write order) — the durable device's own addition over the
   * ephemeral web vault's sync.
   *
   * Once the driver settles, this also runs the client-side trash auto-purge (gap 00; ADR
   * 0012 §5, ADR 0018 §9, §11) and drains its cache writes, the same write-order rule as every
   * other step.
   */
  async sync(): Promise<void> {
    const s = this.#inner;
    call(() => s.syncStart());
    for (;;) {
      const request = call(() => s.syncRequest());
      if (request === undefined) {
        await this.#drain();
        // Mirrors `Device::auto_purge` (rizzy-cli/src/device.rs): whatever the pass journals
        // before it fails is drained too, so the next drain below always runs before the
        // error propagates (class docs' write order) — never skipped by a `call()` rethrow.
        let failure: { error: unknown } | undefined;
        try {
          s.autoPurge(this.#now());
        } catch (e) {
          failure = { error: toCoreError(e) };
        }
        await this.#drain();
        if (failure !== undefined) {
          throw failure.error;
        }
        return;
      }
      let answer: CoreResponse;
      try {
        answer = await this.#transport(takeRequest(request));
      } catch (e) {
        if (this.#inner === s) {
          call(() => s.syncAbort());
        }
        throw e;
      }
      if (this.#inner !== s) {
        throw new CoreError("locked");
      }
      call(() => s.syncRespond(answer.status, answer.body, this.#now()));
      await this.#drain();
    }
  }

  /** The active items, or the trashed ones. */
  items(trash = false): ItemSummary[] {
    return mapFree(
      call(() => this.#inner.items(trash)),
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
      call(() => this.#inner.item(id)),
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
      call(() => this.#inner.itemFields(id)),
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
    return call(() => this.#inner.revealField(id, key));
  }

  /**
   * Signs a WebAuthn assertion with a passkey already stored on this item (ADR 0039 §2). The
   * private key never leaves the wasm boundary; only the signed assertion comes back.
   */
  passkeyAssertion(id: string, passkeyId: string, origin: string, rpId: string, challenge: Uint8Array): PasskeyAssertionResult {
    return mapPasskeyAssertion(call(() => this.#inner.passkeyAssertion(id, passkeyId, origin, rpId, challenge)));
  }

  /**
   * Every stored passkey's non-secret metadata on one item (ADR 0039 §1), for the host to pick
   * which credential to run {@link passkeyAssertion} with — in particular, to filter against
   * the page's `allowCredentials` before picking one (gap 35(b) in the M2 gap audit).
   */
  passkeyCandidates(id: string): PasskeyCandidateResult[] {
    return mapPasskeyCandidates(call(() => this.#inner.passkeyCandidates(id)));
  }

  /** Creates an item; returns its id. Persisted before this resolves (class docs). */
  async createItem(itemType: ItemType, changes: readonly ItemChange[]): Promise<string> {
    const draft = draftOf(changes);
    let id: string;
    try {
      id = call(() => this.#inner.createItem(itemType, draft, this.#now()));
    } finally {
      draft.free();
    }
    await this.#drain();
    return id;
  }

  /** Edits an active item as one op. Persisted before this resolves (class docs). */
  async editItem(id: string, changes: readonly ItemChange[]): Promise<void> {
    const draft = draftOf(changes);
    try {
      call(() => this.#inner.editItem(id, draft, this.#now()));
    } finally {
      draft.free();
    }
    await this.#drain();
  }

  /** Moves an item to the trash. Persisted before this resolves (class docs). */
  async trashItem(id: string): Promise<void> {
    call(() => this.#inner.trashItem(id, this.#now()));
    await this.#drain();
  }

  /** Restores a trashed item. Persisted before this resolves (class docs). */
  async restoreItem(id: string): Promise<void> {
    call(() => this.#inner.restoreItem(id, this.#now()));
    await this.#drain();
  }

  /** Purges a trashed item for good. Persisted before this resolves (class docs). */
  async purgeItem(id: string): Promise<void> {
    call(() => this.#inner.purgeItem(id, this.#now()));
    await this.#drain();
  }

  /** Zeroizes every handle this session holds. Safe to call more than once. */
  lock(): void {
    if (this.#locked) {
      return;
    }
    this.#locked = true;
    this.#inner.lock();
  }

  /**
   * Decides which of `itemUris` are autofill candidates for `pageUrl`, requested by `frame`
   * (ADR 0037 §4, §5), under this account's own settings (ADR 0042 §6): a URI whose mode is
   * {@link MatchMode.AccountDefault} uses the account's match default, and the account's
   * disabled global groups and user-defined groups shape the equivalence view. Settings this
   * build cannot read fail the call (`settings_update_required`, `invalid_server_response`): no
   * candidate is offered under settings the core could not apply.
   */
  decideMatchCandidates(
    pageUrl: string,
    frame: MatchFrameInfo,
    itemUris: readonly MatchUriInput[],
  ): MatchDecisionResult {
    const inputs = itemUris.map((u) => new UriInput(u.itemId, u.uriId, u.value, u.mode));
    return decisionOf(
      call(() => this.#inner.decideMatchCandidates(pageUrl, frame.isTopFrame, frame.frameOrigin, inputs)),
    );
  }

  /** The account's matching settings (ADR 0042 §3), read-only here. */
  matchSettings(): MatchSettings {
    return matchSettingsOf(call(() => this.#inner.matchSettings()));
  }
}

// ---------------------------------------------------------------------------------------------
// URL matching for autofill (ADR 0037, ADR 0038; M2). Over `rizzy-match` through
// `rizzy_client::matching` (that crate's module docs explain the split): every check and every
// narrowing rule is decided in Rust, never reimplemented here.

/** `uri/<id>/match`'s wire values (ADR 0037 §4). `AccountDefault` (`0x0000`) is a URI's "no
 * override": the core resolves it to the account-level match default — the account's own
 * setting through a session's `decideMatchCandidates` ({@link DurableSession.decideMatchCandidates},
 * {@link VaultSession.matchCandidates}; ADR 0042 §6), or the `accountDefaultMode` argument of
 * the free {@link decideMatchCandidates}. It is never itself an account default. */
export const MatchMode = {
  AccountDefault: 0x0000,
  BaseDomain: 0x0001,
  Host: 0x0002,
  StartsWith: 0x0003,
  Exact: 0x0004,
  Regex: 0x0005,
  Never: 0x0006,
} as const;

/** One of {@link MatchMode}'s values. */
export type MatchModeValue = (typeof MatchMode)[keyof typeof MatchMode];

/** One saved URI to match against (ADR 0037 §2, §4). */
export interface MatchUriInput {
  readonly itemId: string;
  readonly uriId: string;
  readonly value: string;
  readonly mode: MatchModeValue;
}

/** What the content script reports about the frame asking for candidates (ADR 0037 §5). */
export interface MatchFrameInfo {
  readonly isTopFrame: boolean;
  readonly frameOrigin: string;
}

/** One candidate offered for autofill. */
export interface MatchCandidate {
  readonly itemId: string;
  readonly uriId: string;
  /** Whether the fill UI must show the equivalence-only warning (ADR 0037 §5) before the
   * fill. */
  readonly needsWarning: boolean;
  /** The saved URI's exact normalised host, A-label form (ADR 0037 §5 "Exact host shown";
   * gap 31 in the M2 gap audit). Never decode this to Unicode in a host UI: a mixed-script
   * host must keep showing its punycode `xn--` form. */
  readonly savedHost: string;
  /** The saved URI's own port, `undefined` when it is its scheme's default (ADR 0037 §2 rule
   * 5). `savedHost` alone is the page's *registrable-domain-narrowed* candidate set (ADR 0037
   * §4's `BaseDomain` mode, autofill's own default); a caller doing a destructive "same site"
   * decision on top of it — never autofill itself — must compare this alongside `savedHost`
   * against {@link MatchDecisionResult.pagePort}, or two different ports on the same host are
   * wrongly treated as the same site. */
  readonly savedPort?: number | undefined;
}

/** The result of one {@link decideMatchCandidates} call. */
export interface MatchDecisionResult {
  /** The page's own exact normalised host, A-label form (ADR 0037 §5 "Exact host shown";
   * gap 31 in the M2 gap audit): what the fill UI always shows, matching or not. */
  readonly pageHost: string;
  /** The page's own port, `undefined` when it is its scheme's default ({@link
   * MatchCandidate.savedPort}'s own doc explains why a "same site" gate must compare this). */
  readonly pagePort: number | undefined;
  readonly candidates: readonly MatchCandidate[];
  readonly warnings: readonly string[];
}

/** The page's own normalised URL (ADR 0037 §2), in the same canonical form matching uses. */
export function normalizePageUrl(url: string): string {
  ensureReady();
  return call(() => wasmNormalizePageUrl(url));
}

/** `url`'s registrable domain (eTLD+1, ADR 0037 §2 rule 7), for a host that needs to key state
 * by "the same site" across a same-tab navigation (the extension's save-prompt continuity) —
 * never computed outside `rizzy-match` (ADR 0037 §1), so a phishing-relevant PSL bug is fixed
 * once. `undefined` only for a bare public suffix (`co.uk`, `com`), which has no registrable
 * domain beneath it, not an error; an IP-literal host is its own registrable domain (never run
 * through the PSL, which has no concept of one). */
export function registrableDomainOf(url: string): string | undefined {
  ensureReady();
  return call(() => wasmRegistrableDomainOf(url));
}

/** The global groups {@link decideMatchCandidates} uses, verified on its first call. */
let globalWithoutCache: GlobalEquivalence | undefined;

/**
 * Decides which of `itemUris` are autofill candidates for `pageUrl`, requested by `frame`
 * (ADR 0037 §4, §5). `accountDefaultMode` resolves any URI whose own mode is `0x0000`. The
 * merged equivalence view is the compiled-in global list alone (ADR 0037 §7, ADR 0038 §5):
 * this function holds no session and so no account settings. A host with a session calls the
 * session's own `decideMatchCandidates` / `matchCandidates` instead, which apply the account's
 * match default, disabled global groups and user-defined groups (ADR 0042 §6).
 *
 * The global list is verified once per module load, not per call (ADR 0051 §4), from
 * `highest_accepted_version = 0`: like the web vault, this free function keeps no cache and so
 * no persisted floor (ADR 0051 §5). A durable session verifies against its cache's floor.
 */
export function decideMatchCandidates(
  pageUrl: string,
  frame: MatchFrameInfo,
  accountDefaultMode: MatchModeValue,
  itemUris: readonly MatchUriInput[],
): MatchDecisionResult {
  ensureReady();
  globalWithoutCache ??= call(() => GlobalEquivalence.withoutCache());
  const global = globalWithoutCache;
  const inputs = itemUris.map((u) => new UriInput(u.itemId, u.uriId, u.value, u.mode));
  return decisionOf(
    call(() =>
      wasmDecideMatchCandidates(pageUrl, frame.isTopFrame, frame.frameOrigin, accountDefaultMode, inputs, global),
    ),
  );
}

/** A generated match decision as a plain object, freed. */
function decisionOf(decision: WasmMatchDecision): MatchDecisionResult {
  try {
    const candidates = decision.candidates.map((c) => {
      try {
        return { itemId: c.itemId, uriId: c.uriId, needsWarning: c.needsWarning, savedHost: c.savedHost, savedPort: c.savedPort };
      } finally {
        c.free();
      }
    });
    return { pageHost: decision.pageHost, pagePort: decision.pagePort, candidates, warnings: [...decision.warnings] };
  } finally {
    decision.free();
  }
}

// ---------------------------------------------------------------------------------------------
// Account match settings (ADR 0037 §6–§7, ADR 0042): the account-level match default, the
// global equivalence groups the account disabled and its own user-defined groups. They live in
// the signed account state's `ACCOUNT_SETTINGS`; the core reads, checks and writes them.

/** One equivalence group as the settings screen shows it. Domains are A-label form: never decode
 * them to Unicode for display (ADR 0037 §2 point 4). */
export interface EquivalenceGroupInfo {
  /** The group id, 32 lowercase hex digits. */
  readonly id: string;
  readonly domains: readonly string[];
  /** For a global group: whether the account disabled it. Always `false` for a user group. */
  readonly disabled: boolean;
}

/** The account's matching settings. */
export interface MatchSettings {
  /** The mode a website with no override of its own uses (`0x0001`–`0x0006`). */
  readonly matchDefault: MatchModeValue;
  /** The account's own groups. */
  readonly userGroups: readonly EquivalenceGroupInfo[];
  /** This build's signed global list, each with its disabled flag; empty while none is shipped. */
  readonly globalGroups: readonly EquivalenceGroupInfo[];
  /** Disabled ids that name no group of this build's global list, hex: still disabled. */
  readonly otherDisabled: readonly string[];
}

/** One change to the account's matching settings: one `account/commit` (ADR 0042 §5). */
export type SettingsChange =
  | { readonly kind: "matchDefault"; readonly mode: MatchModeValue }
  | { readonly kind: "addUserGroup"; readonly domains: readonly string[] }
  | { readonly kind: "removeUserGroup"; readonly id: string }
  | { readonly kind: "disableGlobalGroup"; readonly id: string }
  | { readonly kind: "enableGlobalGroup"; readonly id: string };

/** A generated settings view as a plain object, freed. */
function matchSettingsOf(view: WasmMatchSettingsView): MatchSettings {
  return mapOne(view, (v) => {
    const group = (g: WasmEquivalenceGroupView): EquivalenceGroupInfo => ({
      id: g.id,
      domains: [...g.domains],
      disabled: g.disabled,
    });
    return {
      matchDefault: v.matchDefault as MatchModeValue,
      userGroups: mapFree(v.userGroups, group),
      globalGroups: mapFree(v.globalGroups, group),
      otherDisabled: [...v.otherDisabled],
    };
  });
}

/** The core call that builds the commit of `change`. */
function settingsRequest(s: Session, change: SettingsChange): HttpRequest {
  switch (change.kind) {
    case "matchDefault":
      return s.setMatchDefaultRequest(change.mode);
    case "addUserGroup":
      return s.addUserGroupRequest([...change.domains]);
    case "removeUserGroup":
      return s.removeUserGroupRequest(change.id);
    case "disableGlobalGroup":
      return s.disableGlobalGroupRequest(change.id);
    case "enableGlobalGroup":
      return s.enableGlobalGroupRequest(change.id);
  }
}
