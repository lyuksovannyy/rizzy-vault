// The messages between the UI thread and the core Worker (ADR 0013 §4 "Where the core lives").
//
// The Worker holds the only wasm instance, every handle and every key; the UI thread holds
// none. They exchange only what ADR 0013 §3 rule 3 lets cross: summaries, field views without
// concealed values, a value the user asked to reveal, generated values, counts, and the files
// the user asked for (exports, the Emergency Kit). Secrets the user types travel as UTF-8 byte
// arrays whose buffers are transferred, so no copy stays on the UI side, and the core zeroes
// them after use (`SecretInput` of packages/core).
//
// This module is types and pure checks only; it imports no wasm.
import type {
  DetectedImportFormat,
  DeviceView,
  EncryptedExport,
  FieldView,
  Generated,
  ImportFormat,
  ImportReport,
  ItemChange,
  ItemSummary,
  ItemType,
  TotpCode,
  TwoFactorSetup,
} from "@rizzy-vault/core";

/** The session state the UI shows. */
export interface SessionInfo {
  readonly locked: boolean;
  readonly accountId: string;
  readonly deviceId: string;
  readonly readOnly: boolean;
  readonly unsentChanges: number;
}

/** The Emergency Kit as it crosses to the UI: bytes the UI zeroes once rendered. */
export interface KitMessage {
  readonly serverOrigin: string;
  readonly loginName: string;
  readonly secretKey: Uint8Array;
  readonly recoveryCode: Uint8Array | undefined;
}

/**
 * The calls the Worker serves. Each is one user action (ADR 0013 §3 rule 6). The UI never
 * names a server origin: the Worker uses its own (`self.location.origin`), the vault's origin.
 */
export interface CoreApi {
  /** Loads the wasm module and checks that the server speaks `v1`. */
  start(): { version: string };
  login(
    loginName: string,
    secretKey: Uint8Array,
    password: Uint8Array,
  ): SessionInfo;
  signupStart(
    loginName: string,
    password: Uint8Array,
    invite: string | undefined,
    issueRecoveryCode: boolean,
  ): void;
  signupKit(): KitMessage;
  signupConfirm(lastGroup: string): void;
  signupRetryCommit(): void;
  signupLogin(): SessionInfo;
  signupCancel(): void;
  status(): SessionInfo | undefined;
  lock(): void;
  sync(): SessionInfo;
  items(trash: boolean): ItemSummary[];
  item(id: string): ItemSummary;
  fields(id: string): FieldView[];
  reveal(id: string, key: string): string;
  createItem(itemType: ItemType, changes: ItemChange[]): string;
  editItem(id: string, changes: ItemChange[]): void;
  trashItem(id: string): void;
  restoreItem(id: string): void;
  purgeItem(id: string): void;
  totp(id: string): TotpCode;
  exportEncrypted(password: Uint8Array): EncryptedExport;
  exportBlockers(): string[];
  csvExportWarning(): string;
  reauthenticate(secretKey: Uint8Array, password: Uint8Array): void;
  reauthFresh(): boolean;
  plaintextWarningShown(): number;
  exportPlaintext(format: "json" | "csv", typedPhrase: string): Uint8Array;
  detectImportFormat(file: Uint8Array): DetectedImportFormat;
  importFile(format: ImportFormat, file: Uint8Array): ImportReport;
  importEncrypted(file: Uint8Array, password: Uint8Array): ImportReport;
  devices(): DeviceView[];
  enableTwoFactor(): TwoFactorSetup;
  confirmTwoFactor(code: string): void;
  disableTwoFactor(code: string): void;
  generatePassword(length: number, symbols: boolean, excludeAmbiguous: boolean): Generated;
  generatePassphrase(words: number): Generated;
  plaintextExportWarning(): string;
  plaintextExportPhrase(): string;
}

/** A method name of {@link CoreApi}. */
export type Method = keyof CoreApi;

/** The method names, for checking an incoming call. */
export const METHODS: readonly Method[] = [
  "start",
  "login",
  "signupStart",
  "signupKit",
  "signupConfirm",
  "signupRetryCommit",
  "signupLogin",
  "signupCancel",
  "status",
  "lock",
  "sync",
  "items",
  "item",
  "fields",
  "reveal",
  "createItem",
  "editItem",
  "trashItem",
  "restoreItem",
  "purgeItem",
  "totp",
  "exportEncrypted",
  "exportBlockers",
  "csvExportWarning",
  "reauthenticate",
  "reauthFresh",
  "plaintextWarningShown",
  "exportPlaintext",
  "detectImportFormat",
  "importFile",
  "importEncrypted",
  "devices",
  "enableTwoFactor",
  "confirmTwoFactor",
  "disableTwoFactor",
  "generatePassword",
  "generatePassphrase",
  "plaintextExportWarning",
  "plaintextExportPhrase",
];

/** UI → Worker: a call. */
export interface CallMessage {
  readonly kind: "call";
  readonly id: number;
  readonly method: Method;
  readonly args: readonly unknown[];
}

/** UI → Worker: the answer to an {@link AskTotpMessage}; `null` when the user cancelled. */
export interface TotpMessage {
  readonly kind: "totp";
  readonly id: number;
  readonly code: string | null;
}

/** Worker → UI: the result of a call. */
export type ResultMessage =
  | { readonly kind: "result"; readonly id: number; readonly ok: true; readonly value: unknown }
  | { readonly kind: "result"; readonly id: number; readonly ok: false; readonly code: string };

/** Worker → UI: the server wants the second factor for the login of call `id`. */
export interface AskTotpMessage {
  readonly kind: "ask-totp";
  readonly id: number;
}

/** Any message to the Worker. */
export type ToWorker = CallMessage | TotpMessage;

/** Any message from the Worker. */
export type FromWorker = ResultMessage | AskTotpMessage;

/**
 * Codes the web vault adds to the core's (packages/core's README lists those): the user
 * closed the second-factor prompt; the core trapped and the page must be reloaded; a message
 * that is not one of ours.
 */
export const TOTP_CANCELLED = "totp_cancelled";
export const CORE_CRASHED = "core_crashed";
export const BAD_MESSAGE = "bad_message";

/** Whether `value` is a call this Worker serves (shape only; the arguments are the core's to check). */
export function isToWorker(value: unknown): value is ToWorker {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const m = value as Record<string, unknown>;
  if (typeof m["id"] !== "number" || !Number.isSafeInteger(m["id"])) {
    return false;
  }
  if (m["kind"] === "call") {
    return (
      typeof m["method"] === "string" &&
      (METHODS as readonly string[]).includes(m["method"]) &&
      Array.isArray(m["args"])
    );
  }
  if (m["kind"] === "totp") {
    return m["code"] === null || typeof m["code"] === "string";
  }
  return false;
}

/** Whether `value` is a message the Worker sends. */
export function isFromWorker(value: unknown): value is FromWorker {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const m = value as Record<string, unknown>;
  if (typeof m["id"] !== "number") {
    return false;
  }
  if (m["kind"] === "ask-totp") {
    return true;
  }
  return (
    m["kind"] === "result" &&
    (m["ok"] === true || (m["ok"] === false && typeof m["code"] === "string"))
  );
}

/** The buffers of the byte arrays in `values`, to transfer rather than copy. */
export function transferables(values: readonly unknown[]): ArrayBuffer[] {
  const out: ArrayBuffer[] = [];
  const visit = (v: unknown) => {
    if (v instanceof Uint8Array) {
      if (v.buffer instanceof ArrayBuffer && !out.includes(v.buffer)) {
        out.push(v.buffer);
      }
    } else if (Array.isArray(v)) {
      v.forEach(visit);
    } else if (typeof v === "object" && v !== null) {
      Object.values(v).forEach(visit);
    }
  };
  values.forEach(visit);
  return out;
}
