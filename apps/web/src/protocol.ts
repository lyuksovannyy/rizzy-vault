// SPDX-License-Identifier: AGPL-3.0-only

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
  AttachmentInfo,
  BreachResult,
  ConflictValue,
  DetectedImportFormat,
  DeviceView,
  CxfExport,
  EncryptedExport,
  FieldHistory,
  FieldView,
  Generated,
  GeneratorLimits,
  HistoryEntry,
  IdentityCountry,
  IdentityDefaults,
  IdentityGeneratorOptions,
  ImportFormat,
  ImportReport,
  CustomFieldAutofill,
  ItemChange,
  ItemSummary,
  ItemType,
  MatchDecisionResult,
  MatchSettings,
  Notice,
  PassphraseOptions,
  PasswordOptions,
  SecurityKeyAnswer,
  SecurityKeyEnrolmentInfo,
  SecurityKeyInfo,
  SessionListView,
  SettingsChange,
  RecoveryNotice,
  StorageUsage,
  TotpCode,
  TwoFactorSetup,
  VaultAlarm,
  VaultInfo,
} from "@rizzy-vault/core";

/** The session state the UI shows. */
export interface SessionInfo {
  readonly locked: boolean;
  readonly accountId: string;
  readonly deviceId: string;
  readonly readOnly: boolean;
  readonly unsentChanges: number;
  /** The storage usage the server last reported (ADR 0048 §5); unverified, for display. */
  readonly storageUsage?: StorageUsage | undefined;
  /** The server's pending-recovery notice with its last account answer (ADR 0045), if any;
   * advisory only, for the banner (INV-70). An honest server sends none to a web session. */
  readonly recoveryNotice?: RecoveryNotice | undefined;
}

/** The Emergency Kit as it crosses to the UI: bytes the UI zeroes once rendered. */
export interface KitMessage {
  readonly serverOrigin: string;
  readonly loginName: string;
  readonly secretKey: Uint8Array;
  readonly recoveryCode: Uint8Array | undefined;
}

/**
 * An identity draft as it crosses to the UI (ADR 0079 §3): the Worker keeps the core's
 * `IdentityDraft` under `handle` (`identity-drafts.ts`) and sends its plain values. They are
 * generated values, which ADR 0013 §3 rule 3 lets cross.
 */
export interface IdentityDraftMessage {
  readonly handle: number;
  /** The filled fields, by ADR 0018 §7 key. */
  readonly fields: Readonly<Record<string, string>>;
  /** "First Last", the default item name. */
  readonly itemName: string;
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
  /** What each custom field's autocomplete id does (ADR 0076 §2.5): no value. */
  customFieldAutofill(id: string): CustomFieldAutofill[];
  reveal(id: string, key: string): string;
  /** Creates an item in `vaultId` (ADR 0081 §A8); returns its reference. */
  createItem(vaultId: string, itemType: ItemType, changes: ItemChange[]): string;
  /** Every vault (ADR 0081 §A2): Personal first, then the others by name. */
  vaults(): VaultInfo[];
  /** The Personal vault, preselected everywhere (§A8). */
  personalVaultId(): string | undefined;
  /** The vault completeness check's alarms (INV-102). */
  vaultAlarms(): VaultAlarm[];
  /** Unsent changes discarded with vaults deleted elsewhere, since the last call. */
  takeDiscardedChanges(): number;
  /** Creates an owned vault (§A3); returns its id. */
  createVault(name: string): string;
  /** Renames an owned vault (§A4). */
  renameVault(vaultId: string, name: string): void;
  /** Deletes an owned vault (§A5), its items moved to Personal first with `keepItems`. */
  deleteVault(vaultId: string, keepItems: boolean): void;
  /** Copies an item into another vault (§A6); returns the copy's reference. */
  copyItem(id: string, targetVaultId: string): string;
  /** Moves an item into another vault (§A6); returns the new reference. */
  moveItem(id: string, targetVaultId: string): string;
  editItem(id: string, changes: ItemChange[]): void;
  trashItem(id: string): void;
  restoreItem(id: string): void;
  /** Deletes a trashed item for good, after deleting its attachments from the server. */
  purgeItem(id: string): void;
  /** The item's password history: sources, positions and dates, never a value (ADR 0013 §3 rule 3). */
  passwordHistory(id: string): HistoryEntry[];
  /** One password-history entry's value, on the user's request only. */
  revealPasswordHistory(
    id: string,
    source: HistoryEntry["source"],
    index: number,
    entryId: string,
  ): string;
  /** Every field's history: positions and dates per field, never a value (ROADMAP §4.2). */
  itemHistory(id: string): FieldHistory[];
  /** One field-history entry's value, on the user's request only. */
  revealFieldHistory(id: string, key: string, index: number, entryId: string): string;
  /** Restores one field-history entry as the field's current value, an ordinary edit. */
  restoreFieldHistory(id: string, key: string, index: number, entryId: string): void;
  /** A conflicting field's distinct values, concealed ones withheld (ROADMAP §4.5 "keep both / pick one"). */
  fieldConflict(id: string, key: string): ConflictValue[];
  /** One conflicting value, on the user's request only (ADR 0013 §3 rule 3). */
  revealConflictValue(id: string, key: string, index: number, valueId: string): string;
  /** "Pick one": writes the named value back to the field, an ordinary edit. */
  resolveConflictPick(id: string, key: string, index: number, valueId: string): void;
  /** "Keep both": keeps the named value; the others become new fields (or websites). */
  resolveConflictKeepBoth(
    id: string,
    key: string,
    index: number,
    valueId: string,
    label: string | undefined,
  ): string[];
  /** The late-edit and trash notices not yet handed over in this session (gap 02). */
  takeNotices(): Notice[];
  /** Restores the late edits of an item deleted permanently as a new item; returns its id. */
  restoreLateAsNew(id: string, itemType: ItemType): string;
  totp(id: string): TotpCode;
  /** A breach check of the item's password (ADR 0053), read inside the core; `null` when the
   * item has no password. Only a 5-character hash prefix is sent. */
  breachCheckItem(id: string): BreachResult | null;
  /** A breach check of a password the UI already holds (a generated one), as bytes the Worker
   * zeroes; only a 5-character hash prefix is sent. */
  breachCheckPassword(password: Uint8Array): BreachResult;
  /** The icon of an item's website host (ADR 0052), from this server's `icons` role: PNG bytes
   * the core checked, or `null` when there is none to show. Only the hostname is sent. Runs
   * beside the call queue (it touches no session state), and only while unlocked. */
  itemIcon(websiteHost: string): Uint8Array | null;
  exportEncrypted(vaultId: string, password: Uint8Array): EncryptedExport;
  exportBlockers(vaultId: string): string[];
  csvExportWarning(vaultId: string): string;
  reauthenticate(secretKey: Uint8Array, password: Uint8Array): void;
  reauthFresh(): boolean;
  plaintextWarningShown(): number;
  exportPlaintext(vaultId: string, format: "json" | "csv", typedPhrase: string): Uint8Array;
  detectImportFormat(file: Uint8Array): DetectedImportFormat;
  importFile(vaultId: string, format: ImportFormat, file: Uint8Array): ImportReport;
  importEncrypted(vaultId: string, file: Uint8Array, password: Uint8Array): ImportReport;
  /** How many passkeys a CXF export would hold now (ADR 0074 §2). */
  cxfExportPasskeys(vaultId: string): number;
  /** The CXF passkey export (ADR 0074 §2), gated like {@link exportPlaintext}. */
  exportCxf(vaultId: string, typedPhrase: string, password: Uint8Array): CxfExport;
  /** Imports our own CXF passkey export with its file password (ADR 0074 §3). */
  importCxfEncrypted(vaultId: string, file: Uint8Array, password: Uint8Array): ImportReport;
  devices(): DeviceView[];
  /** The account's live sessions (ADR 0075 R1): the server's word, for display. */
  sessions(): SessionListView;
  /** Ends one other session of the last list (R3); needs a fresh login. */
  endSession(id: string): void;
  /** Ends every other password and recovery session (R4); needs a fresh login. */
  endOtherSessions(): void;
  /** Logs in again and switches to the new, fresh session; the old one is ended (§9). */
  refreshSession(secretKey: Uint8Array, password: Uint8Array): void;
  /** The texts of ADR 0075 §6 and §8. */
  sessionNotices(): { ended: string; othersEnded: string; oneEnded: string };
  enableTwoFactor(): TwoFactorSetup;
  confirmTwoFactor(code: string): void;
  disableTwoFactor(code: string): void;
  /** Security keys (ADR 0058): a started enrolment's options, for `navigator.credentials` on
   * the UI thread; needs a fresh login. */
  startSecurityKeyEnrolment(): SecurityKeyEnrolmentInfo;
  /** Confirms an enrolment with the browser's `create()` result (JSON) and a label. */
  confirmSecurityKey(enrolmentId: string, label: string, credential: string): void;
  /** The account's security keys. */
  listSecurityKeys(): SecurityKeyInfo[];
  /** Removes one security key; needs a fresh login. */
  removeSecurityKey(credentialId: string): void;
  /** The account's match default and equivalence groups (ADR 0037 §6–§7, ADR 0042). */
  matchSettings(): MatchSettings;
  /** What autofill would offer on a website, under the account's settings. Ids and hosts only. */
  matchCandidates(pageUrl: string): MatchDecisionResult;
  /** One change to the matching settings (checked with {@link isSettingsChange}). */
  changeMatchSettings(change: SettingsChange): void;
  generatePasswordWithOptions(options: Partial<PasswordOptions>): Generated;
  generatePassphraseWithOptions(options: Partial<PassphraseOptions>): Generated;
  passwordEntropy(options: Partial<PasswordOptions>): number;
  passphraseEntropy(options: Partial<PassphraseOptions>): number;
  generatorLimits(): GeneratorLimits;
  plaintextExportWarning(): string;
  plaintextExportPhrase(): string;
  /** The CXF passkey export's own warning (ADR 0074 §2). */
  cxfExportWarning(): string;
  /** The identity generator's bundled countries, CLDR English names (ADR 0079 §5). */
  identityCountries(): IdentityCountry[];
  /** The identity generator's synced defaults, or `null` until first set (ADR 0079 OQ 7). */
  identityDefaults(): IdentityDefaults | null;
  /** An email domain lower-cased, or `identity_email_domain`(`_not_ascii`) (ADR 0079 §3). */
  normalizeEmailDomain(domain: string): string;
  /** Draws a new identity (ADR 0079 §3, §4); options checked with {@link isIdentityOptions}. */
  identityGenerate(options: IdentityGeneratorOptions): IdentityDraftMessage;
  /** Redraws `fieldKey` and its dependents of draft `handle` (ADR 0079 §4), which is freed: the
   * answer carries the new draft's handle. */
  identityRegenerate(handle: number, fieldKey: string, options: IdentityGeneratorOptions): IdentityDraftMessage;
  /** Frees draft `handle` (an unknown one is a no-op). */
  identityRelease(handle: number): void;
  /** A fresh element id for a new website or custom-field row (`@rizzy-vault/core`'s `newElementId`). */
  newElementId(): string;
  /** The attachments of an item: ids, names, media types and sizes (ADR 0054 §4). */
  attachments(id: string): AttachmentInfo[];
  /** Encrypts a file the user chose and attaches it to an item (ADR 0054); its bytes are
   * transferred and zeroed after use. Returns the attachment id. */
  addAttachment(id: string, name: string, mime: string, data: Uint8Array): string;
  /** A verified attachment's bytes, on the user's request only (ADR 0013 §3 rule 3). */
  downloadAttachment(id: string, attachmentId: string): Uint8Array;
  /** Deletes an attachment from the server and from the item. */
  deleteAttachment(id: string, attachmentId: string): void;
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
  "customFieldAutofill",
  "reveal",
  "createItem",
  "vaults",
  "personalVaultId",
  "vaultAlarms",
  "takeDiscardedChanges",
  "createVault",
  "renameVault",
  "deleteVault",
  "copyItem",
  "moveItem",
  "editItem",
  "trashItem",
  "restoreItem",
  "purgeItem",
  "passwordHistory",
  "revealPasswordHistory",
  "itemHistory",
  "revealFieldHistory",
  "restoreFieldHistory",
  "fieldConflict",
  "revealConflictValue",
  "resolveConflictPick",
  "resolveConflictKeepBoth",
  "takeNotices",
  "restoreLateAsNew",
  "totp",
  "breachCheckItem",
  "breachCheckPassword",
  "itemIcon",
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
  "cxfExportPasskeys",
  "exportCxf",
  "importCxfEncrypted",
  "devices",
  "sessions",
  "endSession",
  "endOtherSessions",
  "refreshSession",
  "sessionNotices",
  "enableTwoFactor",
  "confirmTwoFactor",
  "disableTwoFactor",
  "startSecurityKeyEnrolment",
  "confirmSecurityKey",
  "listSecurityKeys",
  "removeSecurityKey",
  "matchSettings",
  "matchCandidates",
  "changeMatchSettings",
  "generatePasswordWithOptions",
  "generatePassphraseWithOptions",
  "passwordEntropy",
  "passphraseEntropy",
  "generatorLimits",
  "plaintextExportWarning",
  "plaintextExportPhrase",
  "cxfExportWarning",
  "identityCountries",
  "identityDefaults",
  "normalizeEmailDomain",
  "identityGenerate",
  "identityRegenerate",
  "identityRelease",
  "newElementId",
  "attachments",
  "addAttachment",
  "downloadAttachment",
  "deleteAttachment",
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

/** UI → Worker: the answer to an {@link AskSecurityKeyMessage}; `null` when the user cancelled. */
export interface SecurityKeyMessage {
  readonly kind: "security-key";
  readonly id: number;
  readonly answer: SecurityKeyAnswer | null;
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

/** Worker → UI: the login of call `id` needs a security key (ADR 0058): run
 * `navigator.credentials.get` with `options` on the UI thread. */
export interface AskSecurityKeyMessage {
  readonly kind: "ask-security-key";
  readonly id: number;
  readonly options: string;
  readonly totpAllowed: boolean;
}

/** Any message to the Worker. */
export type ToWorker = CallMessage | TotpMessage | SecurityKeyMessage;

/** Any message from the Worker. */
export type FromWorker = ResultMessage | AskTotpMessage | AskSecurityKeyMessage;

/**
 * Codes the web vault adds to the core's (packages/core's README lists those): the user
 * closed the second-factor prompt; the server ended the session; the core trapped and the page
 * must be reloaded; a message that is not one of ours.
 */
export const TOTP_CANCELLED = "totp_cancelled";
/** The user closed the security-key prompt of a login. */
export const SECURITY_KEY_CANCELLED = "security_key_cancelled";
/** The server ended this session (ADR 0075 §6): the Worker locked it, the UI shows the login
 * with "This session has ended. Log in again." */
export const SESSION_ENDED = "session_ended";
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
  if (m["kind"] === "security-key") {
    return m["answer"] === null || isSecurityKeyAnswer(m["answer"]);
  }
  return false;
}

/** Whether `value` is a {@link SecurityKeyAnswer} (shape only). */
function isSecurityKeyAnswer(value: unknown): boolean {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const a = value as Record<string, unknown>;
  switch (a["kind"]) {
    case "credential":
      return typeof a["credential"] === "string";
    case "totp":
      return typeof a["code"] === "string";
    case "retry":
      return true;
    default:
      return false;
  }
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
  if (m["kind"] === "ask-security-key") {
    return typeof m["options"] === "string" && typeof m["totpAllowed"] === "boolean";
  }
  return (
    m["kind"] === "result" &&
    (m["ok"] === true || (m["ok"] === false && typeof m["code"] === "string"))
  );
}

/** The most domains a user group can hold (ADR 0042 §3, `MAX_GROUP_DOMAINS`); the core checks it
 * too, this only keeps an oversized message from being built at all. */
export const MAX_GROUP_DOMAINS = 64;

/** Whether `value` is a {@link SettingsChange} (shape only; the core checks every value). */
export function isSettingsChange(value: unknown): value is SettingsChange {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const c = value as Record<string, unknown>;
  switch (c["kind"]) {
    case "matchDefault":
      return typeof c["mode"] === "number" && Number.isInteger(c["mode"]);
    case "addUserGroup":
      return (
        Array.isArray(c["domains"]) &&
        c["domains"].length <= MAX_GROUP_DOMAINS &&
        c["domains"].every((d) => typeof d === "string")
      );
    case "removeUserGroup":
    case "disableGlobalGroup":
    case "enableGlobalGroup":
      return typeof c["id"] === "string";
    case "identityDefaults":
      return isIdentityDefaults(c["defaults"]);
    default:
      return false;
  }
}

/** The longest email domain a message may carry: the core's limit is 253 bytes (ADR 0079 §3);
 * this only keeps an oversized message from being built, the core checks the rest. */
export const MAX_EMAIL_DOMAIN_TEXT = 1024;

/** A whole age in `0..=255` (the core checks 18–99). */
function isAge(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 255;
}

/** An optional domain: `null`, `undefined` or a string of bounded length. */
function isDomainText(v: unknown): boolean {
  return v === null || v === undefined || (typeof v === "string" && v.length <= MAX_EMAIL_DOMAIN_TEXT);
}

/** Whether `value` is an {@link IdentityDefaults} (shape only; the core checks every value). */
export function isIdentityDefaults(value: unknown): value is IdentityDefaults {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const d = value as Record<string, unknown>;
  return (
    (d["sex"] === "random" || d["sex"] === "male" || d["sex"] === "female") &&
    (d["country"] === null || (typeof d["country"] === "string" && d["country"].length <= 8)) &&
    isAge(d["ageMin"]) &&
    isAge(d["ageMax"]) &&
    (d["emailStyle"] === "name" || d["emailStyle"] === "nickname") &&
    d["emailDomain"] !== undefined &&
    isDomainText(d["emailDomain"])
  );
}

/** Whether `value` is an {@link IdentityGeneratorOptions} (shape only; the core checks every
 * value). A `today` is not taken from the UI: the Worker reads its own clock. */
export function isIdentityOptions(value: unknown): value is IdentityGeneratorOptions {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const o = value as Record<string, unknown>;
  return (
    (o["sex"] === "random" || o["sex"] === "male" || o["sex"] === "female") &&
    typeof o["country"] === "string" &&
    o["country"].length <= 8 &&
    isAge(o["ageMin"]) &&
    isAge(o["ageMax"]) &&
    (o["emailStyle"] === "name" || o["emailStyle"] === "nickname") &&
    isDomainText(o["emailDomain"])
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
