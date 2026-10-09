// Host glue over `@rizzy-vault/core`'s durable-device surface (ADR 0036 §1–§3). Lives in
// `core-host/`, not `core/` (where this module's unimplemented predecessor, `core/bindings.ts`,
// used to live): `eslint.config.mjs` allows a *value* import of `@rizzy-vault/core` only from
// `apps/extension/src/core-host/**` (ADR 0036 §2, "the long-lived context... holds the
// instance"), and this module now does real work against the wasm core, not a documented stub.
// `core/bindings.ts`'s own doc comment explained why every call there threw
// `BindingsNotImplemented`: `rizzy-wasm` had no durable-device/store bindings yet. It does now
// (`cacheStoreNames`, `CacheStore`, `enrolDevice`, `unlockDurableDevice`, `DurableSession` in
// `packages/core/src/index.ts`, landed in 496c23b), so this file wraps them instead of porting
// anything itself — "host glue only": every crypto and store decision still happens inside
// `DurableSession`/`rizzy-wasm`, this module only supplies the transport, the clock and the
// `CacheStore`, and turns the result into the plain shapes `core-context.ts` forwards as
// `PopupResponse`/`ToContentScript` values.
import {
  type CacheStore,
  type Clock,
  type CreatedPasskey,
  type FieldView,
  type ItemChange,
  type ItemSummary,
  type MatchCandidate,
  type MatchFrameInfo,
  type MatchUriInput,
  type PasskeyAssertionResult,
  DurableSession,
  MatchMode,
  PASSKEY_ALG_ES256,
  cacheStoreNames,
  createPasskey as coreCreatePasskey,
  decideMatchCandidates,
  enrolDevice as coreEnrolDevice,
  fetchTransport,
  init,
  newElementId,
  normalizePageUrl,
  unlockDurableDevice,
} from "@rizzy-vault/core";

export type { CacheStore, Clock, CreatedPasskey, DurableSession, FieldView, ItemChange, ItemSummary, MatchCandidate, MatchFrameInfo, PasskeyAssertionResult };
export { MatchMode, PASSKEY_ALG_ES256, cacheStoreNames, decideMatchCandidates, newElementId, normalizePageUrl };

/** `passkey/<id>/*` field-key parts (`crates/rizzy-core/src/item/schema.rs`'s `LIST_PASSKEY`/
 * `ATTR_*` constants, mirrored here the same way `LOGIN_USERNAME_KEY` etc. already are — see
 * this module's own module doc for why: `@rizzy-vault/core` exposes them only as string keys). */
export const PASSKEY_LIST = "passkey";
export const PASSKEY_ATTR_RP_ID = "rp_id";
export const PASSKEY_ATTR_CREATED_MS = "created_ms";

/** Runs `createPasskey` (ADR 0039 §2) — a pure, stateless core-host wrapper, so
 * `content-handler.ts` never imports `@rizzy-vault/core` directly either (this module's own
 * "host glue only" rule, top doc comment). */
export function createPasskey(origin: string, rpId: string, challenge: Uint8Array): CreatedPasskey {
  return coreCreatePasskey(origin, rpId, challenge);
}

/** One stored passkey's non-secret, re-derivable-from-`fields()` metadata — everything
 * {@link sessionPasskeyCandidatesForRpId} and the web vault's own listing need, and nothing a
 * `FieldView` of kind `"bytes"` could give anyway (`FieldView.value` is always `undefined` for a
 * Bytes field — `crates/rizzy-wasm/src/items.rs`'s own "Bytes and order keys have no text" —
 * which is also why this shape carries no `userHandle`/`credentialId`/`publicKeyCose`: there is
 * no `@rizzy-vault/core` call today that returns those back out once stored, only at creation
 * time, `not_done`, reported honestly rather than worked around by reaching past this package's
 * API into wasm internals). */
export interface StoredPasskey {
  readonly elementId: string;
  readonly rpId: string;
  readonly createdMs: number;
}

/** Every `passkey/<id>/…` element of one item's `fields()` call, grouped by element id — the
 * `uri`/`field` analogue is `itemUriFields`, just below. */
export function itemPasskeyFields(fields: readonly FieldView[]): readonly StoredPasskey[] {
  const byElement = new Map<string, { rpId?: string; createdMs?: number }>();
  for (const field of fields) {
    if (field.list !== PASSKEY_LIST || field.element === undefined || field.value === undefined) {
      continue;
    }
    const entry = byElement.get(field.element) ?? {};
    if (field.attribute === PASSKEY_ATTR_RP_ID) {
      entry.rpId = field.value;
    } else if (field.attribute === PASSKEY_ATTR_CREATED_MS) {
      entry.createdMs = Number(field.value);
    }
    byElement.set(field.element, entry);
  }
  const out: StoredPasskey[] = [];
  for (const [elementId, entry] of byElement) {
    if (entry.rpId !== undefined) {
      out.push({ elementId, rpId: entry.rpId, createdMs: entry.createdMs ?? 0 });
    }
  }
  return out;
}

/** Every stored passkey, across every active item, whose `rp_id` exactly equals `rpId` (ADR
 * 0039 §2: a `get` ceremony's candidate list for a `navigator.credentials.get()` call with no
 * `allowCredentials`, or one this project's own API has no way to narrow further by credential
 * id — `StoredPasskey`'s own doc on why). Exact string equality, not a PSL/suffix comparison:
 * `rp_id` is already the resolved value `verify_rp_id` accepted at creation time (INV-64), so
 * there is nothing left to re-derive here — the actual authority for "is this `rpId` allowed for
 * the calling origin" stays in Rust, re-checked again on the assertion call itself
 * (`DurableSession.passkeyAssertion`), never trusted from this list alone. */
export function sessionPasskeyCandidatesForRpId(
  session: DurableSession,
  rpId: string,
): ReadonlyArray<{ readonly itemId: string; readonly elementId: string; readonly itemTitle: string; readonly userName: string }> {
  const out: Array<{ itemId: string; elementId: string; itemTitle: string; userName: string }> = [];
  for (const item of session.items()) {
    for (const passkey of itemPasskeyFields(session.fields(item.id))) {
      if (passkey.rpId === rpId) {
        out.push({ itemId: item.id, elementId: passkey.elementId, itemTitle: item.title, userName: item.username ?? "" });
      }
    }
  }
  return out;
}

export interface AddPasskeyInput {
  readonly elementId: string;
  readonly rpId: string;
  readonly userHandle: Uint8Array;
  readonly credentialId: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly publicKeyCose: Uint8Array;
  readonly createdMs: number;
}

/** The `createItem`/`editItem` changeset for ADR 0039 §1's `addPasskey` op — one place building
 * it, so a future second passkey-writing caller (e.g. the web vault, if it ever creates one
 * itself) cannot drift from this one's field choices. Always ES256 (`alg: PASSKEY_ALG_ES256`)
 * and always discoverable (ADR 0039 §1: "every credential we create is... resident"), since
 * `createPasskey` only ever produces that combination today. */
export function addPasskeyChange(input: AddPasskeyInput): ItemChange {
  return {
    op: "addPasskey",
    element: input.elementId,
    rpId: input.rpId,
    userHandle: input.userHandle,
    credentialId: input.credentialId,
    privateKey: input.privateKey,
    publicKeyCose: input.publicKeyCose,
    alg: PASSKEY_ALG_ES256,
    discoverable: true,
    createdMs: input.createdMs,
  };
}

/** A new, title-defaulted Login changeset carrying one fresh passkey (ADR 0039 §1's "a passkey
 * is... an alternative or additional credential for a site a user already has, or is creating, a
 * Login item for" — the "creating" half: no existing Login matched this `rpId`, so
 * `core-context.ts` saves a new one, title and username set from the ceremony's own RP/user data,
 * exactly as {@link newLoginChangeset} defaults a saved-from-submit Login's title to the page's
 * host). */
export function newLoginWithPasskeyChangeset(title: string, username: string, passkey: AddPasskeyInput): readonly ItemChange[] {
  return [
    { op: "set", key: ITEM_NAME_KEY, value: title },
    { op: "set", key: LOGIN_USERNAME_KEY, value: username },
    addPasskeyChange(passkey),
  ];
}

/** Fixed field keys (`crates/rizzy-core/src/item/schema.rs`), mirrored here because
 * `@rizzy-vault/core` exposes them only as string keys, never as named constants: `login.username`
 * is plain text (never concealed, so `fields()` already carries its value); `login.password` is
 * concealed (needs {@link DurableSession.reveal}); `item.name` is every item type's title field. */
export const LOGIN_USERNAME_KEY = "login.username";
export const LOGIN_PASSWORD_KEY = "login.password";
export const ITEM_NAME_KEY = "item.name";

let initialised: Promise<void> | undefined;

/** Loads the wasm module once (ADR 0036 §2: the long-lived context loads it "once... for the
 * whole extension lifetime"). Idempotent: every caller after the first gets the same promise,
 * so `core-context.ts`'s `startCoreContext` and this module's own callers never race a second
 * `init()`. Must resolve before {@link cacheStoreNames} or any other core call. */
export function initCore(): Promise<void> {
  initialised ??= init().then(() => undefined);
  return initialised;
}

/** Two-factor mid-enrolment is not implemented yet (`not_done`): {@link enrolDevice} never opens
 * an interactive prompt while a `EnrolFlow` is in progress. If the account has 2FA and
 * `input.totp` is missing or wrong, enrolment throws this instead of hanging on a callback
 * nothing answers. The popup should collect a TOTP code up front (same screen as the master
 * password) when the owner knows the account has 2FA enabled, until a mid-flow prompt exists. */
export class TotpRequired extends Error {
  constructor() {
    super("totp_required");
    this.name = "TotpRequired";
  }
}

export interface EnrolDeviceInput {
  readonly serverOrigin: string;
  readonly loginName: string;
  readonly secretKey: string;
  readonly masterPassword: string;
  readonly totp?: string;
}

/** Enrols this browser as a durable device (CRYPTO.md §11.2; ADR 0036 §1), then authenticates
 * it online (CRYPTO.md §5.10), same as {@link unlockDevice} does after its own offline part.
 * `@rizzy-vault/core`'s own `enrolDevice` doc comment ("returns it unlocked") describes the
 * cache/lock state only, not auth: `DurableSession.sync`'s doc says every request is "signed
 * with this device's key (`authenticate` first)," and the underlying `syncStart` throws
 * `wrong_state` until that handshake has run once — found empirically while writing this
 * change's E2E coverage, where a freshly enrolled device's own first sync failed with exactly
 * that code. Device-cert upload during enrolment (CRYPTO.md §11.2 step 7) reuses the *login*
 * OPAQUE session to authenticate the upload to the server; that is a separate thing from the
 * device signing its own later requests, which still needs this handshake once, same as any
 * later unlock. `cacheStore` must already have every {@link cacheStoreNames} object store
 * created (`cache/idb.ts`'s `ExtensionCache.open`, which itself needs {@link initCore} to have
 * resolved first — `cacheStoreNames()` calls the core's own readiness check). */
export async function enrolDevice(input: EnrolDeviceInput, cacheStore: CacheStore, clock: Clock = Date.now): Promise<DurableSession> {
  const transport = fetchTransport(input.serverOrigin);
  const session = await coreEnrolDevice(
    transport,
    {
      origin: input.serverOrigin,
      loginName: input.loginName,
      secretKey: input.secretKey,
      password: input.masterPassword,
      ...(input.totp !== undefined ? { totp: input.totp } : {}),
    },
    cacheStore,
    () => {
      throw new TotpRequired();
    },
    clock,
  );
  await session.authenticate();
  return session;
}

/** Unlocks a previously enrolled device from its persisted cache (CRYPTO.md §11.3's offline
 * part), then authenticates it online (CRYPTO.md §5.10) so `sync`/item calls can sign requests
 * immediately. `serverOrigin` is not itself part of the cache (ADR 0026 §3 carries no server
 * URL); the caller supplies the account's saved origin fresh each unlock. */
export async function unlockDevice(
  serverOrigin: string,
  cacheStore: CacheStore,
  masterPassword: string,
  clock: Clock = Date.now,
): Promise<DurableSession> {
  const transport = fetchTransport(serverOrigin);
  const session = await unlockDurableDevice(transport, cacheStore, masterPassword, clock);
  await session.authenticate();
  return session;
}

/** The popup's `ItemSummary` shape, mapped from `@rizzy-vault/core`'s richer one
 * (`messaging/contract.ts`'s `ItemSummary`: title/username/itemId only, list views never carry
 * more, ADR 0013 §3 rule 3). */
export function toContractItemSummary(item: ItemSummary): { itemId: string; title: string; username: string } {
  return { itemId: item.id, title: item.title, username: item.username ?? "" };
}

/** The `createItem` changeset for a brand-new Login saved from a submitted form (ROADMAP §4.4
 * "save... on submit"): title defaults to the page's own host (the user can rename later in the
 * web vault — the popup does not offer a rename field, out of scope for this change), one URI
 * row pointing at the page that was submitted. Username/password are set even when empty, so a
 * password-only or username-only form still saves something rather than silently dropping half
 * of what the user typed. */
export function newLoginChangeset(pageUrl: string, usernameValue: string, passwordValue: string): readonly ItemChange[] {
  const title = (() => {
    try {
      return new URL(pageUrl).hostname || pageUrl;
    } catch {
      return pageUrl;
    }
  })();
  return [
    { op: "set", key: ITEM_NAME_KEY, value: title },
    { op: "set", key: LOGIN_USERNAME_KEY, value: usernameValue },
    { op: "set", key: LOGIN_PASSWORD_KEY, value: passwordValue },
    { op: "addUri", element: newElementId(), uri: pageUrl },
  ];
}

/** The `editItem` changeset for updating an existing Login's credentials (ROADMAP §4.4
 * "...or update on submit"): only the two credential fields change; the item's URIs, title and
 * tags are left exactly as they were. */
export function updateLoginChangeset(usernameValue: string, passwordValue: string): readonly ItemChange[] {
  return [
    { op: "set", key: LOGIN_USERNAME_KEY, value: usernameValue },
    { op: "set", key: LOGIN_PASSWORD_KEY, value: passwordValue },
  ];
}

/** Every `uri/<id>/value` field of one item's `fields()` call, grouped by the list element id
 * (ADR 0018 §7, ADR 0037 §2). `uri/<id>/match` is reserved but still never written by any client
 * under owner decision 2 (`crates/rizzy-core/src/item/schema.rs`'s module docs): every URI here
 * resolves through the account-default match mode, never a per-URI override, until a later
 * change starts writing that field. */
export function itemUriFields(fields: readonly FieldView[]): ReadonlyArray<{ uriId: string; value: string }> {
  const out: Array<{ uriId: string; value: string }> = [];
  for (const field of fields) {
    // `FieldKey`'s grammar (`crates/rizzy-core/src/item/key.rs`): `list()` is the repeated
    // group's name ("uri"), `element()` its per-entry hex id, `attribute()` which column
    // ("value"/"match"/"order"). Only `value` is ever written (see this module's doc comment).
    if (field.list === "uri" && field.attribute === "value" && field.element !== undefined && field.value !== undefined) {
      out.push({ uriId: field.element, value: field.value });
    }
  }
  return out;
}

/** Every saved URI of every active item, as `decideMatchCandidates` needs them (ADR 0037 §4).
 * `mode` is always {@link MatchMode.BaseDomain}: `itemUriFields`'s doc explains why every URI's
 * own `match` field is unresolved (never written yet) and must be treated as the account
 * default already applied — this module's one `accountDefaultMode` choice, `BaseDomain`, is also
 * `rizzy-match`'s own documented default for an unset mode
 * (`crates/rizzy-match/src/modes.rs`'s `account_default_resolves_to_base_domain_when_unset`
 * test), so this is a resolved value, not a guess. */
export function sessionItemUris(session: DurableSession): readonly MatchUriInput[] {
  const out: MatchUriInput[] = [];
  for (const item of session.items()) {
    for (const uri of itemUriFields(session.fields(item.id))) {
      out.push({ itemId: item.id, uriId: uri.uriId, value: uri.value, mode: MatchMode.BaseDomain });
    }
  }
  return out;
}

/** Decides autofill candidates for `pageUrl` against every saved item (ADR 0037 §4–§5): one
 * call wrapping `sessionItemUris` + `decideMatchCandidates` so `content-handler.ts` never
 * touches `@rizzy-vault/core` shapes directly either. */
export function decideCandidates(
  session: DurableSession,
  pageUrl: string,
  frame: MatchFrameInfo,
): { candidates: readonly MatchCandidate[]; warnings: readonly string[] } {
  return decideMatchCandidates(pageUrl, frame, MatchMode.BaseDomain, sessionItemUris(session));
}

/** The first active item whose saved URI normalises to the same URL as `pageUrl` (ADR 0037 §2's
 * normalisation) — used to offer "update" rather than "save" on a submitted form that already
 * has a matching item. Deliberately simpler than full match-mode matching (no equivalence list,
 * no base-domain narrowing): this is only a save-prompt *suggestion*, not an autofill decision,
 * and a wrong suggestion here costs the user one extra click, never a wrong fill. */
export function findItemForUpdate(session: DurableSession, pageUrl: string): ItemSummary | undefined {
  let normalized: string;
  try {
    normalized = normalizePageUrl(pageUrl);
  } catch {
    return undefined;
  }
  for (const item of session.items()) {
    for (const uri of itemUriFields(session.fields(item.id))) {
      try {
        if (normalizePageUrl(uri.value) === normalized) {
          return item;
        }
      } catch {
        // A saved URI that no longer parses: skip it, do not let it abort the search.
      }
    }
  }
  return undefined;
}

/** One item's username and password, read back for a fill (ADR 0036 §4: "only the chosen
 * candidate's values"). Username comes straight off `fields()` (never concealed); password
 * needs {@link DurableSession.reveal}, on this one call only, per the user's own trusted-gesture
 * fill request. */
export function itemCredentials(session: DurableSession, itemId: string): { username: string; password: string } {
  const fields = session.fields(itemId);
  const username = fields.find((f) => f.key === LOGIN_USERNAME_KEY)?.value ?? "";
  const password = session.reveal(itemId, LOGIN_PASSWORD_KEY);
  return { username, password };
}
