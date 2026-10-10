// SPDX-License-Identifier: AGPL-3.0-only

// packages/core end to end against a real `rizzy-vault` server, through the wasm module:
// signup → Emergency Kit → login → items → sync → a second session sees them → reveal → edit →
// trash and restore → TOTP → encrypted export behind a re-authentication, recognised and
// imported → plaintext export behind a re-authentication and the 10-second hold → devices →
// 2FA enrolment and the second-factor login state → lock.
//
// The server is the built binary (`cargo build -p rizzy-server`, or `cargo test --workspace`),
// spawned on a loopback port with a temporary SQLite database and a fresh secrets file, as
// `rv`'s end-to-end tests start it. `RIZZY_VAULT_BIN` names another binary. Without a binary
// the suite is skipped and says so, unless `CI` is set: there a missing binary fails the run,
// so that a CI job that forgot to build the server cannot pass without this suite.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { createConnection, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  type CacheRow,
  type CacheStore,
  type Clock,
  CoreError,
  type HistoryEntry,
  Signup,
  type Transport,
  type VaultSession,
  checkServer,
  createPasskey,
  PASSKEY_ALG_ES256,
  fetchTransport,
  detectImportFormat,
  enrolDevice,
  login,
  newElementId,
  plaintextExportHoldMs,
  plaintextExportPhrase,
  unlockDurableDevice,
} from "../src/index.js";
import { loadCore } from "./load.js";

/** Whether two byte arrays hold the same bytes. */
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** A `createPasskey`/`addPasskey` COSE `EC2` ES256 public key (`rizzy-client`'s
 * `cbor::cose_key_es256`: a fixed-layout map, `kty`/`alg`/`crv` then 32-byte `x` at offset 10
 * and 32-byte `y` at offset 45) as a Node `KeyObject`, so the test can verify a signature
 * against it without pulling in a CBOR library for one fixed shape. */
function publicKeyFromCose(cose: Uint8Array): ReturnType<typeof createPublicKey> {
  const x = Buffer.from(cose.slice(10, 42)).toString("base64url");
  const y = Buffer.from(cose.slice(45, 77)).toString("base64url");
  return createPublicKey({ key: { kty: "EC", crv: "P-256", x, y }, format: "jwk" });
}

/** An in-memory {@link CacheStore} standing in for the extension's `IndexedDB` adapter: every
 * value through it is still the opaque bytes `rizzy-wasm`'s `store` bindings encoded. */
function memoryCacheStore(seed: readonly CacheRow[] = []): CacheStore {
  const rows: CacheRow[] = [...seed];
  return {
    async get(store, key) {
      return rows.find((r) => r.store === store && sameBytes(r.key, key))?.value;
    },
    async put(store, key, value) {
      const i = rows.findIndex((r) => r.store === store && sameBytes(r.key, key));
      if (i >= 0) {
        rows[i] = { store, key, value };
      } else {
        rows.push({ store, key, value });
      }
    },
    async delete(store, key) {
      const i = rows.findIndex((r) => r.store === store && sameBytes(r.key, key));
      if (i >= 0) {
        rows.splice(i, 1);
      }
    },
    async list(store) {
      return rows.filter((r) => r.store === store);
    },
  };
}

const PASSWORD = "correct horse battery staple";

/** The server binary (module docs). */
function serverBinary(): string | undefined {
  const named = process.env["RIZZY_VAULT_BIN"];
  if (named !== undefined) {
    return named;
  }
  const root = fileURLToPath(new URL("../../../", import.meta.url));
  const built = join(root, "target", "debug", "rizzy-vault");
  return existsSync(built) ? built : undefined;
}

const binary = serverBinary();
if (binary === undefined && process.env["CI"] !== undefined) {
  throw new Error(
    "e2e: CI is set but there is no rizzy-vault binary (`cargo build -p rizzy-server`, or RIZZY_VAULT_BIN)",
  );
}
if (binary === undefined) {
  console.warn(
    "e2e: no rizzy-vault binary (build it with `cargo build -p rizzy-server`); skipping",
  );
}

/** A free loopback port. */
async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => {
        if (address !== null && typeof address === "object") {
          resolve(address.port);
        } else {
          reject(new Error("no port"));
        }
      });
    });
  });
}

/** Waits until something accepts connections on `port`. */
async function waitForPort(port: number, child: ChildProcess): Promise<void> {
  const deadline = Date.now() + 60_000;
  for (;;) {
    if (child.exitCode !== null) {
      throw new Error(`rizzy-vault exited at start: ${child.exitCode}`);
    }
    const open = await new Promise<boolean>((resolve) => {
      const socket = createConnection({ host: "127.0.0.1", port }, () => {
        socket.destroy();
        resolve(true);
      });
      socket.once("error", () => resolve(false));
    });
    if (open) {
      return;
    }
    if (Date.now() > deadline) {
      throw new Error("rizzy-vault did not start");
    }
    await new Promise((r) => setTimeout(r, 50));
  }
}

describe.skipIf(binary === undefined)("against a real server", () => {
  let child: ChildProcess | undefined;
  let dir = "";
  let origin = "";

  beforeAll(async () => {
    loadCore();
    dir = mkdtempSync(join(tmpdir(), "rizzy-core-e2e-"));
    mkdirSync(join(dir, "data"));
    mkdirSync(join(dir, "secrets"));
    const port = await freePort();
    origin = `http://127.0.0.1:${port}`;
    const env = {
      RIZZY_ORIGIN: origin,
      RIZZY_LISTEN: `127.0.0.1:${port}`,
      RIZZY_SIGNUP: "open",
      RIZZY_DATA_DIR: join(dir, "data"),
      RIZZY_SECRETS_FILE: join(dir, "secrets", "secrets.json"),
    };
    const init = spawnSync(binary as string, ["secrets", "init"], { env, stdio: "ignore" });
    expect(init.status).toBe(0);
    child = spawn(binary as string, [], { env, stdio: "ignore" });
    await waitForPort(port, child);
  });

  afterAll(() => {
    child?.kill();
    if (dir !== "") {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("runs a web-vault account from signup to lock", async () => {
    const transport = fetchTransport(origin);
    await checkServer(transport);

    // The host's clock, which the test moves forward over the plaintext-export hold.
    let skew = 0;
    const clock = () => Date.now() + skew;

    // Signup, in the order of "Secrets before commit".
    const signup = await Signup.start(
      transport,
      {
        origin,
        loginName: "Alice",
        password: PASSWORD,
        issueRecoveryCode: true,
      },
      clock,
    );
    const kit = signup.emergencyKit();
    // The kit's secrets are bytes the host zeroes once rendered (ADR 0019 §3).
    expect(kit.secretKey).toBeInstanceOf(Uint8Array);
    const secretKey = new TextDecoder().decode(kit.secretKey);
    expect(secretKey).toMatch(/^RV1-/);
    expect(new TextDecoder().decode(kit.recoveryCode)).toMatch(/^RVR1-/);
    kit.secretKey.fill(0);
    kit.recoveryCode?.fill(0);
    expect(kit.loginName).toBe("alice");
    // The kit goes out once.
    expect(() => signup.emergencyKit()).toThrowError(
      expect.objectContaining({ code: "already_shown" }),
    );
    // A wrong confirmation is refused, and nothing is committed.
    await expect(signup.confirm("ZZZZ")).rejects.toMatchObject({
      code: "emergency_kit_not_confirmed",
    });
    const lastGroup = secretKey.split("-").at(-1) ?? "";
    await signup.confirm(lastGroup);
    const first = await signup.login();

    // Items, written in memory, uploaded by a sync.
    expect(first.items()).toEqual([]);
    const id = first.createItem("login", [
      { op: "set", key: "item.name", value: "Example" },
      { op: "set", key: "login.username", value: "alice@example.com" },
      { op: "set", key: "login.password", value: "hunter2-but-longer" },
      { op: "addUri", element: newElementId(), uri: "https://example.com/login" },
      {
        op: "addCustomField",
        element: newElementId(),
        label: "PIN",
        kind: "hidden",
        value: "4321",
      },
      { op: "tag", name: "work" },
    ]);
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(first.unsentChanges).toBe(1);
    await first.sync();
    expect(first.unsentChanges).toBe(0);
    expect(first.readOnly).toBe(false);

    // A second session (a new login) reads what the first uploaded.
    const second = await login(transport, {
      origin,
      loginName: "alice",
      secretKey,
      password: PASSWORD,
    });
    expect(second.accountId).toBe(first.accountId);
    expect(second.deviceId).not.toBe(first.deviceId);
    await second.sync();
    const [summary] = second.items();
    expect(summary).toMatchObject({
      id,
      itemType: "login",
      title: "Example",
      username: "alice@example.com",
      favorite: false,
      hasTotp: false,
      trashed: false,
      tags: ["work"],
      websiteHost: "example.com",
    });

    // Concealed values do not cross until revealed.
    const fields = second.fields(id);
    const password = fields.find((f) => f.key === "login.password");
    expect(password).toMatchObject({ concealed: true, value: undefined, kind: "text" });
    expect(second.reveal(id, "login.password")).toBe("hunter2-but-longer");
    const uri = fields.find((f) => f.list === "uri" && f.attribute === "value");
    expect(uri?.value).toBe("https://example.com/login");
    const pin = fields.find((f) => f.list === "field" && f.attribute === "value");
    expect(pin).toMatchObject({ concealed: true, value: undefined });
    expect(fields.some((f) => f.tag === "work")).toBe(true);

    // A repeated add under the same minted element id — as a retried save would send after an
    // unclear outcome — must not create a second element (module docs, "idempotent save").
    const retryId = newElementId();
    second.editItem(id, [{ op: "addUri", element: retryId, uri: "https://retry.example.test" }]);
    second.editItem(id, [{ op: "addUri", element: retryId, uri: "https://retry.example.test" }]);
    expect(
      second
        .fields(id)
        .filter((f) => f.list === "uri" && f.attribute === "value" && f.value === "https://retry.example.test"),
    ).toHaveLength(1);

    // An edit, then the first session follows it.
    second.editItem(id, [
      { op: "set", key: "login.password", value: "a-new-password" },
      { op: "removeElement", list: "uri", element: uri?.element ?? "" },
      { op: "removeElement", list: "uri", element: retryId },
    ]);
    await second.sync();
    await first.sync();
    expect(first.reveal(id, "login.password")).toBe("a-new-password");
    expect(first.fields(id).some((f) => f.list === "uri")).toBe(false);

    // Trash and restore.
    first.trashItem(id);
    expect(first.items()).toEqual([]);
    expect(first.items(true).map((i) => i.id)).toEqual([id]);
    first.restoreItem(id);
    expect(first.items().map((i) => i.id)).toEqual([id]);

    // Permanent delete, on a dedicated item so the export/import counts below stay
    // unaffected: gone for good on this session, rejected on a non-trashed or unknown item,
    // and gone on the second session once it syncs (gap 03; the web vault's confirm dialog and
    // the durable-device binding below have their own tests).
    const toPurge = first.createItem("login", [{ op: "set", key: "item.name", value: "To purge" }]);
    first.trashItem(toPurge);
    first.purgeItem(toPurge);
    expect(first.items().some((i) => i.id === toPurge)).toBe(false);
    expect(first.items(true).some((i) => i.id === toPurge)).toBe(false);
    expect(() => first.purgeItem(toPurge)).toThrowError(expect.objectContaining({ code: "unknown_item" }));
    expect(() => first.purgeItem("0".repeat(32))).toThrowError(expect.objectContaining({ code: "unknown_item" }));
    await first.sync();
    await second.sync();
    expect(second.items().some((i) => i.id === toPurge)).toBe(false);
    expect(second.items(true).some((i) => i.id === toPurge)).toBe(false);

    // TOTP from an item's secret (RFC 6238's SHA-1 key, as Base32).
    const totpItem = first.createItem("login", [
      { op: "set", key: "item.name", value: "With 2FA" },
      { op: "set", key: "login.totp", value: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" },
    ]);
    const code = first.totp(totpItem);
    expect(code.code).toMatch(/^[0-9]{6}$/);
    expect(code.periodSeconds).toBe(30);
    await first.sync();

    // A passkey (ADR 0039): created client-side, stored as `passkey/<id>/*` fields on a Login,
    // and later signed over without the private key ever leaving the wasm boundary.
    const passkeyOrigin = "https://example.com";
    const passkeyRpId = "example.com";
    const created = createPasskey(passkeyOrigin, passkeyRpId, new Uint8Array([1, 2, 3, 4]));
    expect(created.credentialId).toHaveLength(32);
    const passkeyElement = newElementId();
    const passkeyItem = first.createItem("login", [
      { op: "set", key: "item.name", value: "Has a passkey" },
      {
        op: "addPasskey",
        element: passkeyElement,
        rpId: passkeyRpId,
        userHandle: new Uint8Array([9, 9, 9]),
        credentialId: created.credentialId,
        privateKey: created.privateKey,
        publicKeyCose: created.publicKeyCose,
        alg: PASSKEY_ALG_ES256,
        discoverable: true,
        createdMs: Date.now(),
      },
    ]);
    await first.sync();
    // The second session, after its own sync, can sign an assertion too — the private key
    // travelled only as part of the normal encrypted sync, never in cleartext off this process.
    await second.sync();
    const assertionChallenge = new Uint8Array([5, 6, 7, 8]);
    const assertion = second.passkeyAssertion(
      passkeyItem,
      passkeyElement,
      passkeyOrigin,
      passkeyRpId,
      assertionChallenge,
    );
    expect(assertion.credentialId).toEqual(created.credentialId);
    const clientDataJson = JSON.parse(new TextDecoder().decode(assertion.clientDataJson)) as {
      type: string;
      origin: string;
    };
    expect(clientDataJson.type).toBe("webauthn.get");
    expect(clientDataJson.origin).toBe(passkeyOrigin);
    const message = Buffer.concat([
      assertion.authenticatorData,
      createHash("sha256").update(assertion.clientDataJson).digest(),
    ]);
    expect(
      verifySignature(
        "sha256",
        message,
        { key: publicKeyFromCose(created.publicKeyCose), dsaEncoding: "der" },
        assertion.signatureDer,
      ),
    ).toBe(true);
    // A wrong rpId is INV-64's job to refuse, not this test's — `rizzy-client::passkey`'s own
    // unit tests already cover that table; here only the happy path through two full wasm
    // sessions and a real sync matters.

    // The assertion verifying only proves `credential_id`/`private_key` round-tripped; check
    // the other written fields too, so a corrupted `alg`/`discoverable`/`rp_id`/`created_ms`
    // (the earlier wrong `alg: -7` would have been stored silently: `Expected::Enum` accepts
    // any `u16`) would fail a test rather than pass one that happens not to look.
    const passkeyFields = second.fields(passkeyItem).filter((f) => f.list === "passkey" && f.element === passkeyElement);
    expect(passkeyFields.find((f) => f.attribute === "rp_id")).toMatchObject({
      kind: "text",
      value: passkeyRpId,
      concealed: false,
    });
    expect(passkeyFields.find((f) => f.attribute === "alg")).toMatchObject({
      kind: "enum",
      value: String(PASSKEY_ALG_ES256),
      concealed: false,
    });
    expect(passkeyFields.find((f) => f.attribute === "discoverable")).toMatchObject({
      kind: "bool",
      value: "true",
      concealed: false,
    });
    // ADR 0039 §1: concealed by default like `login.password` — the private key is never in
    // `fields()`'s output, only reachable through `passkeyAssertion`'s own internal read.
    expect(passkeyFields.find((f) => f.attribute === "private_key")).toMatchObject({
      kind: "bytes",
      value: undefined,
      concealed: true,
    });

    // Encrypted export (behind a re-authentication: a wrong password is refused and allows
    // nothing), imported back as new items; the file is recognised from its bytes.
    expect(() => first.exportEncrypted("export password 1")).toThrowError(
      expect.objectContaining({ code: "reauth_required" }),
    );
    await expect(first.reauthenticate(secretKey, "not the password")).rejects.toMatchObject({
      code: "wrong_password_or_secret_key",
    });
    expect(first.reauthFresh()).toBe(false);
    expect(() => first.exportEncrypted("export password 1")).toThrowError(
      expect.objectContaining({ code: "reauth_required" }),
    );
    await first.reauthenticate(secretKey, PASSWORD);
    expect(first.reauthFresh()).toBe(true);
    // A refused file password spends nothing.
    expect(() => first.exportEncrypted("")).toThrowError(
      expect.objectContaining({ code: "invalid_input" }),
    );
    const exported = first.exportEncrypted("export password 1");
    expect(first.reauthFresh()).toBe(false);
    expect(detectImportFormat(exported.file)).toBe("rizzy-encrypted");
    expect(exported.items).toBe(3);
    expect(exported.file.byteLength).toBeGreaterThan(0);
    await expect(
      Promise.resolve().then(() => first.importEncrypted(exported.file, "wrong")),
    ).rejects.toMatchObject({ code: "export_decryption_failed" });
    const imported = first.importEncrypted(exported.file, "export password 1");
    expect(imported.imported).toBe(3);
    expect(first.items()).toHaveLength(6);
    await first.sync();

    // A plaintext export needs a re-authentication first.
    expect(() => first.exportPlaintext("json", plaintextExportPhrase())).toThrowError(
      expect.objectContaining({ code: "reauth_required" }),
    );
    await first.reauthenticate(secretKey, PASSWORD);
    expect(() => first.exportPlaintext("json", "export plaintext")).toThrowError(
      expect.objectContaining({ code: "plaintext_export_not_acknowledged" }),
    );
    // The warning must be shown, and its hold of ten seconds over.
    expect(() => first.exportPlaintext("json", plaintextExportPhrase())).toThrowError(
      expect.objectContaining({ code: "plaintext_export_hold" }),
    );
    expect(plaintextExportHoldMs()).toBe(10_000);
    expect(first.plaintextWarningShown()).toBe(10_000);
    skew += 9_000;
    expect(first.plaintextHoldRemainingMs()).toBeGreaterThan(0);
    expect(() => first.exportPlaintext("json", plaintextExportPhrase())).toThrowError(
      expect.objectContaining({ code: "plaintext_export_hold" }),
    );
    skew += 1_000;
    expect(first.plaintextHoldRemainingMs()).toBe(0);
    const jsonBytes = first.exportPlaintext("json", plaintextExportPhrase());
    expect(detectImportFormat(jsonBytes)).toBe("rizzy-json");
    const json = new TextDecoder().decode(jsonBytes);
    expect(json).toContain("a-new-password");
    // One export per re-authentication.
    expect(() => first.exportPlaintext("csv", plaintextExportPhrase())).toThrowError(
      expect.objectContaining({ code: "reauth_required" }),
    );

    // A transport failure mid-sync aborts the sync in the core: writes are accepted again at
    // once, and the next sync sends the unsent change. Once before the upload reached the
    // server, once after it was stored but the answer was lost (an unknown outcome).
    const secretKeyBytes = new TextEncoder().encode(secretKey);
    const passwordBytes = new TextEncoder().encode(PASSWORD);
    let failUpload: "before" | "after" | undefined;
    const flaky: Transport = async (request) => {
      if (request.path === "/api/v1/vault/upload" && failUpload !== undefined) {
        const when = failUpload;
        failUpload = undefined;
        if (when === "after") {
          await transport(request);
        }
        throw new CoreError("transport_failed");
      }
      return transport(request);
    };
    const third = await login(flaky, {
      origin,
      loginName: "alice",
      secretKey: secretKeyBytes,
      password: passwordBytes,
    });
    // Secrets passed as bytes come back zeroed.
    expect(secretKeyBytes.every((b) => b === 0)).toBe(true);
    expect(passwordBytes.every((b) => b === 0)).toBe(true);
    await third.sync();
    for (const when of ["before", "after"] as const) {
      const flakyItem = third.createItem("login", [
        { op: "set", key: "item.name", value: `flaky ${when}` },
      ]);
      failUpload = when;
      await expect(third.sync()).rejects.toMatchObject({ code: "transport_failed" });
      expect(third.unsentChanges).toBe(1);
      // Not stuck: a write is accepted, and the next sync uploads both.
      third.editItem(flakyItem, [{ op: "set", key: "login.username", value: "bob" }]);
      expect(third.unsentChanges).toBe(2);
      await third.sync();
      expect(third.unsentChanges).toBe(0);
      expect(third.readOnly).toBe(false);
      await first.sync();
      expect(first.item(flakyItem)).toMatchObject({ title: `flaky ${when}`, username: "bob" });
    }
    third.lock();

    // A web-vault-only account has no durable device.
    expect(first.devices()).toEqual([]);

    // 2FA: enrol with a code computed by the core from the server's secret, then a login
    // without a code stops at the second factor.
    const setup = await first.enableTwoFactor();
    expect(setup.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
    const helper = first.createItem("login", [
      { op: "set", key: "item.name", value: "authenticator" },
      { op: "set", key: "login.totp", value: setup.secret },
    ]);
    await first.confirmTwoFactor(first.totp(helper).code);
    let asked = false;
    const refused = await login(
      transport,
      { origin, loginName: "alice", secretKey, password: PASSWORD },
      async () => {
        asked = true;
        return "000000";
      },
    ).catch((e: unknown) => e);
    expect(asked).toBe(true);
    expect(refused).toBeInstanceOf(CoreError);

    // A wrong password says nothing about which part was wrong.
    const wrong = await login(transport, {
      origin,
      loginName: "alice",
      secretKey,
      password: "not the password",
      totp: "000000",
    }).catch((e: unknown) => e);
    expect((wrong as CoreError).code).toBe("wrong_password_or_secret_key");

    // Lock wipes the session; every call is refused after it.
    lockAll(first, second);
    expect(() => first.items()).toThrowError(expect.objectContaining({ code: "locked" }));
  });

  // The durable device (ADR 0036 §1, `device_kind` `Extension`): enrol against the real
  // server, persist the cache rows through a `CacheStore`, device-authenticate, write and sync
  // an item, then reopen from that same store as a fresh browser session would and read the
  // item back — the full cycle `DeviceSession`'s module docs describe, against the real
  // protocol rather than the fake test server.
  it("enrols a durable device (kind 2), writes and syncs an item, and reopens from its cache store", async () => {
    const transport = fetchTransport(origin);
    const signup = await Signup.start(
      transport,
      { origin, loginName: "Bob", password: PASSWORD, issueRecoveryCode: false },
      Date.now,
    );
    const kit = signup.emergencyKit();
    const secretKey = new TextDecoder().decode(kit.secretKey);
    kit.secretKey.fill(0);
    const lastGroup = secretKey.split("-").at(-1) ?? "";
    await signup.confirm(lastGroup);
    const owner = await signup.login();
    const ownerAccountId = owner.accountId;
    owner.lock();

    const store = memoryCacheStore();
    const session = await enrolDevice(
      transport,
      { origin, loginName: "bob", secretKey, password: PASSWORD },
      store,
    );
    expect((await store.list("device_state")).length).toBe(1);
    expect(session.accountId).toBe(ownerAccountId);
    expect(session.isAuthenticated()).toBe(false);

    await session.authenticate();
    expect(session.isAuthenticated()).toBe(true);
    const signed = session.signRequest("POST", "/api/v1/vault/upload", new Uint8Array());
    expect(signed.requestCounter).toBe(1n);
    expect(signed.bearer.startsWith("Bearer ")).toBe(true);
    const deviceId = session.deviceId;

    // Sync pulls the owner's personal vault (empty so far), then this device writes and
    // syncs an item of its own: persisted through `store` before each call resolves.
    await session.sync();
    expect(session.items()).toEqual([]);
    const id = await session.createItem("login", [
      { op: "set", key: "item.name", value: "Extension item" },
      { op: "set", key: "login.username", value: "extension-user" },
    ]);
    expect(session.unsentChanges).toBe(1);
    await session.sync();
    expect(session.unsentChanges).toBe(0);
    expect(session.readOnly).toBe(false);
    expect((await store.list("ops")).length).toBeGreaterThan(0);
    session.lock();

    // A fresh browser session: only the persisted store, reopened and re-authenticated.
    await expect(unlockDurableDevice(transport, store, "not the password")).rejects.toMatchObject({
      code: "wrong_password_or_secret_key",
    });

    const reopened = await unlockDurableDevice(transport, store, PASSWORD);
    expect(reopened.accountId).toBe(ownerAccountId);
    expect(reopened.deviceId).toBe(deviceId);
    expect(reopened.isAuthenticated()).toBe(false);
    await reopened.authenticate();
    expect(reopened.isAuthenticated()).toBe(true);

    // The item this device wrote and synced is there without any further sync: `load::load`
    // already rebuilt the vault from the store's own `vaults`/`ops`/`wraps` rows.
    const [summary] = reopened.items();
    expect(summary).toMatchObject({ id, itemType: "login", title: "Extension item" });
    expect(reopened.reveal(id, "login.username")).toBe("extension-user");

    // Permanent delete through the async durable-device binding (index.ts:2001): purges,
    // rejected on a non-trashed item, and the deletion persists across a reopen from the
    // store without any further sync.
    await reopened.trashItem(id);
    await reopened.purgeItem(id);
    expect(reopened.items()).toEqual([]);
    await expect(reopened.purgeItem(id)).rejects.toMatchObject({ code: "unknown_item" });
    reopened.lock();

    const reopenedAgain = await unlockDurableDevice(transport, store, PASSWORD);
    await reopenedAgain.authenticate();
    expect(reopenedAgain.items()).toEqual([]);
    reopenedAgain.lock();
  });

  // Gap 00 (ADR 0012 §5, ADR 0018 §9, §11): `VaultSession.sync` runs the client-side trash
  // auto-purge once the fetch/upload driver settles. Before the retention period, trashing
  // alone must not purge; past it, the next `sync()` does, and the server never does it
  // (ADR 0022) — only this client-side pass does.
  it("auto-purges a trashed item once its retention period has elapsed, on sync", async () => {
    const transport = fetchTransport(origin);
    let skew = 0;
    const clock = () => Date.now() + skew;
    const signup = await Signup.start(
      transport,
      { origin, loginName: "Carol", password: PASSWORD, issueRecoveryCode: false },
      clock,
    );
    const lastGroup = (() => {
      const kit = signup.emergencyKit();
      const secretKey = new TextDecoder().decode(kit.secretKey);
      kit.secretKey.fill(0);
      return secretKey.split("-").at(-1) ?? "";
    })();
    await signup.confirm(lastGroup);
    const first = await signup.login();

    const id = first.createItem("login", [{ op: "set", key: "item.name", value: "To expire" }]);
    await first.sync();
    first.trashItem(id);
    await first.sync();
    // Well before 30 days: trashing alone never purges.
    expect(first.items(true).map((i) => i.id)).toEqual([id]);

    // Past the 30-day default retention (ADR 0012 §5): the next sync purges it client-side.
    skew += 30 * 24 * 60 * 60 * 1000 + 60_000;
    await first.sync();
    expect(first.items(true)).toEqual([]);
    expect(first.items()).toEqual([]);

    first.lock();
  });

  /**
   * A confirmed signup of `loginName` and its first session, with the Secret Key text. `clock`
   * (default `Date.now`) is the session's clock for every write it makes afterwards: a frozen
   * clock forces two edits to land on the very same millisecond, on purpose, for a test.
   */
  async function freshAccount(
    loginName: string,
    clock: Clock = Date.now,
  ): Promise<{ session: VaultSession; secretKey: string }> {
    const transport = fetchTransport(origin);
    const signup = await Signup.start(
      transport,
      {
        origin,
        loginName,
        password: PASSWORD,
        issueRecoveryCode: false,
      },
      clock,
    );
    const kit = signup.emergencyKit();
    const secretKey = new TextDecoder().decode(kit.secretKey);
    kit.secretKey.fill(0);
    await signup.confirm(secretKey.split("-").at(-1) ?? "");
    return { session: await signup.login(), secretKey };
  }

  // Gap 01 (ADR 0012 §5, ADR 0013 §3 rule 3): the history crosses as dates only; one value
  // crosses per reveal, bound to the entry's own id (finding 0), not its display date. A
  // frozen clock forces every edit onto the same millisecond, so two entries share one
  // `changedMs` by construction, not by luck: the deterministic version of the race a sync
  // between the listing and the reveal could otherwise cause only sometimes.
  it("lists password history without values and reveals one entry on request", async () => {
    const frozen = Date.now();
    const { session: s } = await freshAccount("Dave", () => frozen);
    const id = s.createItem("login", [
      { op: "set", key: "item.name", value: "Mail" },
      { op: "set", key: "login.password", value: "v0" },
    ]);
    const bare = s.createItem("note", [{ op: "set", key: "item.name", value: "No history" }]);

    // Empty: one value only, or no password at all.
    expect(s.passwordHistory(id)).toEqual([]);
    expect(s.passwordHistory(bare)).toEqual([]);

    s.editItem(id, [{ op: "set", key: "login.password", value: "v1" }]);
    s.editItem(id, [{ op: "set", key: "login.password", value: "v2" }]);
    await s.sync();
    const two = s.passwordHistory(id);
    expect(two.map((h) => [h.source, h.index])).toEqual([
      ["merge", 0],
      ["merge", 1],
    ]);
    for (const entry of two) {
      expect(typeof entry.changedMs).toBe("number");
      expect(typeof entry.id).toBe("string");
      // Dates only: no value of any kind in the listing.
      expect(Object.keys(entry).sort()).toEqual(["changedMs", "id", "index", "source"]);
    }
    // The collision this test forces: the same millisecond, by the frozen clock above.
    expect(two[0]?.changedMs).toBe(frozen);
    expect(two[1]?.changedMs).toBe(frozen);
    // Distinguishable all the same: each entry's own dot.
    expect(two[0]?.id).not.toBe(two[1]?.id);
    expect(JSON.stringify(two)).not.toContain("v0");
    expect(JSON.stringify(two)).not.toContain("v1");
    const [newer, older] = two as [HistoryEntry, HistoryEntry];
    expect(s.revealPasswordHistory(id, "merge", 0, newer.id)).toBe("v1");
    expect(s.revealPasswordHistory(id, "merge", 1, older.id)).toBe("v0");
    // The two entries' own ids never reveal the other's value, even at the other's index.
    expect(() => s.revealPasswordHistory(id, "merge", 0, older.id)).toThrowError(
      expect.objectContaining({ code: "unknown_item" }),
    );
    const refused = (source: HistoryEntry["source"], index: number, entryId: string) =>
      expect(() => s.revealPasswordHistory(id, source, index, entryId)).toThrowError(
        expect.objectContaining({ code: "unknown_item" }),
      );
    refused("merge", 2, older.id);
    refused("imported", 0, "irrelevant");
    expect(() => s.revealPasswordHistory(id, "other" as never, 0, newer.id)).toThrowError(
      expect.objectContaining({ code: "invalid_input" }),
    );

    // Capped at 50 (the merge's history limit): v0..v54 replaced, the 50 newest kept.
    for (let n = 3; n <= 55; n += 1) {
      s.editItem(id, [{ op: "set", key: "login.password", value: `v${n}` }]);
    }
    const capped = s.passwordHistory(id);
    expect(capped).toHaveLength(50);
    expect(s.revealPasswordHistory(id, "merge", 0, capped[0]?.id ?? "")).toBe("v54");
    expect(s.revealPasswordHistory(id, "merge", 49, capped[49]?.id ?? "")).toBe("v5");
    refused("merge", 50, capped[49]?.id ?? "");
    // A stale listing: position 0 now holds v54, not the v1 the old listing named, even
    // though every entry here shares the exact same frozen date. Refused, never another
    // entry's value under the old entry's identity.
    expect(capped[0]?.id).not.toBe(newer.id);
    refused("merge", 0, newer.id);
    s.lock();
  });

  // Gap 01, imported history (ADR 0018 §7 `pwhist/<id>/value` · `/ms`): the schema shows
  // `pwhist` values, but they never cross through fields(); one crosses per reveal.
  it("keeps imported password history out of fields and reveals it one entry at a time", async () => {
    const { session: s } = await freshAccount("Frank");
    const history = [
      { password: "imported-old-a", lastUsedDate: "2024-01-02T03:04:05.000Z" },
      { password: "imported-old-b", lastUsedDate: "2023-05-06T07:08:09.000Z" },
    ];
    const file = new TextEncoder().encode(
      JSON.stringify({
        encrypted: false,
        items: [
          {
            type: 1,
            name: "Imported login",
            login: { username: "frank", password: "imported-current" },
            passwordHistory: history,
          },
        ],
      }),
    );
    expect(s.importFile("bitwarden-json", file).imported).toBe(1);
    const id = s.items().find((i) => i.title === "Imported login")?.id ?? "";
    expect(id).not.toBe("");

    // fields(): no pwhist row, so no former password crosses with the item view.
    const fields = s.fields(id);
    expect(fields.some((f) => f.list === "pwhist" || f.key.startsWith("pwhist/"))).toBe(false);
    expect(JSON.stringify(fields)).not.toContain("imported-old");

    // The listing: imported entries with their dates, no values.
    const listed = s.passwordHistory(id);
    expect(listed.map((h) => h.source)).toEqual(["imported", "imported"]);
    expect(JSON.stringify(listed)).not.toContain("imported-old");
    const byDate = new Map(history.map((h) => [Date.parse(h.lastUsedDate), h.password]));
    expect(new Set(listed.map((h) => h.changedMs))).toEqual(new Set(byDate.keys()));
    // Every entry's id is its own, never shared with the other.
    expect(listed[0]?.id).not.toBe(listed[1]?.id);

    // Each reveal returns the value of the entry the listing named by id.
    for (const entry of listed) {
      expect(s.revealPasswordHistory(id, "imported", entry.index, entry.id)).toBe(
        byDate.get(entry.changedMs ?? -1),
      );
    }
    // Out of range, the wrong source, or an id the entry does not carry: refused.
    const first = listed[0] as HistoryEntry;
    const second = listed[1] as HistoryEntry;
    for (const [source, index, entryId] of [
      ["imported", 2, first.id],
      ["imported", 99, first.id],
      ["merge", 0, first.id],
      ["imported", first.index, second.id],
      ["imported", first.index, "not-a-real-id"],
    ] as const) {
      expect(() => s.revealPasswordHistory(id, source, index, entryId)).toThrowError(
        expect.objectContaining({ code: "unknown_item" }),
      );
    }

    // Finding 0 (imported branch, deterministic): an importer that wrote no `lastUsedDate`
    // for either row leaves both `changedMs` fields `undefined`. The old date-based guard
    // matched `undefined === undefined` at any index, so a sync that reordered the list
    // could reveal the wrong row's password under the right one's label. The id-based guard
    // never collides, because two different `pwhist` rows never share one.
    const noDates = [{ password: "no-date-a" }, { password: "no-date-b" }];
    const noDatesFile = new TextEncoder().encode(
      JSON.stringify({
        encrypted: false,
        items: [
          {
            type: 1,
            name: "No dates",
            login: { username: "frank2", password: "current" },
            passwordHistory: noDates,
          },
        ],
      }),
    );
    expect(s.importFile("bitwarden-json", noDatesFile).imported).toBe(1);
    const noDatesId = s.items().find((i) => i.title === "No dates")?.id ?? "";
    expect(noDatesId).not.toBe("");

    const listedNoDates = s.passwordHistory(noDatesId);
    expect(listedNoDates).toHaveLength(2);
    for (const entry of listedNoDates) {
      // The old guard's hole exactly: every entry's date is absent.
      expect(entry.changedMs).toBeUndefined();
    }
    // Distinguishable ids, even though the dates coincide (both absent).
    const [a, b] = listedNoDates as [HistoryEntry, HistoryEntry];
    expect(a.id).not.toBe(b.id);

    const byPassword = new Set(
      listedNoDates.map((entry) => s.revealPasswordHistory(noDatesId, "imported", entry.index, entry.id)),
    );
    expect(byPassword).toEqual(new Set(["no-date-a", "no-date-b"]));
    // `a`'s id never reveals `b`'s value at `b`'s index, nor the reverse: no coincidental
    // `undefined === undefined` match.
    expect(() => s.revealPasswordHistory(noDatesId, "imported", b.index, a.id)).toThrowError(
      expect.objectContaining({ code: "unknown_item" }),
    );
    expect(() => s.revealPasswordHistory(noDatesId, "imported", a.index, b.id)).toThrowError(
      expect.objectContaining({ code: "unknown_item" }),
    );
    s.lock();
  });

  // Gap 02 (ADR 0018 §3 "Surfacing", ADR 0012 §5 "Active wins"): each notice is handed over
  // once per session, kept in session memory only, and a late edit restores as a new item.
  it("hands over late-edit and concurrent-trash notices once per session", async () => {
    const transport = fetchTransport(origin);
    const { session: first, secretKey } = await freshAccount("Erin");
    const kept = first.createItem("note", [{ op: "set", key: "item.name", value: "Kept" }]);
    const gone = first.createItem("note", [{ op: "set", key: "item.name", value: "Gone" }]);
    await first.sync();
    // No notice on a quiet vault.
    expect(first.takeNotices()).toEqual([]);

    const second = await login(transport, {
      origin,
      loginName: "erin",
      secretKey,
      password: PASSWORD,
    });
    await second.sync();

    // The first session trashes one item, then purges the other; each time the second edits
    // the item before it has heard of that.
    first.trashItem(kept);
    await first.sync();
    second.editItem(kept, [{ op: "set", key: "item.notes", value: "still needed" }]);
    await second.sync();
    first.trashItem(gone);
    first.purgeItem(gone);
    await first.sync();
    second.editItem(gone, [{ op: "set", key: "item.notes", value: "late" }]);
    await second.sync();

    await first.sync();
    const notices = first.takeNotices();
    expect(notices).toHaveLength(2);
    expect(notices).toContainEqual({
      kind: "concurrent-trash",
      item: kept,
      devices: [first.deviceId, second.deviceId],
      conflictId: expect.any(String),
    });
    expect(notices).toContainEqual({
      kind: "late-edit",
      item: gone,
      devices: [second.deviceId],
      conflictId: undefined,
    });
    // Handed over once in this session, even after another sync.
    expect(first.takeNotices()).toEqual([]);
    await first.sync();
    expect(first.takeNotices()).toEqual([]);
    // The edit kept the trashed item; the purged one stays gone.
    expect(first.items().map((i) => i.id)).toContain(kept);
    expect(first.items().map((i) => i.id)).not.toContain(gone);

    // Restore as a new item of the type the user picks.
    expect(() => first.restoreLateAsNew(kept, "note")).toThrowError(
      expect.objectContaining({ code: "unknown_item" }),
    );
    expect(() => first.restoreLateAsNew(gone, "spaceship" as never)).toThrowError(
      expect.objectContaining({ code: "invalid_input" }),
    );
    const restored = first.restoreLateAsNew(gone, "note");
    expect(restored).not.toBe(gone);
    expect(first.fields(restored).find((f) => f.key === "item.notes")?.value).toBe("late");
    await first.sync();
    expect(first.items().map((i) => i.id)).not.toContain(gone);

    // Still nothing new for the session that was handed them.
    expect(first.takeNotices()).toEqual([]);

    // Finding 3: a second, genuinely distinct conflict between the very same two devices,
    // within this one session, is handed over too -- not silently dropped because it shares
    // a device pair with a conflict already shown.
    const raced = first.createItem("note", [{ op: "set", key: "item.name", value: "Raced" }]);
    await first.sync();
    await second.sync();
    first.trashItem(raced);
    await first.sync();
    second.editItem(raced, [{ op: "set", key: "item.notes", value: "round one" }]);
    await second.sync();
    await first.sync();
    const roundOne = first.takeNotices();
    expect(roundOne).toContainEqual({
      kind: "concurrent-trash",
      item: raced,
      devices: [first.deviceId, second.deviceId],
      conflictId: expect.any(String),
    });
    const roundOneId = roundOne.find((n) => n.item === raced)?.conflictId;
    // Handed over once already, same as any other notice.
    expect(first.takeNotices()).toEqual([]);

    // The conflict resolves: `second` learns of `first`'s trash, then writes an edit whose
    // causal context covers both the losing Trashed op and the kept Active op (ADR 0012 §5).
    await second.sync();
    second.editItem(raced, [{ op: "set", key: "item.notes", value: "resolved" }]);
    await second.sync();

    // The same two devices race again, from that new base: `first` (who never fetched the
    // resolving edit) trashes once more; `second` (who never fetched `first`'s new trash)
    // edits once more too. A fresh, genuinely distinct conflict between the very same pair.
    first.trashItem(raced);
    await first.sync();
    second.editItem(raced, [{ op: "set", key: "item.notes", value: "round two" }]);
    await second.sync();
    await first.sync();
    const roundTwo = first.takeNotices();
    expect(roundTwo).toContainEqual({
      kind: "concurrent-trash",
      item: raced,
      devices: [first.deviceId, second.deviceId],
      conflictId: expect.any(String),
    });
    // Finding 3b (re-review of finding 3): this second race is a genuinely distinct conflict,
    // not a repeat of the first, so its `conflictId` differs -- a host-side dedup keyed on it
    // (the web vault's `noticeKey`) must not mistake it for the one already shown.
    const roundTwoId = roundTwo.find((n) => n.item === raced)?.conflictId;
    expect(roundTwoId).not.toBe(roundOneId);
    expect(first.takeNotices()).toEqual([]);

    // Session memory only: lock, then unlock again (the web vault's unlock is a fresh login
    // of the same account). The marks went with the locked session, so the notices come back,
    // and are again handed over once.
    first.lock();
    const unlocked = await login(transport, {
      origin,
      loginName: "erin",
      secretKey,
      password: PASSWORD,
    });
    await unlocked.sync();
    const again = unlocked.takeNotices().map((n) => [n.kind, n.item]);
    expect(again).toContainEqual(["late-edit", gone]);
    expect(again).toContainEqual(["concurrent-trash", kept]);
    expect(unlocked.takeNotices()).toEqual([]);
    await unlocked.sync();
    expect(unlocked.takeNotices()).toEqual([]);
    lockAll(first, second, unlocked);
  });
});

/** Locks every session. */
function lockAll(...sessions: VaultSession[]): void {
  for (const s of sessions) {
    s.lock();
    expect(s.locked).toBe(true);
  }
}
