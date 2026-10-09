// The passkey provider end to end (ADR 0039 §2; THREAT_MODEL A7's "Passkey provider" section),
// against a real account, a real unlocked device, and a real test relying party served over
// genuine TLS (`https-server.ts` — INV-64 and `rizzy_client::passkey::verify_rp_id` both demand
// `https:` literally; `server.ts`'s plain `http://127.0.0.1` cannot be reused here). Registers a
// passkey through the consent UI, verifies the attestation independently (ES256 public key
// extracted from the hand-written CBOR, `webauthn-verify.ts`), signs in with it and verifies that
// assertion's signature against the same key, and confirms a decline falls back to the browser's
// own (here, nonexistent) authenticator rather than hanging or fabricating a result.
//
// Headless (`headless: true, channel: "chromium"`), same reasoning as every other spec in this
// directory: only the installed full Chromium's headless mode can load an unpacked extension.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { type BrowserContext, type Page, chromium, test as base, expect } from "@playwright/test";

import { signUp } from "./account.ts";
import { type RunningHttpsServer, startHttpsTestPage } from "./https-server.ts";
import { type RunningServer, startServer } from "./server.ts";
import { extractEs256PublicKeyFromAttestationObject, verifyEs256Assertion } from "./webauthn-verify.ts";

const EXTENSION_PATH = fileURLToPath(new URL("../dist/chromium", import.meta.url));
const TEST_ACCOUNT_PASSWORD = "correct horse battery staple";

/** Exposes `navigator.credentials.create`/`.get` as a pair of page-global helper functions that
 * take/return base64 strings only (`page.evaluate`'s own argument/return serialization has no
 * `ArrayBuffer` support) — the actual call still goes through the real, shimmed
 * `navigator.credentials`, exactly as a real site's own code would. */
const TEST_RP_PAGE = `<!doctype html><html><body><script>
function b64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
window.rizzyTestCreate = async (opts) => {
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: opts.rpName },
      user: { id: b64ToBuf(opts.userIdB64), name: opts.userName, displayName: opts.userDisplayName },
      challenge: b64ToBuf(opts.challengeB64),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      timeout: opts.timeoutMs,
    },
  });
  return {
    id: cred.id,
    attestationObjectB64: bufToB64(cred.response.attestationObject),
    clientDataJsonB64: bufToB64(cred.response.clientDataJSON),
  };
};
window.rizzyTestGet = async (opts) => {
  const cred = await navigator.credentials.get({
    publicKey: { challenge: b64ToBuf(opts.challengeB64), timeout: opts.timeoutMs },
  });
  return {
    id: cred.id,
    authenticatorDataB64: bufToB64(cred.response.authenticatorData),
    clientDataJsonB64: bufToB64(cred.response.clientDataJSON),
    signatureB64: bufToB64(cred.response.signature),
  };
};
</script></body></html>`;

interface CreateResult {
  readonly id: string;
  readonly attestationObjectB64: string;
  readonly clientDataJsonB64: string;
}

interface GetResult {
  readonly id: string;
  readonly authenticatorDataB64: string;
  readonly clientDataJsonB64: string;
  readonly signatureB64: string;
}

declare global {
  interface Window {
    rizzyTestCreate(opts: {
      rpName: string;
      userIdB64: string;
      userName: string;
      userDisplayName: string;
      challengeB64: string;
      timeoutMs: number;
    }): Promise<CreateResult>;
    rizzyTestGet(opts: { challengeB64: string; timeoutMs: number }): Promise<GetResult>;
  }
}

function b64(text: string): string {
  return Buffer.from(text, "utf8").toString("base64");
}

const test = base.extend<{ server: RunningServer; rp: RunningHttpsServer; context: BrowserContext; extensionId: string }>({
  server: async ({}, use) => {
    const server = await startServer();
    await use(server);
    server.stop();
  },
  rp: async ({}, use) => {
    const rp = await startHttpsTestPage(TEST_RP_PAGE);
    await use(rp);
    await rp.stop();
  },
  context: async ({}, use) => {
    const userDataDir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-passkey-"));
    const context = await chromium.launchPersistentContext(userDataDir, {
      headless: true,
      channel: "chromium",
      ignoreHTTPSErrors: true,
      args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`],
    });
    await use(context);
    await context.close();
  },
  extensionId: async ({ context }, use) => {
    let [worker] = context.serviceWorkers();
    if (worker === undefined) {
      worker = await context.waitForEvent("serviceworker");
    }
    await use(new URL(worker.url()).host);
  },
});

async function enrol(context: BrowserContext, extensionId: string, server: RunningServer, loginName: string): Promise<string> {
  const setupPage = await context.newPage();
  const secretKey = await signUp(setupPage, server.origin, loginName);
  await setupPage.close();

  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/src/popup/index.html`);
  await popup.getByLabel("Server URL").fill(server.origin);
  await popup.getByLabel("Account (login name)").fill(loginName);
  await popup.getByLabel("Secret Key").fill(secretKey);
  await popup.getByLabel("Master password").fill(TEST_ACCOUNT_PASSWORD);
  await popup.getByRole("button", { name: "Set up" }).click();
  await expect(popup.getByRole("button", { name: "Lock" })).toBeVisible({ timeout: 30_000 });
  await popup.close();
  return secretKey;
}

/** Opens `rp.origin` and waits for the page-world shim to install (module docs on the race this
 * guards: `<script src>` injection is asynchronous) before returning. */
async function openTestRpPage(context: BrowserContext, rpOrigin: string): Promise<Page> {
  const page = await context.newPage();
  await page.goto(rpOrigin);
  await page.waitForFunction(() => (navigator.credentials as unknown as { __rizzyVaultPasskeyShimReady?: boolean }).__rizzyVaultPasskeyShimReady === true);
  return page;
}

test.setTimeout(120_000);

test("registers a passkey through consent, verifies the attestation, signs in with it and verifies the assertion, and falls back on decline", async ({
  context,
  extensionId,
  server,
  rp,
}) => {
  await enrol(context, extensionId, server, "pkuser");
  const page = await openTestRpPage(context, rp.origin);

  // --- Registration: the consent UI shows "Test RP" (create ceremony), a trusted click
  // approves it.
  const createPromise = page.evaluate(
    (opts) => window.rizzyTestCreate(opts),
    {
      rpName: "Test RP",
      userIdB64: b64("user-1"),
      userName: "alice",
      userDisplayName: "Alice",
      challengeB64: b64("create-challenge-1"),
      timeoutMs: 20_000,
    },
  );
  const consentFrame = page.frameLocator("iframe[data-rizzy-passkey-consent]");
  await expect(consentFrame.getByRole("button", { name: "Test RP" })).toBeVisible({ timeout: 8_000 });
  await consentFrame.getByRole("button", { name: "Test RP" }).click();

  const created = await createPromise;
  expect(created.id.length).toBeGreaterThan(0);
  const attestationObject = Buffer.from(created.attestationObjectB64, "base64");
  const clientDataJson = JSON.parse(Buffer.from(created.clientDataJsonB64, "base64").toString("utf8")) as {
    type: string;
    origin: string;
    challenge: string;
  };
  expect(clientDataJson.type).toBe("webauthn.create");
  expect(clientDataJson.origin).toBe(rp.origin);
  const publicKey = extractEs256PublicKeyFromAttestationObject(attestationObject);
  expect(publicKey.x).toHaveLength(32);
  expect(publicKey.y).toHaveLength(32);

  // --- Sign-in: the consent UI offers the one matching passkey ("Test RP (alice)" — the Login
  // the create ceremony just saved, title/username from the RP's own `rp.name`/`user.name`), a
  // trusted click on it approves the assertion.
  const getPromise = page.evaluate((opts) => window.rizzyTestGet(opts), { challengeB64: b64("get-challenge-1"), timeoutMs: 20_000 });
  await expect(consentFrame.getByRole("button", { name: /Test RP \(alice\)/ })).toBeVisible({ timeout: 15_000 });
  await consentFrame.getByRole("button", { name: /Test RP \(alice\)/ }).click();

  const assertion = await getPromise;
  expect(assertion.id).toBe(created.id);
  const authenticatorData = Buffer.from(assertion.authenticatorDataB64, "base64");
  const assertionClientDataJson = Buffer.from(assertion.clientDataJsonB64, "base64");
  const signature = Buffer.from(assertion.signatureB64, "base64");
  const parsedAssertionClientData = JSON.parse(assertionClientDataJson.toString("utf8")) as { type: string; origin: string };
  expect(parsedAssertionClientData.type).toBe("webauthn.get");
  expect(parsedAssertionClientData.origin).toBe(rp.origin);
  // The independent verification this suite exists for: a relying party that only ever saw the
  // registration's public key, never this extension's private key, can check the signature.
  expect(verifyEs256Assertion(publicKey, authenticatorData, assertionClientDataJson, signature)).toBe(true);

  // --- Decline: clicking "Not now" must fall back to the real browser authenticator, never
  // hang and never fabricate a result. Found while writing this test: with no CDP virtual
  // authenticator registered, headless Chromium's native WebAuthn `get()` does not reject — it
  // waits forever for a transport/device that can never arrive in this environment, which hung
  // this exact test for a full 120s before this fix. A CDP `WebAuthn` virtual authenticator with
  // no credentials enrolled on it gives the native call something real to ask and fail against
  // (`NotAllowedError`, no matching credential), so this assertion can require the promise to
  // *settle* within a bounded time, proving the native path was actually taken rather than this
  // shim's own code looping or hanging on the decline.
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  const declinePromise = page
    .evaluate((opts) => window.rizzyTestGet(opts), { challengeB64: b64("get-challenge-2"), timeoutMs: 5_000 })
    .then(
      () => ({ settled: "resolved" as const }),
      () => ({ settled: "rejected" as const }),
    );
  await expect(consentFrame.getByRole("button", { name: "Not now" })).toBeVisible({ timeout: 15_000 });
  await consentFrame.getByRole("button", { name: "Not now" }).click();
  const outcome = await declinePromise;
  // Chromium's native WebAuthn, given no authenticator, rejects — this project's own code never
  // produces a "resolved" outcome on a decline (the shim only ever resolves with a credential on
  // `outcome.ok`, module docs), so either settlement here proves the real native call ran; a
  // `rejected` settlement is what this environment is expected to produce.
  expect(outcome.settled).toBe("rejected");
});

/** Logs in to the web vault (`apps/web/e2e/helpers.ts`'s own `logIn`, inlined rather than
 * imported: the two apps keep separate `tsconfig.json`/dependency trees, same reason
 * `account.ts`'s own module doc gives for not sharing `signUp` either). */
async function logInToWebVault(page: import("@playwright/test").Page, loginName: string, secretKey: string): Promise<void> {
  await page.getByLabel("Login name").fill(loginName);
  await page.getByLabel("Secret Key", { exact: true }).fill(secretKey);
  await page.getByLabel("Master password", { exact: true }).fill(TEST_ACCOUNT_PASSWORD);
  await page.getByRole("button", { name: /^(Log in|Unlock)$/ }).click();
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible();
}

test("a passkey the extension created shows up in the web vault, with no private key reveal, and can be deleted", async ({
  context,
  extensionId,
  server,
  rp,
}) => {
  const secretKey = await enrol(context, extensionId, server, "webuser");
  const page = await openTestRpPage(context, rp.origin);
  const createPromise = page.evaluate(
    (opts) => window.rizzyTestCreate(opts),
    {
      rpName: "Test RP",
      userIdB64: b64("user-1"),
      userName: "alice",
      userDisplayName: "Alice",
      challengeB64: b64("create-challenge-1"),
      timeoutMs: 20_000,
    },
  );
  const consentFrame = page.frameLocator("iframe[data-rizzy-passkey-consent]");
  await expect(consentFrame.getByRole("button", { name: "Test RP" })).toBeVisible({ timeout: 8_000 });
  await consentFrame.getByRole("button", { name: "Test RP" }).click();
  await createPromise;
  await page.close();

  // --- The web vault (the real `rizzy-vault` server binary, `server.ts`), a second, independent
  // session logging in to the very same account: the Login the create ceremony saved shows its
  // passkey (`ItemView.tsx`'s `PasskeyLine`) — rp id, the item's own username, a created date —
  // and nothing that could reveal the private key (no "Show"/"Reveal" control on that row at
  // all, unlike a password or TOTP secret field).
  const vault = await context.newPage();
  await vault.goto(server.origin);
  await logInToWebVault(vault, "webuser", secretKey);
  await vault.getByRole("button", { name: /Test RP/ }).click();
  await expect(vault.getByRole("heading", { name: "Test RP" })).toBeVisible();
  const passkeyRow = vault.locator("[data-passkey]");
  await expect(passkeyRow).toBeVisible();
  await expect(passkeyRow).toContainText("localhost");
  await expect(passkeyRow).toContainText("alice");
  await expect(passkeyRow).toContainText("Created");
  await expect(passkeyRow.getByRole("button", { name: /Show|Reveal/ })).toHaveCount(0);

  // --- Delete, through the confirm dialog (never immediate, `ItemView.tsx` module docs).
  await passkeyRow.getByRole("button", { name: "Delete" }).click();
  await expect(vault.getByRole("dialog", { name: "Delete this passkey?" })).toBeVisible();
  await vault.getByRole("dialog", { name: "Delete this passkey?" }).getByRole("button", { name: "Delete passkey" }).click();
  await expect(vault.getByText("Passkey deleted.")).toBeVisible();
  await expect(vault.locator("[data-passkey]")).toHaveCount(0);
});
