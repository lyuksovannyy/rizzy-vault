// SPDX-License-Identifier: AGPL-3.0-only

// The browser's WebAuthn API for security keys as a second factor (ADR 0058, CRYPTO.md §11.17),
// on the UI thread: `navigator.credentials` does not exist in a Worker. The core builds and
// reads every request and answer; this module only turns the server's options JSON (binary
// values as base64url) into the dictionaries the browser takes, and the browser's
// `PublicKeyCredential` back into JSON text. It decides nothing about the ceremony: the
// browser binds the credential to this origin, and the server verifies it.

/** Whether this browser offers WebAuthn here (a secure context with `PublicKeyCredential`). */
export function webauthnAvailable(): boolean {
  return (
    typeof window !== "undefined" &&
    window.isSecureContext &&
    typeof window.PublicKeyCredential === "function" &&
    typeof navigator.credentials?.create === "function"
  );
}

/** base64url (no padding) to bytes; throws on anything else. */
export function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error("not base64url");
  }
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/** Bytes to base64url without padding. */
export function toBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const b of view) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

type Json = Record<string, unknown>;

function record(value: unknown): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("malformed options");
  }
  return value as Json;
}

/** A copy of `value` without `null` members: the browser's dictionaries refuse `null` where the
 * server's JSON uses it for "absent". */
function dropNulls(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(dropNulls);
  }
  if (typeof value === "object" && value !== null) {
    const out: Json = {};
    for (const [k, v] of Object.entries(value)) {
      if (v !== null) {
        out[k] = dropNulls(v);
      }
    }
    return out;
  }
  return value;
}

/** The `publicKey` member of the server's options JSON, without `null` members. */
function publicKeyOf(json: string): Json {
  return record(dropNulls(record(JSON.parse(json))["publicKey"]));
}

function text(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("malformed options");
  }
  return value;
}

/** `excludeCredentials` / `allowCredentials` entries, ids decoded. */
function descriptors(value: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new Error("malformed options");
  }
  return value.map((entry) => {
    const d = record(entry);
    const out: PublicKeyCredentialDescriptor = {
      type: "public-key",
      id: fromBase64Url(text(d["id"])),
    };
    if (Array.isArray(d["transports"])) {
      out.transports = d["transports"] as AuthenticatorTransport[];
    }
    return out;
  });
}

/** The server's creation options (`{"publicKey": {...}}`) as the browser takes them. */
export function creationOptions(json: string): PublicKeyCredentialCreationOptions {
  const pk = publicKeyOf(json);
  const user = record(pk["user"]);
  const options: PublicKeyCredentialCreationOptions = {
    ...(pk as unknown as PublicKeyCredentialCreationOptions),
    challenge: fromBase64Url(text(pk["challenge"])),
    user: {
      id: fromBase64Url(text(user["id"])),
      name: text(user["name"]),
      displayName: text(user["displayName"]),
    },
  };
  const exclude = descriptors(pk["excludeCredentials"]);
  if (exclude === undefined) {
    delete options.excludeCredentials;
  } else {
    options.excludeCredentials = exclude;
  }
  return options;
}

/** The server's request options (`{"publicKey": {...}}`) as the browser takes them. */
export function requestOptions(json: string): PublicKeyCredentialRequestOptions {
  const pk = publicKeyOf(json);
  const options: PublicKeyCredentialRequestOptions = {
    ...(pk as unknown as PublicKeyCredentialRequestOptions),
    challenge: fromBase64Url(text(pk["challenge"])),
  };
  const allow = descriptors(pk["allowCredentials"]);
  if (allow === undefined) {
    delete options.allowCredentials;
  } else {
    options.allowCredentials = allow;
  }
  return options;
}

/** The fields of a `PublicKeyCredential` the server reads, as JSON text. */
function credentialJson(credential: PublicKeyCredential, response: Json): string {
  return JSON.stringify({
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response,
    clientExtensionResults: {},
  });
}

/** Runs `navigator.credentials.create` for the server's creation options; the result as JSON. */
export async function createCredential(optionsJson: string): Promise<string> {
  const credential = await navigator.credentials.create({
    publicKey: creationOptions(optionsJson),
  });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("no credential");
  }
  const response = credential.response as AuthenticatorAttestationResponse;
  return credentialJson(credential, {
    attestationObject: toBase64Url(response.attestationObject),
    clientDataJSON: toBase64Url(response.clientDataJSON),
  });
}

/** Runs `navigator.credentials.get` for the server's request options; the result as JSON. */
export async function getAssertion(optionsJson: string): Promise<string> {
  const credential = await navigator.credentials.get({ publicKey: requestOptions(optionsJson) });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("no credential");
  }
  const response = credential.response as AuthenticatorAssertionResponse;
  return credentialJson(credential, {
    authenticatorData: toBase64Url(response.authenticatorData),
    clientDataJSON: toBase64Url(response.clientDataJSON),
    signature: toBase64Url(response.signature),
    userHandle: response.userHandle === null ? null : toBase64Url(response.userHandle),
  });
}
