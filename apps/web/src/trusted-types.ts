// Trusted Types (THREAT_MODEL §7.1 "T"; the web role's CSP carries
// `require-trusted-types-for 'script'`). In a browser that enforces it, every script URL must
// be a `TrustedScriptURL`, the core Worker's included. This module holds the one policy, and
// it allows exactly one URL: the Worker's own, which the build fixes. Nothing else in the web
// vault creates trusted values. Browsers without Trusted Types get the plain URL.

/** The subset of the Trusted Types API this module uses. */
interface TrustedTypePolicyFactoryLike {
  createPolicy(
    name: string,
    rules: { createScriptURL(input: string): string },
  ): { createScriptURL(input: string): unknown };
}

/** The Worker's script URL, as a trusted value where the browser enforces Trusted Types. */
export function workerScriptUrl(url: string): string | URL {
  const allowed = new URL(url, document.baseURI).href;
  const factory = (globalThis as { trustedTypes?: TrustedTypePolicyFactoryLike }).trustedTypes;
  if (factory === undefined) {
    return allowed;
  }
  const policy = factory.createPolicy("rizzy-core-worker", {
    createScriptURL(input: string): string {
      if (input !== allowed) {
        throw new TypeError("script URL not allowed");
      }
      return input;
    },
  });
  // A TrustedScriptURL; the Worker constructor accepts it where the DOM types say string.
  return policy.createScriptURL(allowed) as string;
}
