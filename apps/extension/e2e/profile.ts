// SPDX-License-Identifier: AGPL-3.0-only

// The Chromium profile directory of a test's persistent context. Extensions load only into a
// persistent context, so every spec here launches one on a profile directory of its own, which
// `chromium.launchPersistentContext` creates files in but never removes: Playwright deletes only
// the profile it makes itself for an empty `userDataDir`. A profile is about 13 MB, and a
// fixture that only closes its context left one behind per test in the temporary directory.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Runs `body` with a new empty directory in the system temporary directory, named `prefix`
 * and a random suffix, and removes it with everything in it once `body` settles, whether it
 * returned or threw (a launch that fails, a test that fails, a context that fails to close).
 */
export async function withProfileDir<T>(prefix: string, body: (userDataDir: string) => Promise<T>): Promise<T> {
  const userDataDir = mkdtempSync(join(tmpdir(), prefix));
  try {
    return await body(userDataDir);
  } finally {
    // `maxRetries`: a just-closed Chromium can still be releasing files in the profile.
    rmSync(userDataDir, { recursive: true, force: true, maxRetries: 3 });
  }
}
