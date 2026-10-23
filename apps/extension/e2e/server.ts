// SPDX-License-Identifier: AGPL-3.0-only

// Starts the real `rizzy-vault` binary for the extension's end-to-end tests, the same way
// `apps/web/e2e/server.ts` does for the web vault's: a loopback port, a temporary SQLite
// database and a fresh secrets file. Duplicated here (not imported from `apps/web/e2e`) rather
// than shared: the two apps' `tsconfig.json`/`include` trees are separate, and this is one
// small, self-contained file, not worth a cross-app module boundary for.
//
// The binary must be built with the web vault embedded (the extension signs up its test
// account through the web vault's own UI, the same account-creation path `apps/web`'s e2e
// suite uses — see this file's own `e2e/account.ts`):
//   pnpm run build:wasm && pnpm run build
//   cargo build -p rizzy-server --bin rizzy-vault --features embed-web
// `RIZZY_VAULT_BIN` names another binary. A binary without the web vault fails the test (its
// page has no login/signup form), rather than being skipped.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** The server binary. */
export function serverBinary(): string {
  const named = process.env["RIZZY_VAULT_BIN"];
  if (named !== undefined) {
    return named;
  }
  const root = fileURLToPath(new URL("../../../", import.meta.url));
  const built = join(root, "target", "debug", "rizzy-vault");
  if (!existsSync(built)) {
    throw new Error("no rizzy-vault binary: cargo build -p rizzy-server --bin rizzy-vault --features embed-web");
  }
  return built;
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

/** How many newly probed ports a start tries before it gives up. */
const START_ATTEMPTS = 10;

/** How long a start may take: long, since a debug build on a loaded host is slow to start. */
const START_TIMEOUT_MS = 120_000;

/** How much of a server's standard error is kept for a failure report. */
const LOG_KEEP = 64 * 1024;

/** The last lines of `log`, for a failure report. */
function tail(log: string): string {
  return log.split("\n").slice(-40).join("\n");
}

/** Whether `line` is the log line a serving process writes once it listens on `port`. */
function saysListening(line: string, port: number): boolean {
  let event: unknown;
  try {
    event = JSON.parse(line);
  } catch {
    return false;
  }
  if (typeof event !== "object" || event === null) {
    return false;
  }
  const fields = event as Record<string, unknown>;
  return fields["event"] === "listening" && fields["port"] === port;
}

/**
 * Spawns the serving process on `port` and waits until it logs that it listens there;
 * `undefined` if the port is taken.
 *
 * Ready means this process's own `listening` line on its standard error, never a connection to
 * the port: the port was free when `freePort` probed it, but another process (the server of a
 * test running in parallel, in this suite or another) may have bound it since. This one then exits with
 * `listener: address in use` while a connection reaches the other one, and the test would go
 * on against a stranger's server. Standard error is read for the process's whole life, so the
 * pipe never fills.
 */
async function spawnListening(
  binary: string,
  env: Record<string, string>,
  port: number,
): Promise<ChildProcess | undefined> {
  const child = spawn(binary, [], { env, stdio: ["ignore", "ignore", "pipe"] });
  let log = "";
  let ready = false;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`rizzy-vault did not listen within ${START_TIMEOUT_MS} ms\n${tail(log)}`));
    }, START_TIMEOUT_MS);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => {
      log = (log + chunk).slice(-LOG_KEEP);
      if (!ready && log.split("\n").some((line) => saysListening(line, port))) {
        ready = true;
        clearTimeout(timer);
        resolve(child);
      }
    });
    // `close` comes after the last of standard error, unlike `exit`.
    child.once("close", (code) => {
      clearTimeout(timer);
      if (ready) {
        return;
      }
      if (log.includes("listener: address in use")) {
        resolve(undefined);
      } else {
        reject(new Error(`rizzy-vault exited at start: ${String(code)}\n${tail(log)}`));
      }
    });
  });
}

/** A running server: its origin, and a stop that removes its files. */
export interface RunningServer {
  readonly origin: string;
  stop(): void;
}

/** Starts a server with open signup. `publicOrigin`, when given, is the origin clients use
 * (a proxy in front of the server, `icons.spec.ts`); the server's own listener is then
 * reached only through it. */
export async function startServer(options: { readonly publicOrigin?: string } = {}): Promise<RunningServer> {
  const binary = serverBinary();
  const dir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-server-"));
  mkdirSync(join(dir, "data"));
  mkdirSync(join(dir, "secrets"));
  const settings = (port: number): Record<string, string> => ({
    RIZZY_ORIGIN: options.publicOrigin ?? `http://127.0.0.1:${port}`,
    RIZZY_LISTEN: `127.0.0.1:${port}`,
    // An ephemeral admin port, so parallel servers never collide on 8081 (ADR 0060 §2).
    RIZZY_ADMIN_LISTEN: "127.0.0.1:0",
    RIZZY_SIGNUP: "open",
    RIZZY_DATA_DIR: join(dir, "data"),
    RIZZY_SECRETS_FILE: join(dir, "secrets", "secrets.json"),
  });
  // The secrets file does not depend on the port.
  const init = spawnSync(binary, ["secrets", "init"], {
    env: settings(await freePort()),
    stdio: ["ignore", "ignore", "pipe"],
    encoding: "utf8",
  });
  if (init.status !== 0) {
    throw new Error(`rizzy-vault secrets init failed: ${init.status}\n${tail(init.stderr)}`);
  }
  for (let attempt = 0; attempt < START_ATTEMPTS; attempt++) {
    const port = await freePort();
    const child = await spawnListening(binary, settings(port), port);
    if (child !== undefined) {
      return {
        origin: `http://127.0.0.1:${port}`,
        stop() {
          child.kill();
          rmSync(dir, { recursive: true, force: true });
        },
      };
    }
  }
  throw new Error("rizzy-vault found every port it tried taken");
}
