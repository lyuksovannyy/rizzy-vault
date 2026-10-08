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
import { createConnection, createServer } from "node:net";
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

/** Waits until the server accepts connections. */
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

/** A running server: its origin, and a stop that removes its files. */
export interface RunningServer {
  readonly origin: string;
  stop(): void;
}

/** Starts a server with open signup. */
export async function startServer(): Promise<RunningServer> {
  const binary = serverBinary();
  const dir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-server-"));
  mkdirSync(join(dir, "data"));
  mkdirSync(join(dir, "secrets"));
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  const env = {
    RIZZY_ORIGIN: origin,
    RIZZY_LISTEN: `127.0.0.1:${port}`,
    RIZZY_SIGNUP: "open",
    RIZZY_DATA_DIR: join(dir, "data"),
    RIZZY_SECRETS_FILE: join(dir, "secrets", "secrets.json"),
  };
  const init = spawnSync(binary, ["secrets", "init"], { env, stdio: "ignore" });
  if (init.status !== 0) {
    throw new Error(`rizzy-vault secrets init failed: ${init.status}`);
  }
  const child = spawn(binary, [], { env, stdio: "ignore" });
  await waitForPort(port, child);
  return {
    origin,
    stop() {
      child.kill();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
