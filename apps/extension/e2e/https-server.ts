// A real (self-signed) HTTPS test-RP server for the passkey E2E suite (`passkey.spec.ts`).
// INV-64 requires `https:` and this project's Rust layer (`rizzy-client::passkey::
// verify_rp_id`) enforces it literally — no loopback exception, unlike a real browser's own
// WebAuthn implementation — so, unlike every other E2E test page in this directory (`server.ts`'s
// plain `http://127.0.0.1`), the passkey test RP must be served over genuine TLS. The host is
// `localhost`, not the `127.0.0.1` IP literal every other E2E page uses: `rizzy_client::passkey::
// verify_rp_id`'s own `rp_id_is_a_valid_leaf` refuses an IP-literal `rpId` outright (WebAuthn
// never accepts one), so an IP-literal origin could never pass INV-64 at all, however it is
// served — `localhost` is a dotless single-label hostname, accepted through that function's
// exact-host-match branch. The certificate is generated fresh per test run with the system
// `openssl` binary (a throwaway, self-signed, 1-day EC P-256 cert for `localhost`) — no new
// npm/cargo dependency — and the browser context the test launches with
// `ignoreHTTPSErrors: true` to accept it without installing a trust anchor.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer as createHttpsServer, type Server } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface RunningHttpsServer {
  readonly origin: string;
  stop(): Promise<void>;
}

/** Starts an HTTPS server on `127.0.0.1` serving `html` for every request. */
export async function startHttpsTestPage(html: string): Promise<RunningHttpsServer> {
  const dir = mkdtempSync(join(tmpdir(), "rizzy-ext-e2e-tls-"));
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "cert.pem");
  const gen = spawnSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:prime256v1",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      "1",
      "-nodes",
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=DNS:localhost",
    ],
    { stdio: "ignore" },
  );
  if (gen.status !== 0) {
    rmSync(dir, { recursive: true, force: true });
    throw new Error("startHttpsTestPage: openssl failed to generate a test certificate");
  }
  const key = readFileSync(keyPath);
  const cert = readFileSync(certPath);
  const server: Server = createHttpsServer({ key, cert }, (_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(html);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  return {
    origin: `https://localhost:${port}`,
    async stop() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
