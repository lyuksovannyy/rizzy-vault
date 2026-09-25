# ADR 0013: Shared Rust client core (wasm + UniFFI)

- Status: Accepted
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1 (wasm for the web vault, native for the CLI) / M3 (Tauri) / M7 (UniFFI)

## Context

Three sources ask for one shared core:
- [ROADMAP §5](../ROADMAP.md#5-architecture-decisions-to-make-in-m0-with-current-recommendation) recommends a shared Rust core: wasm for the web vault and extension, UniFFI for mobile, native for the CLI and Tauri. The stated reason is "One crypto implementation to audit".
- [ROADMAP §4.10](../ROADMAP.md#410-mobile--passkeys-m7), Must, M7: "Shared Rust core via UniFFI bindings (no crypto re-implemented in Kotlin/Swift)".
- [CRYPTO.md §1](../CRYPTO.md#1-goals-non-goals-and-rules), goal 6, says the same.

The platforms differ in what they allow:
- **Browsers** have no filesystem and get randomness from `crypto.getRandomValues`.
- **iOS AutoFill extensions** run under a memory cap of about 120 MB (L).
- **Tauri** has a Rust process next to the webview.
- **The CLI** is plain Rust.

Tool facts (fact sheet, V unless marked):
- **wasm-bindgen 0.2.129.** The repository moved to `github.com/wasm-bindgen/wasm-bindgen`. The rustwasm working group sunset is U.
- **UniFFI 0.32.2**, MPL-2.0, which is on our licence allow-list. It is pre-1.0, so minor releases break.
- **getrandom 0.4** on `wasm32-unknown-unknown` needs the `wasm_js` feature, enabled only in the final crate (README).
- **Argon2id cost** at 64 MiB, t=3, p=4 on the M0 machine: about 309 ms in wasm (Node 22) against about 236 ms native. Both are single-threaded: the approved argon2 feature set has no `parallel` (rayon) feature, because OS threads would break the no-I/O rule for `rizzy-core` ([ADR 0016](0016-workspace-layout.md) R1). The 116 ms four-thread figure in the M0 fact sheet needs that feature and does not apply to our build. wasm gains nothing from p > 1 either.

In the browser, wasm and JavaScript share one heap. The boundary between `rizzy-core` and the UI is therefore an audit boundary, not a security boundary ([THREAT_MODEL TB-10](../THREAT_MODEL.md#33-trust-boundaries)). In Tauri and on mobile it is a process or language boundary, and keys can stay on the Rust side.

## Decision

### 1. One implementation, three kinds of host

| Layer | Crate | Contents | Runs on |
|---|---|---|---|
| Crypto, formats, item model | `rizzy-core` | everything in [CRYPTO.md](../CRYPTO.md) | every client, and the server |
| Sync engine | `rizzy-sync` | [ADR 0012](0012-sync-engine.md) | every client; the server uses its types only |
| Wire types | `rizzy-proto` | [ADR 0002](0002-own-protocol.md) | every client, and the server |
| Importers | `rizzy-import` | [ADR 0002](0002-own-protocol.md) | every client |
| URL matching (M2) | `rizzy-match` | normalisation, PSL, signed equivalence lists | every client |
| Client orchestration | `rizzy-client` | signup, login, unlock, lock, rotation and sync flows; cache policy; a sans-I/O state machine | every client |
| Bindings | `rizzy-wasm` (M1), `rizzy-ffi` (M7) | thin generated wrappers over `rizzy-client` | wasm32; Android and iOS |
| Native hosts | `rizzy-cli` (M1), `rizzy-desktop` (M3) | link `rizzy-client` directly, with no FFI | Linux, macOS, Windows |

No TypeScript, Kotlin or Swift code implements cryptography, envelope parsing, signature checks, merge or URL matching.

### 2. A sans-I/O client

`rizzy-client` does no I/O either.
- It exposes a state machine. The host feeds in events: user input, HTTP responses, stored bytes, timer ticks. The state machine returns effects: HTTP requests to send, bytes to store, UI state to show.
- The flows (login, rotation, sync, rollback checks) are security logic, so they must exist once.
- Transport differs by platform for good reasons: browser fetch semantics, iOS background sessions, platform proxy and certificate settings. It stays in the host.

Each host provides five capabilities:

| Capability | Web vault | Extension (M2) | Desktop (Tauri) | Mobile | CLI |
|---|---|---|---|---|---|
| HTTP transport | `fetch` | `fetch` | Rust HTTP client, rustls | platform HTTP stack | Rust HTTP client, rustls |
| Persistent storage (opaque bytes) | **none**: everything stays in memory. Only the Secret Key goes into browser storage, and only if the user opts in ([CRYPTO.md §11.4](../CRYPTO.md#114-web-vault)). The web vault is not a durable device | IndexedDB, for wrapped device state and ciphertext only ([INV-63](../THREAT_MODEL.md#8-security-invariants)) | SQLite ([ADR 0011](0011-storage.md)) | SQLite | SQLite |
| Randomness | getrandom 0.4 with `wasm_js`, in `rizzy-wasm` only | same as web vault | getrandom | getrandom | getrandom |
| Wall clock | `Date.now()` through the binding | same as web vault | std | std | std |
| Key storage for local unlock | none | none. Unlocked keys stay in memory in the long-lived context (§4), or in `storage.session` (rule 2, INV-63) | OS keystore, under [INV-62](../THREAT_MODEL.md#8-security-invariants) (M3) | Keychain / Keystore, under INV-62 (M7) | OS keyring, or a 0600 file, for device state only. Never a keystore-unlock secret, because neither enforces user presence (INV-62) |

The Rust HTTP client crate is chosen in M1. It must use rustls, and `deny.toml` already bans OpenSSL. This matches [ADR 0009](0009-crypto-dependency-policy.md)'s RNG rules as [ADR 0016](0016-workspace-layout.md) R2 states them: no first-party library depends on getrandom directly, and only `rizzy-wasm` enables `wasm_js`.

### 3. Rules for the FFI surface

These rules apply to `rizzy-wasm`, `rizzy-ffi` and the Tauri IPC commands ([ADR 0015](0015-desktop-tauri.md)).

1. **Keys stay in Rust.** No function returns an account, vault, item, identity or device key, and none returns `export_key`, `pw_in` or an unlock key. Hosts hold opaque handles (`Session`, `UnlockedVault`). The key material behind a handle lives in Rust memory and is zeroized on lock or drop.
2. **Named exceptions, and only these:**
   - the master password goes in, because it is typed into host UI (M1);
   - the Secret Key and recovery code go out once, to render the Emergency Kit (M1);
   - the Secret Key goes in when typed on a new device (M1);
   - the recovery code goes in for recovery ([CRYPTO.md §11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit), M1), and when the user keeps the current code during a rotation ([§11.6](../CRYPTO.md#116-key-rotation));
   - the export password goes in, for encrypted export and its import ([§11.14](../CRYPTO.md#1114-encrypted-export-m1), M1);
   - the device state record goes out as opaque bytes for the host to persist. It holds the Secret Key unwrapped until an OS keychain is used ([CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory)). The web vault has no device state record;
   - a per-device *local unlock secret* goes out to the platform keystore for biometric unlock (M3, M7). It opens only `E_ks`, the keystore wrap of the account key on that one device ([CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory)), and it is not the account key;
   - the pairing QR payload, which carries `pairing_secret`, goes out on the existing device to render the QR, and goes in on the new device from the camera ([§11.7](../CRYPTO.md#117-new-device-in-on-device-mode), M4);
   - share secrets go out as part of the share URL, and come in from the URL fragment when a share is opened; the share passphrase goes in when a share is created or opened ([§11.10–§11.11](../CRYPTO.md#1110-public-share-link-creation-m5), M5);
   - **extension only (M2):** the unlocked key state goes out as opaque bytes into `storage.session`, and comes back in when the extension's long-lived context restarts (§4). INV-63 allows this. What protects it: the browser keeps `storage.session` in memory and clears it when the browser closes, and at its default access level only trusted extension contexts can read it (Chromium; Firefox to confirm in M2; general knowledge, U). The extension also clears it on lock. Any code running in those contexts can read it, just as it can read the wasm heap. It is used only if M2 shows the long-lived context cannot be kept alive;
   - an explicit plaintext export, after re-authentication.

   Adding an exception changes this ADR.
3. **Plaintext crosses at the smallest useful size.**
   - List views get summaries: title, username, icon reference, flags.
   - A secret field value crosses only when the user reveals it.
   - Copy to clipboard is a core call. Where the host allows it (desktop, mobile), the core writes the clipboard through the host and does not return the value. In the browser the value has to cross.
4. **Errors are typed and carry no secrets.** They cross as enums with stable codes, never with key bytes, plaintext or passwords ([INV-21](../THREAT_MODEL.md#8-security-invariants)).
5. **Ciphertext crosses as bytes.** Hosts store and transmit envelopes as opaque bytes and never parse them.
6. **The API is coarse.** There is one call per user-level action ("unlock", "save item", "sync now"), not one per primitive. `rizzy-core`'s primitive API is not exported through any binding.
7. **Bindings are generated.** wasm-bindgen and UniFFI generate the glue. There is no hand-written C ABI and no hand-written `unsafe`.
8. **Host input is untrusted.** The core validates every value that crosses the boundary as if it came from the network.

### 4. Web and extension

- **Build.** `rizzy-wasm` is built with `wasm-bindgen-cli` pinned to exactly the `wasm-bindgen` crate version in `Cargo.lock`; the two must match. There is no wasm-pack dependency. The output goes to `packages/core` ([ADR 0014](0014-ui-stack.md)) as a generated artifact, and it is not committed.
- **One entry point for UI code.** UI code imports only `packages/core`, a typed TypeScript wrapper. No component calls wasm exports directly. That wrapper is the file set to review when the boundary changes.
- **Where the core lives.** Rule 1 holds only if every handle and the KDF output stay in one wasm instance. A Web Worker is a separate wasm instance, and anything passed between instances crosses JavaScript `postMessage` as plain bytes. So the core is never split across contexts:
  - **Web vault:** one dedicated Worker holds the whole `rizzy-client` instance and every handle, and runs the KDF. Long calls stay off the UI thread that way. The UI thread holds no wasm instance with keys. It exchanges only summaries and revealed values (rule 3) with the Worker, by message.
  - **Extension (M2):** one long-lived context holds the instance: an offscreen document on Chromium, the background page on Firefox. The popup, the options page, the inline menu and the fill path reach it through extension messaging.
  - **Not the MV3 service worker.** Chromium terminates an idle service worker after about 30 s (general knowledge, U), which would destroy the instance and every `UnlockedVault` handle. The service worker only routes messages.
  - **Lifetimes are confirmed in M2 (U):** how long the offscreen document and the Firefox background page live. If either can be torn down while the user expects to stay unlocked, the extension restores the unlocked state from `storage.session` (rule 2), never from `storage.local` or IndexedDB ([INV-63](../THREAT_MODEL.md#8-security-invariants)).
- **Honest limit.** JavaScript strings, and anything rendered into the DOM, cannot be wiped ([CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene)). Rule 1 buys less in the web vault than in native clients: an XSS can call the same core API the UI calls.
- **Size budget.** A wasm size budget is set in M1, after the first measurement. CI reports the size of every build and fails when it exceeds the budget.

### 5. Mobile (M7)

- UniFFI is pinned to an exact version. Upgrades are deliberate PRs, handled like crypto crates.
- CI generates the Kotlin and Swift packages from `rizzy-ffi`.
- The iOS AutoFill extension uses the keychain-cached local unlock secret instead of running Argon2id ([THREAT_MODEL Q-13, AR-17](../THREAT_MODEL.md#10-open-questions-for-the-owner)). The memory footprint of `rizzy-ffi` inside the extension is measured in M7.

### 6. Tests

- The vector files from [CRYPTO.md §15](../CRYPTO.md#15-testing) run:
  - natively;
  - under wasm, with `wasm-bindgen-test` in Node;
  - from M7, through Kotlin and Swift.

  The outputs must be byte-for-byte equal. A difference is a release blocker.
- The `rizzy-client` flows run against a simulated server in plain Rust tests, so every platform shares the same flow tests.

### Owner decisions (2026-09-25)

The owner answered the open questions on 2026-09-25:

1. **No `unsafe` exception for the binding crates** → Confirmed. `forbid` stays in every crate, `rizzy-wasm` and `rizzy-ffi` included, and is re-checked on every binding-generator upgrade through the CI builds. If a future generator ever needs `unsafe`, that is a new ADR, and the mechanism is the one recommended: the crate drops `lints.workspace = true` and copies the whole workspace lint table with only `unsafe_code` changed, and `xtask`'s R7 check compares that copy with the workspace table ([ADR 0016](0016-workspace-layout.md)). Cargo rejects a local `[lints.rust]` override next to `workspace = true`, and an in-source attribute cannot lower the command-line `forbid` (both checked on 1.94.1, V).
2. **`rizzy-client` as its own crate** → Yes, its own crate, not a module of `rizzy-core`.
3. **The rule "copy never returns the value" on desktop and mobile** → Keep the rule. The UI shows "Copied", never the value.

## Consequences

### Positive

- The M8 audit covers one crypto implementation and one sync implementation.
- A fix reaches every platform at once.
- Platform code is thin and mostly UI.
- Because the client is sans-I/O, every flow runs in deterministic tests without a network.

### Negative

- Every client build needs Rust, plus wasm or UniFFI tooling in CI.
- For Argon2id, wasm is about 1.3 times slower than single-threaded native, and it gets no parallelism (fact sheet, V).
- Two binding generators, both pre-1.0 (wasm-bindgen 0.2.x, UniFFI 0.32). Either can break on upgrade.
- Debugging across a language boundary (JS ↔ wasm, Swift ↔ Rust) is harder than debugging one language.
- A bug in the core is a bug on every platform at the same time.

### Risks

- **Generated code and the unsafe ban.** Checked on the pinned 1.94.1 toolchain in M0 (V):
  - A crate with `unsafe_code = "forbid"` that uses wasm-bindgen 0.2.129 compiles for wasm32 and for the host. The shapes tested were `#[wasm_bindgen]` functions, a struct with an impl and a constructor, `Result<Vec<u8>, JsError>`, an enum, and an `extern "C"` import.
  - A `forbid` crate using UniFFI 0.32.2 compiles for the host, with `setup_scaffolding!`, an exported function and an exported Object impl. Android and iOS targets were not built (U; check in M7).

  A generator upgrade could change this. `rizzy-wasm` is checked for wasm32 and `rizzy-ffi` for the host in CI ([ADR 0016](0016-workspace-layout.md) §5), so an upgrade that brings in `unsafe` fails in its own PR. See open question 1.
- **Bundle size.** The wasm bundle may grow large enough to slow extension start-up. The budget in §4 catches it.
- **Extension context lifetimes.** If neither the offscreen document nor the Firefox background page stays alive, the extension depends on the `storage.session` exception (rule 2). That keeps unlocked key state outside Rust memory, readable by any code in the extension's trusted contexts.
- **UniFFI could stall before 1.0.** The fallback is a thin C ABI over `rizzy-client` from a different generator. That may need `unsafe`, which the current rules do not allow (open question 1).

## Alternatives considered

- **Crypto implemented per platform** (WebCrypto plus JS libraries, Kotlin, Swift). Three or four implementations to audit and keep identical. WebCrypto has no Argon2id, no XChaCha20-Poly1305 and no OPAQUE, so the web client would need JS crypto libraries anyway.
- **A Kotlin Multiplatform core.** It covers Android, iOS and part of the web. But the server is Rust, so the wire types and formats would exist twice. We would also need a second audited crypto stack on the Kotlin side.
- **A C or C++ core built on libsodium.** Gives up memory safety, and contradicts the workspace's `unsafe` ban and [ADR 0009](0009-crypto-dependency-policy.md).
- **A Rust core that does its own HTTP on every platform** (for example, an HTTP client with a wasm backend). Less host code, but it brings I/O into the shared core. It bypasses platform networking (proxies, certificate settings, iOS background transfers) and makes flows harder to test deterministically.
- **A full Rust UI** (Leptos, Dioxus), which would remove the UI boundary. See [ADR 0014](0014-ui-stack.md).

## Open questions for the owner

None. All were answered by the owner on 2026-09-25; see [Owner decisions (2026-09-25)](#owner-decisions-2026-09-25) in the Decision section. The answers keep the original question numbers, so a reference to "open question N" means owner decision N.

## References

- [ROADMAP](../ROADMAP.md) §4.10, §5 (row "Client core"), §6.2
- [THREAT_MODEL](../THREAT_MODEL.md) §3.3 (TB-10), §7.1, §7.2, §7.3, §7.4, INV-12, INV-21, INV-58, INV-62, INV-63, Q-13, AR-17
- [CRYPTO.md](../CRYPTO.md) §1 (goal 6), §4.2, §11.4, §11.6, §11.7, §11.9–§11.11, §11.14, §12.1, §12.2, §15
- [ADR 0002](0002-own-protocol.md), [ADR 0009](0009-crypto-dependency-policy.md), [ADR 0011](0011-storage.md), [ADR 0012](0012-sync-engine.md), [ADR 0014](0014-ui-stack.md), [ADR 0015](0015-desktop-tauri.md), [ADR 0016](0016-workspace-layout.md)
- Fact sheet 2026-09-25: wasm-bindgen 0.2.129, UniFFI 0.32.2 (MPL-2.0), getrandom 0.4 `wasm_js` rules, Argon2id timings native vs wasm (V); iOS AutoFill memory cap (L)
- M0 scratch builds on 1.94.1: `forbid(unsafe_code)` with wasm-bindgen 0.2.129 (wasm32 and host) and UniFFI 0.32.2 (host); Cargo's rejection of local lint overrides next to `lints.workspace = true`; E0453 for `allow`/`expect` under `forbid` (V)
- MV3 service-worker idle termination and `storage.session` behaviour: general knowledge, not re-verified (U)
