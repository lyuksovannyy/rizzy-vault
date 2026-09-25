# ADR 0015: Desktop shell: Tauri

- Status: Accepted
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M3

## Context

The relevant ROADMAP rows:
- [ROADMAP §4.5](../ROADMAP.md#45-design-ui--ux--1password-feel-m3), Must, M3: "Desktop app (recommendation: **Tauri** — Rust backend reuses `core`, web UI reuses design system)". Also, Must, M3: a quick-access command palette on a global hotkey.
- [ROADMAP §4.3](../ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8), Should, M3: unlock with biometrics or the OS keychain.

The threats ([THREAT_MODEL §7.3](../THREAT_MODEL.md#73-desktop-app-tauri-m3)):
- XSS in the webview calls IPC to pull every item.
- A compromised webview escalates through IPC, custom URI schemes or deep links.
- A fake update feed ([INV-55](../THREAT_MODEL.md#8-security-invariants)).
- Keys end up in swap ([AR-10](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)).

The desktop app is one of the clients the threat model recommends to anyone who does not trust their server, because it does not load code from the server ([THREAT_MODEL §4.2.1](../THREAT_MODEL.md#421-the-web-vault-delivery-problem)).

Facts (fact sheet):
- tauri 2.11.6 is the latest stable (2026-09-19). 3.0.0-alpha.2 was published on 2026-09-21 (V).
- Radically Open Security audited v1 (retest February 2022) and v2 (2024-08-07, funded by NLnet/NGI). Both reports are in the repository's `audits/` directory (V). All v2 findings were reported resolved in the v2 release candidate (L).
- Two historical RustSec advisories concern Tauri 1.x's filesystem scope (V).
- Licence: Apache-2.0 OR MIT (V).

Tauri renders with the operating system's webview: WebView2 (Chromium-based) on Windows, WKWebView on macOS, WebKitGTK on Linux (U; general knowledge, to confirm in the M3 docs).

## Decision

1. **Tauri 2,** the latest 2.x stable at the start of M3. No alpha or pre-release; Tauri 3 is alpha today. Upgrades are reviewed like any dependency with a security surface.
2. **Architecture.**
   - The Rust side (`rizzy-desktop`, in `apps/desktop/src-tauri`) links `rizzy-client` directly ([ADR 0013](0013-shared-client-core.md)).
   - All keys, cryptography, network access and disk access live in the Rust process.
   - The webview renders the shared UI ([ADR 0014](0014-ui-stack.md)) and talks only to Rust, through IPC.
   - The webview never loads `rizzy-wasm` and never touches the network.
3. **What the webview may load.**
   - Only assets bundled into the app. No window ever loads a remote URL.
   - Navigation away from the bundled origin is blocked, and new-window requests are denied.
   - External links, such as item URLs, open in the system browser through one Rust command that accepts only `http` and `https` ([INV-42](../THREAT_MODEL.md#8-security-invariants)).
4. **CSP**, set in the Tauri configuration and checked by a test:

   ```
   default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
   connect-src <Tauri IPC origin only>; object-src 'none'; base-uri 'none';
   form-action 'none'; frame-ancestors 'none'
   ```

   - There is no `unsafe-inline`, no `unsafe-eval` and no `wasm-unsafe-eval`; the webview runs no wasm.
   - The exact IPC origin per platform follows Tauri's documentation.
   - Frames are used only for sandboxed untrusted content (INV-35).
5. **Capabilities.** Tauri 2 capabilities gate only the IPC calls that the webview initiates. Rust uses plugins directly and needs no capability for that. So everything the webview does not strictly need stays on the Rust side:
   - **Granted to the main window:** our own commands (point 6); the window-state plugin's permissions only if its JavaScript API is actually used; and the minimal `core:` permissions the frontend is shown to need (the exact set is confirmed in M3, U).
   - **Done in Rust, with no webview permission:**
     - registering the quick-access global shortcut;
     - writing and clearing the clipboard;
     - checking for, downloading and installing updates;
     - opening file dialogs for import and export. The webview never supplies a path.
   - **Why:** the main desktop threat is XSS in the webview ([THREAT_MODEL §7.3](../THREAT_MODEL.md#73-desktop-app-tauri-m3)). With a clipboard-write permission, injected script could replace a value the user just copied. With a global-shortcut permission, it could register system-wide hotkeys and capture those key combinations from every other app.
   - The webview gets nothing for `fs`, `shell`, `http`, `process`, `opener`, `clipboard-manager`, `global-shortcut` or `updater`. No capability applies to a remote origin.
   - CI compares the capability files with a committed allow-list and rejects any clipboard-manager, global-shortcut, updater, fs, shell, http, process or opener permission. Any change to the allow-list needs review.
6. **IPC surface.** Commands are coarse and typed, and the Rust side validates every input as untrusted ([THREAT_MODEL §7.3](../THREAT_MODEL.md#73-desktop-app-tauri-m3), row E).

   | Command | Returns |
   |---|---|
   | `unlock`, `lock`, `status` | lock state |
   | `list_items(filter)` | summaries only, never secret fields |
   | `get_item(id)` | the item with secret fields marked hidden |
   | `reveal_field(item_id, field_id)` | one value, after the user clicks reveal |
   | `copy_field(item_id, field_id)` | nothing. Rust writes the clipboard, sets the platform's "concealed/sensitive" hints where they exist (AR-16), and clears it after 30 s by default |
   | `save_item(draft)`, `trash_item`, `restore_item`, `generate_password(opts)`, `sync_now` | status |
   | `export(format)` | nothing. Rust asks for the master password again, then writes the file |
   | `update_status` | whether a verified update is ready |
   | `install_update` | status. Rust downloads, verifies and installs the update (point 8). The webview only shows the state and asks for the restart |

   - No command returns a key, the Secret Key, the recovery code (except once, when the Emergency Kit is shown) or the whole vault.
   - There is no generic "call a core function" command.
   - Tauri's isolation pattern (a sandboxed iframe that inspects IPC messages) is evaluated in M3. It adds a defence against a compromised frontend dependency. It does not replace validation on the Rust side.
7. **Release hardening.**
   - Devtools are off in release builds.
   - M3 ships no custom URI scheme and no deep link. Adding one amends this ADR, and its input is untrusted.
8. **Updates** ([INV-55](../THREAT_MODEL.md#8-security-invariants)).
   - **Mechanism.** Tauri's updater plugin, driven from Rust only (point 5), with signature verification. The update public key is compiled into the app.
   - **Refusals.** An update without a valid signature is refused, and the updater never installs a version lower than the current one.
   - **Hosting.** The update manifest and artifacts are served from GitHub Releases over HTTPS.
   - **The private key** stays offline (a hardware token or an offline machine), or in a protected CI environment that only release tags can use ([THREAT_MODEL AR-12](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)).
   - **Key rotation:** a new key ships inside an update signed by the old key.
   - **Key loss:** if the key is lost, users must reinstall manually, and the docs say so.
   - **OS code signing is separate from the updater:** macOS Developer ID with notarization, Windows Authenticode, and Linux packages signed per format. The cost is open question 1.
9. **Local data.**
   - The encrypted cache lives in the app data directory and holds ciphertext only ([ADR 0011](0011-storage.md)).
   - Device keys are wrapped under the account key.
   - Biometric unlock (M3, Should) stores the local unlock secret in the OS keystore under [INV-62](../THREAT_MODEL.md#8-security-invariants): released only after an OS-enforced user-presence check, bound to hardware where available. That means a Windows Hello key-credential operation (not plain DPAPI), or the macOS Keychain with a Touch ID access-control flag. The exact APIs are confirmed in M3 (U). On Linux, Secret Service cannot enforce presence, so unlock falls back to the master password.
   - Keys are zeroized on lock. There is no `mlock` (AR-10).
10. **Integration with the browser extension**, such as the desktop app unlocking the extension through native messaging, is out of scope for M3. It is a new IPC surface and needs its own ADR.

### Owner decisions (2026-09-25)

The owner answered the open questions on 2026-09-25:

1. **Code-signing budget** → macOS notarization (Apple Developer Program) from the first M3 release. Windows code signing before M8; unsigned Windows builds in between trigger a SmartScreen warning.
2. **Linux package formats** → AppImage and `.deb` at M3. Flatpak later, if users ask.
3. **Keep the Tauri crate in the main Cargo workspace** → Yes, the same workspace. The WebKitGTK development packages are added to CI in M3.
4. **Default clipboard clear time** → 30 s, configurable.

## Consequences

### Positive

- The Rust side reuses `rizzy-client` with no FFI, and keys never enter the webview.
- A secret reaches the webview only when the user reveals it. Copy goes straight from Rust to the clipboard.
- The capability model lets the webview run with almost no permissions, and CI checks it.
- The install ships no browser engine, so it stays smaller than an Electron build (U; measure at M3).
- The framework has a recent public audit (v2, 2024; V).

### Negative

- Three rendering engines to test. WebKitGTK on Linux lags in features and performance (U), and its security updates come from the Linux distribution, not from us.
- Tauri's ecosystem is smaller than Electron's.
- Code signing costs money and administration on two platforms.
- The workspace gains GUI system dependencies, such as the WebKitGTK development packages on Linux CI (open question 3).

### Risks

- A Tauri bug in IPC or in the webview bridge hits us directly. We track Tauri's advisories and keep upgrades current.
- Tauri 3 may bring breaking changes. Staying on 2.x after its support ends would itself become a risk.
- If WebKitGTK problems block Linux users, the fallback is the CLI or the web vault on Linux, not Electron.

## Alternatives considered

- **Electron.** It bundles Chromium and Node.js, so rendering is the same on every OS and the ecosystem is the largest. Bitwarden's desktop app and, reportedly, 1Password's use it (U). Against it:
  - a larger download and more memory, because it ships a browser engine;
  - we become responsible for patching that browser engine;
  - the Rust core would have to run as a native Node addon (C ABI, `unsafe`) or as wasm, which loses the direct reuse;
  - security depends on settings (context isolation, sandbox, no Node in renderers). Current versions default to the safe values (U), but misconfiguration is common.
- **Native UI per OS** (SwiftUI, WinUI, GTK). The best platform integration. But it means three UIs to build and keep accessible, which is impossible at our size ([ROADMAP §6.2](../ROADMAP.md#6-risks--hard-truths)), and none of them reuses the design system.
- **A Rust-native GUI** (egui, iced, Slint, Dioxus desktop). One language and no webview. But it cannot reuse the web design system, and the web vault has to be web anyway, so we would build two UIs. Accessibility support is uneven (U).
- **Web vault only, or a PWA.** No global hotkey, no OS keychain, and the code comes from the server ([THREAT_MODEL §4.2.1](../THREAT_MODEL.md#421-the-web-vault-delivery-problem)). The desktop app exists precisely to be a client that does not trust the server.

## Open questions for the owner

None. All were answered by the owner on 2026-09-25; see [Owner decisions (2026-09-25)](#owner-decisions-2026-09-25) in the Decision section. The answers keep the original question numbers, so a reference to "open question N" means owner decision N.

## References

- [ROADMAP](../ROADMAP.md) §4.3, §4.5, §5 (row "Desktop"), §6.2
- [THREAT_MODEL](../THREAT_MODEL.md) §4.2.1, §7.3, INV-35, INV-42, INV-55, INV-62, AR-10, AR-12, AR-16
- Tauri 2 capability model (capabilities gate webview-initiated IPC only; Rust calls plugins directly): general knowledge of the Tauri 2 documentation, not re-verified for this ADR; confirm in M3
- [CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene)
- [ADR 0011](0011-storage.md), [ADR 0013](0013-shared-client-core.md), [ADR 0014](0014-ui-stack.md), [ADR 0016](0016-workspace-layout.md)
- Fact sheet 2026-09-25: tauri 2.11.6 and 3.0.0-alpha.2; Radically Open Security audits of v1 and v2 in `tauri/audits/` (V); findings resolved (L); RustSec history for 1.x (V)
