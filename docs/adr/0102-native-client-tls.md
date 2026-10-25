# ADR 0102: Client TLS on the native clients: who terminates TLS per platform, the TLS 1.3 floor, trust anchors, a private CA through the core, and what the core checks regardless of TLS

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3 (macOS, Windows) / M7 (iOS, Android) / the Linux client's milestone (`rizzy-ffi-cpp`, [ADR 0019](0019-native-clients.md) owner decision 12)
- Partially supersedes, under [ADR 0020](0020-partial-supersession.md) point 9 (see "What this ADR supersedes"): [ADR 0030](0030-client-tls-rv.md) Decision 1, the opening parenthetical (in the text [ADR 0052](0052-icon-proxy-role.md) gave it), in part; [ADR 0009](0009-crypto-dependency-policy.md#amendments) Amendments, "2026-10-05: client TLS for `rv`" entry, "Where it is applied" paragraph, first sentence (in the text ADR 0052 gave it), in part; [ADR 0019](0019-native-clients.md) §2 platform table, row "Android", column "Minimum OS", first sentence, in part.

## Context

**Trigger.** The 2026-10-25 ADR gap review ([summary](../reviews/2026-10-25-adr-gap-review.md), major finding M4; raw finding G03-2 in [G03.md](../reviews/2026-10-25-raw/G03.md)). The owner said "start" on 2026-10-25, after the review.

**The gap (G03-2, quoted).** ADR 0019 §5 row "HTTP and TLS": "The same Rust HTTP client as `rv` (chosen in M1, rustls only …)", and line 427: "Self-hosted servers with private CAs must still be reachable." But ADR 0030's title is "Client-side TLS for `rv`", and its platform-verifier alternative is "Better suited to the M3 desktop bindings." The reviewer: "For `rizzy-ffi`/`rizzy-ffi-cpp` (Windows, Linux) and for the URLSession/OkHttp hosts on macOS (M3), iOS and Android, nothing fixes the minimum TLS version, the root store (webpki-roots vs OS store vs platform verifier), how a private CA is configured, or whether the host may relax verification. ADR 0030 itself says TLS is 'the only server authentication on the everyday path', so two implementers would build materially different trust boundaries." Suggested resolution: "TLS 1.3 floor, which root store per platform, private-CA configuration through the core (never a host toggle), and a CI check that host code never installs a custom trust-all delegate."

**What is already decided (Accepted).**
- ADR 0019 §5, owner decision 11: HTTP and TLS are **A (in the Rust binding leaf) on Windows and Linux** and **B (in the host) on Apple and Android**, "as ADR 0013 §2 already says for mobile; macOS shares its Swift code and XCFramework with iOS". [ADR 0013](0013-shared-client-core.md) §2: the sans-I/O state machine "returns effects: HTTP requests to send"; hosts "never parse" what they carry (§3 rule 5, as quoted in `crates/rizzy-wasm/src/http.rs`, V). ADR 0019 §5: "All network traffic goes through the one HTTP path of §5." Spike S4 (not run, ADR 0019 point 16) must show that route A "trusts the platform store or a user-added CA".
- ADR 0030 with [ADR 0035](0035-ca-file-ca-certificates-only.md), for `rv`: `tokio-rustls`/`rustls` on the explicit `ring` provider, TLS 1.3 only, ALPN `http/1.1`, no early data, no client certificates, no key log; `webpki-roots`; `WebPkiServerVerifier`; no revocation checking; no `dangerous()` API in first-party code (scanned by `cargo xtask check-deps`, `DANGER_WORDS` in `crates/xtask/src/rules.rs`, V); a private CA file of at most 64 KiB and 16 `CERTIFICATE` blocks, each `cA=true` (ADR 0035), that **replaces** the public roots; no pinning, no self-signed server certificate; `https://` anywhere, `http://` only to `localhost` or a loopback address; no redirects, no proxy; one fixed `CliError::Tls` kind (`TlsFailure`: `UnknownIssuer`, `Expired`, `NotValidYet`, `WrongName`, `BadCertificate`, `Incompatible`, `Handshake`, `Configuration`; `crates/rizzy-cli/src/error.rs`, V). Pins today: `tokio-rustls =0.26.6`, `rustls =0.23.46`, `webpki-roots =1.0.10` (`Cargo.toml`; ADR 0009 amendment of 2026-10-21; V).
- [ADR 0028](0028-api-v1-http-conventions.md) item 10: the public origin must be HTTPS; CRYPTO.md §2's parser also admits `http`, and the server refuses an `http` origin unless the host is `localhost` or a loopback address, "for local testing only". ADR 0028 item 5 fixes the signed request bytes (the method and the raw request-target).
- [CRYPTO.md](../CRYPTO.md) §5.3 binds `server_origin` into the OPAQUE context; §5.10 binds it into the device-auth and request signatures; §10.2, §10.3 and §11.3 make the client verify the signed `account-state`, its own identity keys and its device certificates.
- [THREAT_MODEL](../THREAT_MODEL.md) A4: with broken TLS a native-client MITM obtains "session tokens and ciphertext", limited by request signing (Q-7). ADR 0030 Context: "For `rv`, TLS is the only server authentication on the everyday path, so the trust store is a security boundary."
- [ADR 0096](0096-binding-secrets-and-kdbx-worker.md) (Proposed, wave 1) lists the transport credentials that cross the binding to a route-B host (the bearer token, its item 17). This ADR does not change that list.

**Forces.** Route B puts the TLS stack, its trust store and its knobs (ATS, Network Security Config, URLSession delegates, OkHttp trust managers) in code this repository does not compile. Each host has a one-line way to disable validation. ADR 0019's private-CA requirement needs a mechanism on every platform, and the only one analysed so far (a CA file that replaces the public roots) exists only in `rv`.

**Facts** (V = primary source read in this repository or its lockfile for this ADR; L = general platform knowledge or a secondary source, not re-read for this ADR; U = unverified):
- Android has platform TLS 1.3 from Android 10, API 29 (L). ADR 0019's Android minimum is API 26 (V, §2 table). Apps targeting API 24 or later do not trust user-installed CAs unless their Network Security Config opts in with `<certificates src="user"/>` (L). Network Security Config can forbid cleartext app-wide and permit it per domain (L); whether a `<domain>` element accepts an IP literal such as `127.0.0.1` is U.
- OkHttp restricts TLS versions through `ConnectionSpec`, has `followRedirects(false)` and `followSslRedirects(false)`, keeps no HTTP cache and no cookies unless configured, and ships `MockWebServer` for tests (L).
- Apple: `URLSessionConfiguration.tlsMinimumSupportedProtocolVersion` exists from iOS 13 and macOS 10.15 (L); the `.ephemeral` configuration keeps no persistent cache, cookies or credentials (L); App Transport Security refuses `http` by default, and `NSAllowsLocalNetworking` admits loopback and local names (L); `SecTrustSetAnchorCertificates` with `SecTrustSetAnchorCertificatesOnly(true)` restricts evaluation to the given anchors (L). A user can add a root CA through a configuration profile and enable full trust for it, after which the default evaluation trusts it (L). Whether Certificate Transparency enforcement applies to custom anchors: U (believed not to, L).
- Qt Network's TLS backend on Linux is the system OpenSSL, loaded at run time (ADR 0019 §5, V there).
- `rustls-webpki` refuses a `cA=true` certificate as the end entity (`CaUsedAsEndEntity`, ADR 0030 Decision 5, V there). Whether Apple's `SecTrust` and Android's `TrustManagerFactory` accept a self-signed `cA=true` server certificate that is also the only anchor: U.

## Decision

### 1. Scope and who terminates TLS

| Client | Who does HTTP and TLS | TLS stack | Public roots | Private CA |
|---|---|---|---|---|
| `rv` (`rizzy-cli`) | Rust | rustls, as ADR 0030 and ADR 0035, **unchanged** | `webpki-roots` | `--ca-file` / `RIZZY_CLI_CA_FILE` |
| Windows (`rizzy-ffi`, route A) | Rust, in the binding leaf | rustls, configured exactly as `rv` (point 2) | `webpki-roots` | Through the core (point 4) |
| Linux (`rizzy-ffi-cpp`, route A) | Rust, in the binding leaf | rustls, configured exactly as `rv` | `webpki-roots` | Through the core |
| macOS, iOS (`rizzy-ffi`, route B) | The Swift host | URLSession (Apple's TLS) | The OS trust store | Through the core; the host applies the anchors (point 5) |
| Android (`rizzy-ffi`, route B) | The Kotlin host | OkHttp over the platform TLS provider | The OS **system** store only | Through the core; the host applies the anchors (point 5) |

The web vault and the extension use the browser's `fetch` and TLS; they are out of scope.

On Apple and Android targets `rizzy-ffi` contains **no** TLS crate: `rustls`, `tokio-rustls`, `webpki-roots` and `ring` are target-specific dependencies of the binding leaves (`[target.'cfg(any(windows, target_os = "linux"))'.dependencies]`). `cargo xtask check-deps` checks this with `cargo tree -p rizzy-ffi --target <t>` for `aarch64-apple-ios`, `aarch64-apple-darwin` and `aarch64-linux-android`.

### 2. Protocol (every native client)

- **TLS 1.3 only.** No TLS 1.2 fallback on any platform.
  - Route A: exactly ADR 0030 Decision 2 (explicit `ring` provider, `TLS13` only, its three suites and three groups in the provider's order, ALPN `http/1.1`, SNI, no early data, no client certificate, in-memory session cache only, `NoKeyLog`).
  - Apple: `tlsMinimumSupportedProtocolVersion = .TLSv13` on the one session configuration of point 5. No ATS key that lowers the floor (point 8).
  - Android: one `ConnectionSpec` built from `ConnectionSpec.RESTRICTED_TLS` with `tlsVersions(TlsVersion.TLS_1_3)`, the only spec for `https`. Android's floor is therefore API 29 (point 9).
- **Suites and groups** on route B are the OS defaults for TLS 1.3 (every TLS 1.3 suite is an AEAD suite, L). HTTP/2, and HTTP/3 where the OS uses it, is allowed on route B: ADR 0028 item 5 signs the method and the request-target, which HTTP/2 carries unchanged in `:method` and `:path` (L).
- **No client certificates, no early data, no key log** on any platform. Route B hosts set nothing that enables them.
- **Nothing TLS-related is written to disk** by our code: no session-ticket store, no certificate cache, no key log.

### 3. Validation rules (every native client)

A connection is accepted only if all of the following hold. No host weakens any of them, and no UI offers to continue past a failure.

1. The chain leads to an anchor of the **effective trust set**: the public roots of point 1, or, when a private CA is set for the origin, **only** that set (it replaces the public roots, as ADR 0030 Decision 4 and its answered open question 2 do for `rv`).
2. The leaf names the origin's host: a `dNSName` SAN for a host name, an `iPAddress` SAN for an IP literal. The Common Name is not used (rustls ignores it; L for Apple and Android).
3. Every certificate in the chain is inside its validity period by the device clock.
4. The leaf is not a CA certificate and is not self-signed. There is no trust-on-first-use, no "accept this certificate" prompt, no certificate or public-key pin and no exception list, on any platform.
5. Revocation: route A checks none (ADR 0030 Decision 3). Route B does what the OS does by default and adds nothing.
6. Host name verification, trust policy and signature-algorithm rules are the stack's own: rustls' `WebPkiServerVerifier`; Apple's default SSL policy for the challenge's host; OkHttp's default `HostnameVerifier` and the platform `X509TrustManager`. First-party code never implements a verifier, a trust manager or a host name check.

### 4. Private CA, configured through the core

- **Input.** The user picks a file in the app's server settings, or in the "add server" step before signup or login. The host reads the bytes and passes them **unparsed** to the binding (`set_private_ca(origin, pem)`); host code never parses PEM or DER.
- **Checks, in Rust, before anything is stored.** The origin must pass point 7. The bytes follow ADR 0030 Decision 4's limits and ADR 0035 point 1 exactly: read whole, at most 65 536 bytes; at most 16 `CERTIFICATE` blocks, at least one; other PEM sections ignored; every block `cA=true`. On route A every block must also become a trust anchor through `RootCertStore::add`. On route B the host then creates each certificate with the OS API (`SecCertificateCreateWithData`, `CertificateFactory.generateCertificate`) and reports a failure back, which refuses the import. Any failure is `ClientError::BadInput` and nothing is stored.
- **Confirmation.** The binding returns, for each anchor, the SHA-256 of its DER (64 hex digits in pairs separated by `:`) and its subject as text; the UI shows them and the set is stored only after the user confirms. This is configuration the user brings out of band, not TOFU: nothing the server sends can create, change or remove a trust set.
- **Storage (versioned format).** One new table in the binding leaf's SQLite database (the [ADR 0026](0026-client-device-state-and-cache.md) cache; migration number: next free at implementation), keyed by origin rather than by account, because the set is needed before signup and login:
  - `server_trust(origin TEXT PRIMARY KEY, format INTEGER NOT NULL, pem BLOB NOT NULL, set_at_ms INTEGER NOT NULL)`, `origin` being the canonical `server_origin` (CRYPTO.md §2).
  - `format = 1`: `pem` is the exact accepted file bytes. On every load the bytes are re-checked by the same Rust code. An unknown `format` or a failed re-check fails closed with `TransportFailure::Tls { kind: Configuration }` for that origin. **It never falls back to the public roots.**
  - The set is not secret and is not covered by the signed `account-state` (it is device-local configuration). It has the cache's file protections (ADR 0026, INV-60). A local attacker who can write the cache can also replace the app; that is outside this ADR.
- **Removal or replacement** is an explicit user action in the same settings screen, with the same confirmation. Removing the set returns the origin to the public roots.
- **`rv` is unchanged**: it keeps `--ca-file` and `RIZZY_CLI_CA_FILE` and stores nothing.
- **Roots installed in the OS.** On Windows and Linux (route A) the OS store is not read: a corporate CA must be imported into the app (open question 3). On Android user-installed CAs are not trusted (`<certificates src="user"/>` is banned, point 8). On Apple, a root the user or an MDM profile installed with full trust is honoured by the OS default evaluation when no private CA is set; this ADR cannot remove that without forcing every user onto a private CA (Risks).

### 5. Route B: what the host does, exactly

The core emits one request record per exchange; the host performs it and returns a reply or a failure. The UniFFI shapes, generated by `rizzy-ffi` (names fixed here):

```
record HttpExchange { method: String, url: String, headers: sequence<Header>, body: bytes,
                      trust: TrustMode, max_response_len: u64, timeout_ms: u64 }
enum   TrustMode    { PublicRoots, PrivateCa { anchors_der: sequence<bytes> } }
record HttpReply    { status: u16, body: bytes }
enum   TransportFailure { InsecureOrigin, Tls { kind: TlsFailure }, Connect,
                          Timeout { delivery: Delivery }, ConnectionLost { delivery: Delivery },
                          ResponseTooLarge, Cancelled { delivery: Delivery } }
enum   TlsFailure   { UnknownIssuer, Expired, NotValidYet, WrongName, BadCertificate,
                      Incompatible, Handshake, Configuration }
enum   Delivery     { NotSent, Unknown }
```

`TlsFailure` has the variants and meanings of `rv`'s (`crates/rizzy-cli/src/error.rs`). Adding a variant to any of these enums is a binding API change under ADR 0019 §8.

- **URL and bytes.** `url` is the canonical origin followed by the core's origin-form request-target. The host builds its request from that string without re-encoding or normalising it (ADR 0028 item 5), sends exactly `method`, `headers` and `body`, and adds only what its stack adds itself (`Host`, `Content-Length`, `User-Agent`, `Accept-Encoding`), never a `Cookie` or an `Authorization` header.
- **No redirects.** Apple: `urlSession(_:task:willPerformHTTPRedirection:newRequest:completionHandler:)` calls the handler with `nil`. OkHttp: `followRedirects(false)` and `followSslRedirects(false)`. A 3xx reaches the core as an `HttpReply`, and the core refuses it as it does today.
- **No cache, no cookies, no stored credentials.** Apple: a `.ephemeral` configuration with `urlCache = nil`, `httpCookieStorage = nil`, `httpShouldSetCookies = false`, `urlCredentialStorage = nil`, `requestCachePolicy = .reloadIgnoringLocalCacheData`. OkHttp: no `Cache` and no `CookieJar` configured.
- **Trust.** For `TrustMode::PublicRoots` the host uses the OS default evaluation (Apple: `.performDefaultHandling` for every challenge). For `TrustMode::PrivateCa`, and only then, the host's one **trust module** (point 8) applies exactly these anchors:
  - Apple: on `NSURLAuthenticationMethodServerTrust`, `SecTrustSetAnchorCertificates(trust, anchors)`, `SecTrustSetAnchorCertificatesOnly(trust, true)`, then `SecTrustEvaluateWithError`; success → `.useCredential` with `URLCredential(trust:)`, anything else → `.cancelAuthenticationChallenge`. Never `SecTrustSetPolicies`, `SecTrustSetExceptions` or `SecTrustSetOptions`. Every other challenge type → `.performDefaultHandling`.
  - Android: a `KeyStore` holding only the anchors; `TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())` initialised with it; an `SSLContext` (`"TLS"`) from its trust managers; `OkHttpClient.Builder().sslSocketFactory(context.socketFactory, trustManager)`. The default `HostnameVerifier` is kept. No class implements `X509TrustManager`.
  - The host may keep one client per (origin, `TrustMode` value) and never shares a client across two of them.
- **Limits.** The host stops reading and returns `ResponseTooLarge` when `Content-Length` or the bytes received exceed `max_response_len`; the core checks again. `timeout_ms` is the whole exchange's deadline, computed by the core as `rv` computes it today (`120 000 + 1 000 × ⌊body_len / 65 536⌋` ms; `crates/rizzy-cli/src/http.rs`, V). The connect timeout is 30 s, as `rv`'s. Apple: `timeoutIntervalForResource = timeout_ms / 1000` and `timeoutIntervalForRequest = 30`; OkHttp: `connectTimeout(30 s)`, `readTimeout(30 s)`, `callTimeout(timeout_ms)`.
- **Proxies.** Route B may use the OS proxy settings (OkHttp's default `ProxySelector`, URLSession's system proxy): TLS stays end to end through `CONNECT`. Route A uses no proxy, as `rv` (Consequences).
- **Failure mapping.** The host maps its errors with the table below. Anything unlisted becomes `Tls { kind: Handshake }` if it arose during the handshake, otherwise `ConnectionLost { delivery: Unknown }`. The host passes no error text, certificate or response data to the core or to any log.

| Host error (L; every row is confirmed by a test of the implementation plan, steps 6–7) | `TransportFailure` |
|---|---|
| Apple `URLError.serverCertificateHasUnknownRoot`, `.serverCertificateUntrusted`; a failed `PrivateCa` evaluation; Android `SSLHandshakeException` caused by `CertPathValidatorException` | `Tls { UnknownIssuer }` |
| Apple `.serverCertificateHasBadDate`; Android cause `CertificateExpiredException` | `Tls { Expired }` (Apple does not separate the two dates; its UI text reads "expired or not yet valid") |
| Android cause `CertificateNotYetValidException` | `Tls { NotValidYet }` |
| Android `SSLPeerUnverifiedException` (host name) | `Tls { WrongName }` |
| Apple `.secureConnectionFailed`; Android `SSLHandshakeException` otherwise | `Tls { Handshake }` (neither reports a protocol-version mismatch separately, L) |
| Android `UnknownServiceException` (cleartext not permitted); Apple `.appTransportSecurityRequiresSecureConnection` | `InsecureOrigin` |
| DNS failure, connection refused, host unreachable | `Connect` |
| Deadline passed | `Timeout { NotSent }` before the request was written, else `Timeout { Unknown }` |

### 6. Route A: what the binding leaf does

- The binding leaf runs `rv`'s transport: the HTTP/1.1 client over `tokio-rustls` with the configuration of point 2, the limits and timeouts of `crates/rizzy-cli/src/http.rs`, no redirects, no proxy, and the private CA of point 4 (or the public roots) as its `RootCertStore`. Failures map to the same `TransportFailure` values as route B, with `rv`'s `failure_of` for the `TlsFailure` kind.
- **One policy, two code locations until open question 2 is answered.** `crates/rizzy-cli/src/tls.rs` is split, with no behaviour change, into `ca_pem.rs` (the PEM limits and ADR 0035's `is_ca_certificate`; `rustls-pki-types` only) and `tls_config.rs` (`public_roots`, `client_config`, `failure_of`; rustls). The binding leaves carry byte-identical copies of both files; `rizzy-ffi` compiles `ca_pem.rs` only on Apple and Android. `cargo xtask check-deps` fails when a copy's SHA-256 differs from `rizzy-cli`'s file.
- An `http` origin is dialled only when every address `localhost` resolves to is a loopback address; otherwise `InsecureOrigin` before any byte is sent.
- Host code (C#, C++, QML) holds no networking code at all (point 8).

### 7. Origin rules (every native client, enforced in the core)

- The origin the user enters is parsed by CRYPTO.md §2's parser into the canonical `server_origin`. The core then admits `https` with any host, and `http` only when the host is `localhost`, an IPv4 address in `127.0.0.0/8`, or `::1` (ADR 0028 item 10, ADR 0030 Decision 6). Anything else is `TransportFailure::InsecureOrigin`, raised by the core **before any request record exists**; a host is never asked to send to such an origin.
- The origin is fixed per account at signup or first login and is the origin bound into OPAQUE, device-auth and request signatures (CRYPTO.md §5.3, §5.10). No response, redirect, `GET /api/meta` answer or host can change it; moving to another server is a new enrolment.
- Host configuration matches: Android's Network Security Config sets `cleartextTrafficPermitted="false"` in `base-config` and permits cleartext only in one `domain-config` for `localhost` (plus `127.0.0.1` and `::1` if Network Security Config accepts IP literals, U). Apple's Info.plist has `NSAllowsLocalNetworking = true` and no other ATS key. The core's rule is the gate; the host configuration is defence in depth.

### 8. Host CI rules (each host repository, from its first networking change)

Each host repository's CI fails when hand-written code (outside the generated binding package, ADR 0019 §4) breaks a rule below. Each route-B host has exactly **one** reviewed trust module file (`TrustModule.swift`, `TrustModule.kt`); tokens marked "module only" may appear there and nowhere else. Test targets are exempt (they host the test servers of the implementation plan).

- **Apple.** Banned everywhere: `SecTrustSetExceptions`, `SecTrustSetPolicies`, `SecTrustSetOptions`, `URLSession.shared`, `NWConnection`, `NWProtocolTLS`, `sec_protocol_options`, `CFStream`; the Info.plist keys `NSAllowsArbitraryLoads`, `NSAllowsArbitraryLoadsForMedia`, `NSAllowsArbitraryLoadsInWebContent`, `NSExceptionDomains`, `NSExceptionAllowsInsecureHTTPLoads`, `NSExceptionMinimumTLSVersion`, `NSExceptionRequiresForwardSecrecy`. Module only: `SecTrustSetAnchorCertificates`, `SecTrustSetAnchorCertificatesOnly`, `SecTrustEvaluateWithError`, `URLCredential(trust:`, `.useCredential`, `NSURLAuthenticationMethodServerTrust`, `serverTrust`, `tlsMinimumSupportedProtocolVersion`, `URLSessionConfiguration`.
- **Android.** Banned everywhere: classes implementing `X509TrustManager` or `HostnameVerifier`, `hostnameVerifier(`, `CertificatePinner`, `HttpsURLConnection`, `HttpURLConnection`, `openConnection(`, `ConnectionSpec.MODERN_TLS`, `ConnectionSpec.COMPATIBLE_TLS`, `TlsVersion.TLS_1_2`, `TlsVersion.TLS_1_1`, `TlsVersion.TLS_1_0`; in the Network Security Config `<certificates src="user"/>`, `overridePins`, `<debug-overrides>`, `<pin-set>`, and `cleartextTrafficPermitted="true"` outside the loopback `domain-config`; `android:usesCleartextTraffic="true"` in the merged manifest. Module only: `TrustManagerFactory`, `SSLContext`, `KeyStore`, `sslSocketFactory(`, `ConnectionSpec`, `OkHttpClient.Builder`.
- **Windows.** Banned in hand-written C#, through ADR 0019 §4's banned-API analyzer: `System.Net.Http`, `HttpClient`, `HttpClientHandler`, `SocketsHttpHandler`, `WebRequest`, `ServicePointManager`, `SslStream`, `ServerCertificateCustomValidationCallback`, `RemoteCertificateValidationCallback`, `System.Net.Sockets`.
- **Linux.** No `Qt6::Network` or `Qt::Network` in any CMake target; banned in hand-written C++ and QML: `QNetworkAccessManager`, `QSslSocket`, `QSslConfiguration`, `QTcpSocket`, `XMLHttpRequest`.
- **This repository.** ADR 0030 Decision 3's `dangerous`/`danger` scan already covers `crates/*/src` and so both binding leaves. The copy check (point 6) and the target check (point 1) are added to `cargo xtask check-deps`.

A token rule is a tripwire, not a proof: the trust modules and these configuration files are also listed for review in every host release (ADR 0019 §9).

### 9. Android minimum API

The TLS 1.3 floor needs platform TLS 1.3, so the Android client's minimum is **API 29** (Android 10) instead of API 26 (open question 1; the replacement text is in "What this ADR supersedes").

### 10. Invariant INV-117 (provisional number): TLS is not the trust root of the core's checks

On every native client:
1. **The core verifies, whatever the transport did:** the OPAQUE context with the configured `server_origin` (CRYPTO.md §5.3); device-auth and request signatures over the same origin (§5.10); the signed `account-state` (its signature, a `state_seq` never below the device's high-water mark, `bundle_hash`, `device_set_hash` and `settings_hash`; §10.2, §11.3); its own identity keys against the decrypted `E_id`, and device certificates (§10.3); the KDF floor and the algorithm allow-list (§6.2, §9.5); every envelope's AEAD with its AAD (§8.4); response size and parse limits. A response that passed TLS but fails one of these is an integrity error, never a transport error, and is never retried over another trust set, origin or scheme.
2. **No host relaxes TLS because the core checks, and no host skips or replaces a core check because TLS succeeded.** The host passes bytes and the fixed `TransportFailure` values only (ADR 0013 §3 rule 5).
3. **Where TLS is the trust root, this ADR says so:** at signup (no prior state exists; A4: an attacker with an accepted certificate can register a user against itself), and for the confidentiality of the bearer token and of metadata on every request. Login on a new device is also protected by OPAQUE and the Secret Key; an enrolled device by the account-state chain and request signing.

### 11. Crash and retry

- A failure with `Delivery::NotSent` (and `InsecureOrigin`, every `Tls` kind and `Connect`, which are always not-sent) means the server received no byte of the request. The core may resend the same request.
- `Delivery::Unknown` failures and `ResponseTooLarge` follow the core's existing at-most-once rules (ADR 0028 item 5's `request_counter` window; [ADR 0012](0012-sync-engine.md)'s op ids). This ADR adds no retry rule.
- A TLS failure is never answered by a fallback: not to `http`, not between the public roots and a private CA, not to another origin. Background sync retries it on its ordinary backoff schedule; a foreground action shows the fixed text at once.
- The `server_trust` row is written, replaced and deleted in single SQLite transactions, so after a crash either the old or the new set is in force. A corrupt row fails closed (point 4).

### What this ADR supersedes

Under ADR 0020 point 9, by name and with full replacement text. Nothing else in ADR 0030, ADR 0009, ADR 0052 or ADR 0019 changes.

1. **[ADR 0030](0030-client-tls-rv.md) Decision 1, its opening parenthetical**, in the text [ADR 0052](0052-icon-proxy-role.md) gave it ("all in `[workspace.dependencies]`, used by `rizzy-cli` and, from this ADR, by `rizzy-icon-proxy` for its own, separately configured outbound TLS client (follows redirects, connects to a pinned `SocketAddr`, no shared state with `rv`'s client); `rizzy-cli` is a leaf and `rizzy-icon-proxy` is not, but [ADR 0016](0016-workspace-layout.md) R2(b) already lets a server-side library pull a third-party crate in directly, so ADR 0016 stays unchanged."), is replaced by:
   > all in `[workspace.dependencies]`, used by `rizzy-cli`; by `rizzy-icon-proxy` for its own, separately configured outbound TLS client (follows redirects, connects to a pinned `SocketAddr`, no shared state with `rv`'s client; [ADR 0052](0052-icon-proxy-role.md)); and, from [ADR 0102](0102-native-client-tls.md), by the binding leaves `rizzy-ffi` (Windows targets only) and `rizzy-ffi-cpp` (Linux), each with its own `ClientConfig` built by the same code as `rv`'s (ADR 0102 point 6). `rizzy-cli`, `rizzy-ffi` and `rizzy-ffi-cpp` are leaves and `rizzy-icon-proxy` is not, but [ADR 0016](0016-workspace-layout.md) R2(b) already lets a server-side library pull a third-party crate in directly, so ADR 0016 stays unchanged. On Apple and Android targets `rizzy-ffi` uses none of these crates; it uses only `rustls-pki-types`, declared in `[workspace.dependencies]` with an exact pin equal to its `Cargo.lock` version, for the CA-file parser (ADR 0102 points 1 and 6).

   Decision points 2–7 of ADR 0030 stay `rv`-specific as written; ADR 0102 points 2–7 apply them, or state their own rule, for the native clients.
2. **[ADR 0009](0009-crypto-dependency-policy.md#amendments) Amendments, "2026-10-05: client TLS for `rv`" entry, "Where it is applied" paragraph, first sentence**, in the text ADR 0052 gave it ("The three crates are declared in `[workspace.dependencies]` with the pins and feature sets above and used by `rizzy-cli` and, from this ADR, by `rizzy-icon-proxy`, each running its own `ClientConfig` with no shared state."), is replaced by:
   > The three crates are declared in `[workspace.dependencies]` with the pins and feature sets above and used by `rizzy-cli`, by `rizzy-icon-proxy` ([ADR 0052](0052-icon-proxy-role.md)), and by `rizzy-ffi` on Windows targets and `rizzy-ffi-cpp` ([ADR 0102](0102-native-client-tls.md)), each running its own `ClientConfig` with no shared state; on Apple and Android targets `rizzy-ffi` uses none of them and only `rustls-pki-types`, exact-pinned to its lockfile version.

   The rest of that paragraph stays as written.
3. **[ADR 0019](0019-native-clients.md) §2 platform table, row "Android", column "Minimum OS", its first sentence** ("API 26, for the Autofill Framework (V).") is replaced by:
   > API 29 (Android 10), the first release with platform TLS 1.3 (L), for the TLS 1.3 floor of [ADR 0102](0102-native-client-tls.md); the Autofill Framework alone would need API 26 (V).

   The rest of the cell (the passkey provider's API 34, androidx.credentials) stays. ADR 0019 §2 itself marks its minimum-OS cells as proposed text inside the Accepted ADR ("Everything else is proposed: … minimum OS"); this ADR names the sentence anyway, so that the change is recorded.

## Consequences

### Positive

- One trust boundary on every native client: TLS 1.3, no host-side relaxation, a private CA configured once through Rust with `rv`'s limits, and no TOFU anywhere.
- Windows and Linux reuse reviewed `rv` code and pins; no new package enters `Cargo.lock`; Linux never loads the system OpenSSL.
- Apple and Android keep the OS stack of owner decision 11, with platform proxies; the private CA reaches them as DER validated in Rust.
- The core's checks are written down as independent of TLS (INV-117), so a broken TLS stack on one host is bounded by A4's existing analysis.

### Negative

- Android 8 and 9 (API 26–28) devices cannot install the app (open question 1).
- Windows and Linux ignore the OS trust store and the OS proxy settings: a corporate root needs an app-level import, and a mandatory proxy is not supported at all.
- What we do not control differs per platform: revocation (none on route A, the OS default on route B), Apple honouring user-installed full-trust roots, HTTP/2 on route B only.
- A second copy of the TLS policy files exists until open question 2 is answered; the copy check keeps them equal but adds a step to every edit.
- Each route-B host carries an error mapping table that only its tests keep honest.

### Risks

- **Apple user-installed roots.** A user, or an MDM profile, that enables full trust for a TLS-inspection root exposes tokens and ciphertext to that proxy (A4, broken TLS). Bounded by request signing and E2EE; documented on acceptance.
- **A self-signed `cA=true` server certificate imported as the private CA on route B** may be accepted by the OS (U), which would turn the CA set into a pin. Implementation plan steps 6–7 settle it. If the OS accepts it, the trust module also refuses a chain whose leaf is itself an anchor, recorded as a dated amendment.
- **Token rules miss an API.** A new platform API that disables validation would pass point 8's lists. Mitigation: the per-release review listing, and a review of the lists when a host raises its SDK.
- **Spike S4** (ADR 0019) has not run. If route A needs first-party `unsafe` on Windows or Linux, owner decision 11 re-opens, and this ADR's route-A rows with it.

## Alternatives considered

- **`rustls-platform-verifier` on Windows and Linux** (route A with the OS verifier): corporate roots and revocation work unchanged. Costs as listed in ADR 0030 (about 20 more packages, `unsafe` in the crate and in `security-framework`, per-OS behaviour; V there) and an ADR 0009 approval. Open question 3.
- **`rustls-native-certs`**: reads the OS store into rustls; rejected in ADR 0030 (a store any local admin or malware can extend silently; `openssl-probe`'s `unsafe` environment writes).
- **Rust TLS on Apple and Android too** (route A everywhere): one stack everywhere, but it reverses owner decision 11, loses platform proxies and needs platform glue in the binding.
- **A host-side "trust this server" toggle, or TOFU on first connection:** rejected. It makes the host's UI the trust root, which G03-2 rules out.
- **TLS 1.2 fallback on Android API 26–28** (or everywhere): keeps older devices and TLS-1.2-only proxies; costs the downgrade surface ADR 0030 refused and a second configuration per host. Open question 1.
- **Bundling Conscrypt on Android** for TLS 1.3 on API 26–28: a BoringSSL native library in the app, outside this repository's review and against the spirit of the OpenSSL ban.
- **Trusting Android user CAs** (`<certificates src="user"/>`): private CAs would work without an app import, but every CA any user action or MDM added would be trusted, for our origin as for any other.

## On acceptance (not made now)

1. ADR 0030's status line gains "[ADR 0102](0102-native-client-tls.md) (Decision 1 in part)"; ADR 0009's gains "ADR 0102 (Amendments, 2026-10-05 entry, "Where it is applied" in part)"; ADR 0019's gains "ADR 0102 (§2 table, Android Minimum OS, in part)"; the README index rows of 0009, 0019, 0030 and 0102 follow. Status changes are the owner's act (ADR 0020).
2. CRYPTO.md §3: two rows below "Transport (`rizzy-icon-proxy`)": "Transport (Windows and Linux bindings) | TLS 1.3, ring provider, Mozilla roots or a private CA set through the core | `tokio-rustls`, `rustls` (`std`, `ring`), `webpki-roots` | the `rv` pins | as `rv`" and "Transport (Apple and Android hosts) | TLS 1.3, OS stack, OS roots (Android: system only) or a private CA set through the core | URLSession; OkHttp | pinned by the host repository (ADR 0019 §11) | OS stacks (U)".
3. THREAT_MODEL: INV-117 under its final number (next free at acceptance), cited from A4's mitigations; A4 gains the Apple user-root residual from Risks.
4. `docs/self-hosting.md`: a "Private CA on the apps" section (file import, fingerprint confirmation, `cA=true` only, the Apple full-trust note, Android API 29).
5. ROADMAP: no row changes. Android's floor is not stated there (V, grep for "API 26"); nothing to edit unless the owner adds one.
6. The CLAUDE.md status list (the lead's edit).
7. The host repositories (`rizzy-vault-apple`, `-android`, `-windows`, `-linux`): point 8's CI rules and trust modules land with each client's first networking change.

## Implementation plan

Each step is its own commit, behind an Accepted ADR.

1. **Split `rv`'s TLS code** (`crates/rizzy-cli/src/tls.rs` → `ca_pem.rs` and `tls_config.rs`), no behaviour change. ADR 0030's and ADR 0035's tests and the `ca_pem` fuzz target pass unchanged.
2. **Core origin rule and shapes** in `rizzy-client`: point 7's check after the CRYPTO.md §2 parser; `TransportFailure`, `Delivery`, `TlsFailure`; `timeout_ms` and `max_response_len` per request. Tests: unit tests for each admitted and refused origin (`http://localhost`, `http://127.0.0.2`, `http://[::1]`, `https://192.0.2.1` admitted; `http://example.com`, `http://localhost.example.com`, `http://127.0.0.1.nip.io`, `http://[::ffff:127.0.0.1]` refused); a property test that no refused origin ever yields a request record; the origin rule added to an existing fuzz target.
3. **INV-117 tests** in `rizzy-client` with a mock transport that always reports TLS success: a tampered `account-state` signature, a `state_seq` below the high-water mark, a bundle mismatch, KDF parameters below the floor, an over-limit body. Each is an integrity error, none is a `TransportFailure`, none is retried.
4. **Trust store in `rizzy-ffi` and `rizzy-ffi-cpp`** (migration next free at implementation): `set_private_ca`, `clear_private_ca`, fingerprints, `server_trust` format 1, fail-closed load. Tests: the limits, non-CA refusal, fingerprint output, a crash between steps (transaction rollback), an unknown `format` and corrupted `pem` each giving `Configuration` and never the public roots.
5. **Route A transport** in the binding leaves: the copies of step 1, the xtask copy and target checks. Integration tests on `x86_64-pc-windows-msvc` and `x86_64-unknown-linux-gnu` runners with a loopback `tokio-rustls` acceptor and the fixtures of `crates/rizzy-cli/tests/fixtures/tls/`: ADR 0030 Decision 7's and ADR 0035 point 4's lists (private CA accepted; unknown CA, wrong name, expired, not yet valid, TLS 1.2-only server, the test certificate under the public roots, self-signed `cA=true` and `cA=false` refused), plus a server issued by `ca2.pem` refused while `ca.pem` is set (replacement, not addition), and `http://localhost` resolving to a non-loopback address refused.
6. **Apple host** (`rizzy-vault-apple`; XCTest on macOS and an iOS simulator): a TLS test server in the test target (a Network.framework listener) serving the same fixtures, copied with a checksum file that CI compares against this repository's fixtures. Cases: every case of step 5; every Apple row of point 5's mapping table; a 3xx not followed; no cookie stored or sent; nothing written to `URLCache`; the request-target bytes received equal the core's; `ResponseTooLarge`; the self-signed `cA=true` question of Risks.
7. **Android host** (`rizzy-vault-android`; instrumented tests on emulators at API 29 and the latest stable API): `MockWebServer` with the fixtures and the same cases; every Android row of the mapping table; the Network Security Config refusing `http` to a non-loopback test host; a release-build check of the merged manifest.
8. **Windows and Linux hosts:** point 8's static checks; one end-to-end smoke test through the binding against a loopback TLS server, with the private CA imported through the UI flow.
9. **Docs:** On-acceptance items 2–4, in the same change as the code they describe.

## Open questions for the owner

1. **Android floor: API 29, or a TLS 1.2 fallback?** Raising the minimum from API 26 to 29 drops Android 8 and 9 devices. The alternatives are TLS 1.2 (ECDHE with AEAD suites only) on API 26–28, or bundling Conscrypt. **Recommendation: API 29.** The Android client is an M7 deliverable, its passkey provider already needs API 34, and a single TLS 1.3 floor keeps one configuration per host.
2. **Shared code: copies, or a new crate?** The route-A policy files could live in one new library crate (for example `rizzy-tls`, used by `rizzy-cli`, `rizzy-ffi` and `rizzy-ffi-cpp`) instead of byte-identical copies; that is an [ADR 0016](0016-workspace-layout.md) change. **Recommendation: copies with the xtask check now**, and a crate ADR only if a divergence or a third copy appears, so that this ADR does not touch crate boundaries.
3. **Windows and Linux: Mozilla roots, or the OS store?** `webpki-roots` (as `rv`) gives identical behaviour and no new crate; `rustls-platform-verifier` honours corporate roots and revocation at the cost ADR 0030 lists. **Recommendation: `webpki-roots` plus the app-level private CA for M3**, revisited after spike S4 or the first corporate-deployment request.

## Related

- [ADR 0009](0009-crypto-dependency-policy.md), [ADR 0012](0012-sync-engine.md), [ADR 0013](0013-shared-client-core.md) §2–§3, [ADR 0016](0016-workspace-layout.md), [ADR 0019](0019-native-clients.md) §2, §4, §5, §8, §9, §11, [ADR 0020](0020-partial-supersession.md) point 9, [ADR 0026](0026-client-device-state-and-cache.md), [ADR 0028](0028-api-v1-http-conventions.md) items 5 and 10, [ADR 0030](0030-client-tls-rv.md), [ADR 0035](0035-ca-file-ca-certificates-only.md), [ADR 0052](0052-icon-proxy-role.md), [ADR 0096](0096-binding-secrets-and-kdbx-worker.md) (Proposed).
- [THREAT_MODEL](../THREAT_MODEL.md) A4, INV-60; [CRYPTO.md](../CRYPTO.md) §2, §3, §5.3, §5.10, §6.2, §8.4, §9.5, §10.2, §10.3, §11.3.
- Review: [2026-10-25 gap review](../reviews/2026-10-25-adr-gap-review.md) M4; [G03.md](../reviews/2026-10-25-raw/G03.md) G03-2.
