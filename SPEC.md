# SPEC: `hello-hash` — Windows Hello Signature → SHA-256 CLI (Rust)

**Status:** Approved design, ready for implementation
**Target platform:** Windows 10/11 (x64) only
**Language/toolchain:** Rust (edition 2021, MSRV 1.85)
**Project type:** Standalone CLI binary, separate from `mfa_locker`

---

## 1. Purpose

This project replicates, as a standalone Rust CLI, the exact core flow performed by the
`biometric_cipher` Windows plugin of the `mfa_locker` project:

1. Convert a challenge string to a UTF-16LE binary buffer.
2. Sign that buffer with a TPM-backed `KeyCredential` via `KeyCredentialManager`
   (this triggers the Windows Hello consent prompt).
3. Compute **SHA-256 over the raw signature bytes** (not over the challenge string, not a
   concatenation).
4. Print the 32-byte digest as lowercase hexadecimal to stdout.

The program performs **no other function**: no AES-GCM encryption, no storage, no config
files. It also provides subcommands to create and delete the Windows Hello key credential,
mirroring the plugin's `generateKey` / `deleteKey` operations.

**Reference implementation (source of truth, C++):**

| Step | File (`packages/biometric_cipher/windows/`) | Lines |
|------|---------------------------------------------|-------|
| Challenge → UTF-16LE buffer | `biometric_cipher_service.cpp` | 85–92 |
| Sign via Windows Hello (prompt) | `windows_hello_repository_impl.cpp` | 48–75 (`RequestSignAsync` at :66) |
| SHA-256 over signature | `winrt_encrypt_repository_impl.cpp` | 20–34 (`HashData` at :23) |
| Key creation (`FailIfExists`) | `windows_hello_repository_impl.cpp` | 77–99 (`RequestCreateAsync` at :90) |
| Key deletion | `windows_hello_repository_impl.cpp` | 101–121 (`DeleteAsync` at :114) |
| Status → error mapping | `windows_hello_repository_impl.cpp` | 143–170 |
| Availability pre-check | `windows_hello_repository_impl.cpp` | 19–46, 133–141 |

---

## 2. Requirements (IMMUTABLE)

- **R1 — Sign & hash:** `sign` requests a signature of the challenge string via Windows Hello
  (`KeyCredential::RequestSignAsync`), computes SHA-256 over the returned signature bytes,
  and writes the digest to stdout.
- **R2 — Hash input:** SHA-256 is computed over **the signature `IBuffer` bytes only**.
  The challenge string itself is never hashed.
- **R3 — Challenge encoding:** the challenge string is converted to UTF-16LE via
  `CryptographicBuffer::ConvertStringToBinary(value, BinaryStringEncoding::Utf16LE)`,
  identical to the C++ service (`biometric_cipher_service.cpp:90`).
- **R4 — Key names match `mfa_locker`:** the default key tag is **`mfa_demo_bio_key`**
  (`example/lib/core/constants/app_constants.dart:23`). Overridable per invocation via option.
- **R5 — Default challenge matches `mfa_locker`:** the default challenge string is
  **`locker_authentication_request`** (`lib/security/models/biometric_config.dart:41`,
  the value the example app actually signs since it never overrides `windowsAuthData`).
  Overridable per invocation via positional argument.
- **R6 — Key management:** `generate-key` creates the credential with
  `KeyCredentialCreationOption::FailIfExists` (mirrors C++ `CreateCredentialAsync`,
  `windows_hello_repository_impl.cpp:90`); `delete-key` removes it via
  `KeyCredentialManager::DeleteAsync`.
- **R7 — No auto-create:** `sign` never creates a missing key; it fails with exit code 3
  ("key not found") if `OpenAsync` returns `NotFound`.
- **R8 — Deterministic output requirement:** for the same key tag and the same challenge
  string, repeated `sign` invocations must produce the **same** SHA-256 digest. This property
  is what `mfa_locker` depends on (it uses the digest as a persistent AES-256 key), and it
  holds because the TPM signs with a deterministic scheme (PKCS#1 v1.5). The implementation
  must not do anything that would break it (no randomization of challenge encoding, etc.).
- **R9 — Output discipline:** stdout receives **only** the 64-character lowercase hex digest
  (+ trailing newline). All diagnostics and errors go to stderr. This makes the tool
  pipe-friendly.

## 3. Success Criteria (MUST ALL BE TRUE)

- [ ] `cargo build --release` succeeds with zero warnings (`#![deny(warnings)]` allowed).
- [ ] `hello-hash generate-key` creates the `mfa_demo_bio_key` credential (Windows Hello
      enrollment prompt appears on first creation).
- [ ] `hello-hash sign "locker_authentication_request"` prints a 64-char lowercase hex digest
      after a successful Windows Hello prompt.
- [ ] Running `sign` twice with identical tag + challenge yields identical digests (R8).
- [ ] Signing the same challenge with a **different** tag (fresh key) yields a different digest.
- [ ] `hello-hash delete-key` deletes the credential; a subsequent `sign` exits with code 3.
- [ ] Canceling the Windows Hello prompt exits with code 2 and a clear stderr message.
- [ ] stdout contains nothing but the digest on success.
- [ ] `clippy` and `cargo fmt --check` pass.

## 4. Anti-Patterns (FORBIDDEN)

- ❌ NO AES-GCM / encryption of any payload (scope: user explicitly limited to sign → hash → output).
- ❌ NO hashing of the challenge string instead of the signature bytes
      (correctness: R2 — the plugin hashes `signatureResult.Result()`, not the input).
- ❌ NO auto-creation of the key inside `sign` (compatibility: R7 — separate setup command
      was explicitly chosen; silent creation would mask missing-key errors).
- ❌ NO default key tag other than `mfa_demo_bio_key`
      (compatibility: R4 — keys must be interoperable with the `mfa_locker` vault).
- ❌ NO `IAsyncOperation::get()` (correctness: removed in `windows` 0.62; blocking call is
      `.join()` — see §8).
- ❌ NO `match` on `KeyCredentialStatus` (correctness: it is a newtype struct with associated
      constants in windows-rs, not a Rust enum — compare with `==`).
- ❌ NO async runtime (tokio etc.) — blocking `.join()` from `main` is sufficient and MTA-safe
      for a console process (simplicity: KISS).
- ❌ NO extra output on stdout (usability: R9 — breaks piping/scripts).

---

## 5. CLI Specification

Binary name: **`hello-hash`**. Argument parsing: `clap` v4 with derive API (or manual parsing
if dependency minimalism is preferred — behavior below is normative either way).

### 5.1 `sign` (default command when first arg is not a known subcommand is NOT supported —
subcommand must be explicit)

```
hello-hash sign [CHALLENGE] [--tag <TAG>]
```

| Element | Kind | Default | Description |
|---------|------|---------|-------------|
| `CHALLENGE` | optional positional | `locker_authentication_request` | String to be signed via Windows Hello |
| `--tag <TAG>` | option | `mfa_demo_bio_key` | Key credential name |

Behavior:

1. **Availability pre-check** (mirrors `CheckWindowsHelloIsStatusAsync`): call
   `KeyCredentialManager::IsSupportedAsync()`. If `false`, fall back to
   `UserConsentVerifier::CheckAvailabilityAsync()` to produce a specific message
   (device not present / not configured for user / disabled by policy / device busy),
   then exit with code 5.
2. `KeyCredentialManager::OpenAsync(tag)` → `.join()`.
3. If retrieval status ≠ `Success`, exit per the status mapping (§7); `NotFound` → exit 3.
4. `CryptographicBuffer::ConvertStringToBinary(HSTRING::from(challenge), Utf16LE)`.
5. `credential.RequestSignAsync(buffer)` → `.join()` — **Windows Hello prompt happens here.**
6. If operation status ≠ `Success`, exit per §7 (e.g. `UserCanceled` → exit 2).
7. Extract signature bytes:
   `CryptographicBuffer::CopyToByteArray(result.Result()?, &mut Array::<u8>::new())`.
8. Print two `[bio-debug]` lines to stdout (always on, mirroring the plugin's
   `debug_log.cpp` format; the signature is hashed exactly once and both debug values
   derive from the same digest):
   ```
   [bio-debug] HH:MM:SS.mmm op=sign tag=<tag> sig=<middle 32 hex chars of signature hex>
   [bio-debug] HH:MM:SS.mmm key=<middle 32 hex chars of SHA-256 hex>
   ```
   "Middle 32" follows the plugin's `SliceMiddle`: empty → `<empty>`, length ≤ 32 → whole
   string, otherwise `hex[(len-32)/2 .. (len-32)/2+32]`. Timestamps are local time via
   `GetLocalTime`. On failure (steps 1–6), nothing is printed to stdout.
9. `Sha256::digest(&bytes)` → print as lowercase hex + `\n` to stdout. Exit 0.
   This is the FINAL stdout line, unchanged from before (scripts may consume it).

### 5.2 `generate-key`

```
hello-hash generate-key [--tag <TAG>]
```

Behavior (mirrors C++ `CreateCredentialAsync`, `windows_hello_repository_impl.cpp:77-99`):

1. Availability pre-check as above.
2. `KeyCredentialManager::RequestCreateAsync(tag, KeyCredentialCreationOption::FailIfExists)`
   → `.join()` — Windows Hello enrollment prompt appears here.
3. Status `CredentialAlreadyExists` → exit 4 with "Key credential already exists.".
   Any other non-Success → §7 mapping. Success → print confirmation to **stderr**
   (keep stdout clean), exit 0.

### 5.3 `delete-key`

```
hello-hash delete-key [--tag <TAG>]
```

Behavior (mirrors C++ `DeleteCredentialAsync`, `windows_hello_repository_impl.cpp:101-121`):

1. Availability pre-check as above.
2. `KeyCredentialManager::DeleteAsync(tag)` → `.join()`.
3. Success → confirmation on stderr, exit 0. WinRT error (incl. key-not-found hresult) →
   descriptive stderr message, exit 8 (per the §6 table row for other WinRT hresults;
   §5.3 previously said exit 7 — that conflicted with §6 where 7 is `UserPrefersPassword`;
   resolved to exit 8, matching the normative §6 table and verified in manual testing).

### 5.4 Global

- `hello-hash --help` / `-h`, `hello-hash --version` / `-V` — standard clap behavior.
- Unknown subcommand / bad usage → usage message on stderr, exit code 64 (`EX_USAGE`;
  configure clap's `exit_code` for `ValueValidation`/`UnknownArgument` errors accordingly).

---

## 6. Exit Codes

| Code | Condition | stderr message (prefix) |
|------|-----------|-------------------------|
| 0 | Success | — |
| 2 | `UserCanceled` (Windows Hello prompt dismissed) | `Error: user canceled the operation.` |
| 3 | `NotFound` (key credential does not exist) | `Error: key credential not found.` |
| 4 | `CredentialAlreadyExists` (generate-key) | `Error: key credential already exists.` |
| 5 | Windows Hello unsupported / unavailable | `Error: Windows Hello is not supported (<reason>).` |
| 6 | `SecurityDeviceLocked` | `Error: security device is locked.` |
| 7 | `UserPrefersPassword` | `Error: user prefers password.` |
| 8 | `UnknownError` or any other `KeyCredentialStatus` / WinRT hresult / internal error | `Error: <description>.` |
| 64 | Invalid arguments / unknown subcommand | clap usage output |

The 1–7 status-to-error mapping mirrors `CheckKeyCredentialStatus`
(`windows_hello_repository_impl.cpp:143-170`) and its error-code semantics
(`error_authentication_canceled`, `error_key_not_found`, `error_key_already_exists`,
`error_secure_device_locked`, `error_user_prefers_password`, `error_fail`).

---

## 7. Status Handling Reference (WinRT → CLI)

`KeyCredentialStatus` values from both `KeyCredentialRetrievalResult` (open/create) and
`KeyCredentialOperationResult` (sign):

| `KeyCredentialStatus` | Open | Sign | Create | CLI exit |
|-----------------------|------|------|--------|----------|
| `Success` (0) | proceed | hash & print | confirm | 0 |
| `NotFound` (2) | exit 3 | — | — | 3 |
| `UserCanceled` (3) | exit 2 | exit 2 | exit 2 | 2 |
| `UserPrefersPassword` (4) | exit 7 | exit 7 | exit 7 | 7 |
| `CredentialAlreadyExists` (5) | — | — | exit 4 | 4 |
| `SecurityDeviceLocked` (6) | exit 6 | exit 6 | exit 6 | 6 |
| `UnknownError` (1) / anything else | exit 8 | exit 8 | exit 8 | 8 |

Note: windows-rs 0.62 projects `KeyCredentialStatus` as `pub struct KeyCredentialStatus(pub i32)`
with associated constants — use `==` comparisons, not `match`.

---

## 8. Technology Stack & Dependencies

```toml
[package]
name = "hello-hash"
version = "0.1.0"
edition = "2021"
rust-version = "1.85"

[dependencies]
clap = { version = "4.5", features = ["derive"] }
sha2 = "0.11.0"
windows = { version = "0.62.2", features = [
    "Security_Credentials",       # KeyCredentialManager, KeyCredential, KeyCredentialStatus, KeyCredentialCreationOption
    "Security_Credentials_UI",    # UserConsentVerifier (availability diagnostics)
    "Security_Cryptography",      # CryptographicBuffer, BinaryStringEncoding
    "Storage_Streams",            # IBuffer (gates RequestSignAsync / Result())
] }

[profile.release]
lto = true
```

Version rationale (verified 2026):

- `windows` 0.62.2 is the latest stable; the four features above are the exact, verified
  feature flags. The old `Foundation` feature is **not** needed for async (async types come
  unconditionally from `windows-future`).
- `sha2` 0.11.0 (RustCrypto) sets the MSRV floor at 1.85. If an MSRV below 1.85 is required,
  use `sha2 = "0.10.9"` instead — API for `Sha256::digest` is unchanged.
- Alternative rejected: Win32 BCrypt/CryptoAPI for SHA-256 — using `sha2` keeps the hash
  implementation pure-Rust, testable, and independent of the WinRT projection.

### Implementation notes (windows-rs specifics)

- **Blocking on async:** use `IAsyncOperation::join()` (e.g.
  `KeyCredentialManager::OpenAsync(&name)?.join()?`). `get()` was removed in 0.62 — copying
  stale blog code will not compile.
- **Threading:** calling `.join()` from an ordinary `fn main()` thread is safe (the thread is
  treated as MTA; the completion handler fires on the WinRT thread pool). Do not initialize
  COM STA on the main thread. No async runtime needed.
- **No timeout on `join()`:** if the user walks away from the prompt, the process blocks —
  acceptable for a CLI (Ctrl+C still works).
- **HSTRING:** build with `HSTRING::from(&str)` (UTF-8 → UTF-16 conversion handled).
- **Foreground/`WH_CBT` hook workaround from the C++ (`windows_hello_repository_impl.cpp:57-64`)
  is NOT replicated:** it exists because the Flutter host window could steal focus from the
  Hello prompt; a console CLI already owns the foreground, so it is unnecessary.

---

## 9. Suggested Module Layout

```
hello-hash/
├── Cargo.toml
├── SPEC.md            # this file
└── src/
    ├── main.rs        # CLI parsing (clap), exit-code dispatch, top-level error type
    ├── hello.rs       # Windows Hello operations: availability check, open, create,
    │                  #   delete, sign (all WinRT calls live here)
    ├── hash.rs        # sha256_digest(bytes: &[u8]) -> [u8; 32], hex_encode (pure,
    │                  #   unit-testable)
    └── debug_log.rs   # [bio-debug] line format (slice_middle, timestamp, log_* wrappers)
```

- `hello.rs` exposes a small facade, e.g.:
  - `fn check_availability() -> Result<(), CliError>`
  - `fn open_credential(tag: &str) -> Result<KeyCredential, CliError>`
  - `fn create_credential(tag: &str) -> Result<(), CliError>`
  - `fn delete_credential(tag: &str) -> Result<(), CliError>`
  - `fn sign(tag: &str, challenge: &str) -> Result<Vec<u8>, CliError>` (returns signature bytes)
- A single `CliError` enum (variants carrying the exit code) converts `windows::core::Error`
  and status values into (exit_code, message) pairs — keeps `main.rs` free of match noise.

---

## 10. Testing Plan

Windows Hello prompts cannot be automated; the plan is split accordingly.

**Unit tests (automated, `cargo test`):**

- `hash.rs`: known-answer tests — SHA-256 of empty input, of `"abc"`, of a 55/56/64-byte
  boundary input; hex encoding is lowercase, 64 chars, no padding.
- Argument parsing: default tag is `mfa_demo_bio_key`, default challenge is
  `locker_authentication_request`; explicit values override; unknown subcommand errors.

**Manual checklist (Windows 10/11 with Hello enrolled):**

1. `hello-hash generate-key` → enrollment prompt → success message.
2. `hello-hash generate-key` again → exit 4, "already exists".
3. `hello-hash sign` → prompt → three stdout lines: two `[bio-debug]` lines (op=sign with
   the `sig=` slice, then the `key=` slice), then the 64-char hex digest as the final line.
4. `hello-hash sign` again (same defaults) → **identical digest** (R8 determinism).
5. `hello-hash sign "different challenge"` → different digest.
6. `hello-hash generate-key --tag test-key-tag` + `hello-hash sign --tag test-key-tag` →
   different digest than step 3 (different key).
7. Cancel the prompt at step 3-style run → exit 2, "user canceled".
8. `hello-hash delete-key` → success; `hello-hash sign` → exit 3, "key credential not found".
9. `hello-hash sign | tail -1 | xxd -r -p | ...` — the final stdout line is exactly 65 bytes
   (digest + `\n`); the two preceding `[bio-debug]` lines have varying content (timestamps,
   per-run signature).

**Consistency with `mfa_locker` (optional but recommended):** temporarily instrument the
example app (or use the tpm_test screen with tag `mfa_demo_bio_key`) to print its SHA-256
key hash — the `LogKeyHash` debug hook (`winrt_encrypt_repository_impl.cpp:28`,
`debug_log.cpp:82`) already does this in debug builds — and verify the Rust CLI prints the
same digest for the same tag + `'locker_authentication_request'`. This proves byte-level
compatibility of the whole sign→hash pipeline.

---

## 11. Non-Goals (Out of Scope)

- AES-256-GCM encryption/decryption of arbitrary payloads (the plugin's use of the digest as
  an AES key is the *consumer's* concern, not this tool's).
- Cross-platform support (no macOS/iOS/Android — this replicates the Windows plugin only).
- Config file / persistent storage of any kind.
- Base64 or other digest output encodings (hex only, per R9; base64 can be added later).
- Retrieving/attesting public keys, TPM status reporting, `isKeyValid` checks.

---

## 12. Design Rationale

### Problem

`mfa_locker` derives its biometric AES key on Windows as `SHA-256(RequestSignAsync(challenge))`
inside a C++ WinRT plugin (`winrt_encrypt_repository_impl.cpp:20-34`). A standalone Rust
equivalent is needed for experimentation, verification, and tooling outside the Flutter app.

### Research Findings

**Codebase (mfa_locker):**
- `packages/biometric_cipher/windows/windows_hello_repository_impl.cpp:48-75` — the sign flow:
  availability check → `OpenAsync(tag)` → `RequestSignAsync(data)` → status mapping.
- `packages/biometric_cipher/windows/winrt_encrypt_repository_impl.cpp:20-34` — SHA-256 is
  computed over the **signature buffer**, then used as an AES-256-GCM key (confirmed by the
  integration test comment at `test/winrt_encrypt_repository_integration_test.cpp:26-27`).
- `example/lib/core/constants/app_constants.dart:23` — production key tag `mfa_demo_bio_key`.
- `lib/security/models/biometric_config.dart:41` — default challenge `locker_authentication_request`;
  the example app (`example/lib/di/factories/repository_factory.dart:47-53`) never overrides
  `windowsAuthData`, so this default is the actually-signed string.
- Key creation uses `RequestCreateAsync(tag, FailIfExists)` (C++ :90) — hence exit code 4 on
  duplicate rather than silent replace.

**External (windows-rs 0.62.2, verified against docs.rs / Microsoft Learn / windows-future source):**
- Feature flags: `Security_Credentials`, `Security_Credentials_UI`, `Security_Cryptography`,
  `Storage_Streams`; `Storage_Streams` transitively gates `RequestSignAsync`/`Result()`.
- Async blocking method is `join()` (windows-future 0.3.2); `get()` was removed in 0.62.
- `OpenAsync` does **not** create the credential (Microsoft Learn: "retrieves an existing key
  credential"); creation is `RequestCreateAsync` — consistent with the C++ plugin's separate
  `CreateCredentialAsync`.
- `KeyCredentialStatus` is a newtype struct with constants (`Success`=0 …
  `SecurityDeviceLocked`=6); not matchable as an enum.
- `sha2` 0.11.0 (RustCrypto, MSRV 1.85) for the hash — pure Rust, independently testable.

### Approaches Considered

1. **Standalone Rust CLI, windows-rs + sha2 (chosen)**
   - Pros: exact WinRT API parity with the C++ plugin; minimal dependency surface; hash logic
     pure-Rust and unit-testable; `.join()` blocking keeps the program tiny.
   - Cons: Windows-only; relies on windows-rs projection quality for KeyCredentialManager
     (no official sample exists, but Chromium uses the same WinRT API as reference behavior).

2. **Rust with Win32 NCrypt/TPM directly**
   - Pros: lower-level control.
   - Cons: the plugin deliberately uses KeyCredentialManager (TPM-backed by OS design);
     raw NCrypt does not reproduce the Windows Hello consent-on-sign semantics; the plugin's
     own NCrypt path is used only for TPM status checks. Rejected for behavioral divergence.

3. **C++ port of the plugin sources**
   - Pros: trivially faithful.
   - Cons: user explicitly requested Rust and a separate project; loses pure-Rust testability.

### Open Questions (resolve during implementation)

- Exact clap exit-code configuration for usage errors (64 vs clap defaults) — cosmetic.
- Whether `DeleteAsync` on a non-existent tag returns an error hresult or succeeds silently
  on all Windows versions — treat whatever arrives via `windows::core::Error` as exit 8 with
  the hresult message; refine after manual testing.
- Confirm on the target machine that `sign` output is stable across reboots (R8 holds across
  TPM sessions — expected, since the key is persistent).
