# SPEC: `hello-hash tpm` — TPM Key Management (NCrypt) Subcommands

**Status:** Approved design, ready for implementation planning
**Date:** 2026-08-31
**Target platform:** Windows 10/11 (x64) only
**Parent project:** `rust_hello_hash` (`hello-hash` CLI, see root `SPEC.md`)

---

## 1. Purpose

Add three TPM operations to the `hello-hash` CLI, replicating the behavior of the
`biometric_cipher` Windows plugin's TPM repository (`mfa_locker`,
`packages/biometric_cipher/windows/windows_tpm_repository_impl.cpp`):

1. **Create** a persisted RSA key in the Microsoft Platform Crypto Provider (TPM).
2. **Delete** a persisted TPM key by name.
3. **List** all persisted TPM keys (name + algorithm).

Important: these operate on **raw NCrypt persisted keys** in
`MS_PLATFORM_CRYPTO_PROVIDER` — a different key namespace from the Windows Hello
`KeyCredential`s managed by the existing `generate-key` / `delete-key` commands
(WinRT `KeyCredentialManager`). The two key types are unrelated; a TPM key created
here does not appear in Windows Hello, and vice versa.

**Reference implementation (source of truth, C++):**

| Operation | File | Function (lines) |
|-----------|------|------------------|
| List keys | `windows_tpm_repository_impl.cpp` | `ListTpmKeys` (:53–92) |
| Create key | `windows_tpm_repository_impl.cpp` | `CreateTpmKey` (:94–124) |
| Delete key | `windows_tpm_repository_impl.cpp` | `DeleteTpmKey` (:126–155) |
| Status → error mapping | `windows_tpm_repository_impl.cpp` | `CheckStatus` (:170–178) |

---

## 2. Requirements (IMMUTABLE)

- **T1 — Create:** `tpm create-key <NAME>` creates a persisted key via
  `NCryptCreatePersistedKey(provider, &key, NCRYPT_RSA_ALGORITHM, name, 0, 0)`
  followed by `NCryptFinalizeKey(key, 0)`. An unfinalized key is discarded when its
  handle closes — finalization is mandatory (C++ comment :120–122).
- **T2 — Create collision:** `NTE_EXISTS` from `NCryptCreatePersistedKey` → exit 4,
  message `TPM key already exists.` (mirrors `error_key_already_exists`).
- **T3 — Delete:** `tpm delete-key <NAME>` opens the key with `NCryptOpenKey`, then
  deletes it with `NCryptDeleteKey`. `NTE_NO_KEY` from either call → exit 3, message
  `TPM key not found.` (mirrors `error_key_not_found`).
- **T4 — Delete frees the handle:** on success, `NCryptDeleteKey` has already freed
  the key handle; the implementation must not free it again (C++ :152–154).
- **T5 — List:** `tpm list-keys` enumerates keys via `NCryptEnumKeys` until
  `NTE_NO_MORE_ITEMS`, collecting `{name, algid}` from each `NCryptKeyName`.
  Enumeration state and each `NCryptKeyName` are freed with `NCryptFreeBuffer`.
- **T6 — Provider:** every command opens `MS_PLATFORM_CRYPTO_PROVIDER` via
  `NCryptOpenStorageProvider` first; failure → exit 5 with the `CheckStatus`
  message style (`NCryptOpenStorageProvider failed: 0x...`), mirroring
  `error_tpm_unsupported`.
- **T7 — Key name argument:** `<NAME>` is a required positional argument for
  `create-key` and `delete-key`. There is **no default** — TPM keys have no
  `mfa_locker` default tag. `list-keys` takes no arguments.
- **T8 — RSA only:** algorithm is hard-coded to `NCRYPT_RSA_ALGORITHM`, exactly as
  in the C++ `CreateTpmKey`. No `--algorithm` option.
- **T9 — Output discipline:** `list-keys` writes one `name<TAB>algid` line per key
  to stdout (nothing if no keys exist) — this is the command's only stdout output.
  `create-key` / `delete-key` print confirmation to **stderr**, keeping stdout clean.

## 3. Success Criteria (MUST ALL BE TRUE)

- [ ] `cargo build --release` succeeds with zero warnings.
- [ ] `hello-hash tpm create-key test_key` → stderr confirmation, exit 0; key appears
      in `hello-hash tpm list-keys` output as `test_key<TAB>RSA`.
- [ ] `hello-hash tpm create-key test_key` again → exit 4, `Error: TPM key already exists.`
- [ ] `hello-hash tpm delete-key test_key` → stderr confirmation, exit 0; subsequent
      `list-keys` omits it.
- [ ] `hello-hash tpm delete-key test_key` when absent → exit 3,
      `Error: TPM key not found.`
- [ ] `hello-hash tpm list-keys` on a machine with TPM keys prints them one per line;
      with none prints nothing on stdout, exit 0.
- [ ] Existing `sign` / `generate-key` / `delete-key` behavior unchanged.
- [ ] `cargo test` (new unit tests) passes; `clippy` and `cargo fmt --check` pass.

## 4. Anti-Patterns (FORBIDDEN)

- ❌ NO skipping `NCryptFinalizeKey` after create (T1 — the key would vanish).
- ❌ NO freeing the key handle after a successful `NCryptDeleteKey` (T4 — double free).
- ❌ NO leaking the provider handle / key handle / enum state on error paths — a RAII
      guard struct handles cleanup so early returns cannot leak.
- ❌ NO default key name, no `--algorithm` option (T7/T8 — YAGNI, mirror the C++).
- ❌ NO Windows Hello / `KeyCredentialManager` involvement in these commands — they
      must not trigger a Hello prompt.
- ❌ NO extra stdout output from `list-keys` (headers, counts — T9 breaks pipelining).
- ❌ NO new cryptography, signing, or export of key material — only create/delete/list.

## 5. CLI Specification

```
hello-hash tpm <COMMAND>

Commands:
  create-key <NAME>   Create a persisted RSA TPM key in the Platform Crypto Provider
  delete-key <NAME>   Delete a persisted TPM key by name
  list-keys           List persisted TPM keys as name<TAB>algid lines
```

Implemented as a nested clap subcommand group: `Command::Tpm(TpmCommand)` where
`TpmCommand` is a derive `Subcommand` enum with variants
`CreateKey { name: String }`, `DeleteKey { name: String }`, `ListKeys`.
`<NAME>` is `required = true` positional (no default value). Help/version
behavior and exit code 64 for usage errors follow the existing global rules
(SPEC.md §5.4).

## 6. Exit Codes (extension of the existing table)

| Code | Condition | stderr message (prefix) |
|------|-----------|-------------------------|
| 3 | `NTE_NO_KEY` from `NCryptOpenKey`/`NCryptDeleteKey` (delete-key) | `Error: TPM key not found.` |
| 4 | `NTE_EXISTS` from `NCryptCreatePersistedKey` (create-key) | `Error: TPM key already exists.` |
| 5 | `NCryptOpenStorageProvider` failure (no TPM / provider unavailable) | `Error: TPM is not available (NCryptOpenStorageProvider failed: 0x...).` |
| 8 | Any other NCrypt failure (`NCryptCreatePersistedKey`, `NCryptFinalizeKey`, `NCryptOpenKey`, `NCryptDeleteKey`, `NCryptEnumKeys`) | `Error: <call> failed: 0x<HRESULT>.` |
| 0 | Success | — |

Codes 3/4/5/8 reuse the existing `CliError` semantics; only the messages are
TPM-specific. The C++ `CheckStatus` message format is preserved:
`<LPCSTR call name> failed: 0x<uppercase hex SECURITY_STATUS>`.

## 7. Module Layout & Dependencies

```
src/
├── main.rs        # + Command::Tpm(TpmCommand) variant, run() match arm
└── tpm.rs         # NEW: NCrypt facade
                   #   pub struct TpmKeyInfo { pub name: String, pub algorithm: String }
                   #   pub fn list_keys() -> Result<Vec<TpmKeyInfo>, CliError>
                   #   pub fn create_key(name: &str) -> Result<(), CliError>
                   #   pub fn delete_key(name: &str) -> Result<(), CliError>
                   #   struct NCryptHandle / status-mapping helpers (pure, unit-testable)
```

- `Cargo.toml`: add `"Win32_Security_Cryptography"` to the existing
  `windows = { version = "0.62.2", features = [...] }` dependency. No other new
  dependencies.
- No `NCryptWrapper` trait abstraction (approach considered and rejected — the
  existing project calls WinRT directly in `hello.rs`; direct NCrypt calls keep the
  same style and KISS).
- Wide-string conversion: key names are UTF-16 (`LPCWSTR`/`PWSTR`); convert via
  `windows`-crate string helpers, lossy is acceptable per the C++
  (`ConvertWideStringToString`).
- The `SECURITY_STATUS`-to-`CliError` mapping and the `name<TAB>algid` line
  formatting live in `tpm.rs` as pure functions so they are unit-testable without
  a TPM.

## 8. Testing Plan

**Unit tests (automated, `cargo test`):**

- Clap parsing: `tpm create-key X` / `tpm delete-key X` parse with `name == "X"`;
  `tpm create-key` without NAME errors; `tpm list-keys` parses with no args and
  rejects extra args; `tpm` alone errors (subcommand required);
  unknown `tpm` subcommand errors.
- Status mapping: `NTE_EXISTS` → exit 4 variant; `NTE_NO_KEY` → exit 3 variant;
  provider-open failure → exit 5 variant; generic SECURITY_STATUS (e.g. `NTE_FAIL`)
  → exit 8 variant with `0x...` message; success (0) → no error.
- Line format: `TpmKeyInfo` renders as `name<TAB>algid`; empty list renders nothing.

**Manual checklist (Windows 10/11 with TPM):**

1. `hello-hash tpm create-key hello_hash_test` → confirmation on stderr, exit 0.
2. `hello-hash tpm list-keys` → includes `hello_hash_test<TAB>RSA` on stdout.
3. `hello-hash tpm create-key hello_hash_test` → exit 4, "TPM key already exists."
4. `hello-hash tpm delete-key hello_hash_test` → confirmation on stderr, exit 0.
5. `hello-hash tpm list-keys` → no longer includes the key.
6. `hello-hash tpm delete-key hello_hash_test` → exit 3, "TPM key not found."
7. Regressions: `hello-hash sign`, `generate-key`, `delete-key` still behave per
   root SPEC.md.

## 9. Non-Goals (Out of Scope)

- TPM version detection (`GetWindowsTpmVersion`) — the plugin has it; this CLI
  does not need it.
- Key usage: signing, exporting public keys, attestation, `tpm sign`.
- Windows Hello prompt or consent of any kind.
- Configurable algorithms, key sizes, or provider selection.
- Distinguishing TPM keys by which user/session created them (the provider
  namespace is per-user).

## 10. Design Rationale

### Problem

`hello-hash` currently covers the Windows Hello (KeyCredential) half of the
plugin's behavior. The plugin additionally manages raw TPM persisted keys through
Win32 NCrypt (`WindowsTpmRepositoryImpl`). Replicating the three management
operations (create/delete/list) gives the CLI feature parity for TPM
experimentation without the Flutter app.

### Choices

- **Direct NCrypt via the `windows` crate (chosen)** — the crate already in use
  projects all functions needed under `Win32_Security_Cryptography`; adds one
  feature flag and no new dependencies; keeps `tpm.rs` symmetric with `hello.rs`.
- **NCryptWrapper trait (rejected)** — the C++ abstracts NCrypt for unit-testing
  in a larger dependency-injection architecture; here the status-mapping and
  formatting logic is extracted as pure functions instead, achieving testability
  without indirection.
- **Raw winapi/extern declarations (rejected)** — duplicates bindings already
  available; no benefit.

### Notes verified against the C++ reference

- `NCryptCreatePersistedKey` with `dwFlags = 0` uses provider defaults (2048-bit
  RSA for the PCP), exactly as the C++ passes `0, 0`.
- `NCryptEnumKeys` with `pszScope = null` lists all persisted keys for the current
  user in the provider.
- `SECURITY_STATUS` is an `NTSTATUS`-style `i32`; `NTE_NO_MORE_ITEMS` terminates
  enumeration. windows-rs 0.62 projects these constants under
  `Win32::Security::Cryptography`.

### Open Questions (resolve during implementation)

- Exact windows-rs 0.62 type of `SECURITY_STATUS` (plain `i32` vs newtype) and the
  `NCryptKeyName` field types (`PWSTR`) — verify at compile time; adjust the
  conversion helpers accordingly.
- Whether `NCryptEnumKeys` can return non-key entries or `pszAlgid == null` for
  some keys — treat null algid as an empty string.
