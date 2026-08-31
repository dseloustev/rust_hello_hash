# TPM Key Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `hello-hash tpm create-key <NAME>` / `tpm delete-key <NAME>` / `tpm list-keys` subcommands that manage raw TPM persisted keys via Win32 NCrypt, mirroring `mfa_locker`'s `windows_tpm_repository_impl.cpp`.

**Architecture:** A new `src/tpm.rs` module (sibling of `hello.rs`) calls NCrypt functions directly through the existing `windows` crate. Errors surface as `Err(windows::core::Error)` whose `.code()` is an `HRESULT` matching `SECURITY_STATUS` values (`NTE_EXISTS` etc. are `HRESULT` constants in `Win32::Foundation`). Handles are owned by `windows::core::Owned<T>` RAII guards that free via `NCryptFreeObject` on drop. `CliError` gains three TPM variants; exit codes 3/4/5/8 reuse the existing table.

**Tech Stack:** Rust (edition 2024), `clap` 4.5 derive, `windows` 0.62.2 (existing dep; add feature `Win32_Security_Cryptography`). No other dependencies.

**Spec:** `docs/superpowers/specs/2026-08-31-tpm-key-management-design.md`

## Global Constraints

- Verbatim stderr messages: success-independent errors are printed by `main` as `Error: <message>`; `TPM key not found.`, `TPM key already exists.`, `TPM is not available (<detail>).` where detail is `NCryptOpenStorageProvider failed: 0x<UPPERCASE-HEX>`.
- Exit codes: `TpmKeyNotFound` = 3, `TpmKeyExists` = 4, `TpmUnavailable` = 5, other NCrypt failure (`Unknown`) = 8, usage error = 64, success = 0.
- Create is hard-coded to `NCRYPT_RSA_ALGORITHM`, flags 0, and MUST call `NCryptFinalizeKey` after `NCryptCreatePersistedKey` succeeds (an unfinalized key is discarded when its handle closes).
- On successful `NCryptDeleteKey` the key handle is already freed by the API — the code MUST NOT free it again (`std::mem::forget` the RAII guard).
- `list-keys` stdout is only `name<TAB>algid` lines; create/delete confirmations go to stderr.
- windows-rs 0.62 specifics (verified against crate source): NCrypt functions return `windows_core::Result<()>`; `NTE_EXISTS`/`NTE_NO_KEY`/`NTE_NO_MORE_ITEMS`/`NTE_FAIL` are `windows::core::HRESULT` consts in `Win32::Foundation`; `NCRYPT_FLAGS(u32)` and `CERT_KEY_SPEC(u32)` are tuple structs (pass `NCRYPT_FLAGS(0)` / `CERT_KEY_SPEC(0)`); `NCryptDeleteKey` takes plain `u32` flags; `MS_PLATFORM_CRYPTO_PROVIDER`/`NCRYPT_RSA_ALGORITHM` are `PCWSTR` consts in `Win32::Security::Cryptography`.
- Test/verify with `cargo test`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` (or `just check` / `just test`). Zero warnings required.
- Windows only; tests run on the dev machine (TPM present). The strict output discipline (R9-style) applies to the new commands.

## File Structure

- Modify: `Cargo.toml` — add `"Win32_Security_Cryptography"` to the `windows` features list.
- Modify: `src/main.rs` — `CliError` TPM variants (Task 1), `mod tpm;` (Task 2), `Command::Tpm(TpmCommand)` group + `run()` arms (Task 6).
- Create: `src/tpm.rs` — all NCrypt logic: `TpmKeyInfo`, `create_key`, `delete_key`, `list_keys`, `format_key_line`, `open_provider`, pure helpers `pwstr_to_string_lossy`, `ncrypt_failure`, `provider_unavailable`, `map_create_key_error`, `map_open_key_error`, `map_delete_key_error`.

---

### Task 1: `CliError` TPM variants

**Files:**
- Modify: `src/main.rs` (enum `CliError`, `exit_code()`, `message()`; tests in `mod tests`)

**Interfaces:**
- Consumes: existing `CliError` enum in `src/main.rs`.
- Produces: `CliError::TpmKeyNotFound` (exit 3, "TPM key not found."), `CliError::TpmKeyExists` (exit 4, "TPM key already exists."), `CliError::TpmUnavailable(String)` (exit 5, "TPM is not available ({detail}).").

- [ ] **Step 1: Write the failing tests**

In `src/main.rs`, append to `mod tests`:

```rust
    #[test]
    fn test_tpm_cli_error_exit_codes() {
        assert_eq!(CliError::TpmKeyNotFound.exit_code(), 3);
        assert_eq!(CliError::TpmKeyExists.exit_code(), 4);
        assert_eq!(CliError::TpmUnavailable("x".into()).exit_code(), 5);
    }

    #[test]
    fn test_tpm_cli_error_messages() {
        assert_eq!(CliError::TpmKeyNotFound.message(), "TPM key not found.");
        assert_eq!(CliError::TpmKeyExists.message(), "TPM key already exists.");
        assert_eq!(
            CliError::TpmUnavailable("no TPM".into()).message(),
            "TPM is not available (no TPM)."
        );
        assert_eq!(
            CliError::Unknown("NCryptEnumKeys failed: 0x8009002A".into()).message(),
            "NCryptEnumKeys failed: 0x8009002A."
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test tpm_cli_error`
Expected: FAIL — compile error `no variant named TpmKeyNotFound` (and `TpmKeyExists`, `TpmUnavailable`).

- [ ] **Step 3: Implement the variants**

In `src/main.rs`, extend the `CliError` enum (after `SecurityDeviceLocked`):

```rust
enum CliError {
    UserCanceled,
    KeyNotFound,
    KeyAlreadyExists,
    HelloUnsupported(String),
    SecurityDeviceLocked,
    UserPrefersPassword,
    Unknown(String),
    Usage(String),
    TpmKeyNotFound,
    TpmKeyExists,
    TpmUnavailable(String),
}
```

In `exit_code()` add (before the `Usage` arm or anywhere in the match):

```rust
            CliError::TpmKeyNotFound => 3,
            CliError::TpmKeyExists => 4,
            CliError::TpmUnavailable(_) => 5,
```

In `message()` add:

```rust
            CliError::TpmKeyNotFound => "TPM key not found.".to_string(),
            CliError::TpmKeyExists => "TPM key already exists.".to_string(),
            CliError::TpmUnavailable(detail) => {
                format!("TPM is not available ({detail}).")
            }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS — all tests including the two new ones (0 failed).

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "Add TPM error variants to CliError"
```

---

### Task 2: `tpm.rs` pure groundwork

**Files:**
- Modify: `Cargo.toml` (windows features list)
- Modify: `src/main.rs` (add `mod tpm;`)
- Create: `src/tpm.rs`

**Interfaces:**
- Consumes: `CliError` variants from Task 1 (`TpmKeyNotFound`, `TpmKeyExists`, `TpmUnavailable`, `Unknown`).
- Produces: `pub struct TpmKeyInfo { pub name: String, pub algorithm: String }`, `pub fn format_key_line(key: &TpmKeyInfo) -> String`, `fn pwstr_to_string_lossy(pw: PWSTR) -> String`, `fn ncrypt_failure(call: &str, err: &Error) -> CliError`, `fn provider_unavailable(err: Error) -> CliError`, `fn map_create_key_error(err: Error) -> CliError`, `fn map_open_key_error(err: Error) -> CliError`, `fn map_delete_key_error(err: Error) -> CliError`. Tasks 3–5 and 6 consume `TpmKeyInfo` + `format_key_line`; Tasks 3–5 consume the mapping helpers.

- [ ] **Step 1: Enable the cryptography feature**

In `Cargo.toml`, extend the `windows` features list (before the `Win32_System_SystemInformation` line; keep the existing comment style):

```toml
windows = { version = "0.62.2", features = [
    "Security_Credentials",       # KeyCredentialManager, KeyCredential, KeyCredentialStatus, KeyCredentialCreationOption
    "Security_Credentials_UI",    # UserConsentVerifier (availability diagnostics)
    "Security_Cryptography",      # CryptographicBuffer, BinaryStringEncoding
    "Storage_Streams",            # IBuffer (gates RequestSignAsync / Result())
    "Win32_System_SystemInformation", # GetLocalTime / SYSTEMTIME (bio-debug timestamps)
    "Win32_Security_Cryptography",    # NCrypt: TPM key create/delete/list
] }
```

(`Win32_Security_Cryptography` transitively enables `Win32_Foundation`, where the `NTE_*` HRESULT constants live.)

- [ ] **Step 2: Create the module with stubs and failing tests**

Add `mod tpm;` next to `mod debug_log;` at the top of `src/main.rs`. Create `src/tpm.rs`:

```rust
use windows::core::{Error, PWSTR};
use windows::Win32::Foundation::{NTE_EXISTS, NTE_NO_KEY, NTE_NO_MORE_ITEMS};

use crate::CliError;

pub struct TpmKeyInfo {
    pub name: String,
    pub algorithm: String,
}

pub fn format_key_line(key: &TpmKeyInfo) -> String {
    todo!()
}

fn pwstr_to_string_lossy(pw: PWSTR) -> String {
    todo!()
}

fn ncrypt_failure(call: &str, err: &Error) -> CliError {
    todo!()
}

fn provider_unavailable(err: Error) -> CliError {
    todo!()
}

fn map_create_key_error(err: Error) -> CliError {
    todo!()
}

fn map_open_key_error(err: Error) -> CliError {
    todo!()
}

fn map_delete_key_error(err: Error) -> CliError {
    todo!()
}
```

Then append the tests module at the end of `src/tpm.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::HRESULT;
    use windows::Win32::Foundation::NTE_FAIL;

    #[test]
    fn test_pwstr_to_string_lossy_basic() {
        let wide: [u16; 3] = [0x41, 0x42, 0x00];
        let pw = PWSTR(wide.as_ptr() as *mut u16);
        assert_eq!(pwstr_to_string_lossy(pw), "AB");
    }

    #[test]
    fn test_pwstr_to_string_lossy_null() {
        assert_eq!(pwstr_to_string_lossy(PWSTR::null()), "");
    }

    #[test]
    fn test_pwstr_to_string_lossy_invalid_utf16_is_lossy() {
        let wide: [u16; 2] = [0xD800, 0x00];
        let pw = PWSTR(wide.as_ptr() as *mut u16);
        assert_eq!(pwstr_to_string_lossy(pw), "\u{FFFD}");
    }

    #[test]
    fn test_format_key_line() {
        let info = TpmKeyInfo {
            name: "hello_hash_test".to_string(),
            algorithm: "RSA".to_string(),
        };
        assert_eq!(format_key_line(&info), "hello_hash_test\tRSA");
    }

    #[test]
    fn test_ncrypt_failure_formats_call_and_hresult() {
        let err = Error::from_hresult(NTE_NO_MORE_ITEMS);
        match ncrypt_failure("NCryptEnumKeys", &err) {
            CliError::Unknown(msg) => {
                assert_eq!(msg, "NCryptEnumKeys failed: 0x8009002A");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn test_provider_unavailable_wraps_detail() {
        let err = Error::from_hresult(HRESULT(0x80090020u32 as i32));
        match provider_unavailable(err) {
            CliError::TpmUnavailable(detail) => {
                assert_eq!(detail, "NCryptOpenStorageProvider failed: 0x80090020");
            }
            other => panic!("expected TpmUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn test_map_create_key_error_exists() {
        assert!(matches!(
            map_create_key_error(Error::from_hresult(NTE_EXISTS)),
            CliError::TpmKeyExists
        ));
    }

    #[test]
    fn test_map_create_key_error_generic() {
        match map_create_key_error(Error::from_hresult(NTE_FAIL)) {
            CliError::Unknown(msg) => {
                assert_eq!(msg, "NCryptCreatePersistedKey failed: 0x80090020");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn test_map_open_key_error_no_key() {
        assert!(matches!(
            map_open_key_error(Error::from_hresult(NTE_NO_KEY)),
            CliError::TpmKeyNotFound
        ));
    }

    #[test]
    fn test_map_open_key_error_generic() {
        match map_open_key_error(Error::from_hresult(NTE_FAIL)) {
            CliError::Unknown(msg) => {
                assert_eq!(msg, "NCryptOpenKey failed: 0x80090020");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn test_map_delete_key_error_no_key() {
        assert!(matches!(
            map_delete_key_error(Error::from_hresult(NTE_NO_KEY)),
            CliError::TpmKeyNotFound
        ));
    }

    #[test]
    fn test_map_delete_key_error_generic() {
        match map_delete_key_error(Error::from_hresult(NTE_FAIL)) {
            CliError::Unknown(msg) => {
                assert_eq!(msg, "NCryptDeleteKey failed: 0x80090020");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --lib` (or `cargo test`, project is a binary crate)
Expected: FAIL — the new tests panic with `not yet implemented` (`todo!()`).

- [ ] **Step 4: Implement the helpers**

Replace every `todo!()` body in `src/tpm.rs`:

```rust
pub fn format_key_line(key: &TpmKeyInfo) -> String {
    format!("{}\t{}", key.name, key.algorithm)
}

fn pwstr_to_string_lossy(pw: PWSTR) -> String {
    if pw.is_null() {
        String::new()
    } else {
        String::from_utf16_lossy(unsafe { pw.as_wide() })
    }
}

fn ncrypt_failure(call: &str, err: &Error) -> CliError {
    CliError::Unknown(format!("{call} failed: 0x{:X}", err.code().0 as u32))
}

fn provider_unavailable(err: Error) -> CliError {
    CliError::TpmUnavailable(format!(
        "NCryptOpenStorageProvider failed: 0x{:X}",
        err.code().0 as u32
    ))
}

fn map_create_key_error(err: Error) -> CliError {
    if err.code() == NTE_EXISTS {
        CliError::TpmKeyExists
    } else {
        ncrypt_failure("NCryptCreatePersistedKey", &err)
    }
}

fn map_open_key_error(err: Error) -> CliError {
    if err.code() == NTE_NO_KEY {
        CliError::TpmKeyNotFound
    } else {
        ncrypt_failure("NCryptOpenKey", &err)
    }
}

fn map_delete_key_error(err: Error) -> CliError {
    if err.code() == NTE_NO_KEY {
        CliError::TpmKeyNotFound
    } else {
        ncrypt_failure("NCryptDeleteKey", &err)
    }
}
```

(The unused `NTE_NO_MORE_ITEMS` import is used by Task 5; keep it only once Task 5 lands — if clippy warns about it now, remove it here and re-add it in Task 5.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS — all tests, zero failures.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/main.rs src/tpm.rs
git commit -m "Add tpm module pure helpers with tests"
```

---

### Task 3: Provider open + `create_key`

**Files:**
- Modify: `src/tpm.rs`

**Interfaces:**
- Consumes: `provider_unavailable`, `map_create_key_error`, `ncrypt_failure` from Task 2.
- Produces: `pub fn create_key(name: &str) -> Result<(), CliError>`, `fn open_provider() -> Result<Owned<NCRYPT_PROV_HANDLE>, CliError>`. Task 4/5 consume `open_provider`; Task 6 consumes `create_key`.

- [ ] **Step 1: Write the failing smoke test**

Append inside `mod tests` in `src/tpm.rs` (after the existing tests):

```rust
    #[test]
    fn test_open_provider_returns_without_panic() {
        match open_provider() {
            Ok(_) => {}
            Err(CliError::TpmUnavailable(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test tpm::tests`
Expected: FAIL — compile error `cannot find function open_provider in this module`.

- [ ] **Step 3: Implement `open_provider` and `create_key`**

In `src/tpm.rs`, update the imports and add the functions:

```rust
use windows::core::{Error, HSTRING, Owned, PWSTR};
use windows::Win32::Foundation::{NTE_EXISTS, NTE_NO_KEY, NTE_NO_MORE_ITEMS};
use windows::Win32::Security::Cryptography::{
    CERT_KEY_SPEC, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
    NCRYPT_RSA_ALGORITHM, NCryptCreatePersistedKey, NCryptFinalizeKey, NCryptOpenStorageProvider,
};

fn open_provider() -> Result<Owned<NCRYPT_PROV_HANDLE>, CliError> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) }
        .map_err(provider_unavailable)?;
    Ok(unsafe { Owned::new(provider) })
}

pub fn create_key(name: &str) -> Result<(), CliError> {
    let _provider = open_provider()?;
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    let key = unsafe {
        NCryptCreatePersistedKey(
            *_provider,
            &mut key_handle,
            NCRYPT_RSA_ALGORITHM,
            &HSTRING::from(name),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
        .map_err(map_create_key_error)?;
        Owned::new(key_handle)
    };
    unsafe { NCryptFinalizeKey(*key, NCRYPT_FLAGS(0)) }
        .map_err(|e| ncrypt_failure("NCryptFinalizeKey", &e))?;
    drop(key);
    Ok(())
}
```

Notes for the implementer (do not put in code comments): `Owned::new` takes ownership; on drop it calls `NCryptFreeObject` via the handle's `Free` impl. If `NCryptFinalizeKey` fails, `key` is dropped and the unfinalized key is discarded by the provider — mirroring the C++ RAII. `NCRYPT_RSA_ALGORITHM` is `PCWSTR` which satisfies the generic string parameter.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS — including `test_open_provider_returns_without_panic` (this machine has a TPM; on machines without one the `TpmUnavailable` arm is an accepted pass).

- [ ] **Step 5: Commit**

```bash
git add src/tpm.rs
git commit -m "Add TPM provider open and create-key"
```

---

### Task 4: `delete_key`

**Files:**
- Modify: `src/tpm.rs`

**Interfaces:**
- Consumes: `open_provider` (Task 3), `map_open_key_error`, `map_delete_key_error` (Task 2).
- Produces: `pub fn delete_key(name: &str) -> Result<(), CliError>`. Task 6 consumes it.

- [ ] **Step 1: Implement `delete_key`**

In `src/tpm.rs`, extend the `Win32::Security::Cryptography` import with `NCryptDeleteKey, NCryptOpenKey` and add:

```rust
pub fn delete_key(name: &str) -> Result<(), CliError> {
    let _provider = open_provider()?;
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    let key = unsafe {
        NCryptOpenKey(
            *_provider,
            &mut key_handle,
            &HSTRING::from(name),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
        .map_err(map_open_key_error)?;
        Owned::new(key_handle)
    };
    unsafe { NCryptDeleteKey(*key, 0) }.map_err(map_delete_key_error)?;
    core::mem::forget(key);
    Ok(())
}
```

Notes (not code comments): `NCryptDeleteKey` takes plain `u32` flags (not `NCRYPT_FLAGS`) — pass `0`. On success it frees the key handle itself, so `core::mem::forget(key)` prevents the RAII guard from double-freeing (C++ equivalent: `keyHandle.detach()`). On any `Err`, the guard drops and frees the handle — same as the C++ RAII on throw. There is no unit-testable surface here without mutating real TPM state; correctness is covered by the Task 7 manual smoke.

- [ ] **Step 2: Run tests to verify nothing regressed**

Run: `cargo test`
Expected: PASS — same set as Task 3, zero failures (delete_key is not yet reachable from the CLI).

- [ ] **Step 3: Commit**

```bash
git add src/tpm.rs
git commit -m "Add TPM delete-key"
```

---

### Task 5: `list_keys`

**Files:**
- Modify: `src/tpm.rs`

**Interfaces:**
- Consumes: `open_provider` (Task 3), `ncrypt_failure` (Task 2), `TpmKeyInfo` + `pwstr_to_string_lossy` (Task 2).
- Produces: `pub fn list_keys() -> Result<Vec<TpmKeyInfo>, CliError>`. Task 6 consumes it.

- [ ] **Step 1: Implement `list_keys`**

In `src/tpm.rs`, extend the `Win32::Security::Cryptography` import with `NCryptEnumKeys, NCryptFreeBuffer, NCryptKeyName` (and `NCRYPT_PROV_HANDLE` is already imported) and add:

```rust
pub fn list_keys() -> Result<Vec<TpmKeyInfo>, CliError> {
    let _provider = open_provider()?;
    let mut keys = Vec::new();
    let mut key_name: *mut NCryptKeyName = core::ptr::null_mut();
    let mut enum_state: *mut core::ffi::c_void = core::ptr::null_mut();
    loop {
        let status = unsafe {
            NCryptEnumKeys(
                *_provider,
                PWSTR::null(),
                &mut key_name,
                &mut enum_state,
                NCRYPT_FLAGS(0),
            )
        };
        match status {
            Ok(()) => {
                if !key_name.is_null() {
                    unsafe {
                        keys.push(TpmKeyInfo {
                            name: pwstr_to_string_lossy((*key_name).pszName),
                            algorithm: pwstr_to_string_lossy((*key_name).pszAlgid),
                        });
                        let _ = NCryptFreeBuffer(key_name.cast());
                    }
                    key_name = core::ptr::null_mut();
                }
            }
            Err(e) if e.code() == NTE_NO_MORE_ITEMS => break,
            Err(e) => {
                free_enum_state(enum_state, key_name);
                return Err(ncrypt_failure("NCryptEnumKeys", &e));
            }
        }
    }
    free_enum_state(enum_state, key_name);
    Ok(keys)
}

fn free_enum_state(enum_state: *mut core::ffi::c_void, key_name: *mut NCryptKeyName) {
    unsafe {
        if !enum_state.is_null() {
            let _ = NCryptFreeBuffer(enum_state.cast());
        }
        if !key_name.is_null() {
            let _ = NCryptFreeBuffer(key_name.cast());
        }
    }
}
```

Notes (not code comments): windows-rs surfaces `NTE_NO_MORE_ITEMS` (end of enumeration) as `Err` with that HRESULT code — that is the loop terminator, matching the C++ `status == NTE_NO_MORE_ITEMS` break. `pszAlgid` may be null for some providers — `pwstr_to_string_lossy` maps null to `""`.

- [ ] **Step 2: Run tests to verify nothing regressed**

Run: `cargo test`
Expected: PASS — zero failures.

- [ ] **Step 3: Commit**

```bash
git add src/tpm.rs
git commit -m "Add TPM list-keys"
```

---

### Task 6: CLI wiring

**Files:**
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `tpm::create_key`, `tpm::delete_key`, `tpm::list_keys`, `tpm::format_key_line`, `tpm::TpmKeyInfo` (Tasks 2–5).
- Produces: CLI surface `hello-hash tpm create-key <NAME>` / `hello-hash tpm delete-key <NAME>` / `hello-hash tpm list-keys`.

- [ ] **Step 1: Write the failing tests**

In `src/main.rs`, append to `mod tests`:

```rust
    #[test]
    fn test_tpm_create_key_parses_name() {
        match parse(&["tpm", "create-key", "my_key"]).expect("tpm create-key must parse") {
            Command::Tpm(TpmCommand::CreateKey { name }) => assert_eq!(name, "my_key"),
            other => panic!("expected Tpm(CreateKey), got {other:?}"),
        }
    }

    #[test]
    fn test_tpm_create_key_requires_name() {
        assert!(parse(&["tpm", "create-key"]).is_err());
    }

    #[test]
    fn test_tpm_delete_key_parses_name() {
        match parse(&["tpm", "delete-key", "my_key"]).expect("tpm delete-key must parse") {
            Command::Tpm(TpmCommand::DeleteKey { name }) => assert_eq!(name, "my_key"),
            other => panic!("expected Tpm(DeleteKey), got {other:?}"),
        }
    }

    #[test]
    fn test_tpm_delete_key_requires_name() {
        assert!(parse(&["tpm", "delete-key"]).is_err());
    }

    #[test]
    fn test_tpm_list_keys_parses() {
        match parse(&["tpm", "list-keys"]).expect("tpm list-keys must parse") {
            Command::Tpm(TpmCommand::ListKeys) => {}
            other => panic!("expected Tpm(ListKeys), got {other:?}"),
        }
    }

    #[test]
    fn test_tpm_list_keys_rejects_extra_args() {
        assert!(parse(&["tpm", "list-keys", "extra"]).is_err());
    }

    #[test]
    fn test_tpm_requires_subcommand() {
        assert!(parse(&["tpm"]).is_err());
    }

    #[test]
    fn test_tpm_unknown_subcommand_errors() {
        assert!(parse(&["tpm", "frobnicate"]).is_err());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test tpm_`
Expected: FAIL — compile error `cannot find type TpmCommand` / `no variant named Tpm`.

- [ ] **Step 3: Implement the CLI surface**

In `src/main.rs`:

1. Add `Command::Tpm(TpmCommand)` as a new variant of the `Command` enum (after `DeleteKey`).
2. Add the nested subcommand enum after `Command` (clap derive naming: variants kebab-case → `create-key`, `delete-key`, `list-keys`):

```rust
#[derive(Debug, Subcommand)]
enum TpmCommand {
    CreateKey {
        name: String,
    },
    DeleteKey {
        name: String,
    },
    ListKeys,
}
```

3. In `run()`, add the match arm:

```rust
        Command::Tpm(command) => match command {
            TpmCommand::CreateKey { name } => {
                tpm::create_key(&name)?;
                eprintln!("TPM key \"{name}\" created.");
                Ok(())
            }
            TpmCommand::DeleteKey { name } => {
                tpm::delete_key(&name)?;
                eprintln!("TPM key \"{name}\" deleted.");
                Ok(())
            }
            TpmCommand::ListKeys => {
                let keys = tpm::list_keys()?;
                for key in &keys {
                    println!("{}", tpm::format_key_line(key));
                }
                Ok(())
            }
        },
```

Note (not a code comment): `name` is `required = true` positional by default in clap derive (no `default_value` given) — do not add a default.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS — all tests including the eight new ones; zero failures.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "Wire tpm subcommand group into CLI"
```

---

### Task 7: Full verification + manual smoke

**Files:** none modified (verification only; commit only if fixes were needed)

**Interfaces:**
- Consumes: everything from Tasks 1–6.

- [ ] **Step 1: Lint, format, and build checks**

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Expected: all pass. If `fmt` fails, run `cargo fmt` and amend the previous commit's files in a new commit. If clippy flags an unused import (e.g. `NTE_NO_MORE_ITEMS` handling), fix and commit.

- [ ] **Step 2: Manual smoke on this machine (has TPM)**

Run each and verify (bash exit code via `echo $?`):

```bash
cargo run --quiet -- tpm list-keys
```
Expected: zero or more `name<TAB>algid` lines on stdout, exit 0.

```bash
cargo run --quiet -- tpm create-key hello_hash_plan_test; echo $?
```
Expected: stderr `TPM key "hello_hash_plan_test" created.`, exit 0.

```bash
cargo run --quiet -- tpm list-keys
```
Expected: output now contains a line `hello_hash_plan_test\tRSA`.

```bash
cargo run --quiet -- tpm create-key hello_hash_plan_test; echo $?
```
Expected: exit 4, stderr `Error: TPM key already exists.`

```bash
cargo run --quiet -- tpm delete-key hello_hash_plan_test; echo $?
```
Expected: stderr `TPM key "hello_hash_plan_test" deleted.`, exit 0.

```bash
cargo run --quiet -- tpm delete-key hello_hash_plan_test; echo $?
```
Expected: exit 3, stderr `Error: TPM key not found.`

- [ ] **Step 3: Regression check of existing commands**

```bash
cargo run --quiet -- --help
cargo run --quiet -- tpm --help
```
Expected: help text lists `tpm` group; `tpm --help` lists the three subcommands. `sign`, `generate-key`, `delete-key` parse tests already cover their behavior (no Windows Hello prompt needed for this verification step — do not run `sign`, it requires interactive prompt).

- [ ] **Step 4: Commit (only if any fix was required)**

```bash
git add -A && git commit -m "Fix issues found in TPM verification" || echo "nothing to commit"
```
