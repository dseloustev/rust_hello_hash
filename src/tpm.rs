use windows::core::{Error, PWSTR};
use windows::Win32::Foundation::{NTE_EXISTS, NTE_NO_KEY};

use crate::CliError;

pub struct TpmKeyInfo {
    pub name: String,
    pub algorithm: String,
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::HRESULT;
    use windows::Win32::Foundation::{NTE_FAIL, NTE_NO_MORE_ITEMS};

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
