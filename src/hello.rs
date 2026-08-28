use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerifierAvailability};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::{BinaryStringEncoding, CryptographicBuffer};
use windows::Storage::Streams::{DataWriter, IBuffer};
use windows::core::{Array, HSTRING};

use crate::CliError;

fn map_status(status: KeyCredentialStatus) -> Result<(), CliError> {
    if status == KeyCredentialStatus::Success {
        Ok(())
    } else if status == KeyCredentialStatus::NotFound {
        Err(CliError::KeyNotFound)
    } else if status == KeyCredentialStatus::UserCanceled {
        Err(CliError::UserCanceled)
    } else if status == KeyCredentialStatus::UserPrefersPassword {
        Err(CliError::UserPrefersPassword)
    } else if status == KeyCredentialStatus::CredentialAlreadyExists {
        Err(CliError::KeyAlreadyExists)
    } else if status == KeyCredentialStatus::SecurityDeviceLocked {
        Err(CliError::SecurityDeviceLocked)
    } else {
        Err(CliError::Unknown(format!(
            "unknown key credential status ({})",
            status.0
        )))
    }
}

fn to_utf16le(value: &str) -> windows::core::Result<IBuffer> {
    if value.is_empty() {
        return DataWriter::new()?.DetachBuffer();
    }
    CryptographicBuffer::ConvertStringToBinary(&HSTRING::from(value), BinaryStringEncoding::Utf16LE)
}

pub fn check_availability() -> Result<(), CliError> {
    let supported = KeyCredentialManager::IsSupportedAsync()?.join()?;
    if supported {
        return Ok(());
    }
    let availability = UserConsentVerifier::CheckAvailabilityAsync()?.join()?;
    if availability == UserConsentVerifierAvailability::Available {
        return Ok(());
    }
    let reason = if availability == UserConsentVerifierAvailability::DeviceNotPresent {
        "device not present"
    } else if availability == UserConsentVerifierAvailability::NotConfiguredForUser {
        "not configured for user"
    } else if availability == UserConsentVerifierAvailability::DisabledByPolicy {
        "disabled by policy"
    } else if availability == UserConsentVerifierAvailability::DeviceBusy {
        "device busy"
    } else {
        "unknown error occurred"
    };
    Err(CliError::HelloUnsupported(reason.to_string()))
}

pub fn open_credential(tag: &str) -> Result<KeyCredential, CliError> {
    let result = KeyCredentialManager::OpenAsync(&HSTRING::from(tag))?.join()?;
    map_status(result.Status()?)?;
    Ok(result.Credential()?)
}

pub fn create_credential(tag: &str) -> Result<(), CliError> {
    check_availability()?;
    let result = KeyCredentialManager::RequestCreateAsync(
        &HSTRING::from(tag),
        KeyCredentialCreationOption::FailIfExists,
    )?
    .join()?;
    map_status(result.Status()?)
}

pub fn delete_credential(tag: &str) -> Result<(), CliError> {
    check_availability()?;
    KeyCredentialManager::DeleteAsync(&HSTRING::from(tag))?.join()?;
    Ok(())
}

pub fn sign(tag: &str, challenge: &str) -> Result<Vec<u8>, CliError> {
    check_availability()?;
    let credential = open_credential(tag)?;
    let buffer = to_utf16le(challenge)?;
    let result = credential.RequestSignAsync(&buffer)?.join()?;
    map_status(result.Status()?)?;
    let mut bytes = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&result.Result()?, &mut bytes)?;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::Array;

    #[test]
    fn test_map_status_success() {
        assert!(map_status(KeyCredentialStatus::Success).is_ok());
    }

    #[test]
    fn test_map_status_not_found() {
        assert!(matches!(
            map_status(KeyCredentialStatus::NotFound),
            Err(CliError::KeyNotFound)
        ));
    }

    #[test]
    fn test_map_status_user_canceled() {
        assert!(matches!(
            map_status(KeyCredentialStatus::UserCanceled),
            Err(CliError::UserCanceled)
        ));
    }

    #[test]
    fn test_map_status_user_prefers_password() {
        assert!(matches!(
            map_status(KeyCredentialStatus::UserPrefersPassword),
            Err(CliError::UserPrefersPassword)
        ));
    }

    #[test]
    fn test_map_status_credential_already_exists() {
        assert!(matches!(
            map_status(KeyCredentialStatus::CredentialAlreadyExists),
            Err(CliError::KeyAlreadyExists)
        ));
    }

    #[test]
    fn test_map_status_security_device_locked() {
        assert!(matches!(
            map_status(KeyCredentialStatus::SecurityDeviceLocked),
            Err(CliError::SecurityDeviceLocked)
        ));
    }

    #[test]
    fn test_map_status_unknown_error_constant() {
        match map_status(KeyCredentialStatus::UnknownError) {
            Err(CliError::Unknown(_)) => {}
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn test_map_status_unmapped_value() {
        match map_status(KeyCredentialStatus(99)) {
            Err(CliError::Unknown(msg)) => assert!(msg.contains("99")),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn test_to_utf16le_byte_layout() {
        let buf = to_utf16le("abc").expect("conversion must succeed");
        let mut bytes = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&buf, &mut bytes).expect("copy must succeed");
        assert_eq!(bytes.to_vec(), vec![0x61, 0x00, 0x62, 0x00, 0x63, 0x00]);
    }

    #[test]
    fn test_to_utf16le_empty_string() {
        let buf = to_utf16le("").expect("conversion must succeed");
        let mut bytes = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&buf, &mut bytes).expect("copy must succeed");
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_check_availability_returns_without_panic() {
        match check_availability() {
            Ok(()) => {}
            Err(CliError::HelloUnsupported(reason)) => assert!(!reason.is_empty()),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_availability_reason_mapping_constants_exist() {
        assert_eq!(UserConsentVerifierAvailability::Available.0, 0);
    }
}
