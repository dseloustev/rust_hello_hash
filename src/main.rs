mod debug_log;
mod hash;
mod hello;
mod tpm;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "hello-hash", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Sign {
        #[arg(default_value = "locker_authentication_request")]
        challenge: String,
        #[arg(long, default_value = "mfa_demo_bio_key")]
        tag: String,
    },
    GenerateKey {
        #[arg(long, default_value = "mfa_demo_bio_key")]
        tag: String,
    },
    DeleteKey {
        #[arg(long, default_value = "mfa_demo_bio_key")]
        tag: String,
    },
    #[command(subcommand)]
    Tpm(TpmCommand),
}

#[derive(Debug, Subcommand)]
enum TpmCommand {
    CreateKey { name: String },
    DeleteKey { name: String },
    ListKeys,
}

#[derive(Debug)]
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

impl CliError {
    fn exit_code(&self) -> i32 {
        match self {
            CliError::UserCanceled => 2,
            CliError::KeyNotFound => 3,
            CliError::KeyAlreadyExists => 4,
            CliError::HelloUnsupported(_) => 5,
            CliError::SecurityDeviceLocked => 6,
            CliError::UserPrefersPassword => 7,
            CliError::Unknown(_) => 8,
            CliError::Usage(_) => 64,
            CliError::TpmKeyNotFound => 3,
            CliError::TpmKeyExists => 4,
            CliError::TpmUnavailable(_) => 5,
        }
    }

    fn message(&self) -> String {
        match self {
            CliError::UserCanceled => "user canceled the operation.".to_string(),
            CliError::KeyNotFound => "key credential not found.".to_string(),
            CliError::KeyAlreadyExists => "key credential already exists.".to_string(),
            CliError::HelloUnsupported(reason) => {
                format!("Windows Hello is not supported ({reason}).")
            }
            CliError::SecurityDeviceLocked => "security device is locked.".to_string(),
            CliError::UserPrefersPassword => "user prefers password.".to_string(),
            CliError::Unknown(description) => {
                format!("{}.", description.trim_end_matches('.'))
            }
            CliError::Usage(usage) => usage.clone(),
            CliError::TpmKeyNotFound => "TPM key not found.".to_string(),
            CliError::TpmKeyExists => "TPM key already exists.".to_string(),
            CliError::TpmUnavailable(detail) => {
                format!("TPM is not available ({detail}).")
            }
        }
    }
}

impl From<windows::core::Error> for CliError {
    fn from(err: windows::core::Error) -> Self {
        CliError::Unknown(err.message().to_string())
    }
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) if err.use_stderr() => {
            let cli_err = CliError::Usage(err.to_string());
            eprint!("{}", cli_err.message());
            std::process::exit(cli_err.exit_code());
        }
        Err(err) => {
            print!("{err}");
            std::process::exit(0);
        }
    };
    if let Err(err) = run(cli.command) {
        eprintln!("Error: {}", err.message());
        std::process::exit(err.exit_code());
    }
}

fn run(command: Command) -> Result<(), CliError> {
    match command {
        Command::Sign { challenge, tag } => {
            let signature = hello::sign(&tag, &challenge)?;
            debug_log::log_signature("sign", &tag, &signature);
            let digest = hash::sha256_digest(&signature);
            debug_log::log_key_hash(&digest);
            println!("{}", hash::hex_encode(&digest));
            Ok(())
        }
        Command::GenerateKey { tag } => {
            hello::create_credential(&tag)?;
            eprintln!("Key credential \"{tag}\" created.");
            Ok(())
        }
        Command::DeleteKey { tag } => {
            hello::delete_credential(&tag)?;
            eprintln!("Key credential \"{tag}\" deleted.");
            Ok(())
        }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(std::iter::once("hello-hash").chain(args.iter().copied()))
            .map(|cli| cli.command)
    }

    #[test]
    fn test_default_tag_and_challenge() {
        let cmd = parse(&["sign"]).expect("sign with defaults must parse");
        match cmd {
            Command::Sign { challenge, tag } => {
                assert_eq!(challenge, "locker_authentication_request");
                assert_eq!(tag, "mfa_demo_bio_key");
            }
            other => panic!("expected Sign, got {other:?}"),
        }
    }

    #[test]
    fn test_explicit_challenge_overrides_default() {
        let cmd = parse(&["sign", "my challenge"]).expect("explicit challenge must parse");
        match cmd {
            Command::Sign { challenge, tag } => {
                assert_eq!(challenge, "my challenge");
                assert_eq!(tag, "mfa_demo_bio_key");
            }
            other => panic!("expected Sign, got {other:?}"),
        }
    }

    #[test]
    fn test_explicit_tag_overrides_default() {
        let cmd = parse(&["sign", "--tag", "other"]).expect("explicit tag must parse");
        match cmd {
            Command::Sign { challenge, tag } => {
                assert_eq!(challenge, "locker_authentication_request");
                assert_eq!(tag, "other");
            }
            other => panic!("expected Sign, got {other:?}"),
        }
    }

    #[test]
    fn test_empty_string_challenge_is_used_not_default() {
        let cmd = parse(&["sign", ""]).expect("empty challenge must parse");
        match cmd {
            Command::Sign { challenge, tag } => {
                assert_eq!(challenge, "");
                assert_eq!(tag, "mfa_demo_bio_key");
            }
            other => panic!("expected Sign, got {other:?}"),
        }
    }

    #[test]
    fn test_unicode_challenge_accepted() {
        let input = "привет 🔐";
        let cmd = parse(&["sign", input]).expect("unicode challenge must parse");
        match cmd {
            Command::Sign { challenge, .. } => assert_eq!(challenge, input),
            other => panic!("expected Sign, got {other:?}"),
        }
    }

    #[test]
    fn test_tag_with_spaces_accepted() {
        let cmd = parse(&["sign", "--tag", "my key tag"]).expect("tag with spaces must parse");
        match cmd {
            Command::Sign { tag, .. } => assert_eq!(tag, "my key tag"),
            other => panic!("expected Sign, got {other:?}"),
        }
    }

    #[test]
    fn test_unknown_subcommand_errors() {
        assert!(parse(&["frobnicate"]).is_err());
    }

    #[test]
    fn test_subcommand_required() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn test_second_positional_rejected() {
        assert!(parse(&["sign", "a", "b"]).is_err());
    }

    #[test]
    fn test_generate_key_and_delete_key_default_tag() {
        match parse(&["generate-key"]).expect("generate-key must parse") {
            Command::GenerateKey { tag } => assert_eq!(tag, "mfa_demo_bio_key"),
            other => panic!("expected GenerateKey, got {other:?}"),
        }
        match parse(&["delete-key"]).expect("delete-key must parse") {
            Command::DeleteKey { tag } => assert_eq!(tag, "mfa_demo_bio_key"),
            other => panic!("expected DeleteKey, got {other:?}"),
        }
    }

    #[test]
    fn test_cli_error_exit_codes() {
        assert_eq!(CliError::UserCanceled.exit_code(), 2);
        assert_eq!(CliError::KeyNotFound.exit_code(), 3);
        assert_eq!(CliError::KeyAlreadyExists.exit_code(), 4);
        assert_eq!(CliError::HelloUnsupported("x".into()).exit_code(), 5);
        assert_eq!(CliError::SecurityDeviceLocked.exit_code(), 6);
        assert_eq!(CliError::UserPrefersPassword.exit_code(), 7);
        assert_eq!(CliError::Unknown("x".into()).exit_code(), 8);
        assert_eq!(CliError::Usage("x".into()).exit_code(), 64);
    }

    #[test]
    fn test_cli_error_message_prefixes() {
        assert_eq!(
            CliError::UserCanceled.message(),
            "user canceled the operation."
        );
        assert_eq!(CliError::KeyNotFound.message(), "key credential not found.");
        assert_eq!(
            CliError::KeyAlreadyExists.message(),
            "key credential already exists."
        );
        assert_eq!(
            CliError::HelloUnsupported("device not present".into()).message(),
            "Windows Hello is not supported (device not present)."
        );
        assert_eq!(
            CliError::SecurityDeviceLocked.message(),
            "security device is locked."
        );
        assert_eq!(
            CliError::UserPrefersPassword.message(),
            "user prefers password."
        );
        assert_eq!(CliError::Unknown("boom".into()).message(), "boom.");
    }

    #[test]
    fn test_unknown_message_no_double_period() {
        assert_eq!(
            CliError::Unknown("some error.".into()).message(),
            "some error."
        );
    }

    #[test]
    fn test_tpm_cli_error_exit_codes() {
        assert_eq!(CliError::TpmKeyNotFound.exit_code(), 3);
        assert_eq!(CliError::TpmKeyExists.exit_code(), 4);
        assert_eq!(CliError::TpmUnavailable("x".into()).exit_code(), 5);
    }

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
}
