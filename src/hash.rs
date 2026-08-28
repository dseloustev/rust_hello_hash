use sha2::{Digest, Sha256};

pub fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{hex_encode, sha256_digest};

    #[test]
    fn test_sha256_empty_input() {
        assert_eq!(
            hex_encode(&sha256_digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        assert_eq!(
            hex_encode(&sha256_digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_boundary_55_bytes() {
        assert_eq!(
            hex_encode(&sha256_digest(&[b'a'; 55])),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
    }

    #[test]
    fn test_sha256_boundary_56_bytes() {
        assert_eq!(
            hex_encode(&sha256_digest(&[b'a'; 56])),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
    }

    #[test]
    fn test_sha256_boundary_64_bytes() {
        assert_eq!(
            hex_encode(&sha256_digest(&[b'a'; 64])),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
    }

    #[test]
    fn test_output_is_64_lowercase_hex_chars() {
        let out = hex_encode(&sha256_digest(b"X"));
        assert_eq!(out.len(), 64);
        assert!(
            out.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "output must be lowercase hex: {out}"
        );
    }

    #[test]
    fn sha256_digest_abc_matches_known_answer() {
        let digest = sha256_digest(b"abc");
        assert_eq!(digest.len(), 32);
        assert_eq!(
            hex_encode(&digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_encode_known_bytes_lowercase() {
        assert_eq!(hex_encode(&[0x9d, 0xe6, 0x0c]), "9de60c");
    }

    #[test]
    fn hex_encode_empty_returns_empty() {
        assert_eq!(hex_encode(&[]), "");
    }
}
