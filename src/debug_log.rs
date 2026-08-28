use windows::Win32::System::SystemInformation::GetLocalTime;

use crate::hash::hex_encode;

pub fn slice_middle(hex: &str) -> String {
    if hex.is_empty() {
        return "<empty>".to_string();
    }
    if hex.len() <= 32 {
        return hex.to_string();
    }
    let start = (hex.len() - 32) / 2;
    hex[start..start + 32].to_string()
}

pub fn timestamp() -> String {
    // GetLocalTime never fails and always returns a fully-initialized SYSTEMTIME.
    let st = unsafe { GetLocalTime() };
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
    )
}

pub fn format_signature_line(ts: &str, op: &str, tag: &str, sig: &[u8]) -> String {
    format!(
        "[bio-debug] {ts} op={op} tag={tag} sig={}",
        slice_middle(&hex_encode(sig))
    )
}

pub fn format_key_line(ts: &str, hash: &[u8]) -> String {
    format!("[bio-debug] {ts} key={}", slice_middle(&hex_encode(hash)))
}

pub fn log_signature(op: &str, tag: &str, sig: &[u8]) {
    println!("{}", format_signature_line(&timestamp(), op, tag, sig));
}

pub fn log_key_hash(hash: &[u8]) {
    println!("{}", format_key_line(&timestamp(), hash));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterned_hex(len: usize) -> String {
        (0..len)
            .map(|i| char::from_digit((i % 16) as u32, 16).unwrap())
            .collect()
    }

    #[test]
    fn slice_middle_empty_returns_placeholder() {
        assert_eq!(slice_middle(""), "<empty>");
    }

    #[test]
    fn slice_middle_short_input_returns_full_string() {
        assert_eq!(slice_middle("abcde"), "abcde");
    }

    #[test]
    fn slice_middle_exact_64_chars_returns_chars_16_to_47() {
        let input = patterned_hex(64);
        assert_eq!(slice_middle(&input), input[16..48]);
    }

    #[test]
    fn slice_middle_long_input_returns_middle_32() {
        let input = patterned_hex(512);
        assert_eq!(slice_middle(&input), input[240..272]);
    }

    #[test]
    fn slice_middle_odd_length_matches_cpp_integer_division() {
        let len33 = patterned_hex(33);
        assert_eq!(slice_middle(&len33), len33[0..32]);
        let len100 = patterned_hex(100);
        assert_eq!(slice_middle(&len100), len100[34..66]);
    }

    #[test]
    fn slice_middle_boundary_32_and_33() {
        let len32 = patterned_hex(32);
        assert_eq!(slice_middle(&len32), len32);
        let len33 = patterned_hex(33);
        assert_eq!(slice_middle(&len33), len33[0..32]);
    }

    #[test]
    fn timestamp_format_is_hh_mm_ss_mmm() {
        let ts = timestamp();
        assert_eq!(ts.len(), 12, "timestamp must be HH:MM:SS.mmm: {ts}");
        let bytes = ts.as_bytes();
        assert_eq!(bytes[2], b':');
        assert_eq!(bytes[5], b':');
        assert_eq!(bytes[8], b'.');
        for (i, b) in bytes.iter().enumerate() {
            if i == 2 || i == 5 || i == 8 {
                continue;
            }
            assert!(b.is_ascii_digit(), "char at {i} must be a digit: {ts}");
        }
    }

    #[test]
    fn format_signature_line_exact_layout() {
        let sig: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            format_signature_line("12:34:56.789", "sign", "mytag", &sig),
            "[bio-debug] 12:34:56.789 op=sign tag=mytag sig=08090a0b0c0d0e0f1011121314151617"
        );
    }

    #[test]
    fn format_key_line_exact_layout() {
        let hash: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            format_key_line("12:34:56.789", &hash),
            "[bio-debug] 12:34:56.789 key=08090a0b0c0d0e0f1011121314151617"
        );
    }
}
