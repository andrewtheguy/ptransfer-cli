//! Crockford Base32 for the human-transcribed Nostr confirmation code.

/// Number of raw HKDF output bytes in a confirmation code (40 bits).
pub const CONFIRMATION_CODE_BYTES: usize = 5;
/// Number of displayed Crockford Base32 characters.
pub const CONFIRMATION_CODE_LENGTH: usize = 8;

const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encode bytes as unpadded Crockford Base32, most-significant bit first.
pub fn encode_crockford_base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0_u32;
    let mut bits = 0_u32;

    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD_ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }

    if bits > 0 {
        out.push(CROCKFORD_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }

    out
}

/// Normalize a typed confirmation code exactly like pTransfer.
///
/// ASCII case is folded, spaces/hyphens are dropped, `I`/`L` become `1`, `O`
/// becomes `0`, and remaining characters outside the Crockford alphabet are
/// discarded.
pub fn normalize_crockford_base32(input: &str) -> String {
    let mut out = String::with_capacity(input.len());

    for byte in input.bytes().map(|byte| byte.to_ascii_uppercase()) {
        match byte {
            b' ' | b'-' | b'\t' | b'\n' => {}
            b'I' | b'L' => out.push('1'),
            b'O' => out.push('0'),
            byte if CROCKFORD_ALPHABET.contains(&byte) => out.push(byte as char),
            _ => {}
        }
    }

    out
}

/// Compare normalized codes without returning early on a mismatched byte.
pub fn constant_time_equal(a: &str, b: &str) -> bool {
    let max_len = a.len().max(b.len());
    let mut difference = a.len() ^ b.len();

    for index in 0..max_len {
        let a_byte = a.as_bytes().get(index).copied().unwrap_or(0);
        let b_byte = b.as_bytes().get(index).copied().unwrap_or(0);
        difference |= usize::from(a_byte ^ b_byte);
    }

    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors_match_web() {
        assert_eq!(encode_crockford_base32(&[0x00]), "00");
        assert_eq!(encode_crockford_base32(&[0xff]), "ZW");
        assert_eq!(encode_crockford_base32(&[0x00, 0x44, 0x32]), "01234");
        assert_eq!(encode_crockford_base32(&[0xab; 5]).len(), 8);
    }

    #[test]
    fn normalization_matches_web() {
        assert_eq!(normalize_crockford_base32("IiLlOo"), "111100");
        assert_eq!(normalize_crockford_base32(" A4bc-d9zt \n"), "A4BCD9ZT");
        assert_eq!(normalize_crockford_base32("A4?B*C%9U"), "A4BC9");
    }

    #[test]
    fn equality_handles_content_and_length_mismatches() {
        assert!(constant_time_equal("A4BCD9ZT", "A4BCD9ZT"));
        assert!(!constant_time_equal("A4BCD9ZT", "A4BCD9ZS"));
        assert!(!constant_time_equal("A4BCD9ZT", "A4BCD9Z"));
    }
}
