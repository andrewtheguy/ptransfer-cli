//! Z85 (ZeroMQ base85) with partial final blocks, the encoding every chunk
//! travels in.
//!
//! It is what the event content is: ~1.25x expansion against base64's ~1.33x,
//! and an alphabet with no character JSON has to escape, so a 48 KiB chunk
//! lands just under the ~63 KiB content ceiling the public relay population
//! actually accepts.

use anyhow::{Result, bail};

const ALPHABET: &[u8; 85] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";

/// The value of a byte that is not a Z85 digit.
const NO_VALUE: u8 = u8::MAX;

/// [`ALPHABET`] reversed, built at compile time. Decoding walks every
/// character of a ~60 KiB event content, so a scan of the alphabet per
/// character is most of what decoding a chunk costs.
const VALUES: [u8; 256] = {
    let mut table = [NO_VALUE; 256];
    let mut index = 0;
    while index < ALPHABET.len() {
        table[ALPHABET[index] as usize] = index as u8;
        index += 1;
    }
    table
};

/// Encode arbitrary-length bytes. A trailing group of 1-3 bytes is zero-padded
/// to four, encoded, and truncated to `remaining + 1` characters — the Ascii85
/// partial-block scheme on the Z85 alphabet.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(4) * 5);
    for group in data.chunks(4) {
        let mut value: u32 = 0;
        for index in 0..4 {
            value = value
                .wrapping_mul(256)
                .wrapping_add(u32::from(group.get(index).copied().unwrap_or(0)));
        }
        let mut digits = [0u8; 5];
        for digit in digits.iter_mut().rev() {
            *digit = ALPHABET[(value % 85) as usize];
            value /= 85;
        }
        let take = if group.len() == 4 { 5 } else { group.len() + 1 };
        out.push_str(std::str::from_utf8(&digits[..take]).expect("alphabet is ASCII"));
    }
    out
}

/// Decode what [`encode`] produced. A trailing group of exactly one character
/// cannot encode a byte, and neither can a group whose value overflows 32
/// bits, so both are refused rather than truncated into something plausible.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    let remainder = bytes.len() % 5;
    if remainder == 1 {
        bail!("Z85 text of an impossible length");
    }
    let mut out = Vec::with_capacity(bytes.len() / 5 * 4 + remainder.saturating_sub(1));
    for group in bytes.chunks(5) {
        let mut value: u64 = 0;
        for index in 0..5 {
            // Short trailing groups are padded with the maximum digit, which
            // mirrors the zero-byte padding the encoder applied.
            let digit = match group.get(index) {
                Some(character) => digit_value(*character)?,
                None => 84,
            };
            value = value * 85 + u64::from(digit);
        }
        if value > u64::from(u32::MAX) {
            bail!("Z85 group out of range");
        }
        let word = (value as u32).to_be_bytes();
        let take = if group.len() == 5 { 4 } else { group.len() - 1 };
        out.extend_from_slice(&word[..take]);
    }
    Ok(out)
}

fn digit_value(character: u8) -> Result<u8> {
    match VALUES[character as usize] {
        NO_VALUE => bail!("Z85 text carries a character the alphabet has no value for"),
        value => Ok(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vector from the Z85 specification, which is what pins the alphabet
    /// and the digit order rather than this implementation's own output.
    #[test]
    fn the_specifications_own_vector_encodes_as_it_says() {
        let data = [0x86, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        assert_eq!(encode(&data), "HelloWorld");
        assert_eq!(decode("HelloWorld").unwrap(), data);
    }

    /// Every partial final block, which is the half of the scheme a
    /// four-byte-aligned test would never reach.
    #[test]
    fn any_length_round_trips() {
        for length in 0..=32usize {
            let data: Vec<u8> = (0..length).map(|index| (index * 7 + 3) as u8).collect();
            let text = encode(&data);
            assert_eq!(text.len(), length / 4 * 5 + (length % 4) + usize::from(length % 4 != 0));
            assert_eq!(decode(&text).unwrap(), data, "length {length}");
        }
    }

    #[test]
    fn text_that_is_not_z85_is_refused() {
        // A lone trailing character cannot encode a byte.
        assert!(decode("HelloWorld1").is_err());
        // A character outside the alphabet, and a group that overflows.
        assert!(decode("Hello`orld").is_err());
        assert!(decode("#####").is_err());
    }
}
