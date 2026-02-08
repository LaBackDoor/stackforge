//! Hexdump and hex string utilities.

use std::fmt::Write;

/// Generate a hexdump of bytes in the style of `xxd` or Scapy's hexdump.
///
/// # Example
/// ```
/// use stackforge_core::hexdump;
/// let data = b"Hello, World!";
/// println!("{}", hexdump(data));
/// ```
pub fn hexdump(data: &[u8]) -> String {
    let mut output = String::new();
    let mut offset = 0;

    for chunk in data.chunks(16) {
        // Offset
        write!(output, "{:08x}  ", offset).unwrap();

        // Hex bytes
        for (i, byte) in chunk.iter().enumerate() {
            if i == 8 {
                output.push(' ');
            }
            write!(output, "{:02x} ", byte).unwrap();
        }

        // Padding for incomplete lines
        if chunk.len() < 16 {
            for i in chunk.len()..16 {
                if i == 8 {
                    output.push(' ');
                }
                output.push_str("   ");
            }
        }

        // ASCII representation
        output.push(' ');
        output.push('|');
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push('|');
        output.push('\n');

        offset += 16;
    }

    output
}

/// Generate a compact hex string representation.
pub fn hexstr(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len() * 2);
    for byte in data {
        write!(output, "{:02x}", byte).unwrap();
    }
    output
}

/// Generate hex string with separator.
pub fn hexstr_sep(data: &[u8], sep: &str) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(sep)
}

/// Parse a hex string into bytes.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().replace(" ", "").replace(":", "").replace("-", "");

    if s.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {}: {}", i, e))
        })
        .collect()
}

/// Convert bytes to a pretty-printed representation (like Scapy's show()).
pub fn pretty_bytes(data: &[u8], indent: usize) -> String {
    let indent_str = " ".repeat(indent);
    let mut output = String::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        if i > 0 {
            output.push('\n');
        }
        output.push_str(&indent_str);

        for byte in chunk {
            write!(output, "{:02x} ", byte).unwrap();
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hexdump() {
        let data = b"Hello, World!";
        let dump = hexdump(data);
        assert!(dump.contains("48 65 6c 6c")); // "Hell"
        assert!(dump.contains("|Hello, World!|"));
    }

    #[test]
    fn test_hexstr() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hexstr(&data), "deadbeef");
        assert_eq!(hexstr_sep(&data, ":"), "de:ad:be:ef");
    }

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            parse_hex("de:ad:be:ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            parse_hex("de ad be ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(parse_hex("dea").is_err()); // Odd length
    }
}
