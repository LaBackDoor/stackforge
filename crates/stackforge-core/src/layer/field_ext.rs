//! Extended field types for complex protocol fields.
//!
//! This module provides:
//! - `DnsName`: DNS domain name with pointer compression support
//! - `FlagValue`: Named bit flags with display support
//! - Bit field reader utilities

use std::collections::HashMap;
use std::fmt;

use super::field::FieldError;

// ============================================================================
// DNS Name (RFC 1035 Section 4.1.4)
// ============================================================================

/// Maximum number of pointer hops to prevent infinite loops.
const DNS_MAX_POINTER_HOPS: usize = 128;
/// Maximum label length per RFC 1035.
const DNS_MAX_LABEL_LEN: usize = 63;
/// Maximum total name length per RFC 1035.
const DNS_MAX_NAME_LEN: usize = 253;
/// Pointer flag: top 2 bits set indicates a compression pointer.
const DNS_POINTER_FLAG: u8 = 0xC0;

/// A DNS domain name consisting of labels.
///
/// Supports encoding/decoding with RFC 1035 compression pointers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DnsName {
    /// The labels making up the domain name (e.g., ["www", "example", "com"]).
    pub labels: Vec<String>,
}

impl DnsName {
    /// Create a new `DnsName` from labels.
    #[must_use]
    pub fn new(labels: Vec<String>) -> Self {
        Self { labels }
    }

    /// Create a root name (empty labels).
    #[must_use]
    pub fn root() -> Self {
        Self { labels: vec![] }
    }

    /// Parse a DNS name from a dot-separated string.
    /// "www.example.com" → labels: ["www", "example", "com"]
    /// "www.example.com." → same (trailing dot is ignored)
    pub fn from_str_dotted(s: &str) -> Result<Self, FieldError> {
        if s.is_empty() || s == "." {
            return Ok(Self::root());
        }
        let s = s.strip_suffix('.').unwrap_or(s);
        let labels: Vec<String> = s.split('.').map(std::string::ToString::to_string).collect();
        // Validate label lengths
        for label in &labels {
            if label.len() > DNS_MAX_LABEL_LEN {
                return Err(FieldError::InvalidValue(format!(
                    "DNS label too long: {} bytes (max {})",
                    label.len(),
                    DNS_MAX_LABEL_LEN
                )));
            }
        }
        let total_len: usize = labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1;
        if total_len > DNS_MAX_NAME_LEN + 2 {
            return Err(FieldError::InvalidValue(format!(
                "DNS name too long: {total_len} bytes (max {DNS_MAX_NAME_LEN})"
            )));
        }
        Ok(Self { labels })
    }

    /// Check if this is the root name.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Get the fully qualified domain name string.
    /// Returns "www.example.com." with trailing dot.
    #[must_use]
    pub fn to_fqdn(&self) -> String {
        if self.labels.is_empty() {
            return ".".to_string();
        }
        format!("{}.", self.labels.join("."))
    }

    /// Encode to wire format without compression.
    /// Each label is preceded by its length byte, terminated by a zero byte.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for label in &self.labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0); // root label
        out
    }

    /// Encode to wire format with compression.
    /// Uses `compression_map` to track previously written name positions.
    /// `current_offset` is where this name will be written in the packet.
    pub fn encode_compressed(
        &self,
        current_offset: usize,
        compression_map: &mut HashMap<String, u16>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut offset = current_offset;

        for i in 0..self.labels.len() {
            // Check if the suffix from this label onwards was already written
            let suffix = self.labels[i..].join(".");
            if let Some(&ptr) = compression_map.get(&suffix) {
                // Write a pointer to the previous occurrence
                out.push(DNS_POINTER_FLAG | ((ptr >> 8) as u8));
                out.push((ptr & 0xFF) as u8);
                return out;
            }
            // Record this suffix position in the compression map
            if offset < 0x3FFF {
                compression_map.insert(suffix, offset as u16);
            }
            // Write the label
            let label = &self.labels[i];
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
            offset += 1 + label.len();
        }
        out.push(0); // root label
        out
    }

    /// Decode a DNS name from wire format with pointer decompression.
    ///
    /// `packet` is the full packet buffer (needed for pointer resolution).
    /// `offset` is the starting position of the name.
    ///
    /// Returns the decoded name and the number of bytes consumed from `offset`
    /// (not counting bytes reached via pointers).
    pub fn decode(packet: &[u8], offset: usize) -> Result<(Self, usize), FieldError> {
        let mut labels = Vec::new();
        let mut pos = offset;
        let mut bytes_consumed = 0;
        let mut followed_pointer = false;
        let mut hops = 0;

        loop {
            if pos >= packet.len() {
                return Err(FieldError::BufferTooShort {
                    offset: pos,
                    need: 1,
                    have: packet.len(),
                });
            }

            let len_or_ptr = packet[pos];

            if len_or_ptr == 0 {
                // Root label — end of name
                if !followed_pointer {
                    bytes_consumed = pos - offset + 1;
                }
                break;
            } else if len_or_ptr & DNS_POINTER_FLAG == DNS_POINTER_FLAG {
                // Compression pointer
                if pos + 1 >= packet.len() {
                    return Err(FieldError::BufferTooShort {
                        offset: pos,
                        need: 2,
                        have: packet.len(),
                    });
                }
                let ptr = (((len_or_ptr & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);

                if !followed_pointer {
                    bytes_consumed = pos - offset + 2;
                    followed_pointer = true;
                }

                hops += 1;
                if hops > DNS_MAX_POINTER_HOPS {
                    return Err(FieldError::InvalidValue(
                        "DNS name compression loop detected".to_string(),
                    ));
                }

                if ptr >= packet.len() {
                    return Err(FieldError::InvalidValue(format!(
                        "DNS compression pointer {:#06x} out of bounds (packet len {})",
                        ptr,
                        packet.len()
                    )));
                }

                pos = ptr;
            } else {
                // Regular label
                let label_len = len_or_ptr as usize;
                if label_len > DNS_MAX_LABEL_LEN {
                    return Err(FieldError::InvalidValue(format!(
                        "DNS label too long: {label_len} bytes (max {DNS_MAX_LABEL_LEN})"
                    )));
                }
                if pos + 1 + label_len > packet.len() {
                    return Err(FieldError::BufferTooShort {
                        offset: pos + 1,
                        need: label_len,
                        have: packet.len() - pos - 1,
                    });
                }
                let label =
                    String::from_utf8_lossy(&packet[pos + 1..pos + 1 + label_len]).into_owned();
                labels.push(label);
                pos += 1 + label_len;
            }
        }

        Ok((Self { labels }, bytes_consumed))
    }

    /// Wire-format length of this name without compression.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        if self.labels.is_empty() {
            return 1; // just the root label (0x00)
        }
        self.labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            write!(f, ".")
        } else {
            write!(f, "{}.", self.labels.join("."))
        }
    }
}

impl From<&str> for DnsName {
    fn from(s: &str) -> Self {
        DnsName::from_str_dotted(s).unwrap_or_default()
    }
}

// ============================================================================
// FlagValue - Named bit flags
// ============================================================================

/// Named bit flags for protocol fields.
///
/// Stores a flag value along with names for each bit position.
#[derive(Debug, Clone)]
pub struct FlagValue {
    /// The raw flag bits.
    pub value: u64,
    /// Flag names indexed by bit position (LSB = index 0).
    pub names: &'static [&'static str],
}

impl FlagValue {
    #[must_use]
    pub fn new(value: u64, names: &'static [&'static str]) -> Self {
        Self { value, names }
    }

    /// Check if a specific flag bit is set.
    #[must_use]
    pub fn has(&self, bit: usize) -> bool {
        (self.value >> bit) & 1 != 0
    }

    /// Check if a named flag is set. Returns None if name not found.
    #[must_use]
    pub fn has_named(&self, name: &str) -> Option<bool> {
        self.names
            .iter()
            .position(|&n| n == name)
            .map(|bit| self.has(bit))
    }

    /// Set a specific flag bit.
    pub fn set(&mut self, bit: usize) {
        self.value |= 1u64 << bit;
    }

    /// Clear a specific flag bit.
    pub fn clear(&mut self, bit: usize) {
        self.value &= !(1u64 << bit);
    }

    /// Get the list of set flag names.
    #[must_use]
    pub fn set_flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        for (i, &name) in self.names.iter().enumerate() {
            if !name.is_empty() && self.has(i) {
                flags.push(name);
            }
        }
        flags
    }
}

impl fmt::Display for FlagValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = self.set_flags();
        if flags.is_empty() {
            write!(f, "0")
        } else {
            write!(f, "{}", flags.join("+"))
        }
    }
}

impl PartialEq for FlagValue {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for FlagValue {}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // DnsName tests
    // ========================================================================

    #[test]
    fn test_dns_name_from_str() {
        let name = DnsName::from_str_dotted("www.example.com").unwrap();
        assert_eq!(name.labels, vec!["www", "example", "com"]);
        assert_eq!(name.to_fqdn(), "www.example.com.");
        assert_eq!(name.to_string(), "www.example.com.");
    }

    #[test]
    fn test_dns_name_from_str_trailing_dot() {
        let name = DnsName::from_str_dotted("www.example.com.").unwrap();
        assert_eq!(name.labels, vec!["www", "example", "com"]);
    }

    #[test]
    fn test_dns_name_root() {
        let name = DnsName::from_str_dotted(".").unwrap();
        assert!(name.is_root());
        assert_eq!(name.to_fqdn(), ".");
    }

    #[test]
    fn test_dns_name_empty() {
        let name = DnsName::from_str_dotted("").unwrap();
        assert!(name.is_root());
    }

    #[test]
    fn test_dns_name_encode() {
        let name = DnsName::from_str_dotted("www.example.com").unwrap();
        let encoded = name.encode();
        assert_eq!(
            encoded,
            vec![
                3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
                b'm', 0
            ]
        );
    }

    #[test]
    fn test_dns_name_encode_root() {
        let name = DnsName::root();
        assert_eq!(name.encode(), vec![0]);
        assert_eq!(name.wire_len(), 1);
    }

    #[test]
    fn test_dns_name_decode_simple() {
        let data = vec![
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ];
        let (name, consumed) = DnsName::decode(&data, 0).unwrap();
        assert_eq!(name.labels, vec!["www", "example", "com"]);
        assert_eq!(consumed, 17);
    }

    #[test]
    fn test_dns_name_decode_with_pointer() {
        // Build a packet with a pointer:
        // offset 0: \x07example\x03com\x00  (13 bytes)
        // offset 13: \x03www\xc0\x00        (www + pointer to offset 0)
        let mut data = vec![];
        // "example.com" at offset 0
        data.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // "www" + pointer to offset 0
        data.extend_from_slice(&[3, b'w', b'w', b'w', 0xC0, 0x00]);

        let (name, consumed) = DnsName::decode(&data, 13).unwrap();
        assert_eq!(name.labels, vec!["www", "example", "com"]);
        assert_eq!(consumed, 6); // 1+3 for "www" + 2 for pointer
    }

    #[test]
    fn test_dns_name_decode_pointer_loop() {
        // Create a loop: offset 0 points to offset 2, offset 2 points to offset 0
        let data = vec![0xC0, 0x02, 0xC0, 0x00];
        let result = DnsName::decode(&data, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("loop detected"));
    }

    #[test]
    fn test_dns_name_decode_pointer_out_of_bounds() {
        let data = vec![0xC0, 0xFF]; // Pointer to offset 0x3FF, way beyond buffer
        let result = DnsName::decode(&data, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_name_label_too_long() {
        let long_label = "a".repeat(64);
        let result = DnsName::from_str_dotted(&long_label);
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_name_compression_roundtrip() {
        let name1 = DnsName::from_str_dotted("www.example.com").unwrap();
        let name2 = DnsName::from_str_dotted("mail.example.com").unwrap();

        let mut compression_map = HashMap::new();
        let mut packet = Vec::new();

        // Write first name at offset 0
        let encoded1 = name1.encode_compressed(0, &mut compression_map);
        packet.extend_from_slice(&encoded1);

        // Write second name — should compress "example.com" part
        let encoded2 = name2.encode_compressed(packet.len(), &mut compression_map);
        packet.extend_from_slice(&encoded2);

        // The second name should use a pointer for "example.com"
        // It should be shorter than encoding without compression
        let uncompressed2 = name2.encode();
        assert!(encoded2.len() < uncompressed2.len());

        // Decode both names and verify
        let (decoded1, _) = DnsName::decode(&packet, 0).unwrap();
        assert_eq!(decoded1, name1);

        let (decoded2, _) = DnsName::decode(&packet, encoded1.len()).unwrap();
        assert_eq!(decoded2, name2);
    }

    #[test]
    fn test_dns_name_wire_len() {
        let name = DnsName::from_str_dotted("www.example.com").unwrap();
        assert_eq!(name.wire_len(), 17); // 1+3 + 1+7 + 1+3 + 1
    }

    #[test]
    fn test_dns_name_decode_at_offset() {
        // Simulating a DNS packet where the name starts at a non-zero offset
        let mut data = vec![0xAA, 0xBB]; // Some header bytes
        data.extend_from_slice(&[4, b't', b'e', b's', b't', 0]);
        let (name, consumed) = DnsName::decode(&data, 2).unwrap();
        assert_eq!(name.labels, vec!["test"]);
        assert_eq!(consumed, 6);
    }

    // ========================================================================
    // FlagValue tests
    // ========================================================================

    static TCP_FLAG_NAMES: &[&str] = &["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"];

    #[test]
    fn test_flag_value_display() {
        let flags = FlagValue::new(0b00010010, TCP_FLAG_NAMES); // SYN + ACK
        assert_eq!(flags.to_string(), "SYN+ACK");
    }

    #[test]
    fn test_flag_value_empty() {
        let flags = FlagValue::new(0, TCP_FLAG_NAMES);
        assert_eq!(flags.to_string(), "0");
    }

    #[test]
    fn test_flag_value_has() {
        let flags = FlagValue::new(0b00000010, TCP_FLAG_NAMES); // SYN
        assert!(flags.has(1)); // SYN bit
        assert!(!flags.has(0)); // FIN bit
        assert!(!flags.has(4)); // ACK bit
    }

    #[test]
    fn test_flag_value_has_named() {
        let flags = FlagValue::new(0b00010010, TCP_FLAG_NAMES);
        assert_eq!(flags.has_named("SYN"), Some(true));
        assert_eq!(flags.has_named("ACK"), Some(true));
        assert_eq!(flags.has_named("FIN"), Some(false));
        assert_eq!(flags.has_named("NONEXISTENT"), None);
    }

    #[test]
    fn test_flag_value_set_clear() {
        let mut flags = FlagValue::new(0, TCP_FLAG_NAMES);
        flags.set(1); // Set SYN
        assert!(flags.has(1));
        assert_eq!(flags.value, 2);

        flags.set(4); // Set ACK
        assert_eq!(flags.to_string(), "SYN+ACK");

        flags.clear(1); // Clear SYN
        assert_eq!(flags.to_string(), "ACK");
    }

    #[test]
    fn test_flag_value_set_flags() {
        let flags = FlagValue::new(0b00010011, TCP_FLAG_NAMES); // FIN+SYN+ACK
        let set = flags.set_flags();
        assert_eq!(set, vec!["FIN", "SYN", "ACK"]);
    }
}
