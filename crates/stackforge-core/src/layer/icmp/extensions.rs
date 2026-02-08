//! ICMP Extensions Framework (RFC 4884)
//!
//! ICMP error messages can include extensions that provide additional diagnostic
//! information. The extensions framework defines:
//! - Extension Header (4 bytes: version, reserved, checksum)
//! - Extension Objects (variable length: len, classnum, classtype, data)
//!
//! Common extension classes:
//! - Class 1: MPLS Label Stack
//! - Class 2: Interface Information (RFC 5837)
//! - Class 3: Interface Identification

use crate::layer::icmp::checksum::icmp_checksum;
use std::net::{Ipv4Addr, Ipv6Addr};

/// ICMP Extension class numbers (IANA registry)
pub mod class_nums {
    pub const MPLS: u8 = 1;
    pub const INTERFACE_INFORMATION: u8 = 2;
    pub const INTERFACE_IDENTIFICATION: u8 = 3;
}

/// Get human-readable name for extension class number
pub fn class_name(classnum: u8) -> &'static str {
    match classnum {
        class_nums::MPLS => "MPLS",
        class_nums::INTERFACE_INFORMATION => "Interface Information",
        class_nums::INTERFACE_IDENTIFICATION => "Interface Identification",
        _ => "unknown",
    }
}

/// ICMP Extension Header offsets (RFC 4884)
pub mod header_offsets {
    pub const VERSION_RESERVED: usize = 0; // Version (4 bits) + Reserved (12 bits)
    pub const CHECKSUM: usize = 2;
}

pub const EXTENSION_HEADER_LEN: usize = 4;

/// ICMP Extension Object offsets
pub mod object_offsets {
    pub const LEN: usize = 0;
    pub const CLASSNUM: usize = 2;
    pub const CLASSTYPE: usize = 3;
    pub const DATA: usize = 4;
}

pub const EXTENSION_OBJECT_MIN_LEN: usize = 4;

/// Interface Information Object flags (RFC 5837)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceInfoFlags {
    pub has_ifindex: bool,
    pub has_ipaddr: bool,
    pub has_ifname: bool,
    pub has_mtu: bool,
}

impl InterfaceInfoFlags {
    /// Parse flags from the classtype byte
    pub fn from_byte(byte: u8) -> Self {
        Self {
            has_ifindex: (byte & 0b0001_0000) != 0,
            has_ipaddr: (byte & 0b0000_1000) != 0,
            has_ifname: (byte & 0b0000_0100) != 0,
            has_mtu: (byte & 0b0000_0001) != 0,
        }
    }

    /// Convert flags to byte representation
    pub fn to_byte(&self) -> u8 {
        let mut byte = 0u8;
        if self.has_ifindex {
            byte |= 0b0001_0000;
        }
        if self.has_ipaddr {
            byte |= 0b0000_1000;
        }
        if self.has_ifname {
            byte |= 0b0000_0100;
        }
        if self.has_mtu {
            byte |= 0b0000_0001;
        }
        byte
    }
}

/// Address Family Identifier (AFI) for interface IP addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
}

/// Parsed Interface Information extension data (RFC 5837)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInformation {
    pub flags: InterfaceInfoFlags,
    pub ifindex: Option<u32>,
    pub ip_addr: Option<IpAddr>,
    pub ifname: Option<String>,
    pub mtu: Option<u32>,
}

/// IP address enum for interface information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// Check if ICMP extensions are present in an ICMP error message.
///
/// RFC 4884 specifies that extensions are indicated by a length field in the
/// ICMP header being non-zero. For error messages, the original datagram
/// is padded to 128 bytes minimum, and extensions follow.
pub fn has_extensions(icmp_type: u8, payload_len: usize) -> bool {
    use crate::layer::icmp::error;

    // Only error messages can have extensions
    if !error::is_error_type(icmp_type) {
        return false;
    }

    // Extensions require at least the minimum error payload (28 bytes)
    // plus space for the extension header (4 bytes)
    if payload_len < error::ERROR_MIN_PAYLOAD + EXTENSION_HEADER_LEN {
        return false;
    }

    // Additional heuristic: check if there's enough data after the required
    // error payload for a valid extension header + object
    payload_len >= 128 + EXTENSION_HEADER_LEN + EXTENSION_OBJECT_MIN_LEN
}

/// Get the offset where ICMP extensions begin in an error message.
///
/// Returns None if extensions are not present.
pub fn extension_offset(icmp_header_start: usize, icmp_payload: &[u8]) -> Option<usize> {
    // Extensions start after the padded original datagram (128 bytes minimum)
    // RFC 4884 Section 4.1: The original datagram is padded to 128 bytes
    if icmp_payload.len() >= 128 + EXTENSION_HEADER_LEN {
        Some(icmp_header_start + 8 + 128) // ICMP header (8) + padded payload (128)
    } else {
        None
    }
}

/// Parse the ICMP Extension Header
pub fn parse_extension_header(buf: &[u8], offset: usize) -> Option<(u8, u16)> {
    if offset + EXTENSION_HEADER_LEN > buf.len() {
        return None;
    }

    let version_reserved = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    let version = ((version_reserved >> 12) & 0x0F) as u8;
    let checksum = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);

    // Version should be 2 per RFC 4884
    if version != 2 {
        return None;
    }

    Some((version, checksum))
}

/// Verify the extension header checksum
pub fn verify_extension_checksum(buf: &[u8], ext_start: usize, ext_len: usize) -> bool {
    if ext_start + ext_len > buf.len() || ext_len < EXTENSION_HEADER_LEN {
        return false;
    }

    // Create a copy with checksum field zeroed
    let mut data = vec![0u8; ext_len];
    data.copy_from_slice(&buf[ext_start..ext_start + ext_len]);
    data[2] = 0;
    data[3] = 0;

    let computed = icmp_checksum(&data);
    let stored = u16::from_be_bytes([buf[ext_start + 2], buf[ext_start + 3]]);

    computed == stored
}

/// Parse an Extension Object header
pub fn parse_extension_object(buf: &[u8], offset: usize) -> Option<(u16, u8, u8, usize)> {
    if offset + EXTENSION_OBJECT_MIN_LEN > buf.len() {
        return None;
    }

    let len = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    let classnum = buf[offset + 2];
    let classtype = buf[offset + 3];

    // Length must be at least 4 bytes and a multiple of 4 (RFC 4884)
    if len < 4 || len % 4 != 0 {
        return None;
    }

    let data_offset = offset + EXTENSION_OBJECT_MIN_LEN;

    Some((len, classnum, classtype, data_offset))
}

/// Parse Interface Information extension object (RFC 5837)
pub fn parse_interface_information(
    buf: &[u8],
    data_offset: usize,
    data_len: usize,
) -> Option<InterfaceInformation> {
    if data_len == 0 {
        return None;
    }

    // First byte after the object header contains the flags
    let flags_byte = buf[data_offset];
    let flags = InterfaceInfoFlags::from_byte(flags_byte);

    let mut offset = data_offset + 1; // Skip flags byte
    let mut result = InterfaceInformation {
        flags,
        ifindex: None,
        ip_addr: None,
        ifname: None,
        mtu: None,
    };

    // Parse conditional fields based on flags
    if flags.has_ifindex {
        if offset + 4 > buf.len() {
            return None;
        }
        result.ifindex = Some(u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]));
        offset += 4;
    }

    if flags.has_ipaddr {
        if offset + 4 > buf.len() {
            return None;
        }
        let afi = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        offset += 4; // AFI (2) + Reserved (2)

        match afi {
            1 => {
                // IPv4
                if offset + 4 > buf.len() {
                    return None;
                }
                let ip = Ipv4Addr::new(
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                );
                result.ip_addr = Some(IpAddr::V4(ip));
                offset += 4;
            }
            2 => {
                // IPv6
                if offset + 16 > buf.len() {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[offset..offset + 16]);
                result.ip_addr = Some(IpAddr::V6(Ipv6Addr::from(octets)));
                offset += 16;
            }
            _ => return None, // Unknown AFI
        }
    }

    if flags.has_ifname {
        if offset + 1 > buf.len() {
            return None;
        }
        let name_len = buf[offset] as usize;
        offset += 1;

        if offset + name_len > buf.len() {
            return None;
        }
        let name_bytes = &buf[offset..offset + name_len];
        if let Ok(name) = String::from_utf8(name_bytes.to_vec()) {
            result.ifname = Some(name);
        }
        offset += name_len;
    }

    if flags.has_mtu {
        if offset + 4 > buf.len() {
            return None;
        }
        result.mtu = Some(u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]));
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_info_flags() {
        let flags = InterfaceInfoFlags {
            has_ifindex: true,
            has_ipaddr: true,
            has_ifname: false,
            has_mtu: true,
        };

        let byte = flags.to_byte();
        assert_eq!(byte, 0b0001_1001);

        let parsed = InterfaceInfoFlags::from_byte(byte);
        assert_eq!(parsed, flags);
    }

    #[test]
    fn test_parse_extension_header() {
        // Version 2, reserved=0, checksum=0x1234
        let buf = [0x20, 0x00, 0x12, 0x34];
        let result = parse_extension_header(&buf, 0);
        assert_eq!(result, Some((2, 0x1234)));
    }

    #[test]
    fn test_parse_extension_object() {
        // len=8, classnum=2, classtype=0x19
        let buf = [0x00, 0x08, 0x02, 0x19, 0x00, 0x00, 0x00, 0x00];
        let result = parse_extension_object(&buf, 0);
        assert_eq!(result, Some((8, 2, 0x19, 4)));
    }

    #[test]
    fn test_class_name() {
        assert_eq!(class_name(class_nums::MPLS), "MPLS");
        assert_eq!(
            class_name(class_nums::INTERFACE_INFORMATION),
            "Interface Information"
        );
        assert_eq!(class_name(99), "unknown");
    }

    #[test]
    fn test_has_extensions() {
        use crate::layer::icmp::types::types;

        // Time exceeded with sufficient payload
        assert!(has_extensions(types::TIME_EXCEEDED, 200));

        // Echo request (not an error type)
        assert!(!has_extensions(types::ECHO_REQUEST, 200));

        // Error type but insufficient payload
        assert!(!has_extensions(types::TIME_EXCEEDED, 30));
    }
}
