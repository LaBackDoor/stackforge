//! Server Name Indication (SNI) extension (type 0x0000).
//!
//! ```text
//! struct {
//!     ServerNameList server_name_list;
//! } ServerNameIndication;
//!
//! struct {
//!     NameType name_type;    // 1 byte (0=host_name)
//!     uint16 name_length;
//!     opaque name[name_length];
//! } ServerName;
//! ```

use super::Extension;

/// Parse SNI extension data to extract hostnames.
pub fn parse_sni(data: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    if data.len() < 2 {
        return names;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;
    let end = (2 + list_len).min(data.len());

    while offset + 3 <= end {
        let _name_type = data[offset];
        offset += 1;
        let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + name_len <= data.len() {
            if let Ok(name) = String::from_utf8(data[offset..offset + name_len].to_vec()) {
                names.push(name);
            }
            offset += name_len;
        } else {
            break;
        }
    }

    names
}

/// Build SNI extension for a single hostname.
pub fn build_sni(hostname: &str) -> Extension {
    let name_bytes = hostname.as_bytes();
    let name_len = name_bytes.len();
    // server_name_list_len = 1 (type) + 2 (name_len) + name_len
    let list_len = 3 + name_len;

    let mut data = Vec::with_capacity(2 + list_len);
    data.extend_from_slice(&(list_len as u16).to_be_bytes());
    data.push(0x00); // host_name type
    data.extend_from_slice(&(name_len as u16).to_be_bytes());
    data.extend_from_slice(name_bytes);

    Extension::new(0x0000, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_sni() {
        let ext = build_sni("example.com");
        let names = parse_sni(&ext.data);
        assert_eq!(names, vec!["example.com"]);
    }

    #[test]
    fn test_parse_empty_sni() {
        let names = parse_sni(&[]);
        assert!(names.is_empty());
    }
}
