//! Key Share extension (type 0x0033).
//!
//! Used in TLS 1.3 for ECDHE key exchange in the handshake.

use super::Extension;

/// A single key share entry.
#[derive(Debug, Clone)]
pub struct KeyShareEntry {
    /// Named group ID.
    pub group: u16,
    /// Key exchange data.
    pub key_exchange: Vec<u8>,
}

/// Parse key share entries from ClientHello extension data.
pub fn parse_key_share_client(data: &[u8]) -> Vec<KeyShareEntry> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut entries = Vec::new();
    let mut offset = 2;
    let end = (2 + list_len).min(data.len());

    while offset + 4 <= end {
        let group = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let kx_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + kx_len <= data.len() {
            entries.push(KeyShareEntry {
                group,
                key_exchange: data[offset..offset + kx_len].to_vec(),
            });
            offset += kx_len;
        } else {
            break;
        }
    }

    entries
}

/// Parse key share entry from ServerHello extension data.
pub fn parse_key_share_server(data: &[u8]) -> Option<KeyShareEntry> {
    if data.len() < 4 {
        return None;
    }
    let group = u16::from_be_bytes([data[0], data[1]]);
    let kx_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() >= 4 + kx_len {
        Some(KeyShareEntry {
            group,
            key_exchange: data[4..4 + kx_len].to_vec(),
        })
    } else {
        None
    }
}

/// Build key_share extension for ClientHello.
pub fn build_key_share_client(entries: &[KeyShareEntry]) -> Extension {
    let entries_len: usize = entries.iter().map(|e| 4 + e.key_exchange.len()).sum();
    let mut data = Vec::with_capacity(2 + entries_len);
    data.extend_from_slice(&(entries_len as u16).to_be_bytes());
    for entry in entries {
        data.extend_from_slice(&entry.group.to_be_bytes());
        data.extend_from_slice(&(entry.key_exchange.len() as u16).to_be_bytes());
        data.extend_from_slice(&entry.key_exchange);
    }
    Extension::new(0x0033, data)
}

/// Build key_share extension for ServerHello.
pub fn build_key_share_server(entry: &KeyShareEntry) -> Extension {
    let mut data = Vec::with_capacity(4 + entry.key_exchange.len());
    data.extend_from_slice(&entry.group.to_be_bytes());
    data.extend_from_slice(&(entry.key_exchange.len() as u16).to_be_bytes());
    data.extend_from_slice(&entry.key_exchange);
    Extension::new(0x0033, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_key_share() {
        let entries = vec![KeyShareEntry {
            group: 0x001D, // x25519
            key_exchange: vec![0x42; 32],
        }];
        let ext = build_key_share_client(&entries);
        let parsed = parse_key_share_client(&ext.data);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].group, 0x001D);
        assert_eq!(parsed[0].key_exchange.len(), 32);
    }

    #[test]
    fn test_server_key_share() {
        let entry = KeyShareEntry {
            group: 0x0017, // secp256r1
            key_exchange: vec![0x04; 65],
        };
        let ext = build_key_share_server(&entry);
        let parsed = parse_key_share_server(&ext.data).unwrap();
        assert_eq!(parsed.group, 0x0017);
        assert_eq!(parsed.key_exchange.len(), 65);
    }
}
