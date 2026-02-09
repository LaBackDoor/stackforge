//! Common TLS extensions.
//!
//! ALPN, Supported Groups, EC Point Formats, Max Fragment Length, etc.

use super::Extension;

/// Parse ALPN extension data.
///
/// Returns list of protocol name strings.
pub fn parse_alpn(data: &[u8]) -> Vec<String> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut protocols = Vec::new();
    let mut offset = 2;
    let end = (2 + list_len).min(data.len());

    while offset < end {
        let proto_len = data[offset] as usize;
        offset += 1;
        if offset + proto_len <= data.len() {
            if let Ok(name) = String::from_utf8(data[offset..offset + proto_len].to_vec()) {
                protocols.push(name);
            }
            offset += proto_len;
        } else {
            break;
        }
    }

    protocols
}

/// Build ALPN extension.
pub fn build_alpn(protocols: &[&str]) -> Extension {
    let total_len: usize = protocols.iter().map(|p| 1 + p.len()).sum();
    let mut data = Vec::with_capacity(2 + total_len);
    data.extend_from_slice(&(total_len as u16).to_be_bytes());
    for proto in protocols {
        data.push(proto.len() as u8);
        data.extend_from_slice(proto.as_bytes());
    }
    Extension::new(0x0010, data)
}

/// Parse Supported Groups (formerly "elliptic_curves") extension.
pub fn parse_supported_groups(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut groups = Vec::new();
    let mut offset = 2;
    let end = (2 + list_len).min(data.len());
    while offset + 1 < end {
        groups.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;
    }
    groups
}

/// Build Supported Groups extension.
pub fn build_supported_groups(groups: &[u16]) -> Extension {
    let list_len = (groups.len() * 2) as u16;
    let mut data = Vec::with_capacity(2 + groups.len() * 2);
    data.extend_from_slice(&list_len.to_be_bytes());
    for &g in groups {
        data.extend_from_slice(&g.to_be_bytes());
    }
    Extension::new(0x000A, data)
}

/// Parse EC Point Formats extension.
pub fn parse_ec_point_formats(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let list_len = data[0] as usize;
    if data.len() >= 1 + list_len {
        data[1..1 + list_len].to_vec()
    } else {
        data[1..].to_vec()
    }
}

/// Build EC Point Formats extension.
pub fn build_ec_point_formats(formats: &[u8]) -> Extension {
    let mut data = Vec::with_capacity(1 + formats.len());
    data.push(formats.len() as u8);
    data.extend_from_slice(formats);
    Extension::new(0x000B, data)
}

/// Build Renegotiation Info extension (type 0xFF01).
pub fn build_renegotiation_info(info: &[u8]) -> Extension {
    let mut data = Vec::with_capacity(1 + info.len());
    data.push(info.len() as u8);
    data.extend_from_slice(info);
    Extension::new(0xFF01, data)
}

/// Build Extended Master Secret extension (type 0x0017).
pub fn build_extended_master_secret() -> Extension {
    Extension::new(0x0017, Vec::new())
}

/// Build Encrypt-Then-MAC extension (type 0x0016).
pub fn build_encrypt_then_mac() -> Extension {
    Extension::new(0x0016, Vec::new())
}

/// Build Session Ticket extension (type 0x0023).
pub fn build_session_ticket(ticket: &[u8]) -> Extension {
    Extension::new(0x0023, ticket.to_vec())
}

/// Build PSK Key Exchange Modes extension (type 0x002D).
pub fn build_psk_key_exchange_modes(modes: &[u8]) -> Extension {
    let mut data = Vec::with_capacity(1 + modes.len());
    data.push(modes.len() as u8);
    data.extend_from_slice(modes);
    Extension::new(0x002D, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn() {
        let ext = build_alpn(&["h2", "http/1.1"]);
        let protocols = parse_alpn(&ext.data);
        assert_eq!(protocols, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn test_supported_groups() {
        let groups = vec![0x001D, 0x0017, 0x0018]; // x25519, secp256r1, secp384r1
        let ext = build_supported_groups(&groups);
        let parsed = parse_supported_groups(&ext.data);
        assert_eq!(parsed, groups);
    }

    #[test]
    fn test_ec_point_formats() {
        let formats = vec![0x00]; // uncompressed
        let ext = build_ec_point_formats(&formats);
        let parsed = parse_ec_point_formats(&ext.data);
        assert_eq!(parsed, formats);
    }
}
