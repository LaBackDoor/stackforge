//! Supported Versions extension (type 0x002B).
//!
//! ClientHello: list of versions.
//! ServerHello: single selected version.

use super::Extension;

/// Parse supported versions from ClientHello extension data.
pub fn parse_supported_versions_client(data: &[u8]) -> Vec<u16> {
    if data.is_empty() {
        return Vec::new();
    }
    let list_len = data[0] as usize;
    let mut versions = Vec::new();
    let mut offset = 1;
    while offset + 1 < data.len() && offset < 1 + list_len {
        versions.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;
    }
    versions
}

/// Parse supported version from ServerHello extension data.
pub fn parse_supported_versions_server(data: &[u8]) -> Option<u16> {
    if data.len() >= 2 {
        Some(u16::from_be_bytes([data[0], data[1]]))
    } else {
        None
    }
}

/// Build supported_versions extension for ClientHello.
pub fn build_supported_versions_client(versions: &[u16]) -> Extension {
    let list_len = (versions.len() * 2) as u8;
    let mut data = Vec::with_capacity(1 + versions.len() * 2);
    data.push(list_len);
    for &v in versions {
        data.extend_from_slice(&v.to_be_bytes());
    }
    Extension::new(0x002B, data)
}

/// Build supported_versions extension for ServerHello.
pub fn build_supported_versions_server(version: u16) -> Extension {
    Extension::new(0x002B, version.to_be_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_versions() {
        let ext = build_supported_versions_client(&[0x0304, 0x0303]);
        let versions = parse_supported_versions_client(&ext.data);
        assert_eq!(versions, vec![0x0304, 0x0303]);
    }

    #[test]
    fn test_server_version() {
        let ext = build_supported_versions_server(0x0304);
        let version = parse_supported_versions_server(&ext.data);
        assert_eq!(version, Some(0x0304));
    }
}
