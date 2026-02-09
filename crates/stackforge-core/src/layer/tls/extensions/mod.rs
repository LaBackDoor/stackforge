//! TLS Extension parsing and building.
//!
//! Generic extension format:
//! ```text
//! uint16 extension_type;
//! uint16 extension_length;
//! opaque extension_data[extension_length];
//! ```

pub mod common;
pub mod key_share;
pub mod signature_algorithms;
pub mod sni;
pub mod supported_versions;

pub use key_share::{KeyShareEntry, build_key_share_client, build_key_share_server};
pub use signature_algorithms::build_signature_algorithms;
pub use sni::build_sni;
pub use supported_versions::{build_supported_versions_client, build_supported_versions_server};

/// A generic TLS extension.
#[derive(Debug, Clone)]
pub struct Extension {
    /// Extension type ID.
    pub ext_type: u16,
    /// Raw extension data (after the type and length fields).
    pub data: Vec<u8>,
}

impl Extension {
    /// Create a new extension with given type and data.
    pub fn new(ext_type: u16, data: Vec<u8>) -> Self {
        Self { ext_type, data }
    }

    /// Get the name of this extension type.
    pub fn name(&self) -> &'static str {
        super::types::ExtensionType(self.ext_type).name()
    }

    /// Total wire size: 2 (type) + 2 (length) + data.len()
    pub fn wire_len(&self) -> usize {
        4 + self.data.len()
    }

    /// Build this extension into wire format.
    pub fn build(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_len());
        buf.extend_from_slice(&self.ext_type.to_be_bytes());
        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }
}

/// Parse a list of extensions from raw bytes.
///
/// Input should be the extension data after the 2-byte total length field.
pub fn parse_extensions(data: &[u8]) -> Vec<Extension> {
    let mut extensions = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        let ext_data = if offset + ext_len <= data.len() {
            data[offset..offset + ext_len].to_vec()
        } else {
            // Truncated - take what's available
            data[offset..].to_vec()
        };

        extensions.push(Extension {
            ext_type,
            data: ext_data,
        });

        offset += ext_len;
    }

    extensions
}

/// Build a list of extensions into wire format (without the outer length prefix).
pub fn build_extensions(extensions: &[Extension]) -> Vec<u8> {
    let total_len: usize = extensions.iter().map(|e| e.wire_len()).sum();
    let mut buf = Vec::with_capacity(total_len);
    for ext in extensions {
        buf.extend_from_slice(&ext.build());
    }
    buf
}

/// Find an extension by type in a list.
pub fn find_extension(extensions: &[Extension], ext_type: u16) -> Option<&Extension> {
    extensions.iter().find(|e| e.ext_type == ext_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_extensions() {
        let mut data = Vec::new();
        // Extension 1: type=0x0000 (SNI), length=5, data=[1,2,3,4,5]
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
        // Extension 2: type=0x002B (supported_versions), length=3
        data.extend_from_slice(&[0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04]);

        let exts = parse_extensions(&data);
        assert_eq!(exts.len(), 2);
        assert_eq!(exts[0].ext_type, 0x0000);
        assert_eq!(exts[0].data.len(), 5);
        assert_eq!(exts[1].ext_type, 0x002B);
        assert_eq!(exts[1].data.len(), 3);
    }

    #[test]
    fn test_build_extensions() {
        let exts = vec![
            Extension::new(0x0000, vec![0x01, 0x02]),
            Extension::new(0x002B, vec![0x03]),
        ];
        let built = build_extensions(&exts);
        // First ext: 00 00 00 02 01 02
        // Second ext: 00 2B 00 01 03
        assert_eq!(built.len(), 6 + 5);
        assert_eq!(&built[0..4], &[0x00, 0x00, 0x00, 0x02]);
        assert_eq!(&built[6..10], &[0x00, 0x2B, 0x00, 0x01]);
    }

    #[test]
    fn test_roundtrip() {
        let exts = vec![
            Extension::new(0x0001, vec![0xAA, 0xBB, 0xCC]),
            Extension::new(0x0010, vec![0xDD]),
        ];
        let built = build_extensions(&exts);
        let parsed = parse_extensions(&built);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].ext_type, 0x0001);
        assert_eq!(parsed[0].data, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(parsed[1].ext_type, 0x0010);
        assert_eq!(parsed[1].data, vec![0xDD]);
    }

    #[test]
    fn test_find_extension() {
        let exts = vec![
            Extension::new(0x0000, vec![]),
            Extension::new(0x002B, vec![0x01]),
        ];
        assert!(find_extension(&exts, 0x002B).is_some());
        assert!(find_extension(&exts, 0xFFFF).is_none());
    }
}
