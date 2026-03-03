//! TLS `ServerHello` message parsing and building.
//!
//! ```text
//! ProtocolVersion server_version;     // 2 bytes
//! Random random;                      // 32 bytes
//! SessionID session_id;               // 1 byte length + 0-32 bytes
//! CipherSuite cipher_suite;           // 2 bytes
//! CompressionMethod compression;      // 1 byte
//! Extension extensions<0..2^16-1>;    // 2 byte length + variable
//! ```

use super::super::extensions::{Extension, build_extensions, parse_extensions};

/// TLS 1.3 `HelloRetryRequest` magic random value (RFC 8446).
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Parsed TLS `ServerHello` message.
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// Server's selected version (legacy for TLS 1.3).
    pub version: u16,
    /// 32-byte server random.
    pub random: [u8; 32],
    /// Session ID.
    pub session_id: Vec<u8>,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected compression method.
    pub compression_method: u8,
    /// Extensions.
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    /// Parse `ServerHello` from the handshake body.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 38 {
            return None; // 2 + 32 + 1 + 2 + 1 = 38 minimum
        }

        let mut offset = 0;

        let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let mut random = [0u8; 32];
        random.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        if offset >= data.len() {
            return None;
        }
        let sid_len = data[offset] as usize;
        offset += 1;
        if offset + sid_len > data.len() {
            return None;
        }
        let session_id = data[offset..offset + sid_len].to_vec();
        offset += sid_len;

        if offset + 3 > data.len() {
            return None;
        }
        let cipher_suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let compression_method = data[offset];
        offset += 1;

        let extensions = if offset + 2 <= data.len() {
            let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if offset + ext_len <= data.len() {
                parse_extensions(&data[offset..offset + ext_len])
            } else {
                parse_extensions(&data[offset..])
            }
        } else {
            Vec::new()
        };

        Some(Self {
            version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }

    /// Build `ServerHello` body bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&self.random);
        buf.push(self.session_id.len() as u8);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.cipher_suite.to_be_bytes());
        buf.push(self.compression_method);

        if !self.extensions.is_empty() {
            let ext_data = build_extensions(&self.extensions);
            buf.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            buf.extend_from_slice(&ext_data);
        }

        buf
    }

    /// Check if this is a TLS 1.3 `HelloRetryRequest`.
    #[must_use]
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == HELLO_RETRY_REQUEST_RANDOM
    }

    /// Get the selected version from `supported_versions` extension (TLS 1.3).
    #[must_use]
    pub fn selected_version(&self) -> u16 {
        // Check supported_versions extension first
        if let Some(ext) = self.extensions.iter().find(|e| e.ext_type == 0x002B)
            && ext.data.len() >= 2
        {
            return u16::from_be_bytes([ext.data[0], ext.data[1]]);
        }
        // Fall back to record version
        self.version
    }

    /// Get a specific extension by type.
    #[must_use]
    pub fn get_extension(&self, ext_type: u16) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.ext_type == ext_type)
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "ServerHello version=0x{:04x} cipher=0x{:04x} exts={}",
            self.version,
            self.cipher_suite,
            self.extensions.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_server_hello() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        data.extend_from_slice(&[0x42; 32]); // random
        data.push(0x00); // empty session id
        data.extend_from_slice(&[0x13, 0x01]); // cipher: TLS_AES_128_GCM_SHA256
        data.push(0x00); // compression: NULL
        data
    }

    #[test]
    fn test_parse_server_hello() {
        let data = make_minimal_server_hello();
        let sh = ServerHello::parse(&data).unwrap();
        assert_eq!(sh.version, 0x0303);
        assert_eq!(sh.cipher_suite, 0x1301);
        assert_eq!(sh.compression_method, 0);
        assert!(sh.extensions.is_empty());
    }

    #[test]
    fn test_roundtrip_server_hello() {
        let data = make_minimal_server_hello();
        let sh = ServerHello::parse(&data).unwrap();
        let rebuilt = sh.build();
        let sh2 = ServerHello::parse(&rebuilt).unwrap();
        assert_eq!(sh.version, sh2.version);
        assert_eq!(sh.cipher_suite, sh2.cipher_suite);
    }

    #[test]
    fn test_hello_retry_request() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x03, 0x03]);
        data.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        data.push(0x00);
        data.extend_from_slice(&[0x13, 0x01]);
        data.push(0x00);

        let sh = ServerHello::parse(&data).unwrap();
        assert!(sh.is_hello_retry_request());
    }

    #[test]
    fn test_selected_version_from_extension() {
        let mut data = make_minimal_server_hello();
        // Add supported_versions extension: selected TLS 1.3
        let ext = vec![
            0x00, 0x2B, // type: supported_versions
            0x00, 0x02, // length: 2
            0x03, 0x04, // TLS 1.3
        ];
        data.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        data.extend_from_slice(&ext);

        let sh = ServerHello::parse(&data).unwrap();
        assert_eq!(sh.selected_version(), 0x0304);
    }
}
