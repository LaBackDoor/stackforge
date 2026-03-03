//! TLS `ClientHello` message parsing and building.
//!
//! ```text
//! ProtocolVersion client_version;     // 2 bytes
//! Random random;                      // 32 bytes (4 gmt_unix_time + 28 random)
//! SessionID session_id;               // 1 byte length + 0-32 bytes
//! CipherSuites cipher_suites;         // 2 byte length + 2*N bytes
//! CompressionMethods compression;     // 1 byte length + N bytes
//! Extension extensions<0..2^16-1>;    // 2 byte length + variable
//! ```

use super::super::extensions::{Extension, build_extensions, parse_extensions};

/// Parsed TLS `ClientHello` message.
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// Client's supported version (legacy for TLS 1.3).
    pub version: u16,
    /// 32-byte client random.
    pub random: [u8; 32],
    /// Session ID (0-32 bytes).
    pub session_id: Vec<u8>,
    /// List of supported cipher suite IDs.
    pub cipher_suites: Vec<u16>,
    /// List of supported compression methods.
    pub compression_methods: Vec<u8>,
    /// Extensions.
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    /// Parse `ClientHello` from the handshake body (after type+length header).
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 38 {
            return None; // Minimum: 2 (version) + 32 (random) + 1 (sid_len) + 2 (cs_len) + 1 (comp_len)
        }

        let mut offset = 0;

        // Version (2 bytes)
        let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Random (32 bytes)
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Session ID
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

        // Cipher Suites
        if offset + 2 > data.len() {
            return None;
        }
        let cs_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + cs_len > data.len() {
            return None;
        }
        let mut cipher_suites = Vec::with_capacity(cs_len / 2);
        for i in (0..cs_len).step_by(2) {
            if offset + i + 2 <= data.len() {
                cipher_suites.push(u16::from_be_bytes([data[offset + i], data[offset + i + 1]]));
            }
        }
        offset += cs_len;

        // Compression Methods
        if offset >= data.len() {
            return None;
        }
        let comp_len = data[offset] as usize;
        offset += 1;
        if offset + comp_len > data.len() {
            return None;
        }
        let compression_methods = data[offset..offset + comp_len].to_vec();
        offset += comp_len;

        // Extensions (optional)
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
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// Build `ClientHello` body bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Version
        buf.extend_from_slice(&self.version.to_be_bytes());

        // Random
        buf.extend_from_slice(&self.random);

        // Session ID
        buf.push(self.session_id.len() as u8);
        buf.extend_from_slice(&self.session_id);

        // Cipher Suites
        let cs_len = (self.cipher_suites.len() * 2) as u16;
        buf.extend_from_slice(&cs_len.to_be_bytes());
        for &cs in &self.cipher_suites {
            buf.extend_from_slice(&cs.to_be_bytes());
        }

        // Compression Methods
        buf.push(self.compression_methods.len() as u8);
        buf.extend_from_slice(&self.compression_methods);

        // Extensions
        if !self.extensions.is_empty() {
            let ext_data = build_extensions(&self.extensions);
            buf.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            buf.extend_from_slice(&ext_data);
        }

        buf
    }

    /// Get a specific extension by type.
    #[must_use]
    pub fn get_extension(&self, ext_type: u16) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.ext_type == ext_type)
    }

    /// Get the SNI hostname if present.
    #[must_use]
    pub fn sni(&self) -> Option<String> {
        self.get_extension(0x0000).and_then(|ext| {
            // SNI format: 2 bytes list len, 1 byte type (0=hostname), 2 bytes name len, name
            let data = &ext.data;
            if data.len() < 5 {
                return None;
            }
            let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
            if data.len() >= 5 + name_len {
                String::from_utf8(data[5..5 + name_len].to_vec()).ok()
            } else {
                None
            }
        })
    }

    /// Get supported versions from the extension (TLS 1.3).
    #[must_use]
    pub fn supported_versions(&self) -> Vec<u16> {
        match self.get_extension(0x002B) {
            Some(ext) => {
                if ext.data.is_empty() {
                    return Vec::new();
                }
                let list_len = ext.data[0] as usize;
                let mut versions = Vec::new();
                let mut i = 1;
                while i + 1 < ext.data.len() && i < 1 + list_len {
                    versions.push(u16::from_be_bytes([ext.data[i], ext.data[i + 1]]));
                    i += 2;
                }
                versions
            },
            None => Vec::new(),
        }
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "ClientHello version=0x{:04x} ciphers={} exts={}",
            self.version,
            self.cipher_suites.len(),
            self.extensions.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_client_hello() -> Vec<u8> {
        let mut data = Vec::new();
        // Version: TLS 1.2
        data.extend_from_slice(&[0x03, 0x03]);
        // Random: 32 bytes
        data.extend_from_slice(&[0x42; 32]);
        // Session ID: empty
        data.push(0x00);
        // Cipher suites: 2 suites
        data.extend_from_slice(&[0x00, 0x04]); // 4 bytes = 2 suites
        data.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        data.extend_from_slice(&[0x00, 0x2F]); // TLS_RSA_WITH_AES_128_CBC_SHA
        // Compression: NULL only
        data.push(0x01);
        data.push(0x00);
        data
    }

    #[test]
    fn test_parse_client_hello() {
        let data = make_minimal_client_hello();
        let ch = ClientHello::parse(&data).unwrap();
        assert_eq!(ch.version, 0x0303);
        assert_eq!(ch.random, [0x42; 32]);
        assert!(ch.session_id.is_empty());
        assert_eq!(ch.cipher_suites.len(), 2);
        assert_eq!(ch.cipher_suites[0], 0x1301);
        assert_eq!(ch.cipher_suites[1], 0x002F);
        assert_eq!(ch.compression_methods, vec![0x00]);
    }

    #[test]
    fn test_roundtrip_client_hello() {
        let data = make_minimal_client_hello();
        let ch = ClientHello::parse(&data).unwrap();
        let rebuilt = ch.build();
        let ch2 = ClientHello::parse(&rebuilt).unwrap();
        assert_eq!(ch.version, ch2.version);
        assert_eq!(ch.cipher_suites, ch2.cipher_suites);
        assert_eq!(ch.compression_methods, ch2.compression_methods);
    }

    #[test]
    fn test_client_hello_with_extensions() {
        let mut data = make_minimal_client_hello();
        // Add extensions: SNI
        let sni_ext = vec![
            0x00, 0x00, // type: server_name
            0x00, 0x0e, // length: 14
            0x00, 0x0c, // list length: 12
            0x00, // type: hostname
            0x00, 0x09, // name length: 9
            b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', // "localhost"
        ];
        let ext_len = sni_ext.len() as u16;
        data.extend_from_slice(&ext_len.to_be_bytes());
        data.extend_from_slice(&sni_ext);

        let ch = ClientHello::parse(&data).unwrap();
        assert_eq!(ch.extensions.len(), 1);
        assert_eq!(ch.sni(), Some("localhost".to_string()));
    }

    #[test]
    fn test_too_short() {
        assert!(ClientHello::parse(&[0x03, 0x03]).is_none());
    }
}
