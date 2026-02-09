//! TLS Record builder.
//!
//! Provides a builder for constructing TLS record layer packets.
//! Supports the "Permissive Parser, Explicit Builder" pattern:
//! if `length` is set to `Some(val)`, that value is used directly
//! (even if incorrect), enabling fuzzing and security testing.

use super::types::TlsContentType;

/// Builder for TLS record layer packets.
#[derive(Debug, Clone)]
pub struct TlsRecordBuilder {
    content_type: u8,
    version: u16,
    length: Option<u16>,
    fragment: Vec<u8>,
}

impl Default for TlsRecordBuilder {
    fn default() -> Self {
        Self {
            content_type: TlsContentType::Handshake.as_u8(),
            version: 0x0303, // TLS 1.2
            length: None,    // auto-calculate
            fragment: Vec::new(),
        }
    }
}

impl TlsRecordBuilder {
    /// Create a new TLS record builder with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the content type.
    pub fn content_type(mut self, ct: TlsContentType) -> Self {
        self.content_type = ct.as_u8();
        self
    }

    /// Set the content type as raw u8 (for fuzzing/testing).
    pub fn content_type_raw(mut self, ct: u8) -> Self {
        self.content_type = ct;
        self
    }

    /// Set the protocol version.
    pub fn version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    /// Set the length field explicitly (overrides auto-calculation).
    /// Pass `None` to auto-calculate from fragment size.
    pub fn length(mut self, length: Option<u16>) -> Self {
        self.length = length;
        self
    }

    /// Set the fragment data.
    pub fn fragment(mut self, data: Vec<u8>) -> Self {
        self.fragment = data;
        self
    }

    /// Set the fragment data from a slice.
    pub fn fragment_from_slice(mut self, data: &[u8]) -> Self {
        self.fragment = data.to_vec();
        self
    }

    /// Get the total size of the built record.
    pub fn record_size(&self) -> usize {
        5 + self.fragment.len()
    }

    /// Build the TLS record into bytes.
    pub fn build(&self) -> Vec<u8> {
        let frag_len = self.length.unwrap_or(self.fragment.len() as u16);
        let mut out = Vec::with_capacity(5 + self.fragment.len());

        out.push(self.content_type);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&frag_len.to_be_bytes());
        out.extend_from_slice(&self.fragment);

        out
    }
}

/// Builder for TLS Alert messages.
#[derive(Debug, Clone)]
pub struct TlsAlertBuilder {
    level: u8,
    description: u8,
    version: u16,
}

impl Default for TlsAlertBuilder {
    fn default() -> Self {
        Self {
            level: 2,       // fatal
            description: 0, // close_notify
            version: 0x0303,
        }
    }
}

impl TlsAlertBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn level(mut self, level: u8) -> Self {
        self.level = level;
        self
    }

    pub fn description(mut self, desc: u8) -> Self {
        self.description = desc;
        self
    }

    pub fn version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        TlsRecordBuilder::new()
            .content_type(TlsContentType::Alert)
            .version(self.version)
            .fragment(vec![self.level, self.description])
            .build()
    }
}

/// Builder for TLS ChangeCipherSpec messages.
#[derive(Debug, Clone)]
pub struct TlsCcsBuilder {
    version: u16,
}

impl Default for TlsCcsBuilder {
    fn default() -> Self {
        Self { version: 0x0303 }
    }
}

impl TlsCcsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        TlsRecordBuilder::new()
            .content_type(TlsContentType::ChangeCipherSpec)
            .version(self.version)
            .fragment(vec![0x01])
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::tls::record::TlsLayer;
    use crate::layer::{LayerIndex, LayerKind};

    #[test]
    fn test_build_handshake_record() {
        let record = TlsRecordBuilder::new()
            .content_type(TlsContentType::Handshake)
            .version(0x0303)
            .fragment(vec![0x01, 0x00, 0x00, 0x05, 0x03, 0x03, 0x00, 0x00, 0x00])
            .build();

        assert_eq!(record[0], 0x16); // Handshake
        assert_eq!(record[1..3], [0x03, 0x03]); // TLS 1.2
        assert_eq!(u16::from_be_bytes([record[3], record[4]]), 9); // length
        assert_eq!(record[5], 0x01); // ClientHello
    }

    #[test]
    fn test_build_with_explicit_length() {
        // Set length to 100 even though fragment is only 5 bytes (for fuzzing)
        let record = TlsRecordBuilder::new()
            .content_type(TlsContentType::Handshake)
            .length(Some(100))
            .fragment(vec![0x01, 0x02, 0x03, 0x04, 0x05])
            .build();

        assert_eq!(u16::from_be_bytes([record[3], record[4]]), 100);
        assert_eq!(record.len(), 10); // 5 header + 5 fragment
    }

    #[test]
    fn test_roundtrip() {
        let fragment = vec![0x01, 0x00, 0x00, 0x01, 0x00];
        let record = TlsRecordBuilder::new()
            .content_type(TlsContentType::Handshake)
            .version(0x0301)
            .fragment(fragment.clone())
            .build();

        let layer = TlsLayer {
            index: LayerIndex::new(LayerKind::Tls, 0, record.len()),
        };

        assert_eq!(
            layer.content_type(&record).unwrap(),
            TlsContentType::Handshake
        );
        assert_eq!(layer.version(&record).unwrap(), 0x0301);
        assert_eq!(layer.length(&record).unwrap(), 5);
        assert_eq!(layer.fragment(&record), &fragment);
    }

    #[test]
    fn test_build_alert() {
        let alert = TlsAlertBuilder::new()
            .level(2)
            .description(40) // handshake_failure
            .version(0x0303)
            .build();

        assert_eq!(alert[0], 0x15); // Alert
        assert_eq!(alert[1..3], [0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([alert[3], alert[4]]), 2);
        assert_eq!(alert[5], 2); // fatal
        assert_eq!(alert[6], 40); // handshake_failure
    }

    #[test]
    fn test_build_ccs() {
        let ccs = TlsCcsBuilder::new().version(0x0303).build();

        assert_eq!(ccs[0], 0x14); // ChangeCipherSpec
        assert_eq!(ccs[1..3], [0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([ccs[3], ccs[4]]), 1);
        assert_eq!(ccs[5], 0x01);
    }

    #[test]
    fn test_record_size() {
        let builder = TlsRecordBuilder::new().fragment(vec![0; 100]);
        assert_eq!(builder.record_size(), 105);
    }
}
