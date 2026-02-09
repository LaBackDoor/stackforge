//! TLS Record layer view into a packet buffer.
//!
//! Implements parsing for the TLS record header (5 bytes):
//! ```text
//! ContentType  type;           // 1 byte
//! ProtocolVersion version;     // 2 bytes
//! uint16 length;               // 2 bytes
//! opaque fragment[length];     // variable
//! ```

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

use super::types::{HandshakeType, TlsAlertDescription, TlsAlertLevel, TlsContentType, TlsVersion};

/// TLS record header length: 1 (type) + 2 (version) + 2 (length) = 5 bytes.
pub const TLS_RECORD_HEADER_LEN: usize = 5;

/// Maximum TLS record fragment length (RFC 5246: 2^14 = 16384).
pub const TLS_MAX_FRAGMENT_LEN: usize = 16384;

/// Maximum TLS record fragment length with expansion (2^14 + 2048).
pub const TLS_MAX_CIPHERTEXT_LEN: usize = 16384 + 2048;

/// Field names for TLS layer.
pub static TLS_FIELDS: &[&str] = &["type", "version", "len", "fragment"];

/// TLS Record layer view.
#[derive(Debug, Clone)]
pub struct TlsLayer {
    pub index: LayerIndex,
}

impl TlsLayer {
    /// Read the content type field (offset 0, 1 byte).
    pub fn content_type(&self, buf: &[u8]) -> Result<TlsContentType, FieldError> {
        let slice = self.index.slice(buf);
        if slice.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 1,
                have: 0,
            });
        }
        Ok(TlsContentType::from_u8(slice[0]))
    }

    /// Read the content type as raw u8.
    pub fn content_type_raw(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let slice = self.index.slice(buf);
        if slice.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 1,
                have: 0,
            });
        }
        Ok(slice[0])
    }

    /// Read the protocol version field (offset 1, 2 bytes).
    pub fn version(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < 3 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 1,
                need: 2,
                have: slice.len().saturating_sub(1),
            });
        }
        Ok(u16::from_be_bytes([slice[1], slice[2]]))
    }

    /// Read the protocol version as TlsVersion.
    pub fn version_typed(&self, buf: &[u8]) -> Result<TlsVersion, FieldError> {
        self.version(buf).map(TlsVersion)
    }

    /// Read the length field (offset 3, 2 bytes).
    pub fn length(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < 5 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 3,
                need: 2,
                have: slice.len().saturating_sub(3),
            });
        }
        Ok(u16::from_be_bytes([slice[3], slice[4]]))
    }

    /// Get the fragment data (everything after the 5-byte header).
    pub fn fragment<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let slice = self.index.slice(buf);
        if slice.len() <= TLS_RECORD_HEADER_LEN {
            return &[];
        }
        let frag_len = if slice.len() >= 5 {
            let declared_len = u16::from_be_bytes([slice[3], slice[4]]) as usize;
            declared_len.min(slice.len() - TLS_RECORD_HEADER_LEN)
        } else {
            slice.len() - TLS_RECORD_HEADER_LEN
        };
        &slice[TLS_RECORD_HEADER_LEN..TLS_RECORD_HEADER_LEN + frag_len]
    }

    /// Get a human-readable description of the content.
    pub fn content_summary(&self, buf: &[u8]) -> String {
        let ct = match self.content_type(buf) {
            Ok(ct) => ct,
            Err(_) => return "TLS (truncated)".to_string(),
        };
        let version = self.version(buf).unwrap_or(0);
        let ver_name = TlsVersion(version).name();

        match ct {
            TlsContentType::Handshake => {
                let frag = self.fragment(buf);
                if !frag.is_empty() {
                    let hs_type = HandshakeType(frag[0]);
                    format!("TLS {} {} {}", ver_name, ct.name(), hs_type.name())
                } else {
                    format!("TLS {} {}", ver_name, ct.name())
                }
            }
            TlsContentType::Alert => {
                let frag = self.fragment(buf);
                if frag.len() >= 2 {
                    let level = TlsAlertLevel::from_u8(frag[0]);
                    let desc = TlsAlertDescription(frag[1]);
                    format!("TLS {} Alert {} {}", ver_name, level.name(), desc.name())
                } else {
                    format!("TLS {} Alert", ver_name)
                }
            }
            _ => format!("TLS {} {}", ver_name, ct.name()),
        }
    }

    /// Set a field value in the buffer.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        let start = self.index.start;
        match name {
            "type" => {
                let v = match value.as_u8() {
                    Some(v) => v,
                    None => return Some(Err(FieldError::InvalidValue("expected u8".to_string()))),
                };
                if start >= buf.len() {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: start,
                        need: 1,
                        have: 0,
                    }));
                }
                buf[start] = v;
                Some(Ok(()))
            }
            "version" => {
                let v = match value.as_u16() {
                    Some(v) => v,
                    None => return Some(Err(FieldError::InvalidValue("expected u16".to_string()))),
                };
                if start + 3 > buf.len() {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: start + 1,
                        need: 2,
                        have: buf.len().saturating_sub(start + 1),
                    }));
                }
                let bytes = v.to_be_bytes();
                buf[start + 1] = bytes[0];
                buf[start + 2] = bytes[1];
                Some(Ok(()))
            }
            "len" => {
                let v = match value.as_u16() {
                    Some(v) => v,
                    None => return Some(Err(FieldError::InvalidValue("expected u16".to_string()))),
                };
                if start + 5 > buf.len() {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: start + 3,
                        need: 2,
                        have: buf.len().saturating_sub(start + 3),
                    }));
                }
                let bytes = v.to_be_bytes();
                buf[start + 3] = bytes[0];
                buf[start + 4] = bytes[1];
                Some(Ok(()))
            }
            _ => None,
        }
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "type" => Some(self.content_type_raw(buf).map(FieldValue::U8)),
            "version" => Some(self.version(buf).map(FieldValue::U16)),
            "len" => Some(self.length(buf).map(FieldValue::U16)),
            "fragment" => Some(Ok(FieldValue::Bytes(self.fragment(buf).to_vec()))),
            _ => None,
        }
    }

    /// Get field names.
    pub fn field_names(&self) -> &'static [&'static str] {
        TLS_FIELDS
    }
}

impl Layer for TlsLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Tls
    }

    fn summary(&self, data: &[u8]) -> String {
        self.content_summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        let slice = self.index.slice(data);
        if slice.len() < TLS_RECORD_HEADER_LEN {
            return slice.len();
        }
        let frag_len = u16::from_be_bytes([slice[3], slice[4]]) as usize;
        (TLS_RECORD_HEADER_LEN + frag_len).min(slice.len())
    }

    fn field_names(&self) -> &'static [&'static str] {
        TLS_FIELDS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tls_record_header() {
        // TLS 1.2 ClientHello record header
        // type=22 (handshake), version=0x0303 (TLS 1.2), length=5
        let data = vec![
            0x16, // content_type = Handshake
            0x03, 0x03, // version = TLS 1.2
            0x00, 0x05, // length = 5
            // fragment (5 bytes of dummy handshake)
            0x01, 0x00, 0x00, 0x01, 0x00,
        ];

        let layer = TlsLayer {
            index: LayerIndex::new(LayerKind::Tls, 0, data.len()),
        };

        assert_eq!(
            layer.content_type(&data).unwrap(),
            TlsContentType::Handshake
        );
        assert_eq!(layer.version(&data).unwrap(), 0x0303);
        assert_eq!(layer.length(&data).unwrap(), 5);
        assert_eq!(layer.fragment(&data).len(), 5);
        assert_eq!(layer.fragment(&data)[0], 0x01); // ClientHello type
    }

    #[test]
    fn test_parse_alert_record() {
        // TLS Alert: fatal, handshake_failure
        let data = vec![
            0x15, // content_type = Alert
            0x03, 0x03, // version = TLS 1.2
            0x00, 0x02, // length = 2
            0x02, // level = fatal
            0x28, // description = handshake_failure (40)
        ];

        let layer = TlsLayer {
            index: LayerIndex::new(LayerKind::Tls, 0, data.len()),
        };

        assert_eq!(layer.content_type(&data).unwrap(), TlsContentType::Alert);
        let summary = layer.content_summary(&data);
        assert!(summary.contains("Alert"));
        assert!(summary.contains("fatal"));
        assert!(summary.contains("handshake_failure"));
    }

    #[test]
    fn test_parse_ccs_record() {
        let data = vec![
            0x14, // content_type = ChangeCipherSpec
            0x03, 0x03, // version = TLS 1.2
            0x00, 0x01, // length = 1
            0x01, // CCS value
        ];

        let layer = TlsLayer {
            index: LayerIndex::new(LayerKind::Tls, 0, data.len()),
        };

        assert_eq!(
            layer.content_type(&data).unwrap(),
            TlsContentType::ChangeCipherSpec
        );
        assert_eq!(layer.fragment(&data), &[0x01]);
    }

    #[test]
    fn test_truncated_record() {
        // Only 3 bytes - not enough for full header
        let data = vec![0x16, 0x03, 0x03];

        let layer = TlsLayer {
            index: LayerIndex::new(LayerKind::Tls, 0, data.len()),
        };

        assert_eq!(
            layer.content_type(&data).unwrap(),
            TlsContentType::Handshake
        );
        assert!(layer.length(&data).is_err());
    }

    #[test]
    fn test_get_set_fields() {
        let mut data = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];

        let layer = TlsLayer {
            index: LayerIndex::new(LayerKind::Tls, 0, data.len()),
        };

        // Get fields
        assert_eq!(
            layer.get_field(&data, "type").unwrap().unwrap(),
            FieldValue::U8(0x16)
        );
        assert_eq!(
            layer.get_field(&data, "version").unwrap().unwrap(),
            FieldValue::U16(0x0303)
        );
        assert_eq!(
            layer.get_field(&data, "len").unwrap().unwrap(),
            FieldValue::U16(5)
        );

        // Set version to TLS 1.0
        layer
            .set_field(&mut data, "version", FieldValue::U16(0x0301))
            .unwrap()
            .unwrap();
        assert_eq!(layer.version(&data).unwrap(), 0x0301);

        // Set type to Alert
        layer
            .set_field(&mut data, "type", FieldValue::U8(0x15))
            .unwrap()
            .unwrap();
        assert_eq!(layer.content_type(&data).unwrap(), TlsContentType::Alert);
    }

    #[test]
    fn test_header_len() {
        let data = vec![
            0x16, 0x03, 0x03, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x06, 0x03, 0x03, 0x00, 0x00, 0x00,
            0x00,
        ];

        let layer = TlsLayer {
            index: LayerIndex::new(LayerKind::Tls, 0, data.len()),
        };

        // header_len should be 5 (header) + 10 (fragment) = 15
        assert_eq!(layer.header_len(&data), 15);
    }

    #[test]
    fn test_tls13_record() {
        // TLS 1.3 uses version 0x0303 in the record layer (legacy)
        // but the actual version is 0x0301 for compatibility
        let data = vec![
            0x17, // ApplicationData
            0x03, 0x03, // TLS 1.2 (legacy version in TLS 1.3)
            0x00, 0x03, // length = 3
            0xaa, 0xbb, 0xcc, // encrypted data
        ];

        let layer = TlsLayer {
            index: LayerIndex::new(LayerKind::Tls, 0, data.len()),
        };

        assert_eq!(
            layer.content_type(&data).unwrap(),
            TlsContentType::ApplicationData
        );
        assert_eq!(layer.fragment(&data), &[0xaa, 0xbb, 0xcc]);
    }
}
