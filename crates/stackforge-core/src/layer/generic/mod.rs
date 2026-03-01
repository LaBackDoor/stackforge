//! Generic / custom protocol layer for user-defined protocols.
//!
//! [`GenericLayer`] allows a protocol to be defined entirely at runtime
//! (e.g. from Python via PyO3 bindings) as a flat list of named, typed
//! fields.  Field descriptors ([`GenericFieldDesc`]) are shared between all
//! packet instances using `Arc`, so the definition overhead is paid only once.
//!
//! # Example
//!
//! ```rust
//! use std::sync::Arc;
//! use stackforge_core::layer::generic::{GenericFieldDesc, GenericLayer};
//! use stackforge_core::layer::field::{FieldType, FieldValue};
//! use stackforge_core::layer::LayerIndex;
//! use stackforge_core::layer::LayerKind;
//!
//! let descs = Arc::new(vec![
//!     GenericFieldDesc {
//!         name: "opcode".to_string(),
//!         offset: 0,
//!         size: 1,
//!         field_type: FieldType::U8,
//!         default_value: vec![0x00],
//!     },
//!     GenericFieldDesc {
//!         name: "length".to_string(),
//!         offset: 1,
//!         size: 2,
//!         field_type: FieldType::U16,
//!         default_value: vec![0x00, 0x00],
//!     },
//! ]);
//!
//! let buf = vec![0x01u8, 0x00, 0x0A]; // opcode=1, length=10
//! let index = LayerIndex::new(LayerKind::Generic, 0, 3);
//! let layer = GenericLayer::new(index, Arc::from("MyProto"), descs);
//!
//! assert_eq!(
//!     layer.get_field(&buf, "opcode").unwrap().unwrap(),
//!     FieldValue::U8(1)
//! );
//! assert_eq!(
//!     layer.get_field(&buf, "length").unwrap().unwrap(),
//!     FieldValue::U16(10)
//! );
//! ```

pub mod builder;
pub use builder::GenericLayerBuilder;

use std::sync::Arc;

use crate::layer::field::{FieldError, FieldType, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Descriptor for a single field in a dynamically-defined protocol layer.
#[derive(Debug, Clone)]
pub struct GenericFieldDesc {
    /// Field name (must be unique within the protocol).
    pub name: String,
    /// Byte offset from the start of the layer.
    pub offset: usize,
    /// Field size in bytes.
    pub size: usize,
    /// How to interpret the raw bytes.
    pub field_type: FieldType,
    /// Default value used by the builder when no explicit value is given.
    /// Should be `size` bytes long; builder pads/truncates as needed.
    pub default_value: Vec<u8>,
}

/// A dynamically-defined protocol layer for custom / user-defined protocols.
///
/// The field descriptors are shared (`Arc`) so they can be defined once and
/// reused across many packet instances efficiently.
#[derive(Debug, Clone)]
pub struct GenericLayer {
    /// Position of this layer within the packet buffer.
    pub index: LayerIndex,
    /// Protocol name as defined by the caller.
    pub name: Arc<str>,
    /// Shared field descriptors.
    pub field_descs: Arc<Vec<GenericFieldDesc>>,
}

impl GenericLayer {
    /// Create a new `GenericLayer`.
    pub fn new(index: LayerIndex, name: Arc<str>, field_descs: Arc<Vec<GenericFieldDesc>>) -> Self {
        Self {
            index,
            name,
            field_descs,
        }
    }

    /// Human-readable summary: `"<name> (<N> fields)"`.
    pub fn summary(&self, _buf: &[u8]) -> String {
        format!("{} ({} fields)", self.name, self.field_descs.len())
    }

    /// Header length = sum of all field sizes.
    pub fn header_len(&self, _buf: &[u8]) -> usize {
        self.field_descs.iter().map(|f| f.size).sum()
    }

    /// Dynamic list of field names (not `&'static str` because names come from
    /// user-defined strings at runtime).
    pub fn field_names_dynamic(&self) -> Vec<String> {
        self.field_descs.iter().map(|f| f.name.clone()).collect()
    }

    /// Read a field from the buffer.
    ///
    /// Returns:
    /// - `Some(Ok(value))` if the field was found and the buffer is long enough.
    /// - `Some(Err(e))` if the field was found but the buffer is too short.
    /// - `None` if no field with this name exists in this layer.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        let desc = self.field_descs.iter().find(|f| f.name == name)?;
        let layer_slice = self.index.slice(buf);

        let field_end = desc.offset + desc.size;
        if layer_slice.len() < field_end {
            return Some(Err(FieldError::BufferTooShort {
                offset: self.index.start + desc.offset,
                need: desc.size,
                have: layer_slice.len().saturating_sub(desc.offset),
            }));
        }

        let field_slice = &layer_slice[desc.offset..field_end];

        let value = match desc.field_type {
            FieldType::U8 => FieldValue::U8(field_slice[0]),
            FieldType::U16 => {
                let v = u16::from_be_bytes([field_slice[0], field_slice[1]]);
                FieldValue::U16(v)
            }
            FieldType::U32 => {
                let v = u32::from_be_bytes([
                    field_slice[0],
                    field_slice[1],
                    field_slice[2],
                    field_slice[3],
                ]);
                FieldValue::U32(v)
            }
            FieldType::U64 => {
                let v = u64::from_be_bytes([
                    field_slice[0],
                    field_slice[1],
                    field_slice[2],
                    field_slice[3],
                    field_slice[4],
                    field_slice[5],
                    field_slice[6],
                    field_slice[7],
                ]);
                FieldValue::U64(v)
            }
            FieldType::LEU16 => {
                let v = u16::from_le_bytes([field_slice[0], field_slice[1]]);
                FieldValue::U16(v)
            }
            FieldType::LEU32 => {
                let v = u32::from_le_bytes([
                    field_slice[0],
                    field_slice[1],
                    field_slice[2],
                    field_slice[3],
                ]);
                FieldValue::U32(v)
            }
            FieldType::LEU64 => {
                let v = u64::from_le_bytes([
                    field_slice[0],
                    field_slice[1],
                    field_slice[2],
                    field_slice[3],
                    field_slice[4],
                    field_slice[5],
                    field_slice[6],
                    field_slice[7],
                ]);
                FieldValue::U64(v)
            }
            FieldType::Bool => FieldValue::Bool(field_slice[0] != 0),
            // For all other types, return raw bytes.
            _ => FieldValue::Bytes(field_slice.to_vec()),
        };

        Some(Ok(value))
    }

    /// Write a field into the (mutable) buffer.
    ///
    /// Returns:
    /// - `Some(Ok(()))` if the field was found and written successfully.
    /// - `Some(Err(e))` if the field was found but the buffer is too short or
    ///   the value type is wrong.
    /// - `None` if no field with this name exists in this layer.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        let desc = self.field_descs.iter().find(|f| f.name == name)?;

        let abs_offset = self.index.start + desc.offset;
        let abs_end = abs_offset + desc.size;

        if buf.len() < abs_end {
            return Some(Err(FieldError::BufferTooShort {
                offset: abs_offset,
                need: desc.size,
                have: buf.len().saturating_sub(abs_offset),
            }));
        }

        let dest = &mut buf[abs_offset..abs_end];

        let result = match (desc.field_type, &value) {
            (FieldType::U8, FieldValue::U8(v)) => {
                dest[0] = *v;
                Ok(())
            }
            (FieldType::U16, FieldValue::U16(v)) => {
                dest.copy_from_slice(&v.to_be_bytes());
                Ok(())
            }
            (FieldType::U32, FieldValue::U32(v)) => {
                dest.copy_from_slice(&v.to_be_bytes());
                Ok(())
            }
            (FieldType::U64, FieldValue::U64(v)) => {
                dest.copy_from_slice(&v.to_be_bytes());
                Ok(())
            }
            (FieldType::LEU16, FieldValue::U16(v)) => {
                dest.copy_from_slice(&v.to_le_bytes());
                Ok(())
            }
            (FieldType::LEU32, FieldValue::U32(v)) => {
                dest.copy_from_slice(&v.to_le_bytes());
                Ok(())
            }
            (FieldType::LEU64, FieldValue::U64(v)) => {
                dest.copy_from_slice(&v.to_le_bytes());
                Ok(())
            }
            (FieldType::Bool, FieldValue::Bool(v)) => {
                dest[0] = if *v { 1 } else { 0 };
                Ok(())
            }
            (_, FieldValue::Bytes(bytes)) => {
                let copy_len = bytes.len().min(dest.len());
                dest[..copy_len].copy_from_slice(&bytes[..copy_len]);
                Ok(())
            }
            _ => Err(FieldError::InvalidValue(format!(
                "field '{}': value type {:?} does not match declared field type {:?}",
                name, value, desc.field_type
            ))),
        };

        Some(result)
    }
}

impl Layer for GenericLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Generic
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.header_len(data)
    }

    /// The `Layer` trait requires `&'static [&'static str]`, which is not
    /// possible for dynamically-generated field names.  Returns an empty
    /// slice; callers that need the full list should call
    /// [`field_names_dynamic`](Self::field_names_dynamic) directly.
    fn field_names(&self) -> &'static [&'static str] {
        &[]
    }

    fn hashret(&self, _data: &[u8]) -> Vec<u8> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::LayerKind;

    fn make_descs() -> Arc<Vec<GenericFieldDesc>> {
        Arc::new(vec![
            GenericFieldDesc {
                name: "opcode".to_string(),
                offset: 0,
                size: 1,
                field_type: FieldType::U8,
                default_value: vec![0x00],
            },
            GenericFieldDesc {
                name: "length".to_string(),
                offset: 1,
                size: 2,
                field_type: FieldType::U16,
                default_value: vec![0x00, 0x00],
            },
            GenericFieldDesc {
                name: "seq".to_string(),
                offset: 3,
                size: 4,
                field_type: FieldType::U32,
                default_value: vec![0x00, 0x00, 0x00, 0x00],
            },
            GenericFieldDesc {
                name: "payload".to_string(),
                offset: 7,
                size: 8,
                field_type: FieldType::Bytes,
                default_value: vec![0u8; 8],
            },
        ])
    }

    fn make_layer_and_buf() -> (GenericLayer, Vec<u8>) {
        let descs = make_descs();
        let buf = vec![
            0x05u8, // opcode = 5
            0x00, 0x10, // length = 16
            0x00, 0x00, 0x00, 0x01, // seq = 1
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, // payload
        ];
        let index = LayerIndex::new(LayerKind::Generic, 0, 15);
        let layer = GenericLayer::new(index, Arc::from("TestProto"), descs);
        (layer, buf)
    }

    #[test]
    fn test_summary() {
        let (layer, buf) = make_layer_and_buf();
        let s = layer.summary(&buf);
        assert!(s.contains("TestProto"), "summary: {}", s);
        assert!(s.contains("4 fields"), "summary: {}", s);
    }

    #[test]
    fn test_header_len() {
        let (layer, buf) = make_layer_and_buf();
        // 1 + 2 + 4 + 8 = 15
        assert_eq!(layer.header_len(&buf), 15);
    }

    #[test]
    fn test_get_field_u8() {
        let (layer, buf) = make_layer_and_buf();
        let v = layer.get_field(&buf, "opcode").unwrap().unwrap();
        assert_eq!(v, FieldValue::U8(5));
    }

    #[test]
    fn test_get_field_u16() {
        let (layer, buf) = make_layer_and_buf();
        let v = layer.get_field(&buf, "length").unwrap().unwrap();
        assert_eq!(v, FieldValue::U16(16));
    }

    #[test]
    fn test_get_field_u32() {
        let (layer, buf) = make_layer_and_buf();
        let v = layer.get_field(&buf, "seq").unwrap().unwrap();
        assert_eq!(v, FieldValue::U32(1));
    }

    #[test]
    fn test_get_field_bytes() {
        let (layer, buf) = make_layer_and_buf();
        let v = layer.get_field(&buf, "payload").unwrap().unwrap();
        if let FieldValue::Bytes(b) = v {
            assert_eq!(&b[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
        } else {
            panic!("expected Bytes, got {:?}", v);
        }
    }

    #[test]
    fn test_get_field_unknown() {
        let (layer, buf) = make_layer_and_buf();
        assert!(layer.get_field(&buf, "nonexistent").is_none());
    }

    #[test]
    fn test_get_field_buffer_too_short() {
        let descs = make_descs();
        let buf = vec![0x05u8]; // only 1 byte — "length" won't fit
        let index = LayerIndex::new(LayerKind::Generic, 0, 1);
        let layer = GenericLayer::new(index, Arc::from("T"), descs);
        let result = layer.get_field(&buf, "length").unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_set_field_u8() {
        let (layer, mut buf) = make_layer_and_buf();
        layer
            .set_field(&mut buf, "opcode", FieldValue::U8(0xFF))
            .unwrap()
            .unwrap();
        assert_eq!(buf[0], 0xFF);
    }

    #[test]
    fn test_set_field_u16() {
        let (layer, mut buf) = make_layer_and_buf();
        layer
            .set_field(&mut buf, "length", FieldValue::U16(0x0100))
            .unwrap()
            .unwrap();
        assert_eq!(buf[1], 0x01);
        assert_eq!(buf[2], 0x00);
    }

    #[test]
    fn test_set_field_u32() {
        let (layer, mut buf) = make_layer_and_buf();
        layer
            .set_field(&mut buf, "seq", FieldValue::U32(0xDEAD_BEEF))
            .unwrap()
            .unwrap();
        assert_eq!(&buf[3..7], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_set_field_bytes() {
        let (layer, mut buf) = make_layer_and_buf();
        let payload = vec![0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        layer
            .set_field(&mut buf, "payload", FieldValue::Bytes(payload.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(&buf[7..15], payload.as_slice());
    }

    #[test]
    fn test_set_field_unknown() {
        let (layer, mut buf) = make_layer_and_buf();
        assert!(
            layer
                .set_field(&mut buf, "nonexistent", FieldValue::U8(0))
                .is_none()
        );
    }

    #[test]
    fn test_field_names_dynamic() {
        let (layer, _) = make_layer_and_buf();
        let names = layer.field_names_dynamic();
        assert_eq!(names, vec!["opcode", "length", "seq", "payload"]);
    }

    #[test]
    fn test_layer_trait() {
        let (layer, buf) = make_layer_and_buf();
        assert_eq!(layer.kind(), LayerKind::Generic);
        assert_eq!(Layer::header_len(&layer, &buf), 15);
        assert!(Layer::field_names(&layer).is_empty());
    }

    #[test]
    fn test_layer_with_offset() {
        // Layer embedded inside a larger buffer at offset 4.
        let descs = Arc::new(vec![GenericFieldDesc {
            name: "val".to_string(),
            offset: 0,
            size: 2,
            field_type: FieldType::U16,
            default_value: vec![0, 0],
        }]);
        let buf = vec![0x00u8, 0x00, 0x00, 0x00, 0xAB, 0xCD]; // layer starts at byte 4
        let index = LayerIndex::new(LayerKind::Generic, 4, 6);
        let layer = GenericLayer::new(index, Arc::from("Offset"), descs);
        let v = layer.get_field(&buf, "val").unwrap().unwrap();
        assert_eq!(v, FieldValue::U16(0xABCD));
    }

    #[test]
    fn test_bool_field() {
        let descs = Arc::new(vec![GenericFieldDesc {
            name: "flag".to_string(),
            offset: 0,
            size: 1,
            field_type: FieldType::Bool,
            default_value: vec![0x00],
        }]);
        let buf = vec![0x01u8];
        let index = LayerIndex::new(LayerKind::Generic, 0, 1);
        let layer = GenericLayer::new(index, Arc::from("Flags"), descs);
        let v = layer.get_field(&buf, "flag").unwrap().unwrap();
        assert_eq!(v, FieldValue::Bool(true));
    }
}
