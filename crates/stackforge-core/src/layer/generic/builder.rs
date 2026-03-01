//! Builder for dynamically-defined custom protocol layers.

use std::collections::HashMap;
use std::sync::Arc;

use super::{GenericFieldDesc, GenericLayer};
use crate::layer::{LayerIndex, LayerKind};

/// Builder for dynamically-defined custom protocol layers.
///
/// This builder is intended to be constructed once per protocol definition
/// (e.g. in Python via the PyO3 bindings) and then used to produce byte
/// buffers that conform to the protocol layout.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use stackforge_core::layer::generic::builder::GenericLayerBuilder;
/// use stackforge_core::layer::generic::GenericFieldDesc;
/// use stackforge_core::layer::field::FieldType;
///
/// let fields = Arc::new(vec![
///     GenericFieldDesc {
///         name: "type_id".to_string(),
///         offset: 0,
///         size: 2,
///         field_type: FieldType::U16,
///         default_value: vec![0x00, 0x01],
///     },
///     GenericFieldDesc {
///         name: "flags".to_string(),
///         offset: 2,
///         size: 1,
///         field_type: FieldType::U8,
///         default_value: vec![0x00],
///     },
/// ]);
///
/// let buf = GenericLayerBuilder::new(Arc::from("MyProto"), fields)
///     .set_u16("type_id", 0x0042)
///     .build();
///
/// assert_eq!(buf.len(), 3);
/// assert_eq!(buf[0], 0x00);
/// assert_eq!(buf[1], 0x42);
/// assert_eq!(buf[2], 0x00);
/// ```
#[derive(Debug, Clone)]
pub struct GenericLayerBuilder {
    /// Protocol name.
    name: Arc<str>,
    /// Field descriptors shared with all instances.
    field_descs: Arc<Vec<GenericFieldDesc>>,
    /// Explicitly set field values (raw bytes, may be padded/truncated to field size).
    values: HashMap<String, Vec<u8>>,
}

impl GenericLayerBuilder {
    /// Create a builder for the named protocol with the given field descriptors.
    pub fn new(name: Arc<str>, field_descs: Arc<Vec<GenericFieldDesc>>) -> Self {
        Self {
            name,
            field_descs,
            values: HashMap::new(),
        }
    }

    /// Set a field by raw bytes.
    ///
    /// If `value` is shorter than the field's declared size it is zero-padded
    /// (on the right); if it is longer it is truncated.
    pub fn set(mut self, name: &str, value: Vec<u8>) -> Self {
        self.values.insert(name.to_string(), value);
        self
    }

    /// Set a U8 field by name.
    pub fn set_u8(self, name: &str, value: u8) -> Self {
        self.set(name, vec![value])
    }

    /// Set a U16 field by name (stored big-endian).
    pub fn set_u16(self, name: &str, value: u16) -> Self {
        self.set(name, value.to_be_bytes().to_vec())
    }

    /// Set a U32 field by name (stored big-endian).
    pub fn set_u32(self, name: &str, value: u32) -> Self {
        self.set(name, value.to_be_bytes().to_vec())
    }

    /// Total byte size of the protocol header (sum of all field sizes).
    pub fn header_size(&self) -> usize {
        self.field_descs.iter().map(|f| f.size).sum()
    }

    /// Build the layer into a byte buffer.
    ///
    /// Fields not explicitly set fall back to their `default_value`.
    /// Each field value is copied into the buffer starting at `field.offset`,
    /// padded with zeros on the right or truncated if the value's length does
    /// not match `field.size`.
    pub fn build(&self) -> Vec<u8> {
        let total = self.header_size();
        let mut buf = vec![0u8; total];

        for field in self.field_descs.iter() {
            let src: &[u8] = if let Some(v) = self.values.get(&field.name) {
                v
            } else {
                &field.default_value
            };

            let dest_start = field.offset;
            let dest_end = (field.offset + field.size).min(total);
            let dest_slice = &mut buf[dest_start..dest_end];
            let copy_len = src.len().min(dest_slice.len());

            // Copy available bytes, leaving remainder zero (already initialised).
            dest_slice[..copy_len].copy_from_slice(&src[..copy_len]);
        }

        buf
    }

    /// Build the byte buffer and wrap it in a [`GenericLayer`].
    ///
    /// The returned layer's `LayerIndex` covers `[0..header_size]` within the
    /// returned byte buffer.
    pub fn build_layer(&self) -> (GenericLayer, Vec<u8>) {
        let buf = self.build();
        let size = buf.len();
        let index = LayerIndex::new(LayerKind::Generic, 0, size);
        let layer = GenericLayer::new(index, self.name.clone(), self.field_descs.clone());
        (layer, buf)
    }

    /// The protocol name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The layer kind (always `LayerKind::Generic`).
    pub fn kind(&self) -> LayerKind {
        LayerKind::Generic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::field::FieldType;

    fn make_fields() -> Arc<Vec<GenericFieldDesc>> {
        Arc::new(vec![
            GenericFieldDesc {
                name: "type_id".to_string(),
                offset: 0,
                size: 2,
                field_type: FieldType::U16,
                default_value: vec![0x00, 0x01],
            },
            GenericFieldDesc {
                name: "flags".to_string(),
                offset: 2,
                size: 1,
                field_type: FieldType::U8,
                default_value: vec![0xFF],
            },
            GenericFieldDesc {
                name: "payload_len".to_string(),
                offset: 3,
                size: 4,
                field_type: FieldType::U32,
                default_value: vec![0x00, 0x00, 0x00, 0x00],
            },
        ])
    }

    #[test]
    fn test_header_size() {
        let fields = make_fields();
        let builder = GenericLayerBuilder::new(Arc::from("Test"), fields);
        assert_eq!(builder.header_size(), 7); // 2 + 1 + 4
    }

    #[test]
    fn test_build_defaults() {
        let fields = make_fields();
        let builder = GenericLayerBuilder::new(Arc::from("Test"), fields);
        let buf = builder.build();
        assert_eq!(buf.len(), 7);
        // type_id default = 0x0001
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[1], 0x01);
        // flags default = 0xFF
        assert_eq!(buf[2], 0xFF);
        // payload_len default = 0
        assert_eq!(&buf[3..7], &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_build_with_set_u16() {
        let fields = make_fields();
        let builder =
            GenericLayerBuilder::new(Arc::from("Test"), fields).set_u16("type_id", 0xABCD);
        let buf = builder.build();
        assert_eq!(buf[0], 0xAB);
        assert_eq!(buf[1], 0xCD);
        // flags still default
        assert_eq!(buf[2], 0xFF);
    }

    #[test]
    fn test_build_with_set_u32() {
        let fields = make_fields();
        let builder =
            GenericLayerBuilder::new(Arc::from("Test"), fields).set_u32("payload_len", 1024);
        let buf = builder.build();
        assert_eq!(&buf[3..7], &1024u32.to_be_bytes());
    }

    #[test]
    fn test_build_truncation() {
        let fields = Arc::new(vec![GenericFieldDesc {
            name: "f".to_string(),
            offset: 0,
            size: 2,
            field_type: FieldType::U16,
            default_value: vec![0x00, 0x00],
        }]);
        // Setting 4 bytes for a 2-byte field — should be truncated.
        let builder =
            GenericLayerBuilder::new(Arc::from("T"), fields).set("f", vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let buf = builder.build();
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], 0xAA);
        assert_eq!(buf[1], 0xBB);
    }

    #[test]
    fn test_build_zero_padding() {
        let fields = Arc::new(vec![GenericFieldDesc {
            name: "f".to_string(),
            offset: 0,
            size: 4,
            field_type: FieldType::U32,
            default_value: vec![0x00, 0x00, 0x00, 0x00],
        }]);
        // Setting 1 byte for a 4-byte field — rest should be zero.
        let builder = GenericLayerBuilder::new(Arc::from("T"), fields).set("f", vec![0xAA]);
        let buf = builder.build();
        assert_eq!(buf, vec![0xAA, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_build_layer_returns_valid_layer() {
        let fields = make_fields();
        let builder = GenericLayerBuilder::new(Arc::from("MyProto"), fields);
        let (layer, buf) = builder.build_layer();
        assert_eq!(layer.index.start, 0);
        assert_eq!(layer.index.end, 7);
        assert_eq!(buf.len(), 7);
    }

    #[test]
    fn test_kind() {
        let fields = make_fields();
        let builder = GenericLayerBuilder::new(Arc::from("T"), fields);
        assert_eq!(builder.kind(), LayerKind::Generic);
    }
}
