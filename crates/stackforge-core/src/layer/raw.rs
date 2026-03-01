//! Raw Layer Implementation
//!
//! The Raw layer represents arbitrary payload data that doesn't match any
//! known protocol. It's useful for:
//! - Carrying application-level payloads
//! - Storing unparsed or unknown protocol data
//! - Building custom packets with arbitrary content
//!
//! ## Example
//!
//! ```rust
//! use stackforge_core::layer::raw::{RawLayer, RawBuilder};
//! use stackforge_core::LayerIndex;
//!
//! // Build a raw payload
//! let data = RawBuilder::new()
//!     .load(b"Hello, World!")
//!     .build();
//!
//! assert_eq!(&data, b"Hello, World!");
//!
//! // Build from string
//! let text = RawBuilder::from_str("GET / HTTP/1.1\r\n").build();
//! assert_eq!(&text, b"GET / HTTP/1.1\r\n");
//!
//! // Build with hex data
//! let hex = RawBuilder::from_hex("deadbeef").unwrap().build();
//! assert_eq!(&hex, &[0xde, 0xad, 0xbe, 0xef]);
//! ```

use crate::layer::LayerIndex;
use crate::layer::field::{FieldError, FieldValue};

/// Field names for the Raw layer.
pub const RAW_FIELDS: &[&str] = &["load"];

/// A layer representing raw (unparsed) payload data.
///
/// The Raw layer is the simplest layer type - it just holds arbitrary bytes
/// without any protocol-specific parsing. It's typically found at the end of
/// a packet after all known protocols have been parsed.
#[derive(Debug, Clone)]
pub struct RawLayer {
    /// The layer's position within the packet buffer.
    pub index: LayerIndex,
}

impl RawLayer {
    /// Create a new RawLayer with the given index.
    #[inline]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Create a RawLayer that spans the entire buffer from `start` to the end.
    #[inline]
    pub fn from_start(start: usize) -> Self {
        Self {
            index: LayerIndex::new(crate::LayerKind::Raw, start, start),
        }
    }

    /// Get the raw bytes of this layer.
    #[inline]
    pub fn load<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    /// Get the length of the raw payload.
    #[inline]
    pub fn len(&self, buf: &[u8]) -> usize {
        self.load(buf).len()
    }

    /// Check if the payload is empty.
    #[inline]
    pub fn is_empty(&self, buf: &[u8]) -> bool {
        self.load(buf).is_empty()
    }

    /// Get a summary string for this layer.
    pub fn summary(&self, buf: &[u8]) -> String {
        let load = self.load(buf);
        if load.is_empty() {
            "Raw".to_string()
        } else {
            format!("Raw ({} bytes)", load.len())
        }
    }

    /// Get the header length (for Raw, this is the entire payload).
    #[inline]
    pub fn header_len(&self, buf: &[u8]) -> usize {
        self.load(buf).len()
    }

    /// Get a hexdump preview of the payload (first N bytes).
    pub fn hex_preview(&self, buf: &[u8], max_bytes: usize) -> String {
        let load = self.load(buf);
        let preview_len = load.len().min(max_bytes);
        let hex: String = load[..preview_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        if load.len() > max_bytes {
            format!("{}...", hex)
        } else {
            hex
        }
    }

    /// Get an ASCII preview of the payload (printable chars only).
    pub fn ascii_preview(&self, buf: &[u8], max_bytes: usize) -> String {
        let load = self.load(buf);
        let preview_len = load.len().min(max_bytes);

        let ascii: String = load[..preview_len]
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        if load.len() > max_bytes {
            format!("{}...", ascii)
        } else {
            ascii
        }
    }

    /// Compute a hash for request/response matching.
    /// For Raw, we just return the first 8 bytes as a simple hash.
    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        let load = self.load(buf);
        load.iter().take(8).copied().collect()
    }

    /// Check if this Raw layer "answers" another Raw layer.
    /// For Raw payloads, we consider them matching if they have the same content.
    pub fn answers(&self, buf: &[u8], other: &RawLayer, other_buf: &[u8]) -> bool {
        self.load(buf) == other.load(other_buf)
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "load" => Some(Ok(FieldValue::Bytes(self.load(buf).to_vec()))),
            _ => None,
        }
    }

    /// Set a field value by name.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match name {
            "load" => {
                let new_data = match value {
                    FieldValue::Bytes(b) => b,
                    _ => return Some(Err(FieldError::InvalidValue("load must be bytes".into()))),
                };

                let slice = self.index.slice_mut(buf);
                if new_data.len() != slice.len() {
                    return Some(Err(FieldError::InvalidValue(format!(
                        "Cannot change Raw payload size: {} != {}",
                        new_data.len(),
                        slice.len()
                    ))));
                }
                slice.copy_from_slice(&new_data);
                Some(Ok(()))
            },
            _ => None,
        }
    }

    /// Get the list of field names for this layer.
    pub fn field_names() -> &'static [&'static str] {
        RAW_FIELDS
    }
}

/// Builder for constructing Raw layer payloads.
///
/// The builder supports multiple ways to specify payload data:
/// - Raw bytes via `load()`
/// - String content via `from_str()`
/// - Hex-encoded data via `from_hex()`
/// - Repeated patterns via `repeat()`
#[derive(Debug, Clone, Default)]
pub struct RawBuilder {
    data: Vec<u8>,
}

impl RawBuilder {
    /// Create a new empty RawBuilder.
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Create a RawBuilder with the given bytes.
    pub fn with_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a RawBuilder from a string (UTF-8 bytes).
    pub fn from_str(s: &str) -> Self {
        Self {
            data: s.as_bytes().to_vec(),
        }
    }

    /// Create a RawBuilder from a hex string (e.g., "deadbeef").
    ///
    /// Returns None if the hex string is invalid or contains no valid hex digits.
    pub fn from_hex(hex: &str) -> Option<Self> {
        // Remove common separators
        let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();

        // Return None for empty input or odd length
        if clean.is_empty() || clean.len() % 2 != 0 {
            return None;
        }

        let bytes: Result<Vec<u8>, _> = (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
            .collect();

        bytes.ok().map(|data| Self { data })
    }

    /// Set the payload data.
    pub fn load(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }

    /// Append data to the payload.
    pub fn append(mut self, data: &[u8]) -> Self {
        self.data.extend_from_slice(data);
        self
    }

    /// Append a string to the payload.
    pub fn append_str(mut self, s: &str) -> Self {
        self.data.extend_from_slice(s.as_bytes());
        self
    }

    /// Create a payload of `count` repeated `byte` values.
    pub fn repeat(mut self, byte: u8, count: usize) -> Self {
        self.data = vec![byte; count];
        self
    }

    /// Create a payload of zeros with the given length.
    pub fn zeros(self, len: usize) -> Self {
        self.repeat(0, len)
    }

    /// Create a payload filled with a pattern repeated to reach `len` bytes.
    pub fn pattern(mut self, pattern: &[u8], len: usize) -> Self {
        self.data = pattern.iter().cycle().take(len).copied().collect();
        self
    }

    /// Pad the payload to a minimum length with zeros.
    pub fn pad_to(mut self, min_len: usize) -> Self {
        if self.data.len() < min_len {
            self.data.resize(min_len, 0);
        }
        self
    }

    /// Pad the payload to a minimum length with a specific byte.
    pub fn pad_with(mut self, min_len: usize, byte: u8) -> Self {
        if self.data.len() < min_len {
            self.data.resize(min_len, byte);
        }
        self
    }

    /// Build the raw payload bytes.
    pub fn build(self) -> Vec<u8> {
        self.data
    }

    /// Get the current length of the payload.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Display fields for Raw layer in show() output.
pub fn raw_show_fields(layer: &RawLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let load = layer.load(buf);
    let mut fields = Vec::new();

    // Show length
    fields.push(("load", format!("[{} bytes]", load.len())));

    // If small enough, show hex preview
    if !load.is_empty() && load.len() <= 64 {
        fields.push(("hex", layer.hex_preview(buf, 32)));

        // Also show ASCII if mostly printable
        let printable_count = load
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
            .count();
        if printable_count * 2 >= load.len() {
            // More than half are printable
            fields.push(("ascii", format!("\"{}\"", layer.ascii_preview(buf, 32))));
        }
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LayerKind;

    #[test]
    fn test_raw_builder_basic() {
        let data = RawBuilder::new().load(b"Hello").build();
        assert_eq!(data, b"Hello");
    }

    #[test]
    fn test_raw_builder_from_str() {
        let data = RawBuilder::from_str("Hello, World!").build();
        assert_eq!(data, b"Hello, World!");
    }

    #[test]
    fn test_raw_builder_from_hex() {
        let builder = RawBuilder::from_hex("deadbeef").unwrap();
        assert_eq!(builder.build(), vec![0xde, 0xad, 0xbe, 0xef]);

        let builder = RawBuilder::from_hex("de ad be ef").unwrap();
        assert_eq!(builder.build(), vec![0xde, 0xad, 0xbe, 0xef]);

        let builder = RawBuilder::from_hex("DE:AD:BE:EF").unwrap();
        assert_eq!(builder.build(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_raw_builder_from_hex_invalid() {
        assert!(RawBuilder::from_hex("xyz").is_none());
        assert!(RawBuilder::from_hex("abc").is_none()); // Odd length
    }

    #[test]
    fn test_raw_builder_append() {
        let data = RawBuilder::new()
            .load(b"Hello")
            .append(b", ")
            .append_str("World!")
            .build();
        assert_eq!(data, b"Hello, World!");
    }

    #[test]
    fn test_raw_builder_repeat() {
        let data = RawBuilder::new().repeat(0x41, 5).build();
        assert_eq!(data, b"AAAAA");
    }

    #[test]
    fn test_raw_builder_zeros() {
        let data = RawBuilder::new().zeros(10).build();
        assert_eq!(data, vec![0u8; 10]);
    }

    #[test]
    fn test_raw_builder_pattern() {
        let data = RawBuilder::new().pattern(b"AB", 7).build();
        assert_eq!(data, b"ABABABA");
    }

    #[test]
    fn test_raw_builder_pad() {
        let data = RawBuilder::new().load(b"Hi").pad_to(5).build();
        assert_eq!(data, b"Hi\0\0\0");

        let data = RawBuilder::new().load(b"Hello").pad_to(3).build();
        assert_eq!(data, b"Hello"); // No change, already >= 3
    }

    #[test]
    fn test_raw_layer_load() {
        let buf = b"Hello, World!";
        let index = LayerIndex::new(LayerKind::Raw, 0, buf.len());
        let layer = RawLayer::new(index);

        assert_eq!(layer.load(buf), b"Hello, World!");
        assert_eq!(layer.len(buf), 13);
        assert!(!layer.is_empty(buf));
    }

    #[test]
    fn test_raw_layer_summary() {
        let buf = b"Test payload";
        let index = LayerIndex::new(LayerKind::Raw, 0, buf.len());
        let layer = RawLayer::new(index);

        assert_eq!(layer.summary(buf), "Raw (12 bytes)");
    }

    #[test]
    fn test_raw_layer_empty() {
        let buf: &[u8] = b"";
        let index = LayerIndex::new(LayerKind::Raw, 0, 0);
        let layer = RawLayer::new(index);

        assert!(layer.is_empty(buf));
        assert_eq!(layer.summary(buf), "Raw");
    }

    #[test]
    fn test_raw_layer_hex_preview() {
        let buf = b"\xde\xad\xbe\xef\x00\x01\x02\x03";
        let index = LayerIndex::new(LayerKind::Raw, 0, buf.len());
        let layer = RawLayer::new(index);

        let preview = layer.hex_preview(buf, 4);
        assert_eq!(preview, "de ad be ef...");

        let full = layer.hex_preview(buf, 100);
        assert_eq!(full, "de ad be ef 00 01 02 03");
    }

    #[test]
    fn test_raw_layer_ascii_preview() {
        let buf = b"Hello\x00World";
        let index = LayerIndex::new(LayerKind::Raw, 0, buf.len());
        let layer = RawLayer::new(index);

        let preview = layer.ascii_preview(buf, 100);
        assert_eq!(preview, "Hello.World");
    }

    #[test]
    fn test_raw_layer_get_field() {
        let buf = b"Test data";
        let index = LayerIndex::new(LayerKind::Raw, 0, buf.len());
        let layer = RawLayer::new(index);

        let result = layer.get_field(buf, "load").unwrap().unwrap();
        assert!(matches!(result, FieldValue::Bytes(b) if b == buf));

        assert!(layer.get_field(buf, "unknown").is_none());
    }

    #[test]
    fn test_raw_layer_set_field() {
        let mut buf = b"Hello".to_vec();
        let index = LayerIndex::new(LayerKind::Raw, 0, buf.len());
        let layer = RawLayer::new(index);

        // Same size works
        let result = layer
            .set_field(&mut buf, "load", FieldValue::Bytes(b"World".to_vec()))
            .unwrap();
        assert!(result.is_ok());
        assert_eq!(&buf, b"World");

        // Different size fails
        let result = layer
            .set_field(&mut buf, "load", FieldValue::Bytes(b"Hi".to_vec()))
            .unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_raw_layer_hashret() {
        let buf = b"0123456789ABCDEF";
        let index = LayerIndex::new(LayerKind::Raw, 0, buf.len());
        let layer = RawLayer::new(index);

        let hash = layer.hashret(buf);
        assert_eq!(hash, b"01234567");
    }

    #[test]
    fn test_raw_layer_answers() {
        let buf1 = b"Same content";
        let index1 = LayerIndex::new(LayerKind::Raw, 0, buf1.len());
        let layer1 = RawLayer::new(index1);

        let buf2 = b"Same content";
        let index2 = LayerIndex::new(LayerKind::Raw, 0, buf2.len());
        let layer2 = RawLayer::new(index2);

        let buf3 = b"Different";
        let index3 = LayerIndex::new(LayerKind::Raw, 0, buf3.len());
        let layer3 = RawLayer::new(index3);

        assert!(layer1.answers(buf1, &layer2, buf2));
        assert!(!layer1.answers(buf1, &layer3, buf3));
    }
}
