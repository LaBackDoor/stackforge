//! HTTP/2 protocol layer (RFC 7540).
//!
//! This module implements the HTTP/2 framing layer for Stackforge, including:
//! - Frame parsing and building (RFC 7540)
//! - HPACK header compression (RFC 7541)
//! - Layer integration with the Stackforge packet model
//!
//! ## Architecture
//!
//! HTTP/2 operates over TCP as a sequence of frames. Each frame has a 9-byte
//! header followed by a variable-length payload. A connection begins with a
//! 24-byte "preface" string sent by the client.
//!
//! The `Http2Layer` represents one "segment" of HTTP/2 traffic captured within
//! a packet buffer. It identifies whether the segment starts with the connection
//! preface and provides access to the contained frames.
//!
//! ## Usage
//!
//! ```rust
//! use stackforge_core::layer::http2::builder::{Http2Builder, Http2FrameBuilder};
//! use stackforge_core::layer::http2::{Http2Layer, Http2Frame};
//! use stackforge_core::layer::{LayerIndex, LayerKind};
//!
//! // Build a connection initiation
//! let bytes = Http2Builder::new()
//!     .frame(Http2FrameBuilder::settings())
//!     .build();
//!
//! // Parse it back
//! let layer = Http2Layer::new(0, bytes.len(), true);
//! let summary = layer.summary(&bytes);
//! assert!(summary.contains("HTTP/2"));
//! ```

pub mod builder;
pub mod frames;
pub mod hpack;

pub use builder::{Http2Builder, Http2FrameBuilder, build_frame};
pub use frames::{
    HTTP2_FRAME_HEADER_LEN, HTTP2_PREFACE, Http2Frame, Http2FrameType, error_codes, flags,
    parse_all_frames, parse_goaway, parse_rst_stream, parse_settings, parse_window_update,
    settings_id,
};
pub use hpack::{HpackDecoder, HpackEncoder, STATIC_TABLE};

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

// ============================================================================
// HTTP/2 Layer
// ============================================================================

/// Field names exposed by the HTTP/2 layer.
pub const HTTP2_FIELD_NAMES: &[&str] = &["frame_type", "flags", "stream_id", "length"];

/// HTTP/2 protocol layer view.
///
/// Represents one or more HTTP/2 frames within a packet buffer. The `index`
/// covers the portion of the buffer from the start of the HTTP/2 data
/// (preface or first frame header) to the end.
///
/// Note: A single `Http2Layer` may contain multiple frames. Use
/// [`frames::parse_all_frames`] or [`Http2Layer::all_frames`] to iterate them.
#[derive(Debug, Clone)]
pub struct Http2Layer {
    /// Layer boundary index within the packet buffer.
    pub index: LayerIndex,
    /// Whether the layer begins with the HTTP/2 client connection preface.
    pub has_preface: bool,
}

impl Http2Layer {
    /// Create a new HTTP/2 layer from start/end offsets and a preface flag.
    pub fn new(start: usize, end: usize, has_preface: bool) -> Self {
        Http2Layer {
            index: LayerIndex::new(LayerKind::Http2, start, end),
            has_preface,
        }
    }

    /// Create from an existing `LayerIndex`.
    pub fn from_index(index: LayerIndex, has_preface: bool) -> Self {
        Http2Layer { index, has_preface }
    }

    /// Check if `buf` starting at `offset` begins with the HTTP/2 preface.
    pub fn has_preface_at(buf: &[u8], offset: usize) -> bool {
        let end = offset + HTTP2_PREFACE.len();
        if end > buf.len() {
            return false;
        }
        &buf[offset..end] == HTTP2_PREFACE
    }

    /// Get the offset where frames begin (after the preface if present).
    pub fn frames_start(&self) -> usize {
        if self.has_preface {
            self.index.start + HTTP2_PREFACE.len()
        } else {
            self.index.start
        }
    }

    /// Get the first frame in this layer, skipping the preface if present.
    ///
    /// Returns `None` if there are no frames or the buffer is too short.
    pub fn first_frame<'a>(&self, buf: &'a [u8]) -> Option<Http2Frame> {
        let offset = self.frames_start();
        Http2Frame::parse_at(buf, offset)
    }

    /// Parse all frames in this layer's buffer range.
    pub fn all_frames(&self, buf: &[u8]) -> Vec<Http2Frame> {
        let slice = self.index.slice(buf);
        let preface_skip = if self.has_preface {
            HTTP2_PREFACE.len()
        } else {
            0
        };

        if preface_skip > slice.len() {
            return Vec::new();
        }

        // parse_all_frames works on the full buffer; we pass the slice and
        // offset is relative to the slice start, so we use the offset directly.
        // For correctness we parse directly using absolute offsets.
        let mut frames = Vec::new();
        let mut offset = self.index.start + preface_skip;

        loop {
            match Http2Frame::parse_at(buf, offset) {
                Some(frame) => {
                    // Only include frames within our layer's range
                    if frame.payload_offset + frame.length as usize > self.index.end {
                        break;
                    }
                    let total = frame.total_size;
                    frames.push(frame);
                    offset += total;
                    if offset >= self.index.end {
                        break;
                    }
                },
                None => break,
            }
        }

        frames
    }

    /// Generate a human-readable summary for this layer.
    pub fn summary(&self, buf: &[u8]) -> String {
        let preface_str = if self.has_preface { "Preface + " } else { "" };

        if let Some(frame) = self.first_frame(buf) {
            let type_name = frame.frame_type.name();
            if self.has_preface {
                format!(
                    "HTTP/2 {}[{}] stream={}",
                    preface_str, type_name, frame.stream_id
                )
            } else {
                format!("HTTP/2 [{}] stream={}", type_name, frame.stream_id)
            }
        } else if self.has_preface {
            "HTTP/2 Preface".to_string()
        } else {
            "HTTP/2".to_string()
        }
    }

    /// Get the "header length" of this layer.
    ///
    /// This returns the number of bytes that constitute the "header" portion:
    /// - If only a preface: 24 bytes
    /// - If a frame (no preface): 9 bytes (one frame header)
    /// - If preface + at least one frame: 33 bytes (24 + 9)
    pub fn header_len(&self, buf: &[u8]) -> usize {
        if self.has_preface {
            // Check if there's at least one frame after the preface
            let frame_start = self.index.start + HTTP2_PREFACE.len();
            if frame_start + HTTP2_FRAME_HEADER_LEN <= buf.len() {
                HTTP2_PREFACE.len() + HTTP2_FRAME_HEADER_LEN // 33 bytes
            } else {
                HTTP2_PREFACE.len() // 24 bytes, preface only
            }
        } else {
            HTTP2_FRAME_HEADER_LEN // 9 bytes
        }
    }

    /// Get a field value from the first frame by name.
    ///
    /// Supported fields: `frame_type`, `flags`, `stream_id`, `length`.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        let frame = self.first_frame(buf)?;
        match name {
            "frame_type" => Some(Ok(FieldValue::U8(frame.frame_type.as_u8()))),
            "flags" => Some(Ok(FieldValue::U8(frame.flags))),
            "stream_id" => Some(Ok(FieldValue::U32(frame.stream_id))),
            "length" => Some(Ok(FieldValue::U32(frame.length))),
            _ => None,
        }
    }

    /// Set a field value by name.
    ///
    /// Currently only `stream_id` supports mutation. Other fields require
    /// rebuilding the frame.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match name {
            "stream_id" => {
                let id = match value {
                    FieldValue::U32(v) => v,
                    FieldValue::U16(v) => v as u32,
                    FieldValue::U8(v) => v as u32,
                    _ => {
                        return Some(Err(FieldError::InvalidValue(format!(
                            "stream_id: expected integer, got {:?}",
                            value
                        ))));
                    },
                };

                let offset = self.frames_start() + 5; // stream_id at bytes 5-8 of frame header
                if offset + 4 > buf.len() {
                    return Some(Err(FieldError::BufferTooShort {
                        offset,
                        need: 4,
                        have: buf.len().saturating_sub(offset),
                    }));
                }
                let bytes = (id & 0x7FFFFFFF).to_be_bytes();
                buf[offset..offset + 4].copy_from_slice(&bytes);
                Some(Ok(()))
            },
            "flags" => {
                let flag_val = match value {
                    FieldValue::U8(v) => v,
                    _ => {
                        return Some(Err(FieldError::InvalidValue(format!(
                            "flags: expected U8, got {:?}",
                            value
                        ))));
                    },
                };

                let offset = self.frames_start() + 4; // flags at byte 4 of frame header
                if offset >= buf.len() {
                    return Some(Err(FieldError::BufferTooShort {
                        offset,
                        need: 1,
                        have: 0,
                    }));
                }
                buf[offset] = flag_val;
                Some(Ok(()))
            },
            _ => None,
        }
    }

    /// Get the static list of field names for this layer type.
    pub fn field_names() -> &'static [&'static str] {
        HTTP2_FIELD_NAMES
    }
}

// ============================================================================
// Layer trait implementation
// ============================================================================

impl Layer for Http2Layer {
    fn kind(&self) -> LayerKind {
        LayerKind::Http2
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.header_len(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        HTTP2_FIELD_NAMES
    }

    fn hashret(&self, _data: &[u8]) -> Vec<u8> {
        // HTTP/2 hashret could be based on stream ID, but for now return empty
        vec![]
    }
}

// ============================================================================
// HTTP/2 detection helper
// ============================================================================

/// Check if a TCP payload looks like HTTP/2 traffic.
///
/// Returns true if the buffer starts with the HTTP/2 connection preface
/// or if it begins with a valid-looking HTTP/2 frame header.
pub fn is_http2_payload(data: &[u8]) -> bool {
    // Check for preface
    if data.len() >= HTTP2_PREFACE.len() && data.starts_with(HTTP2_PREFACE) {
        return true;
    }

    // Check for a valid frame header: length(3) + type(1) + flags(1) + stream_id(4)
    if data.len() < HTTP2_FRAME_HEADER_LEN {
        return false;
    }

    // Length field is 24-bit; must be reasonable (< 16 MB)
    let length = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
    if length > 0x00FF_FFFF {
        return false;
    }

    // Frame type must be 0-9 (known) or we still accept it for unknown types
    let frame_type = data[3];
    let valid_type = frame_type <= 9;

    // Stream ID must have R bit = 0 in a valid frame
    let stream_word = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
    let r_bit = (stream_word & 0x80000000) == 0; // R bit should be 0

    valid_type && r_bit && length <= 16384 // default MAX_FRAME_SIZE
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::http2::builder::{Http2Builder, Http2FrameBuilder, build_get_request};

    #[test]
    fn test_http2_layer_summary_with_preface() {
        let bytes = Http2Builder::new()
            .frame(Http2FrameBuilder::settings())
            .build();

        let layer = Http2Layer::new(0, bytes.len(), true);
        let summary = layer.summary(&bytes);
        assert!(summary.contains("HTTP/2"));
        assert!(summary.contains("Preface"));
        assert!(summary.contains("SETTINGS"));
    }

    #[test]
    fn test_http2_layer_summary_no_preface() {
        let bytes = Http2FrameBuilder::settings_ack().build();
        let layer = Http2Layer::new(0, bytes.len(), false);
        let summary = layer.summary(&bytes);
        assert!(summary.contains("HTTP/2"));
        assert!(summary.contains("SETTINGS"));
    }

    #[test]
    fn test_http2_layer_header_len_preface_and_frame() {
        let bytes = Http2Builder::new()
            .frame(Http2FrameBuilder::settings())
            .build();
        let layer = Http2Layer::new(0, bytes.len(), true);
        // 24 (preface) + 9 (first frame header)
        assert_eq!(layer.header_len(&bytes), 33);
    }

    #[test]
    fn test_http2_layer_header_len_no_preface() {
        let bytes = Http2FrameBuilder::settings().build();
        let layer = Http2Layer::new(0, bytes.len(), false);
        assert_eq!(layer.header_len(&bytes), 9);
    }

    #[test]
    fn test_http2_layer_get_field() {
        // Build a HEADERS frame on stream 3
        let bytes = Http2FrameBuilder::headers_frame(3, vec![0x82]).build();
        let layer = Http2Layer::new(0, bytes.len(), false);

        let ft = layer.get_field(&bytes, "frame_type").unwrap().unwrap();
        assert_eq!(ft, FieldValue::U8(1)); // HEADERS = 1

        let sid = layer.get_field(&bytes, "stream_id").unwrap().unwrap();
        assert_eq!(sid, FieldValue::U32(3));

        let flags = layer.get_field(&bytes, "flags").unwrap().unwrap();
        assert_eq!(flags, FieldValue::U8(0x04)); // END_HEADERS

        let len = layer.get_field(&bytes, "length").unwrap().unwrap();
        assert_eq!(len, FieldValue::U32(1)); // 1 byte payload
    }

    #[test]
    fn test_http2_layer_set_stream_id() {
        let mut bytes = Http2FrameBuilder::headers_frame(1, vec![0x82]).build();
        let layer = Http2Layer::new(0, bytes.len(), false);

        layer
            .set_field(&mut bytes, "stream_id", FieldValue::U32(5))
            .unwrap()
            .unwrap();

        let sid = layer.get_field(&bytes, "stream_id").unwrap().unwrap();
        assert_eq!(sid, FieldValue::U32(5));
    }

    #[test]
    fn test_http2_layer_all_frames() {
        let bytes = Http2Builder::new()
            .frame(Http2FrameBuilder::settings())
            .frame(Http2FrameBuilder::settings_ack())
            .frame(Http2FrameBuilder::headers_frame(1, vec![0x82]))
            .build();

        let layer = Http2Layer::new(0, bytes.len(), true);
        let frames = layer.all_frames(&bytes);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].frame_type, Http2FrameType::Settings);
        assert_eq!(frames[1].frame_type, Http2FrameType::Settings);
        assert_eq!(frames[2].frame_type, Http2FrameType::Headers);
    }

    #[test]
    fn test_has_preface_at() {
        let mut buf = Vec::new();
        buf.extend_from_slice(HTTP2_PREFACE);
        buf.extend_from_slice(&Http2FrameBuilder::settings().build());

        assert!(Http2Layer::has_preface_at(&buf, 0));
        assert!(!Http2Layer::has_preface_at(&buf, 1));
        assert!(!Http2Layer::has_preface_at(&[], 0));
    }

    #[test]
    fn test_is_http2_payload_preface() {
        let bytes = Http2Builder::new()
            .frame(Http2FrameBuilder::settings())
            .build();
        assert!(is_http2_payload(&bytes));
    }

    #[test]
    fn test_is_http2_payload_frame() {
        let bytes = Http2FrameBuilder::settings_ack().build();
        assert!(is_http2_payload(&bytes));
    }

    #[test]
    fn test_is_http2_payload_not_http2() {
        assert!(!is_http2_payload(b"HTTP/1.1 200 OK\r\n\r\n"));
        assert!(!is_http2_payload(b"GET / HTTP/1.1\r\n"));
        assert!(!is_http2_payload(&[]));
    }

    #[test]
    fn test_layer_kind() {
        let layer = Http2Layer::new(0, 9, false);
        assert_eq!(layer.kind(), LayerKind::Http2);
    }

    #[test]
    fn test_layer_field_names() {
        let layer = Http2Layer::new(0, 9, false);
        let names = layer.field_names();
        assert!(names.contains(&"frame_type"));
        assert!(names.contains(&"flags"));
        assert!(names.contains(&"stream_id"));
        assert!(names.contains(&"length"));
    }

    #[test]
    fn test_get_request_integration() {
        use crate::layer::http2::hpack::HpackDecoder;

        let bytes = build_get_request("example.com", "/api/v1", 1);
        let layer = Http2Layer::new(0, bytes.len(), true);

        let frames = layer.all_frames(&bytes);
        assert!(frames.len() >= 2);

        // Find the HEADERS frame
        let headers_frame = frames
            .iter()
            .find(|f| f.frame_type == Http2FrameType::Headers)
            .unwrap();
        assert!(headers_frame.is_end_headers());
        assert!(headers_frame.is_end_stream());

        // Decode HPACK
        let hpack_data = headers_frame_fragment(headers_frame, &bytes).unwrap();
        let mut decoder = HpackDecoder::new();
        let headers = decoder.decode(hpack_data).unwrap();

        let method = headers
            .iter()
            .find(|(n, _)| n == ":method")
            .map(|(_, v)| v.as_str());
        let path = headers
            .iter()
            .find(|(n, _)| n == ":path")
            .map(|(_, v)| v.as_str());

        assert_eq!(method, Some("GET"));
        assert_eq!(path, Some("/api/v1"));
    }

    // Helper to extract HPACK fragment from a HEADERS frame
    fn headers_frame_fragment<'a>(frame: &Http2Frame, buf: &'a [u8]) -> Option<&'a [u8]> {
        if frame.frame_type != Http2FrameType::Headers {
            return None;
        }
        let payload = frame.payload(buf);
        let mut start = 0;

        if frame.is_padded() {
            if payload.is_empty() {
                return None;
            }
            start += payload[0] as usize + 1;
        }

        if frame.has_priority() {
            start += 5;
        }

        Some(&payload[start..])
    }
}
