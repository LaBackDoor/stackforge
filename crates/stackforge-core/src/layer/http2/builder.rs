//! HTTP/2 frame and connection builders.
//!
//! Provides builder types for constructing HTTP/2 frames and complete
//! HTTP/2 connections (preface + frames). Follows the "Permissive Builder"
//! pattern: allows constructing any frame combination including malformed
//! ones for security testing.

use super::frames::{Http2FrameType, flags};
use super::hpack::HpackEncoder;

// ============================================================================
// Core frame building function
// ============================================================================

/// Build raw bytes for an HTTP/2 frame.
///
/// Format: 3 bytes length (big-endian) | 1 byte type | 1 byte flags | 4 bytes `stream_id` | payload
#[must_use]
pub fn build_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(9 + payload.len());
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push((len & 0xFF) as u8);
    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7FFFFFFF).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// ============================================================================
// Http2FrameBuilder
// ============================================================================

/// Builder for a single HTTP/2 frame.
///
/// # Example
/// ```
/// use stackforge_core::layer::http2::builder::Http2FrameBuilder;
/// use stackforge_core::layer::http2::frames::Http2FrameType;
///
/// let frame = Http2FrameBuilder::settings_ack().build();
/// assert_eq!(frame.len(), 9); // 9-byte header, empty payload
/// ```
#[derive(Debug, Clone)]
pub struct Http2FrameBuilder {
    frame_type: Http2FrameType,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

impl Http2FrameBuilder {
    /// Create a new frame builder for the given frame type.
    #[must_use]
    pub fn new(frame_type: Http2FrameType) -> Self {
        Http2FrameBuilder {
            frame_type,
            flags: 0,
            stream_id: 0,
            payload: Vec::new(),
        }
    }

    /// Set the flags byte.
    #[must_use]
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Set an additional flag bit (OR with existing flags).
    #[must_use]
    pub fn add_flag(mut self, flag: u8) -> Self {
        self.flags |= flag;
        self
    }

    /// Set the stream ID.
    #[must_use]
    pub fn stream_id(mut self, id: u32) -> Self {
        self.stream_id = id;
        self
    }

    /// Set the frame payload.
    #[must_use]
    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    /// Set the `END_STREAM` flag (0x1).
    ///
    /// Used with DATA and HEADERS frames.
    #[must_use]
    pub fn end_stream(mut self) -> Self {
        self.flags |= 0x01;
        self
    }

    /// Set the `END_HEADERS` flag (0x4).
    ///
    /// Used with HEADERS, `PUSH_PROMISE`, and CONTINUATION frames.
    #[must_use]
    pub fn end_headers(mut self) -> Self {
        self.flags |= 0x04;
        self
    }

    /// Build the frame into bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        build_frame(
            self.frame_type.as_u8(),
            self.flags,
            self.stream_id,
            &self.payload,
        )
    }

    // -------------------------------------------------------------------------
    // Frame factory methods
    // -------------------------------------------------------------------------

    /// Create an empty SETTINGS frame (stream 0).
    #[must_use]
    pub fn settings() -> Self {
        Http2FrameBuilder::new(Http2FrameType::Settings)
            .stream_id(0)
            .flags(0)
    }

    /// Create a SETTINGS ACK frame (stream 0, ACK flag set).
    #[must_use]
    pub fn settings_ack() -> Self {
        Http2FrameBuilder::new(Http2FrameType::Settings)
            .stream_id(0)
            .flags(flags::SETTINGS_ACK)
    }

    /// Create a SETTINGS frame with parameters.
    ///
    /// Each entry is (`settings_id`, value). The payload is 6 bytes per entry.
    #[must_use]
    pub fn settings_with_params(params: &[(u16, u32)]) -> Self {
        let mut payload = Vec::with_capacity(params.len() * 6);
        for &(id, val) in params {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&val.to_be_bytes());
        }
        Http2FrameBuilder::new(Http2FrameType::Settings)
            .stream_id(0)
            .payload(payload)
    }

    /// Create a PING frame with 8 bytes of opaque data.
    #[must_use]
    pub fn ping(data: [u8; 8]) -> Self {
        Http2FrameBuilder::new(Http2FrameType::Ping)
            .stream_id(0)
            .payload(data.to_vec())
    }

    /// Create a PING ACK frame (response to a PING).
    #[must_use]
    pub fn ping_ack(data: [u8; 8]) -> Self {
        Http2FrameBuilder::new(Http2FrameType::Ping)
            .stream_id(0)
            .flags(flags::PING_ACK)
            .payload(data.to_vec())
    }

    /// Create a GOAWAY frame.
    ///
    /// # Arguments
    /// - `last_stream`: the last stream ID processed
    /// - `error_code`: the error code (see `frames::error_codes`)
    #[must_use]
    pub fn goaway(last_stream: u32, error_code: u32) -> Self {
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&(last_stream & 0x7FFFFFFF).to_be_bytes());
        payload.extend_from_slice(&error_code.to_be_bytes());
        Http2FrameBuilder::new(Http2FrameType::GoAway)
            .stream_id(0)
            .payload(payload)
    }

    /// Create a `WINDOW_UPDATE` frame.
    ///
    /// # Arguments
    /// - `increment`: window size increment (1-2^31-1)
    /// - `stream_id`: stream ID (0 for connection-level)
    #[must_use]
    pub fn window_update(increment: u32, stream_id: u32) -> Self {
        let mut payload = Vec::with_capacity(4);
        payload.extend_from_slice(&(increment & 0x7FFFFFFF).to_be_bytes());
        Http2FrameBuilder::new(Http2FrameType::WindowUpdate)
            .stream_id(stream_id)
            .payload(payload)
    }

    /// Create a `RST_STREAM` frame.
    ///
    /// # Arguments
    /// - `stream_id`: the stream to reset
    /// - `error_code`: the error code
    #[must_use]
    pub fn rst_stream(stream_id: u32, error_code: u32) -> Self {
        let mut payload = Vec::with_capacity(4);
        payload.extend_from_slice(&error_code.to_be_bytes());
        Http2FrameBuilder::new(Http2FrameType::RstStream)
            .stream_id(stream_id)
            .payload(payload)
    }

    /// Create a HEADERS frame carrying HPACK-encoded header data.
    ///
    /// Sets `END_HEADERS` by default. Use `.flags()` to override.
    #[must_use]
    pub fn headers_frame(stream_id: u32, hpack_data: Vec<u8>) -> Self {
        Http2FrameBuilder::new(Http2FrameType::Headers)
            .stream_id(stream_id)
            .flags(flags::HEADERS_END_HEADERS)
            .payload(hpack_data)
    }

    /// Create a HEADERS frame with `END_STREAM` + `END_HEADERS` flags set.
    #[must_use]
    pub fn headers_frame_final(stream_id: u32, hpack_data: Vec<u8>) -> Self {
        Http2FrameBuilder::new(Http2FrameType::Headers)
            .stream_id(stream_id)
            .flags(flags::HEADERS_END_HEADERS | flags::HEADERS_END_STREAM)
            .payload(hpack_data)
    }

    /// Create a DATA frame.
    #[must_use]
    pub fn data_frame(stream_id: u32, data: Vec<u8>) -> Self {
        Http2FrameBuilder::new(Http2FrameType::Data)
            .stream_id(stream_id)
            .payload(data)
    }

    /// Create a DATA frame with `END_STREAM` set.
    #[must_use]
    pub fn data_frame_final(stream_id: u32, data: Vec<u8>) -> Self {
        Http2FrameBuilder::new(Http2FrameType::Data)
            .stream_id(stream_id)
            .flags(flags::DATA_END_STREAM)
            .payload(data)
    }

    /// Create a CONTINUATION frame.
    #[must_use]
    pub fn continuation(stream_id: u32, hpack_data: Vec<u8>) -> Self {
        Http2FrameBuilder::new(Http2FrameType::Continuation)
            .stream_id(stream_id)
            .payload(hpack_data)
    }

    /// Create a CONTINUATION frame with `END_HEADERS` set.
    #[must_use]
    pub fn continuation_final(stream_id: u32, hpack_data: Vec<u8>) -> Self {
        Http2FrameBuilder::new(Http2FrameType::Continuation)
            .stream_id(stream_id)
            .flags(flags::CONTINUATION_END_HEADERS)
            .payload(hpack_data)
    }

    /// Create a PRIORITY frame.
    ///
    /// # Arguments
    /// - `stream_id`: the stream being prioritized
    /// - `exclusive`: exclusive dependency flag
    /// - `stream_dep`: stream dependency
    /// - `weight`: priority weight (0-255, actual weight = weight + 1)
    #[must_use]
    pub fn priority_frame(stream_id: u32, exclusive: bool, stream_dep: u32, weight: u8) -> Self {
        let dep = if exclusive {
            stream_dep | 0x80000000
        } else {
            stream_dep & 0x7FFFFFFF
        };
        let mut payload = Vec::with_capacity(5);
        payload.extend_from_slice(&dep.to_be_bytes());
        payload.push(weight);
        Http2FrameBuilder::new(Http2FrameType::Priority)
            .stream_id(stream_id)
            .payload(payload)
    }

    /// Create a `PUSH_PROMISE` frame.
    ///
    /// # Arguments
    /// - `stream_id`: the associated stream
    /// - `promised_stream_id`: the stream ID being promised
    /// - `hpack_data`: HPACK-encoded headers for the promised request
    #[must_use]
    pub fn push_promise(stream_id: u32, promised_stream_id: u32, hpack_data: Vec<u8>) -> Self {
        let mut payload = Vec::with_capacity(4 + hpack_data.len());
        payload.extend_from_slice(&(promised_stream_id & 0x7FFFFFFF).to_be_bytes());
        payload.extend_from_slice(&hpack_data);
        Http2FrameBuilder::new(Http2FrameType::PushPromise)
            .stream_id(stream_id)
            .flags(flags::PUSH_PROMISE_END_HEADERS)
            .payload(payload)
    }
}

// ============================================================================
// Http2Builder — full connection builder
// ============================================================================

/// Builder for a complete HTTP/2 connection sequence.
///
/// Optionally includes the client connection preface, followed by one or
/// more frames.
///
/// # Example
/// ```
/// use stackforge_core::layer::http2::builder::{Http2Builder, Http2FrameBuilder};
///
/// let bytes = Http2Builder::new()
///     .frame(Http2FrameBuilder::settings())
///     .frame(Http2FrameBuilder::settings_ack())
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct Http2Builder {
    /// Whether to prepend the client connection preface.
    include_preface: bool,
    /// Ordered list of frames to include.
    frames: Vec<Http2FrameBuilder>,
}

impl Default for Http2Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Http2Builder {
    /// Create a builder that includes the HTTP/2 client connection preface.
    #[must_use]
    pub fn new() -> Self {
        Http2Builder {
            include_preface: true,
            frames: Vec::new(),
        }
    }

    /// Create a builder without the connection preface.
    #[must_use]
    pub fn without_preface() -> Self {
        Http2Builder {
            include_preface: false,
            frames: Vec::new(),
        }
    }

    /// Add a frame to the sequence.
    #[must_use]
    pub fn frame(mut self, f: Http2FrameBuilder) -> Self {
        self.frames.push(f);
        self
    }

    /// Get the total byte size of the built output.
    #[must_use]
    pub fn header_size(&self) -> usize {
        let preface_len = if self.include_preface { 24 } else { 0 };
        let frames_len: usize = self.frames.iter().map(|f| 9 + f.payload.len()).sum();
        preface_len + frames_len
    }

    /// Build the complete HTTP/2 connection sequence into bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header_size());

        if self.include_preface {
            out.extend_from_slice(super::frames::HTTP2_PREFACE);
        }

        for frame in &self.frames {
            out.extend_from_slice(&frame.build());
        }

        out
    }
}

// ============================================================================
// HTTP/2 request/response helpers
// ============================================================================

/// Build a complete HTTP/2 GET request as bytes.
///
/// Produces: preface + SETTINGS frame + HEADERS frame with HPACK-encoded headers.
///
/// # Arguments
/// - `host`: the `:authority` (Host) header value
/// - `path`: the `:path` value (e.g., "/")
/// - `stream_id`: stream identifier (must be odd for client-initiated, typically 1)
#[must_use]
pub fn build_get_request(host: &str, path: &str, stream_id: u32) -> Vec<u8> {
    let encoder = HpackEncoder::new();
    let headers = vec![
        (":method", "GET"),
        (":path", path),
        (":scheme", "https"),
        (":authority", host),
        ("accept", "*/*"),
    ];
    let hpack_data = encoder.encode(&headers);

    Http2Builder::new()
        .frame(Http2FrameBuilder::settings())
        .frame(Http2FrameBuilder::headers_frame_final(
            stream_id, hpack_data,
        ))
        .build()
}

/// Build a complete HTTP/2 200 OK response as bytes.
///
/// Produces: SETTINGS ACK + HEADERS frame + optional DATA frame.
///
/// # Arguments
/// - `stream_id`: the stream ID to respond on
/// - `body`: optional response body; if `Some`, a DATA frame with `END_STREAM` is appended
#[must_use]
pub fn build_response_200(stream_id: u32, body: Option<&[u8]>) -> Vec<u8> {
    let encoder = HpackEncoder::new();
    let headers = vec![(":status", "200"), ("content-type", "application/json")];
    let hpack_data = encoder.encode(&headers);

    let headers_flags = if body.is_none() {
        // END_HEADERS | END_STREAM if no body
        flags::HEADERS_END_HEADERS | flags::HEADERS_END_STREAM
    } else {
        flags::HEADERS_END_HEADERS
    };

    let mut builder = Http2Builder::without_preface()
        .frame(Http2FrameBuilder::settings_ack())
        .frame(
            Http2FrameBuilder::new(Http2FrameType::Headers)
                .stream_id(stream_id)
                .flags(headers_flags)
                .payload(hpack_data),
        );

    if let Some(body_data) = body {
        builder = builder.frame(Http2FrameBuilder::data_frame_final(
            stream_id,
            body_data.to_vec(),
        ));
    }

    builder.build()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::http2::frames::{
        Http2Frame, parse_all_frames, parse_goaway, parse_rst_stream, parse_settings,
        parse_window_update,
    };

    #[test]
    fn test_build_settings_frame() {
        let bytes = Http2FrameBuilder::settings().build();
        assert_eq!(bytes.len(), 9); // empty payload
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert_eq!(frame.frame_type, Http2FrameType::Settings);
        assert!(!frame.is_ack());
        assert_eq!(frame.stream_id, 0);
    }

    #[test]
    fn test_build_settings_ack() {
        let bytes = Http2FrameBuilder::settings_ack().build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert_eq!(frame.frame_type, Http2FrameType::Settings);
        assert!(frame.is_ack());
    }

    #[test]
    fn test_build_settings_with_params() {
        use crate::layer::http2::frames::settings_id;

        let params = [
            (settings_id::INITIAL_WINDOW_SIZE, 65535u32),
            (settings_id::MAX_FRAME_SIZE, 16384),
        ];
        let bytes = Http2FrameBuilder::settings_with_params(&params).build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();

        let settings = parse_settings(frame.payload(&bytes));
        assert_eq!(settings.len(), 2);
        assert_eq!(settings[0], (settings_id::INITIAL_WINDOW_SIZE, 65535));
        assert_eq!(settings[1], (settings_id::MAX_FRAME_SIZE, 16384));
    }

    #[test]
    fn test_build_ping() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let bytes = Http2FrameBuilder::ping(data).build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert_eq!(frame.frame_type, Http2FrameType::Ping);
        assert!(!frame.is_ack());
        assert_eq!(frame.payload(&bytes), &data);
    }

    #[test]
    fn test_build_ping_ack() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let bytes = Http2FrameBuilder::ping_ack(data).build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert!(frame.is_ack());
        assert_eq!(frame.payload(&bytes), &data);
    }

    #[test]
    fn test_build_goaway() {
        use crate::layer::http2::frames::error_codes;
        let bytes = Http2FrameBuilder::goaway(3, error_codes::NO_ERROR).build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert_eq!(frame.frame_type, Http2FrameType::GoAway);
        let (last_id, error) = parse_goaway(frame.payload(&bytes)).unwrap();
        assert_eq!(last_id, 3);
        assert_eq!(error, error_codes::NO_ERROR);
    }

    #[test]
    fn test_build_window_update() {
        let bytes = Http2FrameBuilder::window_update(65535, 0).build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert_eq!(frame.frame_type, Http2FrameType::WindowUpdate);
        let increment = parse_window_update(frame.payload(&bytes)).unwrap();
        assert_eq!(increment, 65535);
    }

    #[test]
    fn test_build_rst_stream() {
        use crate::layer::http2::frames::error_codes;
        let bytes = Http2FrameBuilder::rst_stream(1, error_codes::CANCEL).build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert_eq!(frame.frame_type, Http2FrameType::RstStream);
        assert_eq!(frame.stream_id, 1);
        let error = parse_rst_stream(frame.payload(&bytes)).unwrap();
        assert_eq!(error, error_codes::CANCEL);
    }

    #[test]
    fn test_build_headers_frame() {
        let hpack_data = vec![0x82u8]; // ":method: GET"
        let bytes = Http2FrameBuilder::headers_frame(1, hpack_data.clone()).build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert_eq!(frame.frame_type, Http2FrameType::Headers);
        assert!(frame.is_end_headers());
        assert!(!frame.is_end_stream());
        assert_eq!(frame.payload(&bytes), &hpack_data);
    }

    #[test]
    fn test_build_headers_final() {
        let hpack_data = vec![0x82u8];
        let bytes = Http2FrameBuilder::headers_frame_final(1, hpack_data).build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert!(frame.is_end_headers());
        assert!(frame.is_end_stream());
    }

    #[test]
    fn test_build_data_frame() {
        let data = b"Hello, HTTP/2!";
        let bytes = Http2FrameBuilder::data_frame(1, data.to_vec()).build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert_eq!(frame.frame_type, Http2FrameType::Data);
        assert!(!frame.is_end_stream());
        assert_eq!(frame.payload(&bytes), data);
    }

    #[test]
    fn test_build_data_frame_final() {
        let data = b"last chunk";
        let bytes = Http2FrameBuilder::data_frame_final(1, data.to_vec()).build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert!(frame.is_end_stream());
    }

    #[test]
    fn test_http2_builder_with_preface() {
        let bytes = Http2Builder::new()
            .frame(Http2FrameBuilder::settings())
            .frame(Http2FrameBuilder::settings_ack())
            .build();

        // Should start with preface
        assert!(bytes.starts_with(super::super::frames::HTTP2_PREFACE));

        let frames = parse_all_frames(&bytes);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].frame_type, Http2FrameType::Settings);
        assert_eq!(frames[1].frame_type, Http2FrameType::Settings);
        assert!(frames[1].is_ack());
    }

    #[test]
    fn test_http2_builder_without_preface() {
        let bytes = Http2Builder::without_preface()
            .frame(Http2FrameBuilder::settings_ack())
            .build();

        assert!(!bytes.starts_with(super::super::frames::HTTP2_PREFACE));
        let frames = parse_all_frames(&bytes);
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn test_http2_builder_header_size() {
        let builder = Http2Builder::new()
            .frame(Http2FrameBuilder::settings()) // 9 bytes
            .frame(Http2FrameBuilder::settings_ack()); // 9 bytes

        // 24 (preface) + 9 + 9 = 42
        assert_eq!(builder.header_size(), 42);
        assert_eq!(builder.build().len(), 42);
    }

    #[test]
    fn test_build_get_request() {
        let bytes = build_get_request("example.com", "/", 1);
        assert!(bytes.starts_with(super::super::frames::HTTP2_PREFACE));

        let frames = parse_all_frames(&bytes);
        // Should have at least 2 frames: SETTINGS + HEADERS
        assert!(frames.len() >= 2);
        assert_eq!(frames[0].frame_type, Http2FrameType::Settings);
        assert_eq!(frames[1].frame_type, Http2FrameType::Headers);
        assert!(frames[1].is_end_headers());
        assert!(frames[1].is_end_stream());
        assert_eq!(frames[1].stream_id, 1);
    }

    #[test]
    fn test_build_response_200_no_body() {
        let bytes = build_response_200(1, None);
        let frames = parse_all_frames(&bytes);
        assert!(frames.len() >= 2);
        assert_eq!(frames[0].frame_type, Http2FrameType::Settings);
        assert!(frames[0].is_ack());
        assert_eq!(frames[1].frame_type, Http2FrameType::Headers);
    }

    #[test]
    fn test_build_response_200_with_body() {
        let body = b"{\"ok\": true}";
        let bytes = build_response_200(1, Some(body));
        let frames = parse_all_frames(&bytes);
        assert!(frames.len() >= 3);
        assert_eq!(frames[2].frame_type, Http2FrameType::Data);
        assert!(frames[2].is_end_stream());
        assert_eq!(frames[2].payload(&bytes), body);
    }

    #[test]
    fn test_end_stream_and_end_headers_helpers() {
        let builder = Http2FrameBuilder::new(Http2FrameType::Headers)
            .stream_id(1)
            .end_stream()
            .end_headers()
            .payload(vec![0x82]);

        let bytes = builder.build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert!(frame.is_end_stream());
        assert!(frame.is_end_headers());
    }

    #[test]
    fn test_priority_frame() {
        let bytes = Http2FrameBuilder::priority_frame(1, false, 0, 15).build();
        let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
        assert_eq!(frame.frame_type, Http2FrameType::Priority);
        assert_eq!(frame.stream_id, 1);
        assert_eq!(frame.length, 5);
    }
}
