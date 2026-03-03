//! HTTP/2 frame parsing (RFC 7540 Section 4).
//!
//! HTTP/2 frames have a fixed 9-byte header:
//! ```text
//! +-----------------------------------------------+
//! |                 Length (24)                   |
//! +---------------+---------------+---------------+
//! |   Type (8)    |   Flags (8)   |
//! +-+-------------+---------------+-------------------------------+
//! |R|                 Stream Identifier (31)                      |
//! +=+=============================================================+
//! |                   Frame Payload (0...)                      ...
//! +---------------------------------------------------------------+
//! ```
//!
//! This module provides types and functions for parsing all HTTP/2 frame types.

// ============================================================================
// Constants
// ============================================================================

/// The HTTP/2 client connection preface (RFC 7540 Section 3.5).
pub const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Length of the HTTP/2 frame header in bytes.
pub const HTTP2_FRAME_HEADER_LEN: usize = 9;

// ============================================================================
// Frame Type
// ============================================================================

/// HTTP/2 frame type identifiers (RFC 7540 Section 6).
///
/// Note: Explicit discriminants are not used because the enum has a non-unit
/// variant (`Unknown`). Use `as_u8()` to get the numeric frame type value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Http2FrameType {
    /// DATA frame (type=0x0).
    Data,
    /// HEADERS frame (type=0x1).
    Headers,
    /// PRIORITY frame (type=0x2).
    Priority,
    /// `RST_STREAM` frame (type=0x3).
    RstStream,
    /// SETTINGS frame (type=0x4).
    Settings,
    /// `PUSH_PROMISE` frame (type=0x5).
    PushPromise,
    /// PING frame (type=0x6).
    Ping,
    /// GOAWAY frame (type=0x7).
    GoAway,
    /// `WINDOW_UPDATE` frame (type=0x8).
    WindowUpdate,
    /// CONTINUATION frame (type=0x9).
    Continuation,
    /// Unknown frame type with raw byte value.
    Unknown(u8),
}

impl Http2FrameType {
    /// Convert a raw u8 byte to an `Http2FrameType`.
    #[must_use]
    pub fn from_u8(t: u8) -> Self {
        match t {
            0 => Self::Data,
            1 => Self::Headers,
            2 => Self::Priority,
            3 => Self::RstStream,
            4 => Self::Settings,
            5 => Self::PushPromise,
            6 => Self::Ping,
            7 => Self::GoAway,
            8 => Self::WindowUpdate,
            9 => Self::Continuation,
            _ => Self::Unknown(t),
        }
    }

    /// Get the human-readable name of this frame type.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Data => "DATA",
            Self::Headers => "HEADERS",
            Self::Priority => "PRIORITY",
            Self::RstStream => "RST_STREAM",
            Self::Settings => "SETTINGS",
            Self::PushPromise => "PUSH_PROMISE",
            Self::Ping => "PING",
            Self::GoAway => "GOAWAY",
            Self::WindowUpdate => "WINDOW_UPDATE",
            Self::Continuation => "CONTINUATION",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    /// Convert to raw u8 byte value.
    #[must_use]
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Headers => 1,
            Self::Priority => 2,
            Self::RstStream => 3,
            Self::Settings => 4,
            Self::PushPromise => 5,
            Self::Ping => 6,
            Self::GoAway => 7,
            Self::WindowUpdate => 8,
            Self::Continuation => 9,
            Self::Unknown(t) => *t,
        }
    }
}

impl std::fmt::Display for Http2FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Frame Flags
// ============================================================================

/// Flag constants for HTTP/2 frame types (RFC 7540 Section 6).
pub mod flags {
    /// DATA frame: `END_STREAM` flag (0x1) - indicates the last DATA frame for a stream.
    pub const DATA_END_STREAM: u8 = 0x01;
    /// DATA frame: PADDED flag (0x8) - indicates padding is present.
    pub const DATA_PADDED: u8 = 0x08;

    /// HEADERS frame: `END_STREAM` flag (0x1) - last HEADERS/CONTINUATION for this stream.
    pub const HEADERS_END_STREAM: u8 = 0x01;
    /// HEADERS frame: `END_HEADERS` flag (0x4) - the frame contains a complete header block.
    pub const HEADERS_END_HEADERS: u8 = 0x04;
    /// HEADERS frame: PADDED flag (0x8) - padding is present.
    pub const HEADERS_PADDED: u8 = 0x08;
    /// HEADERS frame: PRIORITY flag (0x20) - priority fields are present.
    pub const HEADERS_PRIORITY: u8 = 0x20;

    /// SETTINGS frame: ACK flag (0x1) - this is an acknowledgment of a SETTINGS frame.
    pub const SETTINGS_ACK: u8 = 0x01;

    /// PING frame: ACK flag (0x1) - this is a PING response.
    pub const PING_ACK: u8 = 0x01;

    /// `PUSH_PROMISE` frame: `END_HEADERS` flag (0x4) - complete header block.
    pub const PUSH_PROMISE_END_HEADERS: u8 = 0x04;
    /// `PUSH_PROMISE` frame: PADDED flag (0x8) - padding is present.
    pub const PUSH_PROMISE_PADDED: u8 = 0x08;

    /// CONTINUATION frame: `END_HEADERS` flag (0x4) - complete header block.
    pub const CONTINUATION_END_HEADERS: u8 = 0x04;
}

// ============================================================================
// HTTP/2 Settings identifiers
// ============================================================================

/// SETTINGS parameter identifiers (RFC 7540 Section 6.5.2).
pub mod settings_id {
    /// `SETTINGS_HEADER_TABLE_SIZE` (0x1): initial value 4096.
    pub const HEADER_TABLE_SIZE: u16 = 0x0001;
    /// `SETTINGS_ENABLE_PUSH` (0x2): initial value 1.
    pub const ENABLE_PUSH: u16 = 0x0002;
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (0x3): initially unlimited.
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x0003;
    /// `SETTINGS_INITIAL_WINDOW_SIZE` (0x4): initial value 65535.
    pub const INITIAL_WINDOW_SIZE: u16 = 0x0004;
    /// `SETTINGS_MAX_FRAME_SIZE` (0x5): initial value 16384.
    pub const MAX_FRAME_SIZE: u16 = 0x0005;
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` (0x6): initially unlimited.
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x0006;

    /// Get the human-readable name of a settings ID.
    #[must_use]
    pub fn name(id: u16) -> &'static str {
        match id {
            HEADER_TABLE_SIZE => "HEADER_TABLE_SIZE",
            ENABLE_PUSH => "ENABLE_PUSH",
            MAX_CONCURRENT_STREAMS => "MAX_CONCURRENT_STREAMS",
            INITIAL_WINDOW_SIZE => "INITIAL_WINDOW_SIZE",
            MAX_FRAME_SIZE => "MAX_FRAME_SIZE",
            MAX_HEADER_LIST_SIZE => "MAX_HEADER_LIST_SIZE",
            _ => "UNKNOWN",
        }
    }
}

// ============================================================================
// HTTP/2 Error Codes
// ============================================================================

/// HTTP/2 error codes (RFC 7540 Section 7).
pub mod error_codes {
    pub const NO_ERROR: u32 = 0x0;
    pub const PROTOCOL_ERROR: u32 = 0x1;
    pub const INTERNAL_ERROR: u32 = 0x2;
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    pub const SETTINGS_TIMEOUT: u32 = 0x4;
    pub const STREAM_CLOSED: u32 = 0x5;
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    pub const REFUSED_STREAM: u32 = 0x7;
    pub const CANCEL: u32 = 0x8;
    pub const COMPRESSION_ERROR: u32 = 0x9;
    pub const CONNECT_ERROR: u32 = 0xa;
    pub const ENHANCE_YOUR_CALM: u32 = 0xb;
    pub const INADEQUATE_SECURITY: u32 = 0xc;
    pub const HTTP_1_1_REQUIRED: u32 = 0xd;

    /// Get the human-readable name for an error code.
    #[must_use]
    pub fn name(code: u32) -> &'static str {
        match code {
            NO_ERROR => "NO_ERROR",
            PROTOCOL_ERROR => "PROTOCOL_ERROR",
            INTERNAL_ERROR => "INTERNAL_ERROR",
            FLOW_CONTROL_ERROR => "FLOW_CONTROL_ERROR",
            SETTINGS_TIMEOUT => "SETTINGS_TIMEOUT",
            STREAM_CLOSED => "STREAM_CLOSED",
            FRAME_SIZE_ERROR => "FRAME_SIZE_ERROR",
            REFUSED_STREAM => "REFUSED_STREAM",
            CANCEL => "CANCEL",
            COMPRESSION_ERROR => "COMPRESSION_ERROR",
            CONNECT_ERROR => "CONNECT_ERROR",
            ENHANCE_YOUR_CALM => "ENHANCE_YOUR_CALM",
            INADEQUATE_SECURITY => "INADEQUATE_SECURITY",
            HTTP_1_1_REQUIRED => "HTTP_1_1_REQUIRED",
            _ => "UNKNOWN",
        }
    }
}

// ============================================================================
// Http2Frame
// ============================================================================

/// A parsed HTTP/2 frame, holding the frame header fields and a reference
/// to where the payload resides in the original buffer.
#[derive(Debug, Clone)]
pub struct Http2Frame {
    /// 24-bit payload length.
    pub length: u32,
    /// Frame type.
    pub frame_type: Http2FrameType,
    /// Flags byte.
    pub flags: u8,
    /// 31-bit stream identifier (R bit masked out).
    pub stream_id: u32,
    /// Byte offset in the original buffer where the payload starts.
    pub payload_offset: usize,
    /// Total frame size in bytes: 9 (header) + payload length.
    pub total_size: usize,
}

impl Http2Frame {
    /// Parse one HTTP/2 frame from `buf` starting at `offset`.
    ///
    /// Returns `None` if there are not enough bytes for the frame header
    /// or if the payload extends beyond the buffer.
    #[must_use]
    pub fn parse_at(buf: &[u8], offset: usize) -> Option<Self> {
        if offset + HTTP2_FRAME_HEADER_LEN > buf.len() {
            return None;
        }

        let header = &buf[offset..offset + HTTP2_FRAME_HEADER_LEN];

        // Length is 3 bytes big-endian
        let length =
            (u32::from(header[0]) << 16) | (u32::from(header[1]) << 8) | u32::from(header[2]);

        let frame_type = Http2FrameType::from_u8(header[3]);
        let flags = header[4];
        // Stream ID: 4 bytes, R bit (MSB) masked out
        let stream_id =
            u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7FFFFFFF;

        let payload_offset = offset + HTTP2_FRAME_HEADER_LEN;
        let total_size = HTTP2_FRAME_HEADER_LEN + length as usize;

        // Verify the payload is within the buffer
        if payload_offset + length as usize > buf.len() {
            return None;
        }

        Some(Http2Frame {
            length,
            frame_type,
            flags,
            stream_id,
            payload_offset,
            total_size,
        })
    }

    /// Get the payload bytes from the original buffer.
    #[must_use]
    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let end = self.payload_offset + self.length as usize;
        if end <= buf.len() {
            &buf[self.payload_offset..end]
        } else {
            &[]
        }
    }

    /// Returns true if the `END_STREAM` flag is set.
    ///
    /// Valid for DATA and HEADERS frames.
    #[must_use]
    pub fn is_end_stream(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    /// Returns true if the `END_HEADERS` flag is set.
    ///
    /// Valid for HEADERS, `PUSH_PROMISE`, and CONTINUATION frames.
    #[must_use]
    pub fn is_end_headers(&self) -> bool {
        (self.flags & 0x04) != 0
    }

    /// Returns true if the ACK flag is set.
    ///
    /// Valid for SETTINGS and PING frames.
    #[must_use]
    pub fn is_ack(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    /// Returns true if the PADDED flag is set.
    ///
    /// Valid for DATA, HEADERS, and `PUSH_PROMISE` frames.
    #[must_use]
    pub fn is_padded(&self) -> bool {
        (self.flags & 0x08) != 0
    }

    /// Returns true if the PRIORITY flag is set.
    ///
    /// Valid for HEADERS frames.
    #[must_use]
    pub fn has_priority(&self) -> bool {
        (self.flags & 0x20) != 0
    }

    /// Get a human-readable summary of this frame.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} stream={} length={} flags={:#04x}",
            self.frame_type.name(),
            self.stream_id,
            self.length,
            self.flags
        )
    }
}

// ============================================================================
// Multi-frame parsing
// ============================================================================

/// Parse all HTTP/2 frames from a buffer.
///
/// If the buffer starts with the HTTP/2 connection preface (24 bytes), it is
/// skipped before parsing frames.
///
/// Returns a list of successfully parsed frames. Stops at the first truncated
/// or malformed frame.
#[must_use]
pub fn parse_all_frames(buf: &[u8]) -> Vec<Http2Frame> {
    let mut frames = Vec::new();
    let start = if buf.starts_with(HTTP2_PREFACE) {
        HTTP2_PREFACE.len()
    } else {
        0
    };

    let mut offset = start;

    loop {
        match Http2Frame::parse_at(buf, offset) {
            Some(frame) => {
                let total = frame.total_size;
                frames.push(frame);
                offset += total;
            },
            None => break,
        }
    }

    frames
}

// ============================================================================
// Frame-specific payload parsers
// ============================================================================

/// Parse a SETTINGS frame payload into a list of (id, value) pairs.
///
/// Each settings entry is 6 bytes: 2-byte identifier + 4-byte value.
#[must_use]
pub fn parse_settings(payload: &[u8]) -> Vec<(u16, u32)> {
    let mut settings = Vec::new();
    let mut pos = 0;

    while pos + 6 <= payload.len() {
        let id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let value = u32::from_be_bytes([
            payload[pos + 2],
            payload[pos + 3],
            payload[pos + 4],
            payload[pos + 5],
        ]);
        settings.push((id, value));
        pos += 6;
    }

    settings
}

/// Parse a GOAWAY frame payload.
///
/// Returns `Some((last_stream_id, error_code))` or `None` if the payload is too short.
#[must_use]
pub fn parse_goaway(payload: &[u8]) -> Option<(u32, u32)> {
    if payload.len() < 8 {
        return None;
    }
    let last_stream_id =
        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7FFFFFFF;
    let error_code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    Some((last_stream_id, error_code))
}

/// Parse a `WINDOW_UPDATE` frame payload.
///
/// Returns `Some(window_size_increment)` or `None` if the payload is too short.
#[must_use]
pub fn parse_window_update(payload: &[u8]) -> Option<u32> {
    if payload.len() < 4 {
        return None;
    }
    // R bit (MSB) must be masked out
    let increment =
        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7FFFFFFF;
    Some(increment)
}

/// Parse a `RST_STREAM` frame payload.
///
/// Returns `Some(error_code)` or `None` if the payload is too short.
#[must_use]
pub fn parse_rst_stream(payload: &[u8]) -> Option<u32> {
    if payload.len() < 4 {
        return None;
    }
    let error_code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    Some(error_code)
}

/// Parse a PRIORITY frame payload.
///
/// Returns `Some((exclusive, stream_dependency, weight))` or `None` if too short.
#[must_use]
pub fn parse_priority(payload: &[u8]) -> Option<(bool, u32, u8)> {
    if payload.len() < 5 {
        return None;
    }
    let word = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let exclusive = (word & 0x80000000) != 0;
    let stream_dependency = word & 0x7FFFFFFF;
    let weight = payload[4];
    Some((exclusive, stream_dependency, weight))
}

/// Extract the header block fragment from a HEADERS frame payload.
///
/// Strips padding and priority fields if the corresponding flags are set.
/// Returns the HPACK-encoded header block fragment slice.
#[must_use]
pub fn headers_fragment<'a>(frame: &Http2Frame, buf: &'a [u8]) -> Option<&'a [u8]> {
    if frame.frame_type != Http2FrameType::Headers {
        return None;
    }

    let payload = frame.payload(buf);
    let mut start = 0;

    let pad_length = if frame.is_padded() {
        if payload.is_empty() {
            return None;
        }
        let pl = payload[0] as usize;
        start += 1;
        pl
    } else {
        0
    };

    if frame.has_priority() {
        start += 5; // 4 bytes stream dependency + 1 byte weight
    }

    let end = payload.len().saturating_sub(pad_length);
    if start > end {
        return None;
    }

    Some(&payload[start..end])
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut out = Vec::new();
        out.push(((len >> 16) & 0xFF) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
        out.push(frame_type);
        out.push(flags);
        out.extend_from_slice(&(stream_id & 0x7FFFFFFF).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn test_parse_settings_frame() {
        // SETTINGS frame with no settings (empty payload), no flags, stream=0
        let frame_bytes = make_frame(4, 0, 0, &[]);
        let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();

        assert_eq!(frame.frame_type, Http2FrameType::Settings);
        assert_eq!(frame.flags, 0);
        assert_eq!(frame.stream_id, 0);
        assert_eq!(frame.length, 0);
    }

    #[test]
    fn test_parse_settings_ack() {
        let frame_bytes = make_frame(4, flags::SETTINGS_ACK, 0, &[]);
        let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();

        assert_eq!(frame.frame_type, Http2FrameType::Settings);
        assert!(frame.is_ack());
    }

    #[test]
    fn test_parse_data_frame() {
        let payload = b"Hello, HTTP/2!";
        let frame_bytes = make_frame(0, flags::DATA_END_STREAM, 1, payload);
        let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();

        assert_eq!(frame.frame_type, Http2FrameType::Data);
        assert!(frame.is_end_stream());
        assert_eq!(frame.stream_id, 1);
        assert_eq!(frame.payload(&frame_bytes), payload);
    }

    #[test]
    fn test_parse_headers_frame() {
        let hpack_data = vec![0x82u8]; // ":method: GET"
        let frame_bytes = make_frame(
            1,
            flags::HEADERS_END_HEADERS | flags::HEADERS_END_STREAM,
            1,
            &hpack_data,
        );
        let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();

        assert_eq!(frame.frame_type, Http2FrameType::Headers);
        assert!(frame.is_end_headers());
        assert!(frame.is_end_stream());
        assert_eq!(frame.stream_id, 1);
    }

    #[test]
    fn test_parse_all_frames_with_preface() {
        let mut buf = Vec::new();
        buf.extend_from_slice(HTTP2_PREFACE);
        // SETTINGS frame
        buf.extend_from_slice(&make_frame(4, 0, 0, &[]));
        // SETTINGS ACK
        buf.extend_from_slice(&make_frame(4, flags::SETTINGS_ACK, 0, &[]));

        let frames = parse_all_frames(&buf);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].frame_type, Http2FrameType::Settings);
        assert_eq!(frames[1].frame_type, Http2FrameType::Settings);
        assert!(frames[1].is_ack());
    }

    #[test]
    fn test_parse_settings_payload() {
        // SETTINGS with two entries: INITIAL_WINDOW_SIZE=65535, MAX_FRAME_SIZE=16384
        let mut payload = Vec::new();
        payload.extend_from_slice(&settings_id::INITIAL_WINDOW_SIZE.to_be_bytes());
        payload.extend_from_slice(&65535u32.to_be_bytes());
        payload.extend_from_slice(&settings_id::MAX_FRAME_SIZE.to_be_bytes());
        payload.extend_from_slice(&16384u32.to_be_bytes());

        let settings = parse_settings(&payload);
        assert_eq!(settings.len(), 2);
        assert_eq!(settings[0], (settings_id::INITIAL_WINDOW_SIZE, 65535));
        assert_eq!(settings[1], (settings_id::MAX_FRAME_SIZE, 16384));
    }

    #[test]
    fn test_parse_goaway_frame() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_be_bytes()); // last_stream_id = 1
        payload.extend_from_slice(&error_codes::NO_ERROR.to_be_bytes());

        let (last_id, error) = parse_goaway(&payload).unwrap();
        assert_eq!(last_id, 1);
        assert_eq!(error, error_codes::NO_ERROR);
    }

    #[test]
    fn test_parse_window_update() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&65535u32.to_be_bytes());
        let increment = parse_window_update(&payload).unwrap();
        assert_eq!(increment, 65535);
    }

    #[test]
    fn test_parse_rst_stream() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&error_codes::CANCEL.to_be_bytes());
        let error = parse_rst_stream(&payload).unwrap();
        assert_eq!(error, error_codes::CANCEL);
    }

    #[test]
    fn test_frame_type_names() {
        assert_eq!(Http2FrameType::Data.name(), "DATA");
        assert_eq!(Http2FrameType::Headers.name(), "HEADERS");
        assert_eq!(Http2FrameType::Settings.name(), "SETTINGS");
        assert_eq!(Http2FrameType::GoAway.name(), "GOAWAY");
        assert_eq!(Http2FrameType::Unknown(0xff).name(), "UNKNOWN");
    }

    #[test]
    fn test_frame_type_roundtrip() {
        for t in 0..=9u8 {
            let ft = Http2FrameType::from_u8(t);
            assert_eq!(ft.as_u8(), t);
        }
    }

    #[test]
    fn test_parse_multiple_frames() {
        let data_payload = b"test data";
        let mut buf = Vec::new();
        buf.extend_from_slice(&make_frame(0, 0x01, 1, data_payload)); // DATA END_STREAM
        buf.extend_from_slice(&make_frame(4, 0x01, 0, &[])); // SETTINGS ACK

        let frames = parse_all_frames(&buf);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].frame_type, Http2FrameType::Data);
        assert_eq!(frames[1].frame_type, Http2FrameType::Settings);
    }

    #[test]
    fn test_frame_too_short() {
        // 8 bytes: not enough for a 9-byte header
        let buf = [0u8; 8];
        let result = Http2Frame::parse_at(&buf, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_frame_payload_truncated() {
        // 9-byte header saying payload length=100, but no payload bytes
        let buf = [
            0x00, 0x00, 0x64, // length = 100
            0x00, // type = DATA
            0x00, // flags = 0
            0x00, 0x00, 0x00, 0x01, // stream_id = 1
        ];
        let result = Http2Frame::parse_at(&buf, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_http2_preface_const() {
        assert_eq!(HTTP2_PREFACE.len(), 24);
        assert_eq!(HTTP2_PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    }

    #[test]
    fn test_ping_frame() {
        let ping_data = [0u8; 8];
        let frame_bytes = make_frame(6, 0, 0, &ping_data);
        let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();

        assert_eq!(frame.frame_type, Http2FrameType::Ping);
        assert!(!frame.is_ack());
        assert_eq!(frame.payload(&frame_bytes).len(), 8);
    }

    #[test]
    fn test_settings_id_names() {
        assert_eq!(
            settings_id::name(settings_id::HEADER_TABLE_SIZE),
            "HEADER_TABLE_SIZE"
        );
        assert_eq!(settings_id::name(settings_id::ENABLE_PUSH), "ENABLE_PUSH");
        assert_eq!(settings_id::name(0x99), "UNKNOWN");
    }

    #[test]
    fn test_error_code_names() {
        assert_eq!(error_codes::name(error_codes::NO_ERROR), "NO_ERROR");
        assert_eq!(
            error_codes::name(error_codes::PROTOCOL_ERROR),
            "PROTOCOL_ERROR"
        );
        assert_eq!(error_codes::name(0x99), "UNKNOWN");
    }
}
