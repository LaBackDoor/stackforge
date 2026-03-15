//! CoAP (Constrained Application Protocol) layer implementation (RFC 7252).
//!
//! Implements zero-copy parsing of CoAP messages over UDP.
//!
//! ## Header Format (4 bytes minimum)
//!
//! ```text
//! Byte 0:    [Ver(2)] [Type(2)] [Token Length(4)]
//! Byte 1:    [Code(8)] — split as class(3).detail(5)
//! Bytes 2-3: Message ID (u16 big-endian)
//! Then:      Token (0-8 bytes based on TKL)
//! Then:      Options (delta-encoded)
//! Then:      Optional 0xFF payload marker + payload
//! ```
//!
//! ## Message Types
//!
//! | Value | Name |
//! |-------|------|
//! | 0     | CON  |
//! | 1     | NON  |
//! | 2     | ACK  |
//! | 3     | RST  |
//!
//! ## Common Codes
//!
//! Request codes: 0.01 GET, 0.02 POST, 0.03 PUT, 0.04 DELETE
//! Response codes: 2.01 Created, 2.05 Content, 4.04 Not Found, etc.

pub mod builder;

pub use builder::CoapBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

// ============================================================================
// Constants
// ============================================================================

/// Minimum CoAP header length: 4 bytes (ver/type/tkl + code + message ID).
pub const COAP_MIN_HEADER_LEN: usize = 4;

/// Default CoAP UDP port (RFC 7252).
pub const COAP_PORT: u16 = 5683;

/// Default CoAP DTLS port (RFC 7252).
pub const COAP_SECURE_PORT: u16 = 5684;

/// Payload marker byte.
const PAYLOAD_MARKER: u8 = 0xFF;

// ============================================================================
// Message type constants
// ============================================================================

/// Confirmable message.
pub const CON: u8 = 0;
/// Non-confirmable message.
pub const NON: u8 = 1;
/// Acknowledgement.
pub const ACK: u8 = 2;
/// Reset.
pub const RST: u8 = 3;

// ============================================================================
// Code constants (class.detail encoded as single byte)
// ============================================================================

/// Empty message (0.00).
pub const CODE_EMPTY: u8 = 0;
/// GET request (0.01).
pub const CODE_GET: u8 = 1;
/// POST request (0.02).
pub const CODE_POST: u8 = 2;
/// PUT request (0.03).
pub const CODE_PUT: u8 = 3;
/// DELETE request (0.04).
pub const CODE_DELETE: u8 = 4;
/// 2.01 Created.
pub const CODE_CREATED: u8 = (2 << 5) | 1;
/// 2.02 Deleted.
pub const CODE_DELETED: u8 = (2 << 5) | 2;
/// 2.03 Valid.
pub const CODE_VALID: u8 = (2 << 5) | 3;
/// 2.04 Changed.
pub const CODE_CHANGED: u8 = (2 << 5) | 4;
/// 2.05 Content.
pub const CODE_CONTENT: u8 = (2 << 5) | 5;
/// 4.00 Bad Request.
pub const CODE_BAD_REQUEST: u8 = (4 << 5) | 0;
/// 4.01 Unauthorized.
pub const CODE_UNAUTHORIZED: u8 = (4 << 5) | 1;
/// 4.02 Bad Option.
pub const CODE_BAD_OPTION: u8 = (4 << 5) | 2;
/// 4.03 Forbidden.
pub const CODE_FORBIDDEN: u8 = (4 << 5) | 3;
/// 4.04 Not Found.
pub const CODE_NOT_FOUND: u8 = (4 << 5) | 4;
/// 4.05 Method Not Allowed.
pub const CODE_METHOD_NOT_ALLOWED: u8 = (4 << 5) | 5;
/// 5.00 Internal Server Error.
pub const CODE_INTERNAL_ERROR: u8 = (5 << 5) | 0;

// ============================================================================
// Option numbers
// ============================================================================

/// If-Match option (opaque, repeatable).
pub const OPT_IF_MATCH: u16 = 1;
/// Uri-Host option (string).
pub const OPT_URI_HOST: u16 = 3;
/// ETag option (opaque, repeatable).
pub const OPT_ETAG: u16 = 4;
/// If-None-Match option (empty).
pub const OPT_IF_NONE_MATCH: u16 = 5;
/// Observe option (uint).
pub const OPT_OBSERVE: u16 = 6;
/// Uri-Port option (uint).
pub const OPT_URI_PORT: u16 = 7;
/// Location-Path option (string, repeatable).
pub const OPT_LOCATION_PATH: u16 = 8;
/// Uri-Path option (string, repeatable).
pub const OPT_URI_PATH: u16 = 11;
/// Content-Format option (uint).
pub const OPT_CONTENT_FORMAT: u16 = 12;
/// Max-Age option (uint).
pub const OPT_MAX_AGE: u16 = 14;
/// Uri-Query option (string, repeatable).
pub const OPT_URI_QUERY: u16 = 15;
/// Accept option (uint).
pub const OPT_ACCEPT: u16 = 17;
/// Location-Query option (string, repeatable).
pub const OPT_LOCATION_QUERY: u16 = 20;
/// Block2 option (uint).
pub const OPT_BLOCK2: u16 = 23;
/// Block1 option (uint).
pub const OPT_BLOCK1: u16 = 27;
/// Size2 option (uint).
pub const OPT_SIZE2: u16 = 28;
/// Proxy-Uri option (string).
pub const OPT_PROXY_URI: u16 = 35;
/// Proxy-Scheme option (string).
pub const OPT_PROXY_SCHEME: u16 = 39;
/// Size1 option (uint).
pub const OPT_SIZE1: u16 = 60;

// ============================================================================
// Field names
// ============================================================================

/// Field names exposed by the CoAP layer.
pub static COAP_FIELD_NAMES: &[&str] = &[
    "ver",
    "type",
    "tkl",
    "code",
    "code_class",
    "code_detail",
    "msg_id",
    "token",
    "options",
    "payload",
];

// ============================================================================
// Detection
// ============================================================================

/// Heuristic check for CoAP payload: version must be 1, TKL <= 8, and
/// buffer must be long enough to hold the header + token.
#[inline]
#[must_use]
pub fn is_coap_payload(buf: &[u8]) -> bool {
    if buf.len() < COAP_MIN_HEADER_LEN {
        return false;
    }
    let ver = (buf[0] >> 6) & 0x03;
    if ver != 1 {
        return false;
    }
    let tkl = buf[0] & 0x0F;
    // RFC 7252: TKL must be 0-8; lengths 9-15 are reserved.
    if tkl > 8 {
        return false;
    }
    // Buffer must be large enough for header + token.
    buf.len() >= COAP_MIN_HEADER_LEN + tkl as usize
}

// ============================================================================
// CoapOption
// ============================================================================

/// A parsed CoAP option (number + value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapOption {
    /// Option number (delta-accumulated).
    pub number: u16,
    /// Option value bytes.
    pub value: Vec<u8>,
}

// ============================================================================
// Helper functions
// ============================================================================

/// Return a human-readable name for a CoAP message type.
#[must_use]
pub fn coap_type_name(t: u8) -> &'static str {
    match t {
        CON => "CON",
        NON => "NON",
        ACK => "ACK",
        RST => "RST",
        _ => "Unknown",
    }
}

/// Return a human-readable name for a CoAP code.
#[must_use]
pub fn coap_code_name(code: u8) -> &'static str {
    match code {
        CODE_EMPTY => "Empty",
        CODE_GET => "GET",
        CODE_POST => "POST",
        CODE_PUT => "PUT",
        CODE_DELETE => "DELETE",
        CODE_CREATED => "2.01 Created",
        CODE_DELETED => "2.02 Deleted",
        CODE_VALID => "2.03 Valid",
        CODE_CHANGED => "2.04 Changed",
        CODE_CONTENT => "2.05 Content",
        CODE_BAD_REQUEST => "4.00 Bad Request",
        CODE_UNAUTHORIZED => "4.01 Unauthorized",
        CODE_BAD_OPTION => "4.02 Bad Option",
        CODE_FORBIDDEN => "4.03 Forbidden",
        CODE_NOT_FOUND => "4.04 Not Found",
        CODE_METHOD_NOT_ALLOWED => "4.05 Method Not Allowed",
        CODE_INTERNAL_ERROR => "5.00 Internal Server Error",
        _ => {
            let class = (code >> 5) & 0x07;
            match class {
                0 => "Request",
                2 => "Success",
                4 => "Client Error",
                5 => "Server Error",
                _ => "Unknown",
            }
        },
    }
}

/// Return a human-readable name for a CoAP option number.
#[must_use]
pub fn coap_option_name(num: u16) -> &'static str {
    match num {
        OPT_IF_MATCH => "If-Match",
        OPT_URI_HOST => "Uri-Host",
        OPT_ETAG => "ETag",
        OPT_IF_NONE_MATCH => "If-None-Match",
        OPT_OBSERVE => "Observe",
        OPT_URI_PORT => "Uri-Port",
        OPT_LOCATION_PATH => "Location-Path",
        OPT_URI_PATH => "Uri-Path",
        OPT_CONTENT_FORMAT => "Content-Format",
        OPT_MAX_AGE => "Max-Age",
        OPT_URI_QUERY => "Uri-Query",
        OPT_ACCEPT => "Accept",
        OPT_LOCATION_QUERY => "Location-Query",
        OPT_BLOCK2 => "Block2",
        OPT_BLOCK1 => "Block1",
        OPT_SIZE2 => "Size2",
        OPT_PROXY_URI => "Proxy-Uri",
        OPT_PROXY_SCHEME => "Proxy-Scheme",
        OPT_SIZE1 => "Size1",
        _ => "Unknown",
    }
}

// ============================================================================
// CoapLayer
// ============================================================================

/// Zero-copy view into a CoAP message within a packet buffer.
#[derive(Debug, Clone)]
pub struct CoapLayer {
    /// Layer index (start/end offsets into the packet buffer).
    pub index: LayerIndex,
}

impl CoapLayer {
    /// Create a new CoAP layer from a layer index.
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Create a CoAP layer starting at offset 0 (for standalone parsing).
    #[must_use]
    pub fn at_start(len: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Coap, 0, len),
        }
    }

    /// Return the slice of the buffer corresponding to this layer.
    #[inline]
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    /// Return a mutable slice of the buffer corresponding to this layer.
    #[inline]
    fn slice_mut<'a>(&self, buf: &'a mut [u8]) -> &'a mut [u8] {
        self.index.slice_mut(buf)
    }

    /// Helper to build a `BufferTooShort` error.
    #[inline]
    fn buf_err(&self, need: usize, have: usize) -> FieldError {
        FieldError::BufferTooShort {
            offset: self.index.start,
            need,
            have,
        }
    }

    // ========== Field accessors ==========

    /// CoAP version (2 bits). Must be 1 for RFC 7252.
    #[inline]
    pub fn ver(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.is_empty() {
            return Err(self.buf_err(1, 0));
        }
        Ok((s[0] >> 6) & 0x03)
    }

    /// Message type (2 bits): CON=0, NON=1, ACK=2, RST=3.
    #[inline]
    pub fn msg_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.is_empty() {
            return Err(self.buf_err(1, 0));
        }
        Ok((s[0] >> 4) & 0x03)
    }

    /// Token length (4 bits, 0-8).
    #[inline]
    pub fn tkl(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.is_empty() {
            return Err(self.buf_err(1, 0));
        }
        Ok(s[0] & 0x0F)
    }

    /// Raw code byte.
    #[inline]
    pub fn code(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 2 {
            return Err(self.buf_err(2, s.len()));
        }
        Ok(s[1])
    }

    /// Code class (upper 3 bits of code byte).
    #[inline]
    pub fn code_class(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.code(buf).map(|c| (c >> 5) & 0x07)
    }

    /// Code detail (lower 5 bits of code byte).
    #[inline]
    pub fn code_detail(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.code(buf).map(|c| c & 0x1F)
    }

    /// Message ID (16-bit big-endian).
    #[inline]
    pub fn msg_id(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 4 {
            return Err(self.buf_err(4, s.len()));
        }
        Ok(u16::from_be_bytes([s[2], s[3]]))
    }

    /// Token bytes (0-8 bytes).
    pub fn token<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8], FieldError> {
        let s = self.slice(buf);
        if s.len() < COAP_MIN_HEADER_LEN {
            return Err(self.buf_err(COAP_MIN_HEADER_LEN, s.len()));
        }
        let tkl = (s[0] & 0x0F) as usize;
        let token_end = COAP_MIN_HEADER_LEN + tkl;
        if s.len() < token_end {
            return Err(self.buf_err(token_end, s.len()));
        }
        Ok(&s[COAP_MIN_HEADER_LEN..token_end])
    }

    /// Offset (relative to layer start) where options begin.
    #[inline]
    fn options_offset(&self, buf: &[u8]) -> Result<usize, FieldError> {
        let s = self.slice(buf);
        if s.len() < COAP_MIN_HEADER_LEN {
            return Err(self.buf_err(COAP_MIN_HEADER_LEN, s.len()));
        }
        let tkl = (s[0] & 0x0F) as usize;
        Ok(COAP_MIN_HEADER_LEN + tkl)
    }

    /// Parse all CoAP options from the message.
    ///
    /// Returns a vector of `CoapOption` structs. Options are delta-encoded:
    /// each option's number is the sum of all preceding deltas.
    pub fn options(&self, buf: &[u8]) -> Vec<CoapOption> {
        let s = self.slice(buf);
        let offset = match self.options_offset(buf) {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        parse_options(s, offset)
    }

    /// Payload bytes (after the 0xFF marker), if present.
    pub fn payload<'a>(&self, buf: &'a [u8]) -> Option<&'a [u8]> {
        let s = self.slice(buf);
        let offset = self.options_offset(buf).ok()?;
        find_payload(s, offset)
    }

    /// Compute the header length: fixed header (4) + token + options + payload marker.
    /// This covers everything up to and including the payload marker (0xFF),
    /// or the entire layer if there is no payload.
    fn compute_header_len(&self, buf: &[u8]) -> usize {
        let s = self.slice(buf);
        let offset = match self.options_offset(buf) {
            Ok(o) => o,
            Err(_) => return s.len(),
        };
        // Walk through options to find end-of-options / payload marker.
        let mut pos = offset;
        while pos < s.len() {
            if s[pos] == PAYLOAD_MARKER {
                // Header includes everything up to and including the marker.
                return pos + 1;
            }
            // Parse delta nibble.
            let delta_nibble = (s[pos] >> 4) & 0x0F;
            let len_nibble = s[pos] & 0x0F;
            pos += 1;
            // Extended delta.
            match delta_nibble {
                13 => pos += 1,
                14 => pos += 2,
                _ => {},
            }
            // Extended length.
            let opt_len: usize = match len_nibble {
                0..=12 => len_nibble as usize,
                13 => {
                    if pos >= s.len() {
                        return s.len();
                    }
                    let v = s[pos] as usize + 13;
                    pos += 1;
                    v
                },
                14 => {
                    if pos + 1 >= s.len() {
                        return s.len();
                    }
                    let v = u16::from_be_bytes([s[pos], s[pos + 1]]) as usize + 269;
                    pos += 2;
                    v
                },
                _ => return s.len(), // 15 is reserved
            };
            pos += opt_len;
        }
        // No payload marker found; entire layer slice is "header".
        s.len()
    }

    /// Generate a human-readable summary of this CoAP message.
    pub fn summary(&self, buf: &[u8]) -> String {
        let type_str = self.msg_type(buf).map(coap_type_name).unwrap_or("?");
        let code_str = self.code(buf).map(coap_code_name).unwrap_or("?");
        let mid = self
            .msg_id(buf)
            .map(|id| id.to_string())
            .unwrap_or_else(|_| "?".into());
        format!("CoAP {type_str} {code_str} MID={mid}")
    }

    // ========== get_field / set_field ==========

    /// Get a field value by name. Returns `None` if the field name is not recognised.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "ver" => Some(self.ver(buf).map(FieldValue::U8)),
            "type" => Some(self.msg_type(buf).map(FieldValue::U8)),
            "tkl" => Some(self.tkl(buf).map(FieldValue::U8)),
            "code" => Some(self.code(buf).map(FieldValue::U8)),
            "code_class" => Some(self.code_class(buf).map(FieldValue::U8)),
            "code_detail" => Some(self.code_detail(buf).map(FieldValue::U8)),
            "msg_id" => Some(self.msg_id(buf).map(FieldValue::U16)),
            "token" => Some(self.token(buf).map(|t| FieldValue::Bytes(t.to_vec()))),
            "options" => {
                // Return the number of options as a U8 summary.
                let count = self.options(buf).len();
                Some(Ok(FieldValue::U8(count as u8)))
            },
            "payload" => Some(Ok(FieldValue::Bytes(
                self.payload(buf).unwrap_or(&[]).to_vec(),
            ))),
            _ => None,
        }
    }

    /// Set a field value by name. Only fixed-header fields (ver, type, tkl, code,
    /// msg_id) can be modified in-place.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match name {
            "ver" => {
                let v = match value {
                    FieldValue::U8(v) => v,
                    _ => return Some(Err(FieldError::InvalidValue("expected U8".into()))),
                };
                let s = self.slice_mut(buf);
                if s.is_empty() {
                    return Some(Err(self.buf_err(1, 0)));
                }
                s[0] = (s[0] & 0x3F) | ((v & 0x03) << 6);
                Some(Ok(()))
            },
            "type" => {
                let v = match value {
                    FieldValue::U8(v) => v,
                    _ => return Some(Err(FieldError::InvalidValue("expected U8".into()))),
                };
                let s = self.slice_mut(buf);
                if s.is_empty() {
                    return Some(Err(self.buf_err(1, 0)));
                }
                s[0] = (s[0] & 0xCF) | ((v & 0x03) << 4);
                Some(Ok(()))
            },
            "tkl" => {
                let v = match value {
                    FieldValue::U8(v) => v,
                    _ => return Some(Err(FieldError::InvalidValue("expected U8".into()))),
                };
                let s = self.slice_mut(buf);
                if s.is_empty() {
                    return Some(Err(self.buf_err(1, 0)));
                }
                s[0] = (s[0] & 0xF0) | (v & 0x0F);
                Some(Ok(()))
            },
            "code" => {
                let v = match value {
                    FieldValue::U8(v) => v,
                    _ => return Some(Err(FieldError::InvalidValue("expected U8".into()))),
                };
                let s = self.slice_mut(buf);
                if s.len() < 2 {
                    return Some(Err(self.buf_err(2, s.len())));
                }
                s[1] = v;
                Some(Ok(()))
            },
            "msg_id" => {
                let v = match value {
                    FieldValue::U16(v) => v,
                    _ => return Some(Err(FieldError::InvalidValue("expected U16".into()))),
                };
                let s = self.slice_mut(buf);
                if s.len() < 4 {
                    return Some(Err(self.buf_err(4, s.len())));
                }
                let bytes = v.to_be_bytes();
                s[2] = bytes[0];
                s[3] = bytes[1];
                Some(Ok(()))
            },
            // Token, options, and payload cannot be set in-place because they
            // are variable-length. Use the builder for constructing new packets.
            "code_class" | "code_detail" | "token" | "options" | "payload" => None,
            _ => None,
        }
    }
}

// ============================================================================
// Layer trait implementation
// ============================================================================

impl Layer for CoapLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Coap
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.compute_header_len(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        COAP_FIELD_NAMES
    }
}

// ============================================================================
// Show-fields helper (used by impl_layer_dispatch)
// ============================================================================

/// Generate show-fields output for the CoAP layer.
pub fn coap_show_fields(l: &CoapLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "ver",
        l.ver(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "type",
        l.msg_type(buf)
            .map_or_else(|_| "?".into(), |v| format!("{} ({})", v, coap_type_name(v))),
    ));
    fields.push((
        "tkl",
        l.tkl(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "code",
        l.code(buf).map_or_else(
            |_| "?".into(),
            |v| {
                let class = (v >> 5) & 0x07;
                let detail = v & 0x1F;
                format!("{}.{:02} ({})", class, detail, coap_code_name(v))
            },
        ),
    ));
    fields.push((
        "msg_id",
        l.msg_id(buf)
            .map_or_else(|_| "?".into(), |v| format!("0x{:04x}", v)),
    ));
    if let Ok(token) = l.token(buf) {
        if !token.is_empty() {
            let hex: String = token.iter().map(|b| format!("{:02x}", b)).collect();
            fields.push(("token", hex));
        }
    }
    let opts = l.options(buf);
    if !opts.is_empty() {
        for opt in &opts {
            let name = coap_option_name(opt.number);
            let val = if opt.value.is_empty() {
                "(empty)".to_string()
            } else if opt.value.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                String::from_utf8_lossy(&opt.value).into_owned()
            } else {
                opt.value.iter().map(|b| format!("{:02x}", b)).collect()
            };
            fields.push(("options", format!("{} ({}): {}", opt.number, name, val)));
        }
    }
    if let Some(payload) = l.payload(buf) {
        fields.push(("payload", format!("{} bytes", payload.len())));
    }
    fields
}

// ============================================================================
// Internal option parsing
// ============================================================================

/// Parse CoAP options starting at `offset` within `data`.
fn parse_options(data: &[u8], offset: usize) -> Vec<CoapOption> {
    let mut opts = Vec::new();
    let mut pos = offset;
    let mut option_number: u16 = 0;

    while pos < data.len() {
        let byte = data[pos];
        // 0xFF is the payload marker — stop parsing options.
        if byte == PAYLOAD_MARKER {
            break;
        }

        let delta_nibble = (byte >> 4) & 0x0F;
        let len_nibble = byte & 0x0F;
        pos += 1;

        // Decode extended delta.
        let delta: u16 = match delta_nibble {
            0..=12 => delta_nibble as u16,
            13 => {
                if pos >= data.len() {
                    break;
                }
                let v = data[pos] as u16 + 13;
                pos += 1;
                v
            },
            14 => {
                if pos + 1 >= data.len() {
                    break;
                }
                let v = u16::from_be_bytes([data[pos], data[pos + 1]]) + 269;
                pos += 2;
                v
            },
            _ => break, // 15 is reserved
        };

        // Decode extended length.
        let opt_len: usize = match len_nibble {
            0..=12 => len_nibble as usize,
            13 => {
                if pos >= data.len() {
                    break;
                }
                let v = data[pos] as usize + 13;
                pos += 1;
                v
            },
            14 => {
                if pos + 1 >= data.len() {
                    break;
                }
                let v = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize + 269;
                pos += 2;
                v
            },
            _ => break, // 15 is reserved
        };

        if pos + opt_len > data.len() {
            break;
        }

        option_number += delta;
        opts.push(CoapOption {
            number: option_number,
            value: data[pos..pos + opt_len].to_vec(),
        });
        pos += opt_len;
    }

    opts
}

/// Find the payload within `data` starting search at `offset`.
/// Returns `Some(payload_slice)` if the 0xFF marker is found.
fn find_payload(data: &[u8], offset: usize) -> Option<&[u8]> {
    let mut pos = offset;
    while pos < data.len() {
        let byte = data[pos];
        if byte == PAYLOAD_MARKER {
            let payload_start = pos + 1;
            if payload_start <= data.len() {
                return Some(&data[payload_start..]);
            }
            return None;
        }
        // Skip option: parse delta + length to advance.
        let delta_nibble = (byte >> 4) & 0x0F;
        let len_nibble = byte & 0x0F;
        pos += 1;

        match delta_nibble {
            13 => pos += 1,
            14 => pos += 2,
            15 => return None,
            _ => {},
        }

        let opt_len: usize = match len_nibble {
            0..=12 => len_nibble as usize,
            13 => {
                if pos >= data.len() {
                    return None;
                }
                let v = data[pos] as usize + 13;
                pos += 1;
                v
            },
            14 => {
                if pos + 1 >= data.len() {
                    return None;
                }
                let v = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize + 269;
                pos += 2;
                v
            },
            _ => return None,
        };
        pos += opt_len;
    }
    None
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal CON GET with no token, no options, no payload.
    fn minimal_con_get() -> Vec<u8> {
        // Ver=1, Type=CON(0), TKL=0 → 0x40
        // Code=0.01 (GET) → 0x01
        // MID=0x0001
        vec![0x40, 0x01, 0x00, 0x01]
    }

    #[test]
    fn test_ver() {
        let data = minimal_con_get();
        let layer = CoapLayer::at_start(data.len());
        assert_eq!(layer.ver(&data).unwrap(), 1);
    }

    #[test]
    fn test_msg_type() {
        let data = minimal_con_get();
        let layer = CoapLayer::at_start(data.len());
        assert_eq!(layer.msg_type(&data).unwrap(), CON);
    }

    #[test]
    fn test_tkl() {
        let data = minimal_con_get();
        let layer = CoapLayer::at_start(data.len());
        assert_eq!(layer.tkl(&data).unwrap(), 0);
    }

    #[test]
    fn test_code() {
        let data = minimal_con_get();
        let layer = CoapLayer::at_start(data.len());
        assert_eq!(layer.code(&data).unwrap(), CODE_GET);
        assert_eq!(layer.code_class(&data).unwrap(), 0);
        assert_eq!(layer.code_detail(&data).unwrap(), 1);
    }

    #[test]
    fn test_msg_id() {
        let data = minimal_con_get();
        let layer = CoapLayer::at_start(data.len());
        assert_eq!(layer.msg_id(&data).unwrap(), 1);
    }

    #[test]
    fn test_token() {
        // CON GET with 4-byte token.
        let data = vec![
            0x44, // Ver=1, Type=CON, TKL=4
            0x01, // Code=GET
            0x00, 0x01, // MID=1
            0xDE, 0xAD, 0xBE, 0xEF, // Token
        ];
        let layer = CoapLayer::at_start(data.len());
        assert_eq!(layer.tkl(&data).unwrap(), 4);
        assert_eq!(layer.token(&data).unwrap(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_options_single() {
        // CON GET with Uri-Path option "temp".
        let mut data = vec![
            0x40, 0x01, 0x00, 0x01, // Header: CON GET MID=1
        ];
        // Option: delta=11 (Uri-Path), length=4
        // delta=11 → nibble 11; length=4 → nibble 4
        data.push(0xB4); // delta=11, length=4
        data.extend_from_slice(b"temp");

        let layer = CoapLayer::at_start(data.len());
        let opts = layer.options(&data);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].number, OPT_URI_PATH);
        assert_eq!(opts[0].value, b"temp");
    }

    #[test]
    fn test_options_multiple() {
        // CON GET with Uri-Path "sensor" and Uri-Path "temp".
        let mut data = vec![
            0x40, 0x01, 0x00, 0x01, // Header
        ];
        // First: Uri-Path (11), delta=11, length=6.
        data.push(0xB6);
        data.extend_from_slice(b"sensor");
        // Second: Uri-Path (11), delta=0 (same number), length=4.
        data.push(0x04);
        data.extend_from_slice(b"temp");

        let layer = CoapLayer::at_start(data.len());
        let opts = layer.options(&data);
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].number, OPT_URI_PATH);
        assert_eq!(opts[0].value, b"sensor");
        assert_eq!(opts[1].number, OPT_URI_PATH);
        assert_eq!(opts[1].value, b"temp");
    }

    #[test]
    fn test_options_extended_delta_13() {
        // Option with delta=13 extended: delta_nibble=13, ext=0 → actual delta=13.
        // This is Max-Age (option 14): first option delta=14 → 13+1.
        let mut data = vec![
            0x40, 0x01, 0x00, 0x01, // Header
        ];
        // delta_nibble=13, len_nibble=1. Extended delta byte = 14-13 = 1.
        data.push(0xD1);
        data.push(0x01); // extended delta: 1+13=14 → Max-Age
        data.push(0x3C); // value = 60

        let layer = CoapLayer::at_start(data.len());
        let opts = layer.options(&data);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].number, OPT_MAX_AGE);
        assert_eq!(opts[0].value, vec![0x3C]);
    }

    #[test]
    fn test_options_extended_delta_14() {
        // Option with delta_nibble=14: ext bytes encode delta-269.
        // Let's encode option number 300: delta=300, ext = 300-269 = 31.
        let mut data = vec![
            0x40, 0x01, 0x00, 0x01, // Header
        ];
        // delta_nibble=14, len_nibble=2
        data.push(0xE2);
        data.extend_from_slice(&31u16.to_be_bytes()); // extended delta
        data.extend_from_slice(b"hi");

        let layer = CoapLayer::at_start(data.len());
        let opts = layer.options(&data);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].number, 300);
        assert_eq!(opts[0].value, b"hi");
    }

    #[test]
    fn test_options_extended_length_13() {
        // Option with length > 12 using extended length (nibble=13).
        let mut data = vec![
            0x40, 0x01, 0x00, 0x01, // Header
        ];
        // Uri-Path (11), length=20: len_nibble=13, ext=20-13=7.
        data.push(0xBD); // delta=11, len_nibble=13
        data.push(0x07); // extended length: 7+13=20
        data.extend_from_slice(&[b'x'; 20]);

        let layer = CoapLayer::at_start(data.len());
        let opts = layer.options(&data);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].number, OPT_URI_PATH);
        assert_eq!(opts[0].value.len(), 20);
    }

    #[test]
    fn test_payload() {
        let mut data = vec![
            0x40, 0x01, 0x00, 0x01, // Header: CON GET MID=1
        ];
        // Uri-Path option: delta=11, len=4, "temp".
        data.push(0xB4);
        data.extend_from_slice(b"temp");
        // Payload marker.
        data.push(PAYLOAD_MARKER);
        data.extend_from_slice(b"hello world");

        let layer = CoapLayer::at_start(data.len());
        let payload = layer.payload(&data);
        assert_eq!(payload, Some(b"hello world".as_slice()));
    }

    #[test]
    fn test_no_payload() {
        let data = minimal_con_get();
        let layer = CoapLayer::at_start(data.len());
        assert_eq!(layer.payload(&data), None);
    }

    #[test]
    fn test_is_coap_payload_valid() {
        assert!(is_coap_payload(&[0x40, 0x01, 0x00, 0x01]));
    }

    #[test]
    fn test_is_coap_payload_wrong_version() {
        // Version 0 instead of 1.
        assert!(!is_coap_payload(&[0x00, 0x01, 0x00, 0x01]));
    }

    #[test]
    fn test_is_coap_payload_too_short() {
        assert!(!is_coap_payload(&[0x40, 0x01]));
    }

    #[test]
    fn test_is_coap_payload_tkl_too_large() {
        // TKL=9 (reserved).
        assert!(!is_coap_payload(&[0x49, 0x01, 0x00, 0x01]));
    }

    #[test]
    fn test_is_coap_payload_tkl_exceeds_buffer() {
        // TKL=8 but buffer only has 4 bytes (header), no room for token.
        assert!(!is_coap_payload(&[0x48, 0x01, 0x00, 0x01]));
    }

    #[test]
    fn test_get_field() {
        let data = vec![
            0x44, 0x01, 0x00, 0x0A, // CON GET MID=10, TKL=4
            0x01, 0x02, 0x03, 0x04, // Token
        ];
        let layer = CoapLayer::at_start(data.len());

        assert_eq!(
            layer.get_field(&data, "ver").unwrap().unwrap(),
            FieldValue::U8(1)
        );
        assert_eq!(
            layer.get_field(&data, "type").unwrap().unwrap(),
            FieldValue::U8(0)
        );
        assert_eq!(
            layer.get_field(&data, "tkl").unwrap().unwrap(),
            FieldValue::U8(4)
        );
        assert_eq!(
            layer.get_field(&data, "code").unwrap().unwrap(),
            FieldValue::U8(1)
        );
        assert_eq!(
            layer.get_field(&data, "code_class").unwrap().unwrap(),
            FieldValue::U8(0)
        );
        assert_eq!(
            layer.get_field(&data, "code_detail").unwrap().unwrap(),
            FieldValue::U8(1)
        );
        assert_eq!(
            layer.get_field(&data, "msg_id").unwrap().unwrap(),
            FieldValue::U16(10)
        );
        assert_eq!(
            layer.get_field(&data, "token").unwrap().unwrap(),
            FieldValue::Bytes(vec![0x01, 0x02, 0x03, 0x04])
        );
        assert!(layer.get_field(&data, "nonexistent").is_none());
    }

    #[test]
    fn test_set_field() {
        let mut data = vec![0x40, 0x01, 0x00, 0x01];
        let layer = CoapLayer::at_start(data.len());

        // Set message type to NON.
        layer
            .set_field(&mut data, "type", FieldValue::U8(NON))
            .unwrap()
            .unwrap();
        assert_eq!(layer.msg_type(&data).unwrap(), NON);
        // Verify other bits unchanged.
        assert_eq!(layer.ver(&data).unwrap(), 1);
        assert_eq!(layer.tkl(&data).unwrap(), 0);

        // Set code to 2.05 Content.
        layer
            .set_field(&mut data, "code", FieldValue::U8(CODE_CONTENT))
            .unwrap()
            .unwrap();
        assert_eq!(layer.code(&data).unwrap(), CODE_CONTENT);

        // Set msg_id.
        layer
            .set_field(&mut data, "msg_id", FieldValue::U16(0x1234))
            .unwrap()
            .unwrap();
        assert_eq!(layer.msg_id(&data).unwrap(), 0x1234);
    }

    #[test]
    fn test_summary() {
        let data = minimal_con_get();
        let layer = CoapLayer::at_start(data.len());
        let s = layer.summary(&data);
        assert!(s.contains("CON"));
        assert!(s.contains("GET"));
        assert!(s.contains("MID=1"));
    }

    #[test]
    fn test_header_len_no_options_no_payload() {
        let data = minimal_con_get();
        let layer = CoapLayer::at_start(data.len());
        assert_eq!(layer.compute_header_len(&data), 4);
    }

    #[test]
    fn test_header_len_with_options() {
        let mut data = vec![0x40, 0x01, 0x00, 0x01];
        data.push(0xB4); // Uri-Path, len=4
        data.extend_from_slice(b"temp");
        let layer = CoapLayer::at_start(data.len());
        // Header = 4 (fixed) + 1 (option header) + 4 (option value) = 9.
        assert_eq!(layer.compute_header_len(&data), 9);
    }

    #[test]
    fn test_header_len_with_payload() {
        let mut data = vec![0x40, 0x01, 0x00, 0x01];
        data.push(0xB4);
        data.extend_from_slice(b"temp");
        data.push(PAYLOAD_MARKER);
        data.extend_from_slice(b"payload");
        let layer = CoapLayer::at_start(data.len());
        // Header = 4 + 1 + 4 + 1 (marker) = 10.
        assert_eq!(layer.compute_header_len(&data), 10);
    }

    #[test]
    fn test_coap_type_names() {
        assert_eq!(coap_type_name(0), "CON");
        assert_eq!(coap_type_name(1), "NON");
        assert_eq!(coap_type_name(2), "ACK");
        assert_eq!(coap_type_name(3), "RST");
        assert_eq!(coap_type_name(4), "Unknown");
    }

    #[test]
    fn test_coap_code_names() {
        assert_eq!(coap_code_name(CODE_EMPTY), "Empty");
        assert_eq!(coap_code_name(CODE_GET), "GET");
        assert_eq!(coap_code_name(CODE_CONTENT), "2.05 Content");
        assert_eq!(coap_code_name(CODE_NOT_FOUND), "4.04 Not Found");
    }

    #[test]
    fn test_coap_option_names() {
        assert_eq!(coap_option_name(OPT_URI_PATH), "Uri-Path");
        assert_eq!(coap_option_name(OPT_CONTENT_FORMAT), "Content-Format");
        assert_eq!(coap_option_name(OPT_BLOCK2), "Block2");
        assert_eq!(coap_option_name(999), "Unknown");
    }

    #[test]
    fn test_response_code_constants() {
        // Verify encoding: class.detail → (class << 5) | detail.
        assert_eq!(CODE_CREATED, 0x41); // 2<<5 | 1 = 65
        assert_eq!(CODE_CONTENT, 0x45); // 2<<5 | 5 = 69
        assert_eq!(CODE_NOT_FOUND, 0x84); // 4<<5 | 4 = 132
        assert_eq!(CODE_INTERNAL_ERROR, 0xA0); // 5<<5 | 0 = 160
    }
}
