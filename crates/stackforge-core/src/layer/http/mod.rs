//! HTTP/1.x layer implementation.
//!
//! This module provides:
//!
//! - **Detection** ([`detection`]) — fast byte-slice heuristics.
//! - **Request parsing** ([`request`]) — zero-copy borrowed [`HttpRequest`].
//! - **Response parsing** ([`response`]) — zero-copy borrowed [`HttpResponse`].
//! - **Builders** ([`builder`]) — fluent owned builders for crafting raw bytes.
//! - **[`HttpLayer`]** — a [`Layer`] implementation that presents a lazy,
//!   index-based view into a packet buffer following the Stackforge
//!   "Lazy Zero-Copy View" architecture.
//!
//! # Architecture
//!
//! [`HttpLayer`] holds only a [`LayerIndex`] (start / end byte offsets).  All
//! field values are read on demand, directly from the caller-supplied buffer.
//! No intermediate allocation is made when the layer is constructed.
//!
//! # Example
//!
//! ```rust
//! use stackforge_core::layer::http::{HttpLayer, HttpRequestBuilder};
//! use stackforge_core::layer::{LayerIndex, LayerKind};
//!
//! let raw = HttpRequestBuilder::new()
//!     .method("GET")
//!     .uri("/api/v1/status")
//!     .header("Host", "example.com")
//!     .build();
//!
//! let index = LayerIndex::new(LayerKind::Http, 0, raw.len());
//! let layer = HttpLayer { index };
//!
//! assert_eq!(layer.method(&raw), Some("GET"));
//! assert_eq!(layer.uri(&raw), Some("/api/v1/status"));
//! ```

pub mod builder;
pub mod detection;
pub mod request;
pub mod response;

pub use builder::{HttpRequestBuilder, HttpResponseBuilder};
pub use request::HttpRequest;
pub use response::HttpResponse;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

// ---------------------------------------------------------------------------
// Field name registry
// ---------------------------------------------------------------------------

/// Canonical field names exposed by [`HttpLayer`].
pub const HTTP_FIELD_NAMES: &[&str] = &[
    "method",
    "uri",
    "version",
    "status_code",
    "reason",
    "headers",
    "body",
];

// ---------------------------------------------------------------------------
// HttpLayer
// ---------------------------------------------------------------------------

/// Lazy, index-based view of an HTTP/1.x message inside a packet buffer.
///
/// The same type represents **either** a request **or** a response; use
/// [`HttpLayer::is_request`] / [`HttpLayer::is_response`] to disambiguate.
#[derive(Debug, Clone)]
pub struct HttpLayer {
    /// Start / end byte offsets of this HTTP message within the enclosing
    /// packet buffer.
    pub index: LayerIndex,
}

impl HttpLayer {
    /// Create a new `HttpLayer` from a [`LayerIndex`].
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Return the slice of `buf` that belongs to this layer.
    #[inline]
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    // -----------------------------------------------------------------------
    // Detection
    // -----------------------------------------------------------------------

    /// Returns `true` when the layer data looks like an HTTP request.
    pub fn is_request(&self, buf: &[u8]) -> bool {
        detection::is_http_request(self.slice(buf))
    }

    /// Returns `true` when the layer data looks like an HTTP response.
    pub fn is_response(&self, buf: &[u8]) -> bool {
        detection::is_http_response(self.slice(buf))
    }

    // -----------------------------------------------------------------------
    // Raw line / header helpers
    // -----------------------------------------------------------------------

    /// Return the first CRLF-terminated line of the HTTP message.
    pub fn first_line<'a>(&self, buf: &'a [u8]) -> Option<&'a [u8]> {
        let slice = self.slice(buf);
        let crlf_pos = slice.windows(2).position(|w| w == b"\r\n")?;
        Some(&slice[..crlf_pos])
    }

    /// Find the offset (relative to `start`) of the first byte **after** the
    /// `\r\n\r\n` header terminator.  Returns `None` when the terminator is
    /// not found in `buf[start..]`.
    pub fn headers_end(buf: &[u8], start: usize) -> Option<usize> {
        let search_area = buf.get(start..)?;
        search_area
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|rel| start + rel + 4)
    }

    // -----------------------------------------------------------------------
    // Request field accessors
    // -----------------------------------------------------------------------

    /// Return the HTTP method for a request (e.g. `"GET"`, `"POST"`).
    ///
    /// Returns `None` for responses or malformed data.
    pub fn method<'a>(&self, buf: &'a [u8]) -> Option<&'a str> {
        if !self.is_request(buf) {
            return None;
        }
        let line = std::str::from_utf8(self.first_line(buf)?).ok()?;
        line.split(' ').next()
    }

    /// Return the request-URI for a request.
    ///
    /// Returns `None` for responses or malformed data.
    pub fn uri<'a>(&self, buf: &'a [u8]) -> Option<&'a str> {
        if !self.is_request(buf) {
            return None;
        }
        let slice = self.slice(buf);
        let text = std::str::from_utf8(slice).ok()?;
        let line_end = text.find("\r\n")?;
        let request_line = &text[..line_end];
        let mut parts = request_line.splitn(3, ' ');
        parts.next(); // method
        parts.next() // uri
    }

    /// Return the HTTP version string (e.g. `"HTTP/1.1"`) for either a
    /// request or a response.
    pub fn http_version<'a>(&self, buf: &'a [u8]) -> Option<&'a str> {
        let slice = self.slice(buf);
        let text = std::str::from_utf8(slice).ok()?;
        let line_end = text.find("\r\n")?;
        let first_line = &text[..line_end];

        if self.is_response(buf) {
            // "HTTP/x.y STATUS REASON" — version is the first token.
            first_line.split(' ').next()
        } else {
            // "METHOD URI HTTP/x.y" — version is the last token.
            first_line.rsplitn(2, ' ').next()
        }
    }

    // -----------------------------------------------------------------------
    // Response field accessors
    // -----------------------------------------------------------------------

    /// Return the numeric status code for a response (e.g. `200`, `404`).
    ///
    /// Returns `None` for requests or malformed data.
    pub fn status_code(&self, buf: &[u8]) -> Option<u16> {
        if !self.is_response(buf) {
            return None;
        }
        let slice = self.slice(buf);
        let text = std::str::from_utf8(slice).ok()?;
        let line_end = text.find("\r\n")?;
        let status_line = &text[..line_end];
        let mut parts = status_line.splitn(3, ' ');
        parts.next(); // version
        parts.next()?.parse().ok()
    }

    /// Return the reason phrase for a response (e.g. `"OK"`, `"Not Found"`).
    ///
    /// Returns `None` for requests or malformed data.
    pub fn reason<'a>(&self, buf: &'a [u8]) -> Option<&'a str> {
        if !self.is_response(buf) {
            return None;
        }
        let slice = self.slice(buf);
        let text = std::str::from_utf8(slice).ok()?;
        let line_end = text.find("\r\n")?;
        let status_line = &text[..line_end];
        let mut parts = status_line.splitn(3, ' ');
        parts.next(); // version
        parts.next(); // status code
        parts.next()
    }

    // -----------------------------------------------------------------------
    // Generic header / body helpers
    // -----------------------------------------------------------------------

    /// Perform a **case-insensitive** lookup for a header by name.
    ///
    /// Returns the trimmed header value if found.
    pub fn header_value<'a>(&self, buf: &'a [u8], name: &str) -> Option<&'a str> {
        let slice = self.slice(buf);
        let text = std::str::from_utf8(slice).ok()?;

        // Skip the first line (request/status line).
        let first_crlf = text.find("\r\n")?;
        let after_first = first_crlf + 2;
        // Find \r\n\r\n starting from the end of the first line so we don't
        // accidentally match the first line's own \r\n as part of the sequence.
        let search_start = first_crlf; // back-up 2 to catch zero-header case
        let headers_end = text[search_start..]
            .find("\r\n\r\n")
            .map(|rel| search_start + rel)?;

        if after_first > headers_end {
            return None; // no headers, and no match for the requested name
        }
        let header_section = &text[after_first..headers_end];
        for line in header_section.split("\r\n") {
            if let Some(colon) = line.find(':') {
                let hdr_name = &line[..colon];
                if hdr_name.eq_ignore_ascii_case(name) {
                    return Some(line[colon + 1..].trim());
                }
            }
        }
        None
    }

    /// Return the absolute byte offset (in `buf`) where the body starts, i.e.
    /// the byte immediately after `\r\n\r\n`.
    ///
    /// Returns `None` when the header terminator is not present.
    pub fn body_offset(&self, buf: &[u8]) -> Option<usize> {
        Self::headers_end(buf, self.index.start)
    }

    /// Parse the `Content-Length` header and return it as a `usize`.
    ///
    /// Returns `None` when the header is absent or cannot be parsed.
    pub fn content_length(&self, buf: &[u8]) -> Option<usize> {
        self.header_value(buf, "content-length")
            .and_then(|v| v.parse().ok())
    }

    /// Return `true` when `Transfer-Encoding: chunked` is present.
    pub fn is_chunked(&self, buf: &[u8]) -> bool {
        self.header_value(buf, "transfer-encoding")
            .map(|v| v.eq_ignore_ascii_case("chunked"))
            .unwrap_or(false)
    }

    // -----------------------------------------------------------------------
    // Summary / header length
    // -----------------------------------------------------------------------

    /// Generate a human-readable one-line summary:
    /// - Request : `"HTTP GET /path HTTP/1.1"`
    /// - Response: `"HTTP 200 OK"`
    pub fn summary_str(&self, buf: &[u8]) -> String {
        if self.is_request(buf) {
            let method = self.method(buf).unwrap_or("?");
            let uri = self.uri(buf).unwrap_or("?");
            let version = self.http_version(buf).unwrap_or("HTTP/?");
            format!("HTTP {} {} {}", method, uri, version)
        } else if self.is_response(buf) {
            let code = self.status_code(buf).unwrap_or(0);
            let reason = self.reason(buf).unwrap_or("?");
            format!("HTTP {} {}", code, reason)
        } else {
            "HTTP".to_owned()
        }
    }

    /// Return the byte length of the HTTP headers section, including the
    /// terminal `\r\n\r\n`, but **excluding** the body.
    ///
    /// Returns `0` when the header block cannot be located.
    pub fn http_header_len(&self, buf: &[u8]) -> usize {
        match self.body_offset(buf) {
            Some(body_start) => body_start.saturating_sub(self.index.start),
            None => 0,
        }
    }

    // -----------------------------------------------------------------------
    // Field name / value API
    // -----------------------------------------------------------------------

    /// Return the static list of field names for this layer.
    pub fn field_names(&self) -> &'static [&'static str] {
        HTTP_FIELD_NAMES
    }

    /// Return a field value by name.
    ///
    /// | Field name    | Type                       | Notes              |
    /// |---------------|----------------------------|--------------------|
    /// | `method`      | `FieldValue::Bytes`        | requests only      |
    /// | `uri`         | `FieldValue::Bytes`        | requests only      |
    /// | `version`     | `FieldValue::Bytes`        | requests + responses |
    /// | `status_code` | `FieldValue::U16`          | responses only     |
    /// | `reason`      | `FieldValue::Bytes`        | responses only     |
    ///
    /// Returns `None` for unrecognised field names or when the field does not
    /// apply to the current message type.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "method" => {
                let v = self.method(buf)?;
                Some(Ok(FieldValue::Bytes(v.as_bytes().to_vec())))
            }
            "uri" => {
                let v = self.uri(buf)?;
                Some(Ok(FieldValue::Bytes(v.as_bytes().to_vec())))
            }
            "version" => {
                let v = self.http_version(buf)?;
                Some(Ok(FieldValue::Bytes(v.as_bytes().to_vec())))
            }
            "status_code" => {
                let v = self.status_code(buf)?;
                Some(Ok(FieldValue::U16(v)))
            }
            "reason" => {
                let v = self.reason(buf)?;
                Some(Ok(FieldValue::Bytes(v.as_bytes().to_vec())))
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Layer trait implementation
// ---------------------------------------------------------------------------

impl Layer for HttpLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Http
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary_str(data)
    }

    /// The header length for an HTTP layer is the number of bytes from the
    /// beginning of the message up to (and including) the `\r\n\r\n`
    /// header terminator.  The body bytes are NOT included.
    fn header_len(&self, data: &[u8]) -> usize {
        self.http_header_len(data)
    }

    fn hashret(&self, _data: &[u8]) -> Vec<u8> {
        // HTTP is stateless at this level; no meaningful hash.
        vec![]
    }

    fn answers(&self, _data: &[u8], _other: &Self, _other_data: &[u8]) -> bool {
        false
    }

    fn extract_padding<'a>(&self, data: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        // HTTP determines its own length via Content-Length or chunked
        // encoding.  We expose the full slice as "data" with no separate
        // padding region.
        let slice = self.index.slice(data);
        (slice, &[])
    }

    fn field_names(&self) -> &'static [&'static str] {
        HTTP_FIELD_NAMES
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_layer(buf: &[u8]) -> HttpLayer {
        HttpLayer {
            index: LayerIndex::new(LayerKind::Http, 0, buf.len()),
        }
    }

    // --- Request tests ------------------------------------------------------

    #[test]
    fn test_request_is_request() {
        let raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let layer = make_layer(raw);
        assert!(layer.is_request(raw));
        assert!(!layer.is_response(raw));
    }

    #[test]
    fn test_request_method() {
        let raw = b"POST /upload HTTP/1.1\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.method(raw), Some("POST"));
    }

    #[test]
    fn test_request_uri() {
        let raw = b"GET /path/to/resource HTTP/1.1\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.uri(raw), Some("/path/to/resource"));
    }

    #[test]
    fn test_request_version() {
        let raw = b"GET / HTTP/1.0\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.http_version(raw), Some("HTTP/1.0"));
    }

    #[test]
    fn test_request_header_value() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.header_value(raw, "host"), Some("example.com"));
        assert_eq!(layer.header_value(raw, "Host"), Some("example.com"));
        assert_eq!(layer.header_value(raw, "Accept"), Some("*/*"));
        assert_eq!(layer.header_value(raw, "X-Missing"), None);
    }

    #[test]
    fn test_request_body_offset() {
        let raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\nbody data";
        let layer = make_layer(raw);
        let offset = layer.body_offset(raw).unwrap();
        assert_eq!(&raw[offset..], b"body data");
    }

    #[test]
    fn test_request_content_length() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 42\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.content_length(raw), Some(42));
    }

    #[test]
    fn test_request_is_chunked() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let layer = make_layer(raw);
        assert!(layer.is_chunked(raw));
    }

    #[test]
    fn test_request_not_chunked() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n";
        let layer = make_layer(raw);
        assert!(!layer.is_chunked(raw));
    }

    #[test]
    fn test_request_summary() {
        let raw = b"DELETE /res HTTP/1.1\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.summary_str(raw), "HTTP DELETE /res HTTP/1.1");
    }

    #[test]
    fn test_request_header_len() {
        let headers = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let body = b"BODY";
        let mut raw = headers.to_vec();
        raw.extend_from_slice(body);
        let layer = make_layer(&raw);
        // header_len should NOT include the body.
        assert_eq!(layer.http_header_len(&raw), headers.len());
    }

    #[test]
    fn test_request_get_field_method() {
        let raw = b"PUT /x HTTP/1.1\r\n\r\n";
        let layer = make_layer(raw);
        if let Some(Ok(FieldValue::Bytes(v))) = layer.get_field(raw, "method") {
            assert_eq!(v, b"PUT");
        } else {
            panic!("expected Bytes value for method");
        }
    }

    #[test]
    fn test_request_get_field_uri() {
        let raw = b"GET /hello HTTP/1.1\r\n\r\n";
        let layer = make_layer(raw);
        if let Some(Ok(FieldValue::Bytes(v))) = layer.get_field(raw, "uri") {
            assert_eq!(v, b"/hello");
        } else {
            panic!("expected Bytes value for uri");
        }
    }

    #[test]
    fn test_request_get_field_version() {
        let raw = b"GET / HTTP/1.0\r\n\r\n";
        let layer = make_layer(raw);
        if let Some(Ok(FieldValue::Bytes(v))) = layer.get_field(raw, "version") {
            assert_eq!(v, b"HTTP/1.0");
        } else {
            panic!("expected Bytes value for version");
        }
    }

    // --- Response tests -----------------------------------------------------

    #[test]
    fn test_response_is_response() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\n";
        let layer = make_layer(raw);
        assert!(layer.is_response(raw));
        assert!(!layer.is_request(raw));
    }

    #[test]
    fn test_response_status_code() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.status_code(raw), Some(404));
    }

    #[test]
    fn test_response_reason() {
        let raw = b"HTTP/1.1 301 Moved Permanently\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.reason(raw), Some("Moved Permanently"));
    }

    #[test]
    fn test_response_version() {
        let raw = b"HTTP/1.0 200 OK\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.http_version(raw), Some("HTTP/1.0"));
    }

    #[test]
    fn test_response_header_value() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(
            layer.header_value(raw, "content-type"),
            Some("application/json")
        );
    }

    #[test]
    fn test_response_body_offset() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
        let layer = make_layer(raw);
        let offset = layer.body_offset(raw).unwrap();
        assert_eq!(&raw[offset..], b"test");
    }

    #[test]
    fn test_response_summary() {
        let raw = b"HTTP/1.1 500 Internal Server Error\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.summary_str(raw), "HTTP 500 Internal Server Error");
    }

    #[test]
    fn test_response_get_field_status_code() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\n";
        let layer = make_layer(raw);
        if let Some(Ok(FieldValue::U16(code))) = layer.get_field(raw, "status_code") {
            assert_eq!(code, 200);
        } else {
            panic!("expected U16 for status_code");
        }
    }

    #[test]
    fn test_response_get_field_reason() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\n";
        let layer = make_layer(raw);
        if let Some(Ok(FieldValue::Bytes(v))) = layer.get_field(raw, "reason") {
            assert_eq!(v, b"OK");
        } else {
            panic!("expected Bytes for reason");
        }
    }

    // --- Layer trait tests --------------------------------------------------

    #[test]
    fn test_layer_kind() {
        let raw = b"GET / HTTP/1.1\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.kind(), LayerKind::Http);
    }

    #[test]
    fn test_layer_field_names() {
        let raw = b"GET / HTTP/1.1\r\n\r\n";
        let layer = make_layer(raw);
        assert_eq!(layer.field_names(), HTTP_FIELD_NAMES);
    }

    // --- Cross-module builder + layer round-trip test ----------------------

    #[test]
    fn test_builder_and_layer_roundtrip_request() {
        let raw = HttpRequestBuilder::new()
            .method("PATCH")
            .uri("/resource/1")
            .header("Authorization", "Bearer token123")
            .header("Content-Type", "application/json")
            .body(b"{\"key\":\"val\"}".to_vec())
            .build();

        let layer = make_layer(&raw);
        assert_eq!(layer.method(&raw), Some("PATCH"));
        assert_eq!(layer.uri(&raw), Some("/resource/1"));
        assert_eq!(layer.http_version(&raw), Some("HTTP/1.1"));
        assert_eq!(
            layer.header_value(&raw, "authorization"),
            Some("Bearer token123")
        );
    }

    #[test]
    fn test_builder_and_layer_roundtrip_response() {
        let raw = HttpResponseBuilder::new()
            .status(201, "Created")
            .header("Location", "/resource/1")
            .body(b"{}".to_vec())
            .build();

        let layer = make_layer(&raw);
        assert_eq!(layer.status_code(&raw), Some(201));
        assert_eq!(layer.reason(&raw), Some("Created"));
        assert_eq!(layer.header_value(&raw, "Location"), Some("/resource/1"));
        let body = &raw[layer.body_offset(&raw).unwrap()..];
        assert_eq!(body, b"{}");
    }
}
