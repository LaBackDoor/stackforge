//! HTTP protocol integration tests.
//!
//! Tests HTTP request/response parsing, builder, field access, detection heuristics,
//! header lookup, body offset, Content-Length, chunked encoding, and summary format.

use stackforge_core::layer::http::{
    HTTP_FIELD_NAMES, HttpLayer, HttpRequestBuilder, HttpResponseBuilder,
    detection::{is_http_request, is_http_response},
};
use stackforge_core::layer::{LayerIndex, LayerKind};

// ============================================================================
// Helper to create an HttpLayer wrapping a full buffer
// ============================================================================

fn make_layer(buf: &[u8]) -> HttpLayer {
    HttpLayer {
        index: LayerIndex::new(LayerKind::Http, 0, buf.len()),
    }
}

// ============================================================================
// HTTP GET request parse
// ============================================================================

#[test]
fn test_http_get_request_is_request() {
    let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let layer = make_layer(raw);
    assert!(layer.is_request(raw));
    assert!(!layer.is_response(raw));
}

#[test]
fn test_http_get_request_method() {
    let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.method(raw), Some("GET"));
}

#[test]
fn test_http_get_request_uri() {
    let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.uri(raw), Some("/index.html"));
}

#[test]
fn test_http_get_request_version() {
    let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.http_version(raw), Some("HTTP/1.1"));
}

// ============================================================================
// HTTP POST request parse
// ============================================================================

#[test]
fn test_http_post_request_method() {
    let raw = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\nbody";
    let layer = make_layer(raw);
    assert_eq!(layer.method(raw), Some("POST"));
}

#[test]
fn test_http_post_request_uri() {
    let raw = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.uri(raw), Some("/api/data"));
}

#[test]
fn test_http_post_request_body_offset() {
    let raw = b"POST / HTTP/1.1\r\nHost: h\r\n\r\nbody content";
    let layer = make_layer(raw);
    let offset = layer.body_offset(raw).unwrap();
    assert_eq!(&raw[offset..], b"body content");
}

// ============================================================================
// HTTP response 200 OK parse
// ============================================================================

#[test]
fn test_http_response_200_is_response() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    let layer = make_layer(raw);
    assert!(layer.is_response(raw));
    assert!(!layer.is_request(raw));
}

#[test]
fn test_http_response_200_status_code() {
    let raw = b"HTTP/1.1 200 OK\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.status_code(raw), Some(200));
}

#[test]
fn test_http_response_200_reason() {
    let raw = b"HTTP/1.1 200 OK\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.reason(raw), Some("OK"));
}

#[test]
fn test_http_response_200_version() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.http_version(raw), Some("HTTP/1.1"));
}

// ============================================================================
// HTTP response 404 parse
// ============================================================================

#[test]
fn test_http_response_404_status_code() {
    let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.status_code(raw), Some(404));
}

#[test]
fn test_http_response_404_reason() {
    let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.reason(raw), Some("Not Found"));
}

// ============================================================================
// HTTP builder request
// ============================================================================

#[test]
fn test_http_request_builder_defaults() {
    let bytes = HttpRequestBuilder::new().build();
    assert!(bytes.starts_with(b"GET / HTTP/1.1\r\n"));
    assert!(bytes.ends_with(b"\r\n\r\n"));
}

#[test]
fn test_http_request_builder_method() {
    let bytes = HttpRequestBuilder::new().method("DELETE").build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.method(&bytes), Some("DELETE"));
}

#[test]
fn test_http_request_builder_uri() {
    let bytes = HttpRequestBuilder::new().uri("/api/v2/resource").build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.uri(&bytes), Some("/api/v2/resource"));
}

#[test]
fn test_http_request_builder_version_10() {
    let bytes = HttpRequestBuilder::new().version("HTTP/1.0").build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.http_version(&bytes), Some("HTTP/1.0"));
}

#[test]
fn test_http_request_builder_headers() {
    let bytes = HttpRequestBuilder::new()
        .method("GET")
        .uri("/test")
        .header("Host", "example.com")
        .header("Accept", "application/json")
        .build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.header_value(&bytes, "host"), Some("example.com"));
    assert_eq!(
        layer.header_value(&bytes, "accept"),
        Some("application/json")
    );
}

#[test]
fn test_http_request_builder_with_body() {
    let body = b"key=value&other=data";
    let bytes = HttpRequestBuilder::new()
        .method("POST")
        .uri("/submit")
        .header("Content-Length", &body.len().to_string())
        .body(body.to_vec())
        .build();
    let layer = make_layer(&bytes);
    let offset = layer.body_offset(&bytes).unwrap();
    assert_eq!(&bytes[offset..], body.as_ref());
}

// ============================================================================
// HTTP builder response
// ============================================================================

#[test]
fn test_http_response_builder_defaults() {
    let bytes = HttpResponseBuilder::new().build();
    assert!(bytes.starts_with(b"HTTP/1.1 200 OK\r\n"));
}

#[test]
fn test_http_response_builder_status() {
    let bytes = HttpResponseBuilder::new().status(201, "Created").build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.status_code(&bytes), Some(201));
    assert_eq!(layer.reason(&bytes), Some("Created"));
}

#[test]
fn test_http_response_builder_headers() {
    let bytes = HttpResponseBuilder::new()
        .status(200, "OK")
        .header("Content-Type", "application/json")
        .header("X-Request-Id", "abc-123")
        .build();
    let layer = make_layer(&bytes);
    assert_eq!(
        layer.header_value(&bytes, "content-type"),
        Some("application/json")
    );
    assert_eq!(layer.header_value(&bytes, "x-request-id"), Some("abc-123"));
}

#[test]
fn test_http_response_builder_with_body() {
    let body = b"{\"status\": \"ok\"}";
    let bytes = HttpResponseBuilder::new()
        .status(200, "OK")
        .header("Content-Length", &body.len().to_string())
        .body(body.to_vec())
        .build();
    let layer = make_layer(&bytes);
    let offset = layer.body_offset(&bytes).unwrap();
    assert_eq!(&bytes[offset..], body.as_ref());
}

// ============================================================================
// Header lookup (case-insensitive)
// ============================================================================

#[test]
fn test_http_header_case_insensitive_lowercase() {
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.header_value(raw, "host"), Some("example.com"));
}

#[test]
fn test_http_header_case_insensitive_uppercase() {
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.header_value(raw, "HOST"), Some("example.com"));
}

#[test]
fn test_http_header_case_insensitive_mixed() {
    let raw = b"GET / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.header_value(raw, "Content-Type"), Some("text/plain"));
    assert_eq!(layer.header_value(raw, "content-type"), Some("text/plain"));
    assert_eq!(layer.header_value(raw, "CONTENT-TYPE"), Some("text/plain"));
}

#[test]
fn test_http_header_missing_returns_none() {
    let raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.header_value(raw, "Authorization"), None);
}

// ============================================================================
// body_offset detection
// ============================================================================

#[test]
fn test_http_body_offset_request_no_body() {
    let raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
    let layer = make_layer(raw);
    let offset = layer.body_offset(raw).unwrap();
    assert_eq!(&raw[offset..], b"");
}

#[test]
fn test_http_body_offset_response_with_body() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
    let layer = make_layer(raw);
    let offset = layer.body_offset(raw).unwrap();
    assert_eq!(&raw[offset..], b"test");
}

#[test]
fn test_http_body_offset_no_terminator_returns_none() {
    let raw = b"GET / HTTP/1.1\r\n"; // missing \r\n\r\n
    let layer = make_layer(raw);
    assert!(layer.body_offset(raw).is_none());
}

// ============================================================================
// Content-Length parsing
// ============================================================================

#[test]
fn test_http_content_length_present() {
    let raw = b"POST / HTTP/1.1\r\nContent-Length: 42\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.content_length(raw), Some(42));
}

#[test]
fn test_http_content_length_absent() {
    let raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.content_length(raw), None);
}

#[test]
fn test_http_content_length_zero() {
    let raw = b"DELETE / HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.content_length(raw), Some(0));
}

// ============================================================================
// Transfer-Encoding: chunked detection
// ============================================================================

#[test]
fn test_http_is_chunked_true() {
    let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    let layer = make_layer(raw);
    assert!(layer.is_chunked(raw));
}

#[test]
fn test_http_is_chunked_false() {
    let raw = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    let layer = make_layer(raw);
    assert!(!layer.is_chunked(raw));
}

#[test]
fn test_http_is_chunked_case_insensitive() {
    let raw = b"POST / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n";
    let layer = make_layer(raw);
    assert!(layer.is_chunked(raw));
}

// ============================================================================
// HTTP detection heuristics
// ============================================================================

#[test]
fn test_is_http_request_all_methods() {
    let methods = [
        b"GET / HTTP/1.1\r\n".as_ref(),
        b"POST /api HTTP/1.1\r\n".as_ref(),
        b"PUT /res HTTP/1.1\r\n".as_ref(),
        b"DELETE /res HTTP/1.1\r\n".as_ref(),
        b"HEAD / HTTP/1.1\r\n".as_ref(),
        b"OPTIONS * HTTP/1.1\r\n".as_ref(),
        b"PATCH /res HTTP/1.1\r\n".as_ref(),
    ];
    for method_raw in &methods {
        assert!(
            is_http_request(method_raw),
            "Should be HTTP request: {:?}",
            method_raw
        );
    }
}

#[test]
fn test_is_http_request_not_response() {
    assert!(!is_http_request(b"HTTP/1.1 200 OK\r\n"));
}

#[test]
fn test_is_http_response_with_version() {
    assert!(is_http_response(b"HTTP/1.1 200 OK\r\n"));
    assert!(is_http_response(b"HTTP/1.0 404 Not Found\r\n"));
}

#[test]
fn test_is_http_response_not_request() {
    assert!(!is_http_response(b"GET / HTTP/1.1\r\n"));
}

// ============================================================================
// HTTP layer kind check
// ============================================================================

#[test]
fn test_http_layer_kind() {
    use stackforge_core::layer::Layer;
    let raw = b"GET / HTTP/1.1\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.kind(), LayerKind::Http);
}

// ============================================================================
// HTTP summary format
// ============================================================================

#[test]
fn test_http_summary_request() {
    let raw = b"GET /path HTTP/1.1\r\n\r\n";
    let layer = make_layer(raw);
    let s = layer.summary_str(raw);
    assert!(s.contains("HTTP"));
    assert!(s.contains("GET"));
    assert!(s.contains("/path"));
}

#[test]
fn test_http_summary_response() {
    let raw = b"HTTP/1.1 200 OK\r\n\r\n";
    let layer = make_layer(raw);
    let s = layer.summary_str(raw);
    assert!(s.contains("HTTP"));
    assert!(s.contains("200"));
    assert!(s.contains("OK"));
}

#[test]
fn test_http_summary_404_response() {
    let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
    let layer = make_layer(raw);
    let s = layer.summary_str(raw);
    assert_eq!(s, "HTTP 404 Not Found");
}

#[test]
fn test_http_summary_delete_request() {
    let raw = b"DELETE /resource HTTP/1.1\r\n\r\n";
    let layer = make_layer(raw);
    let s = layer.summary_str(raw);
    assert_eq!(s, "HTTP DELETE /resource HTTP/1.1");
}

// ============================================================================
// field_names() correctness
// ============================================================================

#[test]
fn test_http_field_names_constant() {
    assert!(HTTP_FIELD_NAMES.contains(&"method"));
    assert!(HTTP_FIELD_NAMES.contains(&"uri"));
    assert!(HTTP_FIELD_NAMES.contains(&"version"));
    assert!(HTTP_FIELD_NAMES.contains(&"status_code"));
    assert!(HTTP_FIELD_NAMES.contains(&"reason"));
}

#[test]
fn test_http_field_names_via_layer() {
    let raw = b"GET / HTTP/1.1\r\n\r\n";
    let layer = make_layer(raw);
    let names = layer.field_names();
    assert!(names.contains(&"method"));
    assert!(names.contains(&"uri"));
    assert!(names.contains(&"version"));
    assert!(names.contains(&"status_code"));
    assert!(names.contains(&"reason"));
}

// ============================================================================
// get_field dynamic access
// ============================================================================

#[test]
fn test_http_get_field_method() {
    use stackforge_core::FieldValue;
    let raw = b"PUT /x HTTP/1.1\r\n\r\n";
    let layer = make_layer(raw);
    if let Some(Ok(FieldValue::Bytes(v))) = layer.get_field(raw, "method") {
        assert_eq!(v, b"PUT");
    } else {
        panic!("expected method field");
    }
}

#[test]
fn test_http_get_field_uri() {
    use stackforge_core::FieldValue;
    let raw = b"GET /hello/world HTTP/1.1\r\n\r\n";
    let layer = make_layer(raw);
    if let Some(Ok(FieldValue::Bytes(v))) = layer.get_field(raw, "uri") {
        assert_eq!(v, b"/hello/world");
    } else {
        panic!("expected uri field");
    }
}

#[test]
fn test_http_get_field_status_code() {
    use stackforge_core::FieldValue;
    let raw = b"HTTP/1.1 302 Found\r\n\r\n";
    let layer = make_layer(raw);
    if let Some(Ok(FieldValue::U16(code))) = layer.get_field(raw, "status_code") {
        assert_eq!(code, 302);
    } else {
        panic!("expected status_code field");
    }
}

#[test]
fn test_http_get_field_reason() {
    use stackforge_core::FieldValue;
    let raw = b"HTTP/1.1 500 Internal Server Error\r\n\r\n";
    let layer = make_layer(raw);
    if let Some(Ok(FieldValue::Bytes(v))) = layer.get_field(raw, "reason") {
        assert_eq!(v, b"Internal Server Error");
    } else {
        panic!("expected reason field");
    }
}

#[test]
fn test_http_get_field_unknown_returns_none() {
    let raw = b"GET / HTTP/1.1\r\n\r\n";
    let layer = make_layer(raw);
    assert!(layer.get_field(raw, "nonexistent").is_none());
}

// ============================================================================
// Builder + layer roundtrip
// ============================================================================

#[test]
fn test_http_builder_layer_roundtrip_request() {
    let bytes = HttpRequestBuilder::new()
        .method("PATCH")
        .uri("/resource/1")
        .header("Authorization", "Bearer mytoken")
        .header("Content-Type", "application/json")
        .body(b"{\"value\": 42}".to_vec())
        .build();

    let layer = make_layer(&bytes);
    assert_eq!(layer.method(&bytes), Some("PATCH"));
    assert_eq!(layer.uri(&bytes), Some("/resource/1"));
    assert_eq!(layer.http_version(&bytes), Some("HTTP/1.1"));
    assert_eq!(
        layer.header_value(&bytes, "authorization"),
        Some("Bearer mytoken")
    );
    assert_eq!(
        layer.header_value(&bytes, "content-type"),
        Some("application/json")
    );
}

#[test]
fn test_http_builder_layer_roundtrip_response() {
    let body = b"created";
    let bytes = HttpResponseBuilder::new()
        .status(201, "Created")
        .header("Location", "/resource/1")
        .header("Content-Length", &body.len().to_string())
        .body(body.to_vec())
        .build();

    let layer = make_layer(&bytes);
    assert_eq!(layer.status_code(&bytes), Some(201));
    assert_eq!(layer.reason(&bytes), Some("Created"));
    assert_eq!(layer.header_value(&bytes, "Location"), Some("/resource/1"));
    let offset = layer.body_offset(&bytes).unwrap();
    assert_eq!(&bytes[offset..], body.as_ref());
}

// ============================================================================
// http_header_len
// ============================================================================

#[test]
fn test_http_header_len_request() {
    let headers = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
    let body = b"BODY_DATA";
    let mut raw = headers.to_vec();
    raw.extend_from_slice(body);
    let layer = make_layer(&raw);
    assert_eq!(layer.http_header_len(&raw), headers.len());
}

#[test]
fn test_http_header_len_response() {
    let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n";
    let body = b"data";
    let mut raw = headers.to_vec();
    raw.extend_from_slice(body);
    let layer = make_layer(&raw);
    assert_eq!(layer.http_header_len(&raw), headers.len());
}

// ============================================================================
// Various HTTP methods
// ============================================================================

#[test]
fn test_http_head_request() {
    let raw = b"HEAD /resource HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.method(raw), Some("HEAD"));
}

#[test]
fn test_http_options_request() {
    let raw = b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.method(raw), Some("OPTIONS"));
}

#[test]
fn test_http_connect_request() {
    let raw = b"CONNECT host.example.com:443 HTTP/1.1\r\nHost: host.example.com:443\r\n\r\n";
    let layer = make_layer(raw);
    assert_eq!(layer.method(raw), Some("CONNECT"));
}
