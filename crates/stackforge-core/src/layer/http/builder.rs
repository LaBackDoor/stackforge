//! Fluent builders for serialising HTTP/1.x request and response messages.
//!
//! Both builders produce a complete, CRLF-terminated byte representation
//! suitable for transmission over a TCP stream.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::http::builder::{HttpRequestBuilder, HttpResponseBuilder};
//!
//! // Build a simple GET request.
//! let bytes = HttpRequestBuilder::new()
//!     .method("GET")
//!     .uri("/index.html")
//!     .header("Host", "example.com")
//!     .header("Accept", "*/*")
//!     .build();
//!
//! assert!(bytes.starts_with(b"GET /index.html HTTP/1.1\r\n"));
//!
//! // Build a 200 OK response with a body.
//! let body = b"Hello, World!";
//! let bytes = HttpResponseBuilder::new()
//!     .status(200, "OK")
//!     .header("Content-Type", "text/plain")
//!     .body(body.to_vec())
//!     .build();
//!
//! assert!(bytes.starts_with(b"HTTP/1.1 200 OK\r\n"));
//! ```

// ---------------------------------------------------------------------------
// HttpRequestBuilder
// ---------------------------------------------------------------------------

/// Builder for HTTP/1.x request messages.
///
/// Default values:
/// - method : `GET`
/// - URI    : `/`
/// - version: `HTTP/1.1`
/// - headers: empty
/// - body   : empty
#[derive(Debug, Clone)]
pub struct HttpRequestBuilder {
    method: String,
    uri: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Default for HttpRequestBuilder {
    fn default() -> Self {
        Self {
            method: "GET".to_owned(),
            uri: "/".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

impl HttpRequestBuilder {
    /// Create a new builder with default values (`GET / HTTP/1.1`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the HTTP method (e.g. `"GET"`, `"POST"`).
    pub fn method(mut self, method: &str) -> Self {
        self.method = method.to_owned();
        self
    }

    /// Set the request-URI.
    pub fn uri(mut self, uri: &str) -> Self {
        self.uri = uri.to_owned();
        self
    }

    /// Set the HTTP version string (e.g. `"HTTP/1.0"` or `"HTTP/1.1"`).
    pub fn version(mut self, version: &str) -> Self {
        self.version = version.to_owned();
        self
    }

    /// Append a request header.
    ///
    /// Headers are written in the order they are added.  No deduplication is
    /// performed.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Set the message body.
    ///
    /// Note: this method does **not** automatically add a `Content-Length`
    /// header; callers should add it explicitly if required.
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Serialise the request to bytes.
    ///
    /// The output uses CRLF line endings and follows the standard HTTP/1.x
    /// wire format:
    ///
    /// ```text
    /// METHOD URI VERSION\r\n
    /// Header-Name: header-value\r\n
    /// ...
    /// \r\n
    /// [body]
    /// ```
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Request line.
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.uri.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.version.as_bytes());
        out.extend_from_slice(b"\r\n");

        // Headers.
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        // Blank line.
        out.extend_from_slice(b"\r\n");

        // Body (may be empty).
        out.extend_from_slice(&self.body);

        out
    }
}

// ---------------------------------------------------------------------------
// HttpResponseBuilder
// ---------------------------------------------------------------------------

/// Builder for HTTP/1.x response messages.
///
/// Default values:
/// - version    : `HTTP/1.1`
/// - status code: `200`
/// - reason     : `OK`
/// - headers    : empty
/// - body       : empty
#[derive(Debug, Clone)]
pub struct HttpResponseBuilder {
    version: String,
    status_code: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Default for HttpResponseBuilder {
    fn default() -> Self {
        Self {
            version: "HTTP/1.1".to_owned(),
            status_code: 200,
            reason: "OK".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

impl HttpResponseBuilder {
    /// Create a new builder with default values (`HTTP/1.1 200 OK`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the HTTP version string.
    pub fn version(mut self, version: &str) -> Self {
        self.version = version.to_owned();
        self
    }

    /// Set the status code and reason phrase together.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stackforge_core::layer::http::builder::HttpResponseBuilder;
    ///
    /// let bytes = HttpResponseBuilder::new()
    ///     .status(404, "Not Found")
    ///     .build();
    ///
    /// assert!(bytes.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    /// ```
    pub fn status(mut self, code: u16, reason: &str) -> Self {
        self.status_code = code;
        self.reason = reason.to_owned();
        self
    }

    /// Append a response header.
    ///
    /// Headers are written in the order they are added.  No deduplication is
    /// performed.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Set the message body.
    ///
    /// Note: this method does **not** automatically add a `Content-Length`
    /// header; callers should add it explicitly if required.
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Serialise the response to bytes.
    ///
    /// The output uses CRLF line endings and follows the standard HTTP/1.x
    /// wire format:
    ///
    /// ```text
    /// VERSION STATUS_CODE REASON\r\n
    /// Header-Name: header-value\r\n
    /// ...
    /// \r\n
    /// [body]
    /// ```
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Status line.
        out.extend_from_slice(self.version.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.status_code.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.reason.as_bytes());
        out.extend_from_slice(b"\r\n");

        // Headers.
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        // Blank line.
        out.extend_from_slice(b"\r\n");

        // Body (may be empty).
        out.extend_from_slice(&self.body);

        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::http::request::HttpRequest;
    use crate::layer::http::response::HttpResponse;

    #[test]
    fn test_request_builder_defaults() {
        let bytes = HttpRequestBuilder::new().build();
        assert!(bytes.starts_with(b"GET / HTTP/1.1\r\n"));
        assert!(bytes.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn test_request_builder_full() {
        let body = b"key=value".to_vec();
        let bytes = HttpRequestBuilder::new()
            .method("POST")
            .uri("/submit")
            .version("HTTP/1.1")
            .header("Host", "example.com")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", &body.len().to_string())
            .body(body.clone())
            .build();

        // Must be parseable by HttpRequest.
        let req = HttpRequest::parse(&bytes).expect("should parse");
        assert_eq!(req.method, "POST");
        assert_eq!(req.uri, "/submit");
        assert_eq!(req.version, "HTTP/1.1");
        assert_eq!(req.headers.len(), 3);
        let parsed_body = &bytes[req.body_offset..];
        assert_eq!(parsed_body, body.as_slice());
    }

    #[test]
    fn test_response_builder_defaults() {
        let bytes = HttpResponseBuilder::new().build();
        assert!(bytes.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(bytes.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn test_response_builder_full() {
        let body = b"Hello, World!".to_vec();
        let bytes = HttpResponseBuilder::new()
            .status(200, "OK")
            .header("Content-Type", "text/plain")
            .header("Content-Length", &body.len().to_string())
            .body(body.clone())
            .build();

        // Must be parseable by HttpResponse.
        let resp = HttpResponse::parse(&bytes).expect("should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.headers.len(), 2);
        let parsed_body = &bytes[resp.body_offset..];
        assert_eq!(parsed_body, body.as_slice());
    }

    #[test]
    fn test_response_builder_404() {
        let bytes = HttpResponseBuilder::new().status(404, "Not Found").build();

        assert!(bytes.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
        let resp = HttpResponse::parse(&bytes).unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.reason, "Not Found");
    }

    #[test]
    fn test_request_builder_http10() {
        let bytes = HttpRequestBuilder::new()
            .version("HTTP/1.0")
            .uri("/old")
            .build();
        assert!(bytes.starts_with(b"GET /old HTTP/1.0\r\n"));
    }

    #[test]
    fn test_multiple_headers_ordering() {
        let bytes = HttpRequestBuilder::new()
            .header("A", "1")
            .header("B", "2")
            .header("C", "3")
            .build();

        let req = HttpRequest::parse(&bytes).unwrap();
        assert_eq!(req.headers[0], ("A", "1"));
        assert_eq!(req.headers[1], ("B", "2"));
        assert_eq!(req.headers[2], ("C", "3"));
    }
}
