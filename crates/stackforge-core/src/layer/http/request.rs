//! HTTP/1.x request parsing (borrowed, zero-copy view).
//!
//! [`HttpRequest`] borrows directly from the original buffer; no heap
//! allocation is required for the metadata fields. Header values are stored
//! as `(&str, &str)` slice pairs pointing into the original buffer.

use super::detection::is_http_request;

/// A parsed HTTP/1.x request.
///
/// All string fields are lifetimed references back into the buffer that was
/// passed to [`HttpRequest::parse`]. The `body_offset` field records where the
/// body begins in that **same** buffer.
#[derive(Debug, Clone)]
pub struct HttpRequest<'a> {
    /// HTTP method (e.g. `"GET"`, `"POST"`).
    pub method: &'a str,
    /// Request-URI (e.g. `"/"`, `"/api/v1/resource"`).
    pub uri: &'a str,
    /// HTTP version string (e.g. `"HTTP/1.1"`).
    pub version: &'a str,
    /// Parsed headers as `(name, value)` pairs.  Header names retain their
    /// original casing from the wire; callers should compare case-insensitively.
    pub headers: Vec<(&'a str, &'a str)>,
    /// Byte offset in the **original buffer** at which the message body starts.
    /// Points to the byte immediately after the blank line (`\r\n\r\n`) that
    /// separates headers from body.  When there is no body this equals the
    /// buffer length.
    pub body_offset: usize,
}

impl<'a> HttpRequest<'a> {
    /// Parse an HTTP/1.x request from `buf`.
    ///
    /// Returns `None` when:
    /// - the buffer does not start with a known HTTP method, or
    /// - the request line is malformed (missing method / URI / version), or
    /// - the header section is not terminated by `\r\n\r\n` within `buf`.
    #[must_use]
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        // Quick rejection — must start with a known method token.
        if !is_http_request(buf) {
            return None;
        }

        let text = std::str::from_utf8(buf).ok()?;

        // Find the end of the first (request) line.
        let first_crlf = text.find("\r\n")?;
        let request_line = &text[..first_crlf];

        // Parse "METHOD URI HTTP/x.y"
        let mut parts = request_line.splitn(3, ' ');
        let method = parts.next()?;
        let uri = parts.next()?;
        let version = parts.next()?;

        // Validate version prefix.
        if !version.starts_with("HTTP/") {
            return None;
        }

        // Find the blank line that ends the header block.
        // Back up 2 bytes from header_block_start so that we also find
        // \r\n\r\n when there are no headers (i.e. the terminator immediately
        // follows the request line's \r\n).
        let header_block_start = first_crlf + 2; // skip past the first \r\n
        let end_marker = "\r\n\r\n";
        let search_start = header_block_start.saturating_sub(2);
        let headers_end_offset = text[search_start..]
            .find(end_marker)
            .map(|rel| search_start + rel)?;
        let body_offset = headers_end_offset + end_marker.len();

        // Parse individual headers (each line is "Name: value").
        let header_text = if header_block_start <= headers_end_offset {
            &text[header_block_start..headers_end_offset]
        } else {
            ""
        };
        let headers = parse_headers(header_text);

        Some(Self {
            method,
            uri,
            version,
            headers,
            body_offset,
        })
    }
}

/// Parse the header block into `(name, value)` pairs.
///
/// Lines that do not contain a `:` are silently skipped, as are any trailing
/// whitespace around header values.
fn parse_headers(header_text: &str) -> Vec<(&str, &str)> {
    header_text
        .split("\r\n")
        .filter_map(|line| {
            let colon_pos = line.find(':')?;
            let name = &line[..colon_pos];
            let value = line[colon_pos + 1..].trim();
            Some((name, value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_get() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let req = HttpRequest::parse(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.uri, "/");
        assert_eq!(req.version, "HTTP/1.1");
        assert_eq!(req.headers.len(), 2);
        assert_eq!(req.headers[0], ("Host", "example.com"));
        assert_eq!(req.headers[1], ("Accept", "*/*"));
        assert_eq!(req.body_offset, raw.len());
    }

    #[test]
    fn test_parse_post_with_body() {
        let raw = b"POST /submit HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let req = HttpRequest::parse(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.uri, "/submit");
        assert_eq!(req.version, "HTTP/1.1");
        // body starts after \r\n\r\n
        let body = &raw[req.body_offset..];
        assert_eq!(body, b"hello");
    }

    #[test]
    fn test_parse_rejects_response() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\n";
        assert!(HttpRequest::parse(raw).is_none());
    }

    #[test]
    fn test_parse_rejects_incomplete() {
        // No \r\n\r\n — headers never end.
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert!(HttpRequest::parse(raw).is_none());
    }

    #[test]
    fn test_header_case_preserved() {
        let raw = b"GET / HTTP/1.0\r\ncontent-type: text/html\r\n\r\n";
        let req = HttpRequest::parse(raw).unwrap();
        assert_eq!(req.headers[0].0, "content-type");
        assert_eq!(req.headers[0].1, "text/html");
    }
}
