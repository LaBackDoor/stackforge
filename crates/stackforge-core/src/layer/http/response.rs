//! HTTP/1.x response parsing (borrowed, zero-copy view).
//!
//! [`HttpResponse`] borrows directly from the original buffer; no heap
//! allocation is required for the metadata fields. Header values are stored
//! as `(&str, &str)` slice pairs pointing into the original buffer.

use super::detection::is_http_response;

/// A parsed HTTP/1.x response.
///
/// All string fields are lifetimed references back into the buffer that was
/// passed to [`HttpResponse::parse`].  The `body_offset` field records where
/// the body begins in that **same** buffer.
#[derive(Debug, Clone)]
pub struct HttpResponse<'a> {
    /// HTTP version string (e.g. `"HTTP/1.1"`).
    pub version: &'a str,
    /// Numeric status code (e.g. `200`, `404`).
    pub status_code: u16,
    /// Reason phrase from the status line (e.g. `"OK"`, `"Not Found"`).
    pub reason: &'a str,
    /// Parsed headers as `(name, value)` pairs.  Header names retain their
    /// original casing from the wire; callers should compare case-insensitively.
    pub headers: Vec<(&'a str, &'a str)>,
    /// Byte offset in the **original buffer** at which the message body starts.
    /// Points to the byte immediately after the blank line (`\r\n\r\n`) that
    /// separates headers from body.  When there is no body this equals the
    /// buffer length.
    pub body_offset: usize,
}

impl<'a> HttpResponse<'a> {
    /// Parse an HTTP/1.x response from `buf`.
    ///
    /// Returns `None` when:
    /// - the buffer does not start with `"HTTP/"`, or
    /// - the status line is malformed, or
    /// - the header section is not terminated by `\r\n\r\n` within `buf`.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        // Quick rejection — must start with "HTTP/".
        if !is_http_response(buf) {
            return None;
        }

        let text = std::str::from_utf8(buf).ok()?;

        // Find the end of the status line.
        let first_crlf = text.find("\r\n")?;
        let status_line = &text[..first_crlf];

        // Parse "HTTP/x.y STATUS_CODE reason phrase"
        // Use splitn(3) so the reason phrase may contain spaces.
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next()?;
        let code_str = parts.next()?;
        let reason = parts.next().unwrap_or("");

        if !version.starts_with("HTTP/") {
            return None;
        }

        let status_code: u16 = code_str.parse().ok()?;

        // Find the blank line that ends the header block.
        // Search only from after the status line so we don't match the CRLF
        // at the end of the status line itself as part of \r\n\r\n.
        let header_block_start = first_crlf + 2;
        let end_marker = "\r\n\r\n";
        // Find \r\n\r\n starting from header_block_start. The blank line is
        // represented as \r\n\r\n where the first \r\n terminates the last
        // header (or is the trailing \r\n after the status line when there
        // are no headers), and the second \r\n is the blank line itself.
        // We search within text[header_block_start - 2..] (backing up 2 bytes
        // so we catch the \r\n at the end of the status line when there are no
        // headers) and compute the absolute offset.
        let search_start = if header_block_start >= 2 {
            header_block_start - 2
        } else {
            0
        };
        let headers_end_offset = text[search_start..]
            .find(end_marker)
            .map(|rel| search_start + rel)?;
        let body_offset = headers_end_offset + end_marker.len();

        // Parse individual headers (the slice between status-line and blank line).
        let header_text = if header_block_start <= headers_end_offset {
            &text[header_block_start..headers_end_offset]
        } else {
            ""
        };
        let headers = parse_headers(header_text);

        Some(Self {
            version,
            status_code,
            reason,
            headers,
            body_offset,
        })
    }
}

/// Parse the header block into `(name, value)` pairs.
///
/// Lines that do not contain a `:` are silently skipped, as are leading /
/// trailing whitespace around header values.
fn parse_headers<'a>(header_text: &'a str) -> Vec<(&'a str, &'a str)> {
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
    fn test_parse_200_ok() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello";
        let resp = HttpResponse::parse(raw).unwrap();
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.headers.len(), 2);
        assert_eq!(resp.headers[0], ("Content-Type", "text/html"));
        assert_eq!(resp.headers[1], ("Content-Length", "5"));
        let body = &raw[resp.body_offset..];
        assert_eq!(body, b"hello");
    }

    #[test]
    fn test_parse_404_not_found() {
        let raw = b"HTTP/1.0 404 Not Found\r\n\r\n";
        let resp = HttpResponse::parse(raw).unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.reason, "Not Found");
        assert!(resp.headers.is_empty());
    }

    #[test]
    fn test_parse_rejects_request() {
        let raw = b"GET / HTTP/1.1\r\n\r\n";
        assert!(HttpResponse::parse(raw).is_none());
    }

    #[test]
    fn test_parse_rejects_incomplete() {
        // No \r\n\r\n — headers never end.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n";
        assert!(HttpResponse::parse(raw).is_none());
    }

    #[test]
    fn test_parse_empty_reason() {
        // Some servers omit the reason phrase.
        let raw = b"HTTP/1.1 204 \r\n\r\n";
        let resp = HttpResponse::parse(raw).unwrap();
        assert_eq!(resp.status_code, 204);
        // reason may be empty or just whitespace after trim
        assert!(resp.reason.trim().is_empty());
    }

    #[test]
    fn test_parse_reason_with_spaces() {
        let raw = b"HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n";
        let resp = HttpResponse::parse(raw).unwrap();
        assert_eq!(resp.reason, "Moved Permanently");
        assert_eq!(resp.headers[0], ("Location", "/new"));
    }
}
