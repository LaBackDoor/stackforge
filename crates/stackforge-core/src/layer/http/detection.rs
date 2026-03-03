//! HTTP traffic detection utilities.
//!
//! Provides functions to quickly determine whether a byte slice looks like
//! HTTP/1.x request or response data, without full parsing.

/// All standard HTTP/1.x request methods, each with a trailing space so a
/// simple `starts_with` check is unambiguous.
const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// Returns `true` if `buf` begins with a recognised HTTP request method token.
///
/// The check is a fast `starts_with` on the first few bytes and does **not**
/// validate the rest of the request line.
#[must_use]
pub fn is_http_request(buf: &[u8]) -> bool {
    HTTP_METHODS.iter().any(|m| buf.starts_with(m))
}

/// Returns `true` if `buf` begins with the HTTP response status-line prefix
/// `"HTTP/"`.
#[must_use]
pub fn is_http_response(buf: &[u8]) -> bool {
    buf.starts_with(b"HTTP/")
}

/// Returns `true` if `buf` looks like any HTTP/1.x traffic (request or
/// response).
#[must_use]
pub fn is_http(buf: &[u8]) -> bool {
    is_http_request(buf) || is_http_response(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_request_methods() {
        assert!(is_http_request(b"GET / HTTP/1.1\r\n"));
        assert!(is_http_request(b"POST /api HTTP/1.1\r\n"));
        assert!(is_http_request(b"HEAD / HTTP/1.0\r\n"));
        assert!(is_http_request(b"PUT /resource HTTP/1.1\r\n"));
        assert!(is_http_request(b"DELETE /res HTTP/1.1\r\n"));
        assert!(is_http_request(b"OPTIONS * HTTP/1.1\r\n"));
        assert!(is_http_request(b"PATCH /res HTTP/1.1\r\n"));
        assert!(is_http_request(b"CONNECT host:443 HTTP/1.1\r\n"));
        assert!(is_http_request(b"TRACE / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_is_http_request_negative() {
        assert!(!is_http_request(b"HTTP/1.1 200 OK\r\n"));
        assert!(!is_http_request(b"INVALID method"));
        assert!(!is_http_request(b""));
        assert!(!is_http_request(b"SSH-2.0"));
    }

    #[test]
    fn test_is_http_response() {
        assert!(is_http_response(b"HTTP/1.1 200 OK\r\n"));
        assert!(is_http_response(b"HTTP/1.0 404 Not Found\r\n"));
        assert!(!is_http_response(b"GET / HTTP/1.1\r\n"));
        assert!(!is_http_response(b""));
    }

    #[test]
    fn test_is_http() {
        assert!(is_http(b"GET / HTTP/1.1\r\n"));
        assert!(is_http(b"HTTP/1.1 200 OK\r\n"));
        assert!(!is_http(b"SSH-2.0-OpenSSH"));
        assert!(!is_http(b""));
    }
}
