//! TLS (Transport Layer Security) protocol layer.
//!
//! Implements parsing and building for the TLS record protocol (RFC 5246, RFC 8446),
//! including support for `SSLv2`, TLS 1.0-1.2, and TLS 1.3.
//!
//! This is a "clean-sheet" implementation that follows Scapy's "Permissive Parser,
//! Explicit Builder" pattern, allowing construction of malformed packets for
//! security research and fuzzing.
//!
//! ## Record Format
//!
//! ```text
//! ContentType  type;           // 1 byte (20-24)
//! ProtocolVersion version;     // 2 bytes
//! uint16 length;               // 2 bytes
//! opaque fragment[length];     // variable
//! ```

pub mod builder;
pub mod cert;
pub mod crypto;
pub mod extensions;
pub mod handshake;
pub mod keyexchange;
pub mod record;
pub mod session;
pub mod sslv2;
pub mod types;

pub use builder::{TlsAlertBuilder, TlsCcsBuilder, TlsRecordBuilder};
pub use cert::TlsCertificate;
pub use extensions::Extension;
pub use handshake::{Certificate, ClientHello, Finished, Handshake, HandshakeBody, ServerHello};
pub use record::{TLS_FIELDS, TLS_RECORD_HEADER_LEN, TlsLayer};
pub use session::TlsSession;
pub use sslv2::{Sslv2ClientHello, Sslv2ClientMasterKey, Sslv2ServerHello};
pub use types::{
    ExtensionType, HandshakeType, NamedGroup, SignatureScheme, TlsAlertDescription, TlsAlertLevel,
    TlsContentType, TlsVersion,
};

/// Standard TLS port (HTTPS).
pub const TLS_PORT: u16 = 443;

/// Additional common TLS ports.
pub const TLS_PORTS: &[u16] = &[443, 465, 636, 853, 993, 995, 8443];

/// Check if a TCP payload looks like TLS traffic.
///
/// Returns true if the data starts with a valid TLS record header:
/// - Content type is 20-24 (valid TLS record types)
/// - Version is a recognized TLS/SSL version
/// - Length is reasonable (< 2^14 + 2048)
#[must_use]
pub fn is_tls_payload(data: &[u8]) -> bool {
    if data.len() < TLS_RECORD_HEADER_LEN {
        return false;
    }

    // Check content type (20-24 are valid)
    let content_type = data[0];
    if !(20..=24).contains(&content_type) {
        // Also check for SSLv2 format (MSB set in first byte)
        if data.len() >= 2 && (data[0] & 0x80) != 0 {
            // SSLv2 2-byte header: length with MSB set
            return true;
        }
        return false;
    }

    // Check version (should be 0x0300-0x0304 or draft versions)
    let version = u16::from_be_bytes([data[1], data[2]]);
    let valid_version = matches!(
        version,
        0x0300..=0x0304 | 0x7f00..=0x7fff
    );
    if !valid_version {
        return false;
    }

    // Check length is reasonable
    let length = u16::from_be_bytes([data[3], data[4]]) as usize;
    length <= TLS_RECORD_HEADER_LEN + record::TLS_MAX_CIPHERTEXT_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tls_payload_valid() {
        // Valid TLS 1.2 Handshake record header
        let data = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        assert!(is_tls_payload(&data));
    }

    #[test]
    fn test_is_tls_payload_alert() {
        let data = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert!(is_tls_payload(&data));
    }

    #[test]
    fn test_is_tls_payload_ccs() {
        let data = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        assert!(is_tls_payload(&data));
    }

    #[test]
    fn test_is_tls_payload_app_data() {
        let data = vec![0x17, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
        assert!(is_tls_payload(&data));
    }

    #[test]
    fn test_is_tls_payload_tls10() {
        let data = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        assert!(is_tls_payload(&data));
    }

    #[test]
    fn test_is_tls_payload_invalid_type() {
        let data = vec![0x19, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(!is_tls_payload(&data));
    }

    #[test]
    fn test_is_tls_payload_invalid_version() {
        let data = vec![0x16, 0x04, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(!is_tls_payload(&data));
    }

    #[test]
    fn test_is_tls_payload_too_short() {
        let data = vec![0x16, 0x03, 0x03, 0x00];
        assert!(!is_tls_payload(&data));
    }

    #[test]
    fn test_is_tls_payload_http() {
        assert!(!is_tls_payload(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn test_is_tls_payload_sslv2() {
        // SSLv2 ClientHello starts with 0x80 (MSB set)
        let data = vec![0x80, 0x2e, 0x01, 0x00, 0x02];
        assert!(is_tls_payload(&data));
    }
}
