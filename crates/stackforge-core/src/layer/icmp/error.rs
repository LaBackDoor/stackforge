//! ICMP error packet handling.
//!
//! ICMP error messages (types 3, 4, 5, 11, 12) contain a copy of the original
//! IP header plus at least the first 8 bytes of the original datagram's data.
//! This module provides utilities for detecting and handling these embedded packets.

use crate::layer::icmp::types::types;

/// ICMP types that contain error information (original packet headers).
pub const ERROR_TYPES: &[u8] = &[
    types::DEST_UNREACH,  // 3
    types::SOURCE_QUENCH, // 4
    types::REDIRECT,      // 5
    types::TIME_EXCEEDED, // 11
    types::PARAM_PROBLEM, // 12
];

/// Check if an ICMP type indicates an error message containing original packet data.
///
/// Error messages include the original IP header + first 8 bytes of transport data.
#[inline]
pub fn is_error_type(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        types::DEST_UNREACH
            | types::SOURCE_QUENCH
            | types::REDIRECT
            | types::TIME_EXCEEDED
            | types::PARAM_PROBLEM
    )
}

/// Get the minimum payload size for error packets.
///
/// RFC 792 specifies that ICMP error messages must include the original
/// IP header (20 bytes minimum) plus the first 8 bytes of the original datagram.
pub const ERROR_MIN_PAYLOAD: usize = 20 + 8; // IP header + 8 bytes of data

/// Calculate the offset where the embedded IP packet starts in an ICMP error message.
///
/// # Arguments
/// * `icmp_type` - The ICMP message type
///
/// # Returns
/// The byte offset from the start of the ICMP header where the embedded packet begins,
/// or None if this is not an error type.
pub fn error_payload_offset(icmp_type: u8) -> Option<usize> {
    if !is_error_type(icmp_type) {
        return None;
    }

    // All error types have 8-byte ICMP header (type, code, checksum, + 4 bytes type-specific)
    Some(8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_error_type() {
        // Error types
        assert!(is_error_type(types::DEST_UNREACH));
        assert!(is_error_type(types::SOURCE_QUENCH));
        assert!(is_error_type(types::REDIRECT));
        assert!(is_error_type(types::TIME_EXCEEDED));
        assert!(is_error_type(types::PARAM_PROBLEM));

        // Non-error types
        assert!(!is_error_type(types::ECHO_REQUEST));
        assert!(!is_error_type(types::ECHO_REPLY));
        assert!(!is_error_type(types::TIMESTAMP));
        assert!(!is_error_type(types::ADDRESS_MASK_REQUEST));
    }

    #[test]
    fn test_error_payload_offset() {
        // Error types should return offset 8
        assert_eq!(error_payload_offset(types::DEST_UNREACH), Some(8));
        assert_eq!(error_payload_offset(types::TIME_EXCEEDED), Some(8));
        assert_eq!(error_payload_offset(types::PARAM_PROBLEM), Some(8));

        // Non-error types should return None
        assert_eq!(error_payload_offset(types::ECHO_REQUEST), None);
        assert_eq!(error_payload_offset(types::ECHO_REPLY), None);
    }
}
