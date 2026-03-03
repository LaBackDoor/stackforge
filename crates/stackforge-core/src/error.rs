//! Error types for the stackforge-core crate.

use crate::layer::LayerKind;
use thiserror::Error;

/// Errors that can occur during packet operations.
#[derive(Debug, Error)]
pub enum PacketError {
    /// The packet buffer is too short to contain the expected data.
    #[error("buffer too short: expected at least {expected} bytes, got {actual}")]
    BufferTooShort { expected: usize, actual: usize },

    /// Invalid field value encountered during parsing.
    #[error("invalid field value: {0}")]
    InvalidField(String),

    /// The layer type is not supported or recognized.
    #[error("unsupported layer type: {0}")]
    UnsupportedLayer(String),

    /// Attempted to access a layer that doesn't exist in the packet.
    #[error("layer not found: {0:?}")]
    LayerNotFound(LayerKind),

    /// Checksum verification failed.
    #[error("checksum mismatch: expected {expected:#06x}, got {actual:#06x}")]
    ChecksumMismatch { expected: u16, actual: u16 },

    /// Invalid protocol number.
    #[error("invalid protocol number: {0}")]
    InvalidProtocol(u8),

    /// Failed to parse layer at the given offset.
    #[error("parse error at offset {offset}: {message}")]
    ParseError { offset: usize, message: String },

    /// Field access error.
    #[error("field error: {0}")]
    FieldError(#[from] crate::layer::field::FieldError),

    /// Layer binding not found.
    #[error("no binding found for {lower:?} -> {upper:?}")]
    BindingNotFound { lower: LayerKind, upper: LayerKind },

    /// Neighbor resolution failed.
    #[error("failed to resolve neighbor for {0}")]
    NeighborResolutionFailed(String),

    /// Invalid MAC address.
    #[error("invalid MAC address: {0}")]
    InvalidMac(String),

    /// Invalid IP address.
    #[error("invalid IP address: {0}")]
    InvalidIp(String),

    /// Operation not supported.
    #[error("operation not supported: {0}")]
    NotSupported(String),

    /// Timeout error.
    #[error("operation timed out after {0} ms")]
    Timeout(u64),

    /// I/O error wrapper.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for PacketError {
    fn from(err: std::io::Error) -> Self {
        PacketError::Io(err.to_string())
    }
}

impl PacketError {
    /// Create a buffer too short error.
    #[must_use]
    pub fn buffer_too_short(expected: usize, actual: usize) -> Self {
        Self::BufferTooShort { expected, actual }
    }

    /// Create a parse error.
    pub fn parse_error(offset: usize, message: impl Into<String>) -> Self {
        Self::ParseError {
            offset,
            message: message.into(),
        }
    }

    /// Create a binding not found error.
    #[must_use]
    pub fn binding_not_found(lower: LayerKind, upper: LayerKind) -> Self {
        Self::BindingNotFound { lower, upper }
    }

    /// Check if this is a recoverable error.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::BufferTooShort { .. } | Self::Timeout(_) | Self::NeighborResolutionFailed(_)
        )
    }
}

/// Result type alias for packet operations.
pub type Result<T> = std::result::Result<T, PacketError>;

/// Extension trait for Result types.
pub trait ResultExt<T> {
    /// Convert to `PacketError` with context.
    fn with_context(self, context: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E: std::fmt::Display> ResultExt<T> for std::result::Result<T, E> {
    fn with_context(self, context: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| PacketError::InvalidField(format!("{}: {}", context(), e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PacketError::BufferTooShort {
            expected: 20,
            actual: 10,
        };
        assert!(err.to_string().contains("20"));
        assert!(err.to_string().contains("10"));
    }

    #[test]
    fn test_error_helpers() {
        let err = PacketError::buffer_too_short(100, 50);
        assert!(matches!(err, PacketError::BufferTooShort { .. }));

        let err = PacketError::parse_error(10, "invalid header");
        assert!(matches!(err, PacketError::ParseError { .. }));
    }

    #[test]
    fn test_is_recoverable() {
        assert!(PacketError::Timeout(1000).is_recoverable());
        assert!(!PacketError::InvalidProtocol(255).is_recoverable());
    }
}
