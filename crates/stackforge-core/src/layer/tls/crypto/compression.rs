//! TLS compression methods.
//!
//! Only NULL compression (identity) is supported, as DEFLATE
//! compression is deprecated due to CRIME attack.

/// TLS compression method IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionMethod(pub u8);

impl CompressionMethod {
    pub const NULL: Self = Self(0);
    pub const DEFLATE: Self = Self(1);

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.0 {
            0 => "null",
            1 => "DEFLATE",
            _ => "unknown",
        }
    }
}

/// Compress data (identity for NULL compression).
#[must_use]
pub fn compress(method: CompressionMethod, data: &[u8]) -> Vec<u8> {
    match method {
        CompressionMethod::NULL => data.to_vec(),
        _ => data.to_vec(), // Unsupported methods fall back to no compression
    }
}

/// Decompress data (identity for NULL compression).
#[must_use]
pub fn decompress(method: CompressionMethod, data: &[u8]) -> Vec<u8> {
    match method {
        CompressionMethod::NULL => data.to_vec(),
        _ => data.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_compression() {
        let data = b"Hello, TLS!";
        let compressed = compress(CompressionMethod::NULL, data);
        assert_eq!(&compressed, data);
        let decompressed = decompress(CompressionMethod::NULL, &compressed);
        assert_eq!(&decompressed, data);
    }
}
