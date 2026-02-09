//! TLS Finished message (type 20).
//!
//! Contains verify_data computed from the handshake transcript.

/// TLS Finished message.
#[derive(Debug, Clone)]
pub struct Finished {
    /// The verify_data (12 bytes for TLS 1.2, hash_len for TLS 1.3).
    pub verify_data: Vec<u8>,
}

impl Finished {
    /// Parse Finished message from body bytes.
    pub fn parse(data: &[u8]) -> Self {
        Self {
            verify_data: data.to_vec(),
        }
    }

    /// Build Finished message body.
    pub fn build(&self) -> Vec<u8> {
        self.verify_data.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finished_roundtrip() {
        let vd = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let f = Finished::parse(&vd);
        assert_eq!(f.verify_data, vd);
        assert_eq!(f.build(), vd);
    }
}
