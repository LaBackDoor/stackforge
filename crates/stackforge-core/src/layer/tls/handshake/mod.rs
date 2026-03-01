//! TLS Handshake message parsing and building.
//!
//! Implements the generic handshake header (type:1 + length:3 + body)
//! and all specific handshake message types.

pub mod certificate;
pub mod client_hello;
pub mod finished;
pub mod key_exchange;
pub mod server_hello;

pub use certificate::{Certificate, CertificateRequest, CertificateVerify};
pub use client_hello::ClientHello;
pub use finished::Finished;
pub use key_exchange::{ClientKeyExchange, ServerKeyExchange};
pub use server_hello::ServerHello;

use super::types::HandshakeType;

/// Generic TLS Handshake message.
///
/// ```text
/// HandshakeType msg_type;    // 1 byte
/// uint24 length;             // 3 bytes
/// body[length];              // variable
/// ```
#[derive(Debug, Clone)]
pub struct Handshake {
    /// Handshake type (1 byte).
    pub msg_type: HandshakeType,
    /// Length of the body (3 bytes, big-endian).
    pub length: u32,
    /// Raw body bytes.
    pub body: Vec<u8>,
}

/// Handshake header size: 1 (type) + 3 (length) = 4 bytes.
pub const HANDSHAKE_HEADER_LEN: usize = 4;

impl Handshake {
    /// Parse a handshake message from raw bytes.
    ///
    /// Returns the parsed handshake and the number of bytes consumed.
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < HANDSHAKE_HEADER_LEN {
            return None;
        }

        let msg_type = HandshakeType(data[0]);
        let length = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let total_len = HANDSHAKE_HEADER_LEN + length as usize;

        let body = if data.len() >= total_len {
            data[HANDSHAKE_HEADER_LEN..total_len].to_vec()
        } else {
            // Truncated - take what we have
            data[HANDSHAKE_HEADER_LEN..].to_vec()
        };

        Some((
            Self {
                msg_type,
                length,
                body,
            },
            total_len.min(data.len()),
        ))
    }

    /// Build the handshake message into bytes.
    pub fn build(&self) -> Vec<u8> {
        let length = if self.length > 0 {
            self.length
        } else {
            self.body.len() as u32
        };
        let len_bytes = length.to_be_bytes();

        let mut buf = Vec::with_capacity(HANDSHAKE_HEADER_LEN + self.body.len());
        buf.push(self.msg_type.0);
        buf.extend_from_slice(&len_bytes[1..4]); // 3 bytes
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Parse the body as a specific handshake message type.
    pub fn parse_body(&self) -> HandshakeBody {
        match self.msg_type {
            HandshakeType::CLIENT_HELLO => match ClientHello::parse(&self.body) {
                Some(ch) => HandshakeBody::ClientHello(ch),
                None => HandshakeBody::Unknown(self.body.clone()),
            },
            HandshakeType::SERVER_HELLO => match ServerHello::parse(&self.body) {
                Some(sh) => HandshakeBody::ServerHello(sh),
                None => HandshakeBody::Unknown(self.body.clone()),
            },
            HandshakeType::CERTIFICATE => match Certificate::parse(&self.body) {
                Some(cert) => HandshakeBody::Certificate(cert),
                None => HandshakeBody::Unknown(self.body.clone()),
            },
            HandshakeType::CERTIFICATE_VERIFY => match CertificateVerify::parse(&self.body) {
                Some(cv) => HandshakeBody::CertificateVerify(cv),
                None => HandshakeBody::Unknown(self.body.clone()),
            },
            HandshakeType::FINISHED => HandshakeBody::Finished(Finished {
                verify_data: self.body.clone(),
            }),
            HandshakeType::SERVER_HELLO_DONE => HandshakeBody::ServerHelloDone,
            HandshakeType::HELLO_REQUEST => HandshakeBody::HelloRequest,
            _ => HandshakeBody::Unknown(self.body.clone()),
        }
    }

    /// Get a human-readable summary.
    pub fn summary(&self) -> String {
        format!("Handshake {} (len={})", self.msg_type.name(), self.length)
    }
}

/// Parsed handshake message body.
#[derive(Debug, Clone)]
pub enum HandshakeBody {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    CertificateRequest(CertificateRequest),
    ServerKeyExchange(ServerKeyExchange),
    ClientKeyExchange(ClientKeyExchange),
    Finished(Finished),
    ServerHelloDone,
    HelloRequest,
    Unknown(Vec<u8>),
}

/// Parse all handshake messages from a TLS record fragment.
///
/// A single TLS record can contain multiple handshake messages.
pub fn parse_handshakes(data: &[u8]) -> Vec<Handshake> {
    let mut messages = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        match Handshake::parse(&data[offset..]) {
            Some((hs, consumed)) => {
                offset += consumed;
                messages.push(hs);
            },
            None => break,
        }
    }

    messages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_handshake_header() {
        // ClientHello: type=1, length=5, body=5 bytes
        let data = vec![0x01, 0x00, 0x00, 0x05, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let (hs, consumed) = Handshake::parse(&data).unwrap();
        assert_eq!(hs.msg_type, HandshakeType::CLIENT_HELLO);
        assert_eq!(hs.length, 5);
        assert_eq!(hs.body.len(), 5);
        assert_eq!(consumed, 9);
    }

    #[test]
    fn test_build_handshake() {
        let hs = Handshake {
            msg_type: HandshakeType::SERVER_HELLO,
            length: 0,
            body: vec![0x01, 0x02, 0x03],
        };
        let built = hs.build();
        assert_eq!(built[0], 0x02); // ServerHello type
        assert_eq!(built[1..4], [0x00, 0x00, 0x03]); // length
        assert_eq!(&built[4..], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_parse_multiple_handshakes() {
        let mut data = Vec::new();
        // First handshake: type=1, length=2, body=[0xAA, 0xBB]
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
        // Second handshake: type=2, length=1, body=[0xCC]
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x01, 0xCC]);

        let messages = parse_handshakes(&data);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].msg_type, HandshakeType::CLIENT_HELLO);
        assert_eq!(messages[1].msg_type, HandshakeType::SERVER_HELLO);
    }

    #[test]
    fn test_truncated_handshake() {
        // Type=1, length=100, but only 5 bytes of body available
        let data = vec![0x01, 0x00, 0x00, 0x64, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let (hs, _) = Handshake::parse(&data).unwrap();
        assert_eq!(hs.length, 100);
        assert_eq!(hs.body.len(), 5); // Only got 5 bytes
    }
}
