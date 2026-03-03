//! `SSLv2` protocol support.
//!
//! Implements parsing and building for `SSLv2` record and handshake messages.
//! `SSLv2` uses a different record format from TLS:
//!
//! 2-byte header (MSB set): (length & 0x7FFF), no padding
//! 3-byte header (MSB clear): length:15, `padding_len:1`

pub mod handshake;
pub mod record;

pub use handshake::{Sslv2ClientHello, Sslv2ClientMasterKey, Sslv2MessageType, Sslv2ServerHello};
pub use record::{Sslv2Record, parse_sslv2_record};

/// `SSLv2` version constant.
pub const SSLV2_VERSION: u16 = 0x0002;

/// Check if data starts with an `SSLv2` record header.
#[must_use]
pub fn is_sslv2(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    // SSLv2 2-byte header has MSB set in first byte
    (data[0] & 0x80) != 0
}
