//! SSH (Secure Shell) protocol layer.
//!
//! Implements parsing for the SSH Binary Packet Protocol (RFC 4253)
//! and the SSH Version Exchange.
//!
//! ## Binary Packet Format
//!
//! ```text
//! uint32    packet_length
//! byte      padding_length
//! byte[n1]  payload; n1 = packet_length - padding_length - 1
//! byte[n2]  random padding; n2 = padding_length
//! byte[m]   mac (Message Authentication Code - MAC); m = mac_length
//! ```

pub mod builder;

pub use builder::SshBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum SSH binary packet header: 4 (`packet_length`) + 1 (`padding_length`).
pub const SSH_BINARY_HEADER_LEN: usize = 5;

/// Standard SSH port.
pub const SSH_PORT: u16 = 22;

/// SSH message type constants (RFC 4250/4253/4252/4254).
pub mod msg_types {
    // Transport layer (RFC 4253)
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const UNIMPLEMENTED: u8 = 3;
    pub const DEBUG: u8 = 4;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const EXT_INFO: u8 = 7; // RFC 8308
    pub const NEWCOMPRESS: u8 = 8;
    pub const KEXINIT: u8 = 20;
    pub const NEWKEYS: u8 = 21;
    // Key exchange (RFC 4253 errata 152)
    pub const KEXDH_INIT: u8 = 30;
    pub const KEXDH_REPLY: u8 = 31;
    // User authentication (RFC 4252)
    pub const USERAUTH_REQUEST: u8 = 50;
    pub const USERAUTH_FAILURE: u8 = 51;
    pub const USERAUTH_SUCCESS: u8 = 52;
    pub const USERAUTH_BANNER: u8 = 53;
    // Connection protocol (RFC 4254)
    pub const CHANNEL_OPEN: u8 = 90;
    pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const CHANNEL_DATA: u8 = 94;
    pub const CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const CHANNEL_EOF: u8 = 96;
    pub const CHANNEL_CLOSE: u8 = 97;
    pub const CHANNEL_REQUEST: u8 = 98;
    pub const CHANNEL_SUCCESS: u8 = 99;
    pub const CHANNEL_FAILURE: u8 = 100;
    pub const GLOBAL_REQUEST: u8 = 80;
    pub const REQUEST_SUCCESS: u8 = 81;
    pub const REQUEST_FAILURE: u8 = 82;

    /// Get a human-readable name for an SSH message type.
    #[must_use]
    pub fn name(msg_type: u8) -> &'static str {
        match msg_type {
            DISCONNECT => "DISCONNECT",
            IGNORE => "IGNORE",
            UNIMPLEMENTED => "UNIMPLEMENTED",
            DEBUG => "DEBUG",
            SERVICE_REQUEST => "SERVICE_REQUEST",
            SERVICE_ACCEPT => "SERVICE_ACCEPT",
            EXT_INFO => "EXT_INFO",
            NEWCOMPRESS => "NEWCOMPRESS",
            KEXINIT => "KEXINIT",
            NEWKEYS => "NEWKEYS",
            KEXDH_INIT => "KEXDH_INIT",
            KEXDH_REPLY => "KEXDH_REPLY",
            USERAUTH_REQUEST => "USERAUTH_REQUEST",
            USERAUTH_FAILURE => "USERAUTH_FAILURE",
            USERAUTH_SUCCESS => "USERAUTH_SUCCESS",
            USERAUTH_BANNER => "USERAUTH_BANNER",
            GLOBAL_REQUEST => "GLOBAL_REQUEST",
            REQUEST_SUCCESS => "REQUEST_SUCCESS",
            REQUEST_FAILURE => "REQUEST_FAILURE",
            CHANNEL_OPEN => "CHANNEL_OPEN",
            CHANNEL_OPEN_CONFIRMATION => "CHANNEL_OPEN_CONFIRMATION",
            CHANNEL_OPEN_FAILURE => "CHANNEL_OPEN_FAILURE",
            CHANNEL_WINDOW_ADJUST => "CHANNEL_WINDOW_ADJUST",
            CHANNEL_DATA => "CHANNEL_DATA",
            CHANNEL_EXTENDED_DATA => "CHANNEL_EXTENDED_DATA",
            CHANNEL_EOF => "CHANNEL_EOF",
            CHANNEL_CLOSE => "CHANNEL_CLOSE",
            CHANNEL_REQUEST => "CHANNEL_REQUEST",
            CHANNEL_SUCCESS => "CHANNEL_SUCCESS",
            CHANNEL_FAILURE => "CHANNEL_FAILURE",
            _ => "UNKNOWN",
        }
    }
}

/// SSH protocol layer view into a packet buffer.
#[derive(Debug, Clone)]
pub struct SshLayer {
    pub index: LayerIndex,
}

/// Field names for SSH layer.
pub static SSH_FIELDS: &[&str] = &[
    "packet_length",
    "padding_length",
    "message_type",
    "version_string",
];

impl SshLayer {
    /// Check if this SSH data is a version exchange (starts with "SSH-").
    #[must_use]
    pub fn is_version_exchange(&self, buf: &[u8]) -> bool {
        let slice = self.index.slice(buf);
        slice.len() >= 4 && &slice[..4] == b"SSH-"
    }

    /// Extract the version string from a version exchange message.
    ///
    /// Returns the version string without the trailing CRLF.
    #[must_use]
    pub fn version_string<'a>(&self, buf: &'a [u8]) -> Option<&'a str> {
        let slice = self.index.slice(buf);
        if slice.len() < 4 || &slice[..4] != b"SSH-" {
            return None;
        }
        // Find CRLF or end of data
        let end = slice
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(slice.len());
        std::str::from_utf8(&slice[..end]).ok()
    }

    /// Read the `packet_length` field (first 4 bytes of binary packet).
    pub fn packet_length(&self, buf: &[u8]) -> Result<u32, FieldError> {
        let slice = self.index.slice(buf);
        if self.is_version_exchange(buf) {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 4,
                have: 0,
            });
        }
        if slice.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 4,
                have: slice.len(),
            });
        }
        Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    /// Read the `padding_length` field (byte at offset 4 of binary packet).
    pub fn padding_length(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let slice = self.index.slice(buf);
        if self.is_version_exchange(buf) {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 5,
                have: 0,
            });
        }
        if slice.len() < 5 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 5,
                have: slice.len(),
            });
        }
        Ok(slice[4])
    }

    /// Read the message type (first byte of payload, at offset 5).
    pub fn message_type(&self, buf: &[u8]) -> Result<Option<u8>, FieldError> {
        if self.is_version_exchange(buf) {
            return Ok(None);
        }
        let slice = self.index.slice(buf);
        if slice.len() < 6 {
            return Ok(None);
        }
        Ok(Some(slice[5]))
    }

    /// Get the payload data (after `padding_length` byte, before `random_padding`).
    #[must_use]
    pub fn payload_data<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let slice = self.index.slice(buf);
        if self.is_version_exchange(buf) {
            return slice;
        }
        if slice.len() < SSH_BINARY_HEADER_LEN {
            return &[];
        }
        let padding_len = slice[4] as usize;
        let pkt_len = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
        // payload starts at offset 5, ends before random_padding
        let payload_len = pkt_len.saturating_sub(padding_len).saturating_sub(1);
        let payload_end = (5 + payload_len).min(slice.len());
        &slice[5..payload_end]
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "packet_length" => {
                if self.is_version_exchange(buf) {
                    return Some(Ok(FieldValue::U32(0)));
                }
                Some(self.packet_length(buf).map(FieldValue::U32))
            },
            "padding_length" => {
                if self.is_version_exchange(buf) {
                    return Some(Ok(FieldValue::U8(0)));
                }
                Some(self.padding_length(buf).map(FieldValue::U8))
            },
            "message_type" => match self.message_type(buf) {
                Ok(Some(t)) => Some(Ok(FieldValue::U8(t))),
                Ok(None) => Some(Ok(FieldValue::U8(0))),
                Err(e) => Some(Err(e)),
            },
            "version_string" => {
                if let Some(vs) = self.version_string(buf) {
                    Some(Ok(FieldValue::Bytes(vs.as_bytes().to_vec())))
                } else {
                    Some(Ok(FieldValue::Bytes(vec![])))
                }
            },
            _ => None,
        }
    }

    /// Set a field value by name (limited support for SSH).
    pub fn set_field(
        &self,
        _buf: &mut [u8],
        _name: &str,
        _value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        // SSH fields are read-only for now (complex protocol)
        None
    }

    /// Get field names.
    #[must_use]
    pub fn field_names(&self) -> &'static [&'static str] {
        SSH_FIELDS
    }
}

impl Layer for SshLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Ssh
    }

    fn summary(&self, data: &[u8]) -> String {
        let buf = self.index.slice(data);
        if self.is_version_exchange(data) {
            if let Some(vs) = self.version_string(data) {
                return format!("SSH Version Exchange {vs}");
            }
            return "SSH Version Exchange".to_string();
        }
        if buf.len() >= 6 {
            let msg_type = buf[5];
            let name = msg_types::name(msg_type);
            format!("SSH {name}")
        } else {
            "SSH".to_string()
        }
    }

    fn header_len(&self, data: &[u8]) -> usize {
        if self.is_version_exchange(data) {
            return self.index.len();
        }
        let slice = self.index.slice(data);
        if slice.len() >= 4 {
            let pkt_len = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
            // Total SSH binary packet = 4 (packet_length field) + packet_length
            (4 + pkt_len).min(slice.len())
        } else {
            slice.len()
        }
    }

    fn hashret(&self, _data: &[u8]) -> Vec<u8> {
        vec![]
    }

    fn field_names(&self) -> &'static [&'static str] {
        SSH_FIELDS
    }
}

/// Check if a TCP payload looks like SSH traffic.
///
/// Returns true if the data starts with "SSH-" (version exchange)
/// or looks like a valid SSH binary packet.
#[must_use]
pub fn is_ssh_payload(data: &[u8]) -> bool {
    if data.len() >= 4 && &data[..4] == b"SSH-" {
        return true;
    }
    if data.len() >= SSH_BINARY_HEADER_LEN {
        let pkt_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let padding_len = data[4] as usize;
        // Sanity checks for SSH binary packet
        (12..=35000).contains(&pkt_len) && padding_len < pkt_len && padding_len >= 4
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_exchange() {
        let data = b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1\r\n";
        let layer = SshLayer {
            index: LayerIndex::new(LayerKind::Ssh, 0, data.len()),
        };
        assert!(layer.is_version_exchange(data));
        assert_eq!(
            layer.version_string(data),
            Some("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1")
        );
        assert!(layer.summary(data).contains("SSH-2.0-OpenSSH_9.2p1"));
    }

    #[test]
    fn test_binary_packet_kexinit() {
        // Minimal SSH binary packet: KEXINIT (type 20)
        let mut data = vec![0u8; 32];
        // packet_length = 24 (covers padding_length + payload + padding)
        data[0..4].copy_from_slice(&24u32.to_be_bytes());
        data[4] = 8; // padding_length = 8
        data[5] = 20; // message_type = KEXINIT
        // rest is payload + padding

        let layer = SshLayer {
            index: LayerIndex::new(LayerKind::Ssh, 0, data.len()),
        };
        assert!(!layer.is_version_exchange(&data));
        assert_eq!(layer.packet_length(&data).unwrap(), 24);
        assert_eq!(layer.padding_length(&data).unwrap(), 8);
        assert_eq!(layer.message_type(&data).unwrap(), Some(20));
        assert!(layer.summary(&data).contains("KEXINIT"));
    }

    #[test]
    fn test_binary_packet_newkeys() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&12u32.to_be_bytes());
        data[4] = 10; // padding
        data[5] = 21; // NEWKEYS

        let layer = SshLayer {
            index: LayerIndex::new(LayerKind::Ssh, 0, data.len()),
        };
        assert_eq!(layer.message_type(&data).unwrap(), Some(21));
        assert!(layer.summary(&data).contains("NEWKEYS"));
    }

    #[test]
    fn test_is_ssh_payload() {
        assert!(is_ssh_payload(b"SSH-2.0-OpenSSH\r\n"));
        assert!(!is_ssh_payload(b"HTTP/1.1"));
        assert!(!is_ssh_payload(b"SH"));
    }
}
