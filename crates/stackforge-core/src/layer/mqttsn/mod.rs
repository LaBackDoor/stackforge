//! MQTT-SN (MQTT for Sensor Networks) layer implementation.
//!
//! Implements MQTT-SN v1.2 packet parsing as a zero-copy view into a packet buffer.
//!
//! ## Header Format
//!
//! MQTT-SN uses a variable-length header:
//!
//! ```text
//! Short form (length 2..=255):
//!   Byte 0:    Length (1 byte)
//!   Byte 1:    Message Type (1 byte)
//!   Byte 2+:   Message body (variable)
//!
//! Extended form (length 256..=65535):
//!   Byte 0:    0x01 (marker)
//!   Byte 1-2:  Length (2 bytes, big-endian)
//!   Byte 3:    Message Type (1 byte)
//!   Byte 4+:   Message body (variable)
//! ```
//!
//! ## Flags Byte (used in CONNECT, PUBLISH, SUBSCRIBE, etc.)
//!
//! ```text
//! Bit:     7     6-5    4      3     2         1-0
//! Field:   DUP   QoS    RETAIN WILL  CleanSess TID_TYPE
//! ```
//!
//! ## Message Types
//!
//! | Value | Name            |
//! |-------|-----------------|
//! | 0x00  | ADVERTISE       |
//! | 0x01  | SEARCHGW        |
//! | 0x02  | GWINFO          |
//! | 0x04  | CONNECT         |
//! | 0x05  | CONNACK         |
//! | 0x06  | WILLTOPICREQ    |
//! | 0x07  | WILLTOPIC       |
//! | 0x08  | WILLMSGREQ      |
//! | 0x09  | WILLMSG         |
//! | 0x0A  | REGISTER        |
//! | 0x0B  | REGACK          |
//! | 0x0C  | PUBLISH         |
//! | 0x0D  | PUBACK          |
//! | 0x0E  | PUBCOMP         |
//! | 0x0F  | PUBREC          |
//! | 0x10  | PUBREL          |
//! | 0x12  | SUBSCRIBE       |
//! | 0x13  | SUBACK          |
//! | 0x14  | UNSUBSCRIBE     |
//! | 0x15  | UNSUBACK        |
//! | 0x16  | PINGREQ         |
//! | 0x17  | PINGRESP        |
//! | 0x18  | DISCONNECT      |
//! | 0x1A  | WILLTOPICUPD    |
//! | 0x1B  | WILLTOPICRESP   |
//! | 0x1C  | WILLMSGUPD      |
//! | 0x1D  | WILLMSGRESP     |
//! | 0xFE  | ENCAPS_MSG      |

pub mod builder;

pub use builder::MqttSnBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

// ============================================================================
// Constants
// ============================================================================

/// Minimum MQTT-SN header: 1 byte length + 1 byte type.
pub const MQTTSN_MIN_HEADER_LEN: usize = 2;

/// Default MQTT-SN UDP port.
pub const MQTTSN_PORT: u16 = 1883;

// Message type constants
pub const ADVERTISE: u8 = 0x00;
pub const SEARCHGW: u8 = 0x01;
pub const GWINFO: u8 = 0x02;
pub const CONNECT: u8 = 0x04;
pub const CONNACK: u8 = 0x05;
pub const WILLTOPICREQ: u8 = 0x06;
pub const WILLTOPIC: u8 = 0x07;
pub const WILLMSGREQ: u8 = 0x08;
pub const WILLMSG: u8 = 0x09;
pub const REGISTER: u8 = 0x0A;
pub const REGACK: u8 = 0x0B;
pub const PUBLISH: u8 = 0x0C;
pub const PUBACK: u8 = 0x0D;
pub const PUBCOMP: u8 = 0x0E;
pub const PUBREC: u8 = 0x0F;
pub const PUBREL: u8 = 0x10;
pub const SUBSCRIBE: u8 = 0x12;
pub const SUBACK: u8 = 0x13;
pub const UNSUBSCRIBE: u8 = 0x14;
pub const UNSUBACK: u8 = 0x15;
pub const PINGREQ: u8 = 0x16;
pub const PINGRESP: u8 = 0x17;
pub const DISCONNECT: u8 = 0x18;
pub const WILLTOPICUPD: u8 = 0x1A;
pub const WILLTOPICRESP: u8 = 0x1B;
pub const WILLMSGUPD: u8 = 0x1C;
pub const WILLMSGRESP: u8 = 0x1D;
pub const ENCAPS_MSG: u8 = 0xFE;

// Return codes
pub const RC_ACCEPTED: u8 = 0x00;
pub const RC_REJ_CONGESTION: u8 = 0x01;
pub const RC_REJ_INVALID_TID: u8 = 0x02;
pub const RC_REJ_NOT_SUPPORTED: u8 = 0x03;

// Topic ID types
pub const TID_NORMAL: u8 = 0b00;
pub const TID_PREDEF: u8 = 0b01;
pub const TID_SHORT: u8 = 0b10;

/// Field names for the MQTT-SN layer.
pub static MQTTSN_FIELD_NAMES: &[&str] = &[
    "length",
    "type",
    "flags",
    "dup",
    "qos",
    "retain",
    "will",
    "cleansess",
    "tid_type",
    "gw_id",
    "duration",
    "radius",
    "gw_addr",
    "prot_id",
    "client_id",
    "return_code",
    "tid",
    "mid",
    "data",
    "topic_name",
    "will_topic",
    "will_msg",
];

// ============================================================================
// Helper functions
// ============================================================================

/// Decode the MQTT-SN variable length field.
///
/// Returns `(header_size, packet_length)` where `header_size` is the number of
/// bytes consumed by the length field itself (1 or 3 bytes).
///
/// - If byte 0 != 0x01: short form, length = byte 0, `header_size` = 1
/// - If byte 0 == 0x01: extended form, length = u16(byte1, byte2), `header_size` = 3
pub fn decode_mqttsn_length(buf: &[u8]) -> Result<(usize, u16), FieldError> {
    if buf.is_empty() {
        return Err(FieldError::BufferTooShort {
            offset: 0,
            need: 1,
            have: 0,
        });
    }
    if buf[0] == 0x01 {
        // Extended length form
        if buf.len() < 3 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 3,
                have: buf.len(),
            });
        }
        let len = u16::from_be_bytes([buf[1], buf[2]]);
        Ok((3, len))
    } else {
        Ok((1, u16::from(buf[0])))
    }
}

/// Check if a UDP payload looks like an MQTT-SN packet.
///
/// Validates that:
/// 1. Buffer has at least 2 bytes
/// 2. The length field is valid (>= 2, <= buffer length)
/// 3. The message type is a known MQTT-SN type
#[must_use]
pub fn is_mqttsn_payload(buf: &[u8]) -> bool {
    if buf.len() < MQTTSN_MIN_HEADER_LEN {
        return false;
    }
    let (len_hdr_size, pkt_len) = match decode_mqttsn_length(buf) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // Packet length must be at least header_size + 1 (for type byte)
    if (pkt_len as usize) < len_hdr_size + 1 {
        return false;
    }
    // Packet length should not exceed buffer
    if (pkt_len as usize) > buf.len() {
        return false;
    }
    let msg_type = buf[len_hdr_size];
    is_known_message_type(msg_type)
}

/// Returns true if the given byte is a known MQTT-SN message type.
fn is_known_message_type(t: u8) -> bool {
    matches!(
        t,
        ADVERTISE
            | SEARCHGW
            | GWINFO
            | CONNECT
            | CONNACK
            | WILLTOPICREQ
            | WILLTOPIC
            | WILLMSGREQ
            | WILLMSG
            | REGISTER
            | REGACK
            | PUBLISH
            | PUBACK
            | PUBCOMP
            | PUBREC
            | PUBREL
            | SUBSCRIBE
            | SUBACK
            | UNSUBSCRIBE
            | UNSUBACK
            | PINGREQ
            | PINGRESP
            | DISCONNECT
            | WILLTOPICUPD
            | WILLTOPICRESP
            | WILLMSGUPD
            | WILLMSGRESP
            | ENCAPS_MSG
    )
}

/// Get the human-readable name for a message type.
#[must_use]
pub fn message_type_name(t: u8) -> &'static str {
    match t {
        ADVERTISE => "ADVERTISE",
        SEARCHGW => "SEARCHGW",
        GWINFO => "GWINFO",
        CONNECT => "CONNECT",
        CONNACK => "CONNACK",
        WILLTOPICREQ => "WILLTOPICREQ",
        WILLTOPIC => "WILLTOPIC",
        WILLMSGREQ => "WILLMSGREQ",
        WILLMSG => "WILLMSG",
        REGISTER => "REGISTER",
        REGACK => "REGACK",
        PUBLISH => "PUBLISH",
        PUBACK => "PUBACK",
        PUBCOMP => "PUBCOMP",
        PUBREC => "PUBREC",
        PUBREL => "PUBREL",
        SUBSCRIBE => "SUBSCRIBE",
        SUBACK => "SUBACK",
        UNSUBSCRIBE => "UNSUBSCRIBE",
        UNSUBACK => "UNSUBACK",
        PINGREQ => "PINGREQ",
        PINGRESP => "PINGRESP",
        DISCONNECT => "DISCONNECT",
        WILLTOPICUPD => "WILLTOPICUPD",
        WILLTOPICRESP => "WILLTOPICRESP",
        WILLMSGUPD => "WILLMSGUPD",
        WILLMSGRESP => "WILLMSGRESP",
        ENCAPS_MSG => "ENCAPS_MSG",
        _ => "UNKNOWN",
    }
}

/// Get the human-readable name for a return code.
#[must_use]
pub fn return_code_name(rc: u8) -> &'static str {
    match rc {
        RC_ACCEPTED => "Accepted",
        RC_REJ_CONGESTION => "Rejected: congestion",
        RC_REJ_INVALID_TID => "Rejected: invalid topic ID",
        RC_REJ_NOT_SUPPORTED => "Rejected: not supported",
        _ => "Unknown",
    }
}

// ============================================================================
// MqttSnLayer
// ============================================================================

/// MQTT-SN layer -- a zero-copy view into a packet buffer.
#[derive(Debug, Clone)]
pub struct MqttSnLayer {
    pub index: LayerIndex,
}

impl MqttSnLayer {
    /// Create a new MQTT-SN layer from a layer index.
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Get a slice of the buffer corresponding to this layer.
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    /// Get the length header size (1 or 3 bytes) and the total packet length.
    fn length_info(&self, buf: &[u8]) -> Result<(usize, u16), FieldError> {
        let s = self.slice(buf);
        decode_mqttsn_length(s)
    }

    /// Offset of the message type byte within the layer slice.
    fn type_offset(&self, buf: &[u8]) -> Result<usize, FieldError> {
        let (len_hdr_size, _) = self.length_info(buf)?;
        Ok(len_hdr_size)
    }

    /// Offset of the body (after the type byte) within the layer slice.
    fn body_offset(&self, buf: &[u8]) -> Result<usize, FieldError> {
        Ok(self.type_offset(buf)? + 1)
    }

    // ========================================================================
    // Core field accessors
    // ========================================================================

    /// Get the total packet length (as encoded in the length field).
    pub fn packet_length(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let (_, len) = self.length_info(buf)?;
        Ok(len)
    }

    /// Get the message type byte.
    pub fn msg_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        let off = self.type_offset(buf)?;
        if s.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 1,
                have: 0,
            });
        }
        Ok(s[off])
    }

    // ========================================================================
    // Flags byte accessors
    // ========================================================================

    /// Returns true if this message type has a flags byte.
    fn has_flags(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let mt = self.msg_type(buf)?;
        Ok(matches!(
            mt,
            CONNECT | WILLTOPIC | PUBLISH | SUBSCRIBE | SUBACK | UNSUBSCRIBE | WILLTOPICUPD
        ))
    }

    /// Get the raw flags byte. Returns an error if this message type has no flags.
    pub fn flags(&self, buf: &[u8]) -> Result<u8, FieldError> {
        if !self.has_flags(buf)? {
            return Err(FieldError::InvalidValue(format!(
                "message type {} has no flags byte",
                self.msg_type(buf)?
            )));
        }
        let s = self.slice(buf);
        let off = self.body_offset(buf)?;
        if s.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 1,
                have: 0,
            });
        }
        Ok(s[off])
    }

    /// Get the DUP flag (bit 7 of flags byte).
    pub fn dup(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok((self.flags(buf)? >> 7) & 1 == 1)
    }

    /// Get the `QoS` level (bits 6-5 of flags byte).
    pub fn qos(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok((self.flags(buf)? >> 5) & 0x03)
    }

    /// Get the RETAIN flag (bit 4 of flags byte).
    pub fn retain(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok((self.flags(buf)? >> 4) & 1 == 1)
    }

    /// Get the WILL flag (bit 3 of flags byte).
    pub fn will(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok((self.flags(buf)? >> 3) & 1 == 1)
    }

    /// Get the `CleanSession` flag (bit 2 of flags byte).
    pub fn cleansess(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok((self.flags(buf)? >> 2) & 1 == 1)
    }

    /// Get the topic ID type (bits 1-0 of flags byte).
    pub fn tid_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok(self.flags(buf)? & 0x03)
    }

    // ========================================================================
    // Message-specific field accessors
    // ========================================================================

    /// Get gateway ID (ADVERTISE, GWINFO).
    pub fn gw_id(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let mt = self.msg_type(buf)?;
        if mt != ADVERTISE && mt != GWINFO {
            return Err(FieldError::InvalidValue(format!(
                "gw_id not available for type {}",
                message_type_name(mt)
            )));
        }
        let s = self.slice(buf);
        let off = self.body_offset(buf)?;
        if s.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 1,
                have: 0,
            });
        }
        Ok(s[off])
    }

    /// Get duration field (ADVERTISE: offset body+1, CONNECT: offset `body+flags+prot_id`,
    /// DISCONNECT: offset body+0 (optional)).
    pub fn duration(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let mt = self.msg_type(buf)?;
        let s = self.slice(buf);
        let body = self.body_offset(buf)?;
        let off = match mt {
            ADVERTISE => body + 1,   // after gw_id
            CONNECT => body + 1 + 1, // after flags + prot_id
            DISCONNECT => body,      // optional, right at body start
            _ => {
                return Err(FieldError::InvalidValue(format!(
                    "duration not available for type {}",
                    message_type_name(mt)
                )));
            },
        };
        if s.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 2,
                have: s.len().saturating_sub(off),
            });
        }
        Ok(u16::from_be_bytes([s[off], s[off + 1]]))
    }

    /// Get radius (SEARCHGW).
    pub fn radius(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let mt = self.msg_type(buf)?;
        if mt != SEARCHGW {
            return Err(FieldError::InvalidValue(format!(
                "radius not available for type {}",
                message_type_name(mt)
            )));
        }
        let s = self.slice(buf);
        let off = self.body_offset(buf)?;
        if s.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 1,
                have: 0,
            });
        }
        Ok(s[off])
    }

    /// Get gateway address bytes (GWINFO, after `gw_id`).
    pub fn gw_addr<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8], FieldError> {
        let mt = self.msg_type(buf)?;
        if mt != GWINFO {
            return Err(FieldError::InvalidValue(format!(
                "gw_addr not available for type {}",
                message_type_name(mt)
            )));
        }
        let s = self.slice(buf);
        let (_, pkt_len) = self.length_info(buf)?;
        let off = self.body_offset(buf)? + 1; // after gw_id
        let end = (pkt_len as usize).min(s.len());
        if off > end {
            return Ok(&[]);
        }
        Ok(&s[off..end])
    }

    /// Get protocol ID (CONNECT, after flags byte).
    pub fn prot_id(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let mt = self.msg_type(buf)?;
        if mt != CONNECT {
            return Err(FieldError::InvalidValue(format!(
                "prot_id not available for type {}",
                message_type_name(mt)
            )));
        }
        let s = self.slice(buf);
        let off = self.body_offset(buf)? + 1; // after flags
        if s.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 1,
                have: 0,
            });
        }
        Ok(s[off])
    }

    /// Get client ID string (CONNECT, PINGREQ).
    pub fn client_id<'a>(&self, buf: &'a [u8]) -> Result<&'a str, FieldError> {
        let mt = self.msg_type(buf)?;
        let s = self.slice(buf);
        let (_, pkt_len) = self.length_info(buf)?;
        let body = self.body_offset(buf)?;
        let off = match mt {
            CONNECT => body + 1 + 1 + 2, // after flags + prot_id + duration
            PINGREQ => body,             // client_id is the entire body
            _ => {
                return Err(FieldError::InvalidValue(format!(
                    "client_id not available for type {}",
                    message_type_name(mt)
                )));
            },
        };
        let end = (pkt_len as usize).min(s.len());
        if off > end {
            return Ok("");
        }
        std::str::from_utf8(&s[off..end]).map_err(|e| FieldError::InvalidValue(e.to_string()))
    }

    /// Get return code (CONNACK, REGACK, PUBACK, SUBACK, WILLTOPICRESP, WILLMSGRESP).
    pub fn return_code(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let mt = self.msg_type(buf)?;
        let s = self.slice(buf);
        let body = self.body_offset(buf)?;
        let off = match mt {
            CONNACK | WILLTOPICRESP | WILLMSGRESP => body,
            REGACK | PUBACK => body + 4, // after tid(2) + mid(2)
            SUBACK => body + 1 + 2 + 2,  // after flags(1) + tid(2) + mid(2)
            _ => {
                return Err(FieldError::InvalidValue(format!(
                    "return_code not available for type {}",
                    message_type_name(mt)
                )));
            },
        };
        if s.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 1,
                have: 0,
            });
        }
        Ok(s[off])
    }

    /// Get topic ID (REGISTER, REGACK, PUBLISH, PUBACK, SUBSCRIBE/UNSUBSCRIBE, SUBACK).
    pub fn tid(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let mt = self.msg_type(buf)?;
        let s = self.slice(buf);
        let body = self.body_offset(buf)?;
        let off = match mt {
            REGISTER | REGACK | PUBACK => body,      // tid is first in body
            PUBLISH => body + 1,                     // after flags
            SUBSCRIBE | UNSUBSCRIBE => body + 1 + 2, // after flags + mid
            SUBACK => body + 1,                      // after flags
            _ => {
                return Err(FieldError::InvalidValue(format!(
                    "tid not available for type {}",
                    message_type_name(mt)
                )));
            },
        };
        if s.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 2,
                have: s.len().saturating_sub(off),
            });
        }
        Ok(u16::from_be_bytes([s[off], s[off + 1]]))
    }

    /// Get message ID (REGISTER, REGACK, PUBLISH, PUBACK, PUBCOMP, PUBREC, PUBREL,
    /// SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK).
    pub fn mid(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let mt = self.msg_type(buf)?;
        let s = self.slice(buf);
        let body = self.body_offset(buf)?;
        let off = match mt {
            REGISTER | REGACK | PUBACK => body + 2,       // after tid
            PUBLISH => body + 1 + 2,                      // after flags + tid
            PUBCOMP | PUBREC | PUBREL | UNSUBACK => body, // mid is first
            SUBSCRIBE | UNSUBSCRIBE => body + 1,          // after flags
            SUBACK => body + 1 + 2,                       // after flags + tid
            _ => {
                return Err(FieldError::InvalidValue(format!(
                    "mid not available for type {}",
                    message_type_name(mt)
                )));
            },
        };
        if s.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 2,
                have: s.len().saturating_sub(off),
            });
        }
        Ok(u16::from_be_bytes([s[off], s[off + 1]]))
    }

    /// Get publish data payload (PUBLISH, after flags+tid+mid).
    pub fn data<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8], FieldError> {
        let mt = self.msg_type(buf)?;
        if mt != PUBLISH {
            return Err(FieldError::InvalidValue(format!(
                "data not available for type {}",
                message_type_name(mt)
            )));
        }
        let s = self.slice(buf);
        let (_, pkt_len) = self.length_info(buf)?;
        let off = self.body_offset(buf)? + 1 + 2 + 2; // flags + tid + mid
        let end = (pkt_len as usize).min(s.len());
        if off > end {
            return Ok(&[]);
        }
        Ok(&s[off..end])
    }

    /// Get topic name (REGISTER, SUBSCRIBE/UNSUBSCRIBE with `TID_NORMAL`).
    pub fn topic_name<'a>(&self, buf: &'a [u8]) -> Result<&'a str, FieldError> {
        let mt = self.msg_type(buf)?;
        let s = self.slice(buf);
        let (_, pkt_len) = self.length_info(buf)?;
        let body = self.body_offset(buf)?;
        let off = match mt {
            REGISTER => body + 2 + 2,                    // after tid + mid
            SUBSCRIBE | UNSUBSCRIBE => body + 1 + 2 + 2, // after flags + mid + tid
            _ => {
                return Err(FieldError::InvalidValue(format!(
                    "topic_name not available for type {}",
                    message_type_name(mt)
                )));
            },
        };
        let end = (pkt_len as usize).min(s.len());
        if off > end {
            return Ok("");
        }
        std::str::from_utf8(&s[off..end]).map_err(|e| FieldError::InvalidValue(e.to_string()))
    }

    /// Get will topic (WILLTOPIC, WILLTOPICUPD).
    pub fn will_topic<'a>(&self, buf: &'a [u8]) -> Result<&'a str, FieldError> {
        let mt = self.msg_type(buf)?;
        if mt != WILLTOPIC && mt != WILLTOPICUPD {
            return Err(FieldError::InvalidValue(format!(
                "will_topic not available for type {}",
                message_type_name(mt)
            )));
        }
        let s = self.slice(buf);
        let (_, pkt_len) = self.length_info(buf)?;
        let off = self.body_offset(buf)? + 1; // after flags
        let end = (pkt_len as usize).min(s.len());
        if off > end {
            return Ok("");
        }
        std::str::from_utf8(&s[off..end]).map_err(|e| FieldError::InvalidValue(e.to_string()))
    }

    /// Get will message (WILLMSG, WILLMSGUPD).
    pub fn will_msg<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8], FieldError> {
        let mt = self.msg_type(buf)?;
        if mt != WILLMSG && mt != WILLMSGUPD {
            return Err(FieldError::InvalidValue(format!(
                "will_msg not available for type {}",
                message_type_name(mt)
            )));
        }
        let s = self.slice(buf);
        let (_, pkt_len) = self.length_info(buf)?;
        let off = self.body_offset(buf)?;
        let end = (pkt_len as usize).min(s.len());
        if off > end {
            return Ok(&[]);
        }
        Ok(&s[off..end])
    }

    // ========================================================================
    // Set field helpers
    // ========================================================================

    /// Set the message type byte in the buffer.
    pub fn set_msg_type(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + self.type_offset(buf)?;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: 0,
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Set the flags byte in the buffer.
    pub fn set_flags(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        if !self.has_flags(buf)? {
            return Err(FieldError::InvalidValue(
                "this message type has no flags byte".into(),
            ));
        }
        let off = self.index.start + self.body_offset(buf)?;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: 0,
            });
        }
        buf[off] = value;
        Ok(())
    }

    // ========================================================================
    // Compute header length
    // ========================================================================

    /// Compute the header length for this MQTT-SN packet.
    fn compute_header_len(&self, buf: &[u8]) -> usize {
        let s = self.slice(buf);
        match decode_mqttsn_length(s) {
            Ok((_, pkt_len)) => (pkt_len as usize).min(s.len()),
            Err(_) => s.len(),
        }
    }

    // ========================================================================
    // Summary
    // ========================================================================

    /// Generate a one-line summary of this MQTT-SN layer.
    fn make_summary(&self, buf: &[u8]) -> String {
        let mt = self.msg_type(buf).unwrap_or(0xFF);
        let name = message_type_name(mt);
        match mt {
            PUBLISH => {
                let tid = self.tid(buf).map_or_else(|_| "?".into(), |v| v.to_string());
                format!("MQTT-SN {name} tid={tid}")
            },
            CONNECT => {
                let cid = self.client_id(buf).unwrap_or("?");
                format!("MQTT-SN {name} client_id={cid}")
            },
            CONNACK | WILLTOPICRESP | WILLMSGRESP => {
                let rc = self.return_code(buf).unwrap_or(0xFF);
                format!("MQTT-SN {} rc={} ({})", name, rc, return_code_name(rc))
            },
            _ => format!("MQTT-SN {name}"),
        }
    }

    // ========================================================================
    // Field access API
    // ========================================================================

    /// Get the field names for this layer.
    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        MQTTSN_FIELD_NAMES
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "length" => Some(self.packet_length(buf).map(FieldValue::U16)),
            "type" => Some(self.msg_type(buf).map(FieldValue::U8)),
            "flags" => Some(self.flags(buf).map(FieldValue::U8)),
            "dup" => Some(self.dup(buf).map(FieldValue::Bool)),
            "qos" => Some(self.qos(buf).map(FieldValue::U8)),
            "retain" => Some(self.retain(buf).map(FieldValue::Bool)),
            "will" => Some(self.will(buf).map(FieldValue::Bool)),
            "cleansess" => Some(self.cleansess(buf).map(FieldValue::Bool)),
            "tid_type" => Some(self.tid_type(buf).map(FieldValue::U8)),
            "gw_id" => Some(self.gw_id(buf).map(FieldValue::U8)),
            "duration" => Some(self.duration(buf).map(FieldValue::U16)),
            "radius" => Some(self.radius(buf).map(FieldValue::U8)),
            "prot_id" => Some(self.prot_id(buf).map(FieldValue::U8)),
            "return_code" => Some(self.return_code(buf).map(FieldValue::U8)),
            "tid" => Some(self.tid(buf).map(FieldValue::U16)),
            "mid" => Some(self.mid(buf).map(FieldValue::U16)),
            "client_id" => Some(self.client_id(buf).map(|s| FieldValue::Str(s.to_string()))),
            "topic_name" => Some(self.topic_name(buf).map(|s| FieldValue::Str(s.to_string()))),
            "will_topic" => Some(self.will_topic(buf).map(|s| FieldValue::Str(s.to_string()))),
            "data" => Some(self.data(buf).map(|d| FieldValue::Bytes(d.to_vec()))),
            "will_msg" => Some(self.will_msg(buf).map(|d| FieldValue::Bytes(d.to_vec()))),
            "gw_addr" => Some(self.gw_addr(buf).map(|d| FieldValue::Bytes(d.to_vec()))),
            _ => None,
        }
    }

    /// Set a field value by name.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match name {
            "type" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_msg_type(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "type: expected U8, got {value:?}"
                    ))))
                }
            },
            "flags" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_flags(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "flags: expected U8, got {value:?}"
                    ))))
                }
            },
            _ => None,
        }
    }
}

impl Layer for MqttSnLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::MqttSn
    }

    fn summary(&self, data: &[u8]) -> String {
        self.make_summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.compute_header_len(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        MQTTSN_FIELD_NAMES
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a short-form MQTT-SN packet from raw body bytes.
    fn make_packet(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let total = 2 + body.len(); // 1 byte length + 1 byte type + body
        assert!(total <= 255, "use make_extended_packet for >255 bytes");
        let mut buf = Vec::with_capacity(total);
        buf.push(total as u8);
        buf.push(msg_type);
        buf.extend_from_slice(body);
        buf
    }

    /// Helper: create MqttSnLayer from buffer covering entire buffer.
    fn layer_from(buf: &[u8]) -> MqttSnLayer {
        MqttSnLayer::new(LayerIndex::new(LayerKind::MqttSn, 0, buf.len()))
    }

    #[test]
    fn test_decode_length_short() {
        let buf = [0x05, 0x04]; // length=5
        let (hdr_size, len) = decode_mqttsn_length(&buf).unwrap();
        assert_eq!(hdr_size, 1);
        assert_eq!(len, 5);
    }

    #[test]
    fn test_decode_length_extended() {
        let buf = [0x01, 0x01, 0x00]; // length=256
        let (hdr_size, len) = decode_mqttsn_length(&buf).unwrap();
        assert_eq!(hdr_size, 3);
        assert_eq!(len, 256);
    }

    #[test]
    fn test_decode_length_empty() {
        let buf: [u8; 0] = [];
        assert!(decode_mqttsn_length(&buf).is_err());
    }

    #[test]
    fn test_decode_length_extended_too_short() {
        let buf = [0x01, 0x01]; // missing second length byte
        assert!(decode_mqttsn_length(&buf).is_err());
    }

    #[test]
    fn test_is_mqttsn_payload_valid_searchgw() {
        let pkt = make_packet(SEARCHGW, &[0x00]);
        assert!(is_mqttsn_payload(&pkt));
    }

    #[test]
    fn test_is_mqttsn_payload_too_short() {
        let buf = [0x01];
        assert!(!is_mqttsn_payload(&buf));
    }

    #[test]
    fn test_is_mqttsn_payload_unknown_type() {
        let buf = [0x02, 0xFF]; // length=2, type=0xFF (unknown)
        assert!(!is_mqttsn_payload(&buf));
    }

    #[test]
    fn test_message_type_name_values() {
        assert_eq!(message_type_name(CONNECT), "CONNECT");
        assert_eq!(message_type_name(PUBLISH), "PUBLISH");
        assert_eq!(message_type_name(PINGREQ), "PINGREQ");
        assert_eq!(message_type_name(0xFF), "UNKNOWN");
    }

    #[test]
    fn test_return_code_name_values() {
        assert_eq!(return_code_name(RC_ACCEPTED), "Accepted");
        assert_eq!(return_code_name(RC_REJ_CONGESTION), "Rejected: congestion");
        assert_eq!(return_code_name(0xFF), "Unknown");
    }

    #[test]
    fn test_advertise() {
        let pkt = make_packet(ADVERTISE, &[0x01, 0x00, 0x3C]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), ADVERTISE);
        assert_eq!(l.gw_id(&pkt).unwrap(), 1);
        assert_eq!(l.duration(&pkt).unwrap(), 60);
        assert_eq!(l.packet_length(&pkt).unwrap(), 5);
    }

    #[test]
    fn test_searchgw() {
        let pkt = make_packet(SEARCHGW, &[0x03]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), SEARCHGW);
        assert_eq!(l.radius(&pkt).unwrap(), 3);
    }

    #[test]
    fn test_gwinfo() {
        let pkt = make_packet(GWINFO, &[0x01, 0xC0, 0xA8, 0x01, 0x01]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), GWINFO);
        assert_eq!(l.gw_id(&pkt).unwrap(), 1);
        assert_eq!(l.gw_addr(&pkt).unwrap(), &[0xC0, 0xA8, 0x01, 0x01]);
    }

    #[test]
    fn test_connect() {
        let pkt = make_packet(CONNECT, &[0x0C, 0x01, 0x00, 0x3C, b't', b'e', b's', b't']);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), CONNECT);
        assert_eq!(l.flags(&pkt).unwrap(), 0x0C);
        assert!(l.will(&pkt).unwrap());
        assert!(l.cleansess(&pkt).unwrap());
        assert!(!l.dup(&pkt).unwrap());
        assert_eq!(l.qos(&pkt).unwrap(), 0);
        assert!(!l.retain(&pkt).unwrap());
        assert_eq!(l.tid_type(&pkt).unwrap(), 0);
        assert_eq!(l.prot_id(&pkt).unwrap(), 1);
        assert_eq!(l.duration(&pkt).unwrap(), 60);
        assert_eq!(l.client_id(&pkt).unwrap(), "test");
    }

    #[test]
    fn test_connack() {
        let pkt = make_packet(CONNACK, &[RC_ACCEPTED]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), CONNACK);
        assert_eq!(l.return_code(&pkt).unwrap(), RC_ACCEPTED);
    }

    #[test]
    fn test_register() {
        let pkt = make_packet(REGISTER, &[0x00, 0x01, 0x00, 0x02, b'a', b'/', b'b']);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), REGISTER);
        assert_eq!(l.tid(&pkt).unwrap(), 1);
        assert_eq!(l.mid(&pkt).unwrap(), 2);
        assert_eq!(l.topic_name(&pkt).unwrap(), "a/b");
    }

    #[test]
    fn test_regack() {
        let pkt = make_packet(REGACK, &[0x00, 0x05, 0x00, 0x03, RC_ACCEPTED]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), REGACK);
        assert_eq!(l.tid(&pkt).unwrap(), 5);
        assert_eq!(l.mid(&pkt).unwrap(), 3);
        assert_eq!(l.return_code(&pkt).unwrap(), RC_ACCEPTED);
    }

    #[test]
    fn test_publish() {
        let pkt = make_packet(PUBLISH, &[0x20, 0x00, 0x01, 0x00, 0x02, b'h', b'i']);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), PUBLISH);
        assert_eq!(l.qos(&pkt).unwrap(), 1);
        assert_eq!(l.tid(&pkt).unwrap(), 1);
        assert_eq!(l.mid(&pkt).unwrap(), 2);
        assert_eq!(l.data(&pkt).unwrap(), b"hi");
    }

    #[test]
    fn test_puback() {
        let pkt = make_packet(PUBACK, &[0x00, 0x01, 0x00, 0x02, RC_ACCEPTED]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), PUBACK);
        assert_eq!(l.tid(&pkt).unwrap(), 1);
        assert_eq!(l.mid(&pkt).unwrap(), 2);
        assert_eq!(l.return_code(&pkt).unwrap(), RC_ACCEPTED);
    }

    #[test]
    fn test_pubcomp() {
        let pkt = make_packet(PUBCOMP, &[0x00, 0x07]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), PUBCOMP);
        assert_eq!(l.mid(&pkt).unwrap(), 7);
    }

    #[test]
    fn test_suback() {
        let pkt = make_packet(SUBACK, &[0x00, 0x00, 0x01, 0x00, 0x02, RC_ACCEPTED]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), SUBACK);
        assert_eq!(l.tid(&pkt).unwrap(), 1);
        assert_eq!(l.mid(&pkt).unwrap(), 2);
        assert_eq!(l.return_code(&pkt).unwrap(), RC_ACCEPTED);
    }

    #[test]
    fn test_unsuback() {
        let pkt = make_packet(UNSUBACK, &[0x00, 0x05]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), UNSUBACK);
        assert_eq!(l.mid(&pkt).unwrap(), 5);
    }

    #[test]
    fn test_pingreq_empty() {
        let pkt = make_packet(PINGREQ, &[]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), PINGREQ);
        assert_eq!(l.client_id(&pkt).unwrap(), "");
    }

    #[test]
    fn test_pingreq_with_client_id() {
        let pkt = make_packet(PINGREQ, b"sensor1");
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), PINGREQ);
        assert_eq!(l.client_id(&pkt).unwrap(), "sensor1");
    }

    #[test]
    fn test_pingresp() {
        let pkt = make_packet(PINGRESP, &[]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), PINGRESP);
    }

    #[test]
    fn test_disconnect_empty() {
        let pkt = make_packet(DISCONNECT, &[]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), DISCONNECT);
    }

    #[test]
    fn test_disconnect_with_duration() {
        let pkt = make_packet(DISCONNECT, &[0x00, 0x3C]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), DISCONNECT);
        assert_eq!(l.duration(&pkt).unwrap(), 60);
    }

    #[test]
    fn test_willtopic() {
        let pkt = make_packet(WILLTOPIC, &[0x00, b'w', b'/', b't']);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), WILLTOPIC);
        assert_eq!(l.will_topic(&pkt).unwrap(), "w/t");
    }

    #[test]
    fn test_willmsg() {
        let pkt = make_packet(WILLMSG, &[b'b', b'y', b'e']);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), WILLMSG);
        assert_eq!(l.will_msg(&pkt).unwrap(), b"bye");
    }

    #[test]
    fn test_willtopicresp() {
        let pkt = make_packet(WILLTOPICRESP, &[RC_ACCEPTED]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), WILLTOPICRESP);
        assert_eq!(l.return_code(&pkt).unwrap(), RC_ACCEPTED);
    }

    #[test]
    fn test_willmsgresp() {
        let pkt = make_packet(WILLMSGRESP, &[RC_REJ_NOT_SUPPORTED]);
        let l = layer_from(&pkt);
        assert_eq!(l.msg_type(&pkt).unwrap(), WILLMSGRESP);
        assert_eq!(l.return_code(&pkt).unwrap(), RC_REJ_NOT_SUPPORTED);
    }

    #[test]
    fn test_flags_all_bits() {
        let pkt = make_packet(CONNECT, &[0xFF, 0x01, 0x00, 0x3C]);
        let l = layer_from(&pkt);
        assert!(l.dup(&pkt).unwrap());
        assert_eq!(l.qos(&pkt).unwrap(), 3);
        assert!(l.retain(&pkt).unwrap());
        assert!(l.will(&pkt).unwrap());
        assert!(l.cleansess(&pkt).unwrap());
        assert_eq!(l.tid_type(&pkt).unwrap(), 0x03);
    }

    #[test]
    fn test_get_field_type() {
        let pkt = make_packet(CONNECT, &[0x04, 0x01, 0x00, 0x3C, b'x']);
        let l = layer_from(&pkt);
        match l.get_field(&pkt, "type") {
            Some(Ok(FieldValue::U8(v))) => assert_eq!(v, CONNECT),
            other => panic!("expected Some(Ok(U8(CONNECT))), got {:?}", other),
        }
    }

    #[test]
    fn test_get_field_unknown() {
        let pkt = make_packet(PINGRESP, &[]);
        let l = layer_from(&pkt);
        assert!(l.get_field(&pkt, "nonexistent").is_none());
    }

    #[test]
    fn test_set_msg_type() {
        let mut pkt = make_packet(PINGREQ, &[]);
        let l = layer_from(&pkt);
        l.set_msg_type(&mut pkt, PINGRESP).unwrap();
        assert_eq!(l.msg_type(&pkt).unwrap(), PINGRESP);
    }

    #[test]
    fn test_set_flags() {
        let mut pkt = make_packet(CONNECT, &[0x00, 0x01, 0x00, 0x3C]);
        let l = layer_from(&pkt);
        l.set_flags(&mut pkt, 0x0C).unwrap();
        assert!(l.will(&pkt).unwrap());
        assert!(l.cleansess(&pkt).unwrap());
    }

    #[test]
    fn test_set_flags_no_flags_msg() {
        let mut pkt = make_packet(PINGRESP, &[]);
        let l = layer_from(&pkt);
        assert!(l.set_flags(&mut pkt, 0x00).is_err());
    }

    #[test]
    fn test_summary_publish() {
        let pkt = make_packet(PUBLISH, &[0x00, 0x00, 0x05, 0x00, 0x01, b'x']);
        let l = layer_from(&pkt);
        let s = l.make_summary(&pkt);
        assert!(s.contains("PUBLISH"));
        assert!(s.contains("tid=5"));
    }

    #[test]
    fn test_summary_connect() {
        let pkt = make_packet(CONNECT, &[0x04, 0x01, 0x00, 0x3C, b's', b'1']);
        let l = layer_from(&pkt);
        let s = l.make_summary(&pkt);
        assert!(s.contains("CONNECT"));
        assert!(s.contains("client_id=s1"));
    }

    #[test]
    fn test_summary_connack() {
        let pkt = make_packet(CONNACK, &[RC_ACCEPTED]);
        let l = layer_from(&pkt);
        let s = l.make_summary(&pkt);
        assert!(s.contains("CONNACK"));
        assert!(s.contains("Accepted"));
    }

    #[test]
    fn test_layer_trait_kind() {
        let pkt = make_packet(PINGRESP, &[]);
        let l = layer_from(&pkt);
        assert_eq!(l.kind(), LayerKind::MqttSn);
    }

    #[test]
    fn test_layer_trait_header_len() {
        let pkt = make_packet(SEARCHGW, &[0x05]);
        let l = layer_from(&pkt);
        assert_eq!(Layer::header_len(&l, &pkt), 3);
    }

    #[test]
    fn test_layer_trait_field_names() {
        let pkt = make_packet(PINGRESP, &[]);
        let l = layer_from(&pkt);
        let names = Layer::field_names(&l);
        assert!(names.contains(&"type"));
        assert!(names.contains(&"length"));
        assert!(names.contains(&"flags"));
    }

    #[test]
    fn test_extended_length_packet() {
        let mut buf = vec![0u8; 260];
        buf[0] = 0x01;
        buf[1] = 0x01;
        buf[2] = 0x04; // length = 260
        buf[3] = PUBLISH;
        buf[4] = 0x00; // flags
        let l = layer_from(&buf);
        assert_eq!(l.packet_length(&buf).unwrap(), 260);
        assert_eq!(l.msg_type(&buf).unwrap(), PUBLISH);
    }

    #[test]
    fn test_roundtrip_builder_parse() {
        let built = MqttSnBuilder::connect()
            .cleansess(true)
            .prot_id(1)
            .duration(60)
            .client_id(b"test")
            .build();
        let l = layer_from(&built);
        assert_eq!(l.msg_type(&built).unwrap(), CONNECT);
        assert!(l.cleansess(&built).unwrap());
        assert_eq!(l.prot_id(&built).unwrap(), 1);
        assert_eq!(l.duration(&built).unwrap(), 60);
        assert_eq!(l.client_id(&built).unwrap(), "test");
    }
}
