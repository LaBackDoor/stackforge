//! MQTT (Message Queuing Telemetry Transport) layer implementation.
//!
//! Implements MQTT v3.1, v3.1.1, and v5.0 packet parsing as a zero-copy view
//! into a packet buffer.
//!
//! ## Fixed Header Format
//!
//! ```text
//! Byte 0:  [msg_type(4 bits)] [dup(1)] [qos(2)] [retain(1)]
//! Byte 1+: Remaining Length (variable-length encoded, 1-4 bytes)
//! ```
//!
//! ## Message Types
//!
//! | Value | Name        | Direction       |
//! |-------|-------------|-----------------|
//! | 1     | CONNECT     | Client -> Server|
//! | 2     | CONNACK     | Server -> Client|
//! | 3     | PUBLISH     | Both            |
//! | 4     | PUBACK      | Both            |
//! | 5     | PUBREC      | Both            |
//! | 6     | PUBREL      | Both            |
//! | 7     | PUBCOMP     | Both            |
//! | 8     | SUBSCRIBE   | Client -> Server|
//! | 9     | SUBACK      | Server -> Client|
//! | 10    | UNSUBSCRIBE | Client -> Server|
//! | 11    | UNSUBACK    | Server -> Client|
//! | 12    | PINGREQ     | Client -> Server|
//! | 13    | PINGRESP    | Server -> Client|
//! | 14    | DISCONNECT  | Both (v5.0)     |
//! | 15    | AUTH        | Both (v5.0)     |

pub mod builder;

pub use builder::MqttBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum MQTT header: 1 byte fixed header + at least 1 byte remaining length.
pub const MQTT_MIN_HEADER_LEN: usize = 2;

/// Default MQTT TCP port.
pub const MQTT_PORT: u16 = 1883;

// ============================================================================
// Message type constants
// ============================================================================

pub const CONNECT: u8 = 1;
pub const CONNACK: u8 = 2;
pub const PUBLISH: u8 = 3;
pub const PUBACK: u8 = 4;
pub const PUBREC: u8 = 5;
pub const PUBREL: u8 = 6;
pub const PUBCOMP: u8 = 7;
pub const SUBSCRIBE: u8 = 8;
pub const SUBACK: u8 = 9;
pub const UNSUBSCRIBE: u8 = 10;
pub const UNSUBACK: u8 = 11;
pub const PINGREQ: u8 = 12;
pub const PINGRESP: u8 = 13;
pub const DISCONNECT: u8 = 14;
pub const AUTH: u8 = 15;

/// Field names exported for Python/generic access.
pub static MQTT_FIELD_NAMES: &[&str] = &[
    "msg_type",
    "dup",
    "qos",
    "retain",
    "remaining_length",
    "topic",
    "topic_len",
    "msgid",
    "value",
    "proto_name",
    "proto_level",
    "connect_flags",
    "klive",
    "client_id",
    "usernameflag",
    "passwordflag",
    "willretainflag",
    "willQOSflag",
    "willflag",
    "cleansess",
    "sess_present_flag",
    "retcode",
    "retcodes",
];

// ============================================================================
// Variable-length integer encoding/decoding (MQTT spec section 1.5.5)
// ============================================================================

/// Decode a variable-length integer from `buf` starting at `offset`.
///
/// Returns `(value, bytes_consumed)` on success.
///
/// Each byte encodes 7 bits of data in bits 6-0, with bit 7 as a continuation
/// flag. At most 4 bytes are used, encoding values up to 268,435,455.
pub fn decode_variable_length(buf: &[u8], offset: usize) -> Result<(u32, usize), FieldError> {
    let mut value: u32 = 0;
    let mut multiplier: u32 = 1;
    let mut idx = offset;

    loop {
        if idx >= buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: idx,
                need: 1,
                have: 0,
            });
        }
        let encoded_byte = buf[idx];
        value = match u32::from(encoded_byte & 0x7F)
            .checked_mul(multiplier)
            .and_then(|v| value.checked_add(v))
        {
            Some(v) => v,
            None => {
                return Err(FieldError::InvalidValue(
                    "variable-length integer overflow".into(),
                ));
            }
        };

        if multiplier > 128 * 128 * 128 {
            return Err(FieldError::InvalidValue(
                "variable-length integer exceeds 4 bytes".into(),
            ));
        }

        idx += 1;
        if encoded_byte & 0x80 == 0 {
            break;
        }
        multiplier = multiplier.saturating_mul(128);
    }

    Ok((value, idx - offset))
}

/// Encode a value as an MQTT variable-length integer.
///
/// Max encodable value is 268,435,455 (0x0FFFFFFF).
#[must_use]
pub fn encode_variable_length(value: u32) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let mut result = Vec::with_capacity(4);
    let mut x = value;
    while x > 0 {
        let mut encoded_byte = (x % 128) as u8;
        x /= 128;
        if x > 0 {
            encoded_byte |= 0x80;
        }
        result.push(encoded_byte);
    }
    result
}

/// Return the string name for an MQTT message type value.
#[must_use]
pub fn message_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        CONNECT => "CONNECT",
        CONNACK => "CONNACK",
        PUBLISH => "PUBLISH",
        PUBACK => "PUBACK",
        PUBREC => "PUBREC",
        PUBREL => "PUBREL",
        PUBCOMP => "PUBCOMP",
        SUBSCRIBE => "SUBSCRIBE",
        SUBACK => "SUBACK",
        UNSUBSCRIBE => "UNSUBSCRIBE",
        UNSUBACK => "UNSUBACK",
        PINGREQ => "PINGREQ",
        PINGRESP => "PINGRESP",
        DISCONNECT => "DISCONNECT",
        AUTH => "AUTH",
        _ => "UNKNOWN",
    }
}

/// Check whether a TCP payload looks like an MQTT packet.
///
/// Validates that the first byte contains a valid message type (1-15) in bits
/// 7-4 and that the remaining length can be decoded.
#[must_use]
pub fn is_mqtt_payload(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let msg_type = (buf[0] >> 4) & 0x0F;
    if !(1..=15).contains(&msg_type) {
        return false;
    }
    // Verify we can decode the remaining length
    decode_variable_length(buf, 1).is_ok()
}

// ============================================================================
// MqttLayer — zero-copy view into a packet buffer
// ============================================================================

/// MQTT layer -- a zero-copy view into a packet buffer.
#[derive(Debug, Clone)]
pub struct MqttLayer {
    pub index: LayerIndex,
}

impl MqttLayer {
    /// Create a new MQTT layer from a layer index.
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Create an MQTT layer starting at offset 0 (for standalone parsing).
    #[must_use]
    pub fn at_start(len: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Mqtt, 0, len),
        }
    }

    /// Return a reference to the slice of the buffer corresponding to this layer.
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    // ========================================================================
    // Fixed header field accessors
    // ========================================================================

    /// Get the message type (bits 7-4 of byte 0).
    pub fn msg_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 1,
                have: 0,
            });
        }
        Ok((s[0] >> 4) & 0x0F)
    }

    /// Get the DUP flag (bit 3 of byte 0).
    pub fn dup(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let s = self.slice(buf);
        if s.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 1,
                have: 0,
            });
        }
        Ok((s[0] >> 3) & 0x01 == 1)
    }

    /// Get the `QoS` level (bits 2-1 of byte 0).
    pub fn qos(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 1,
                have: 0,
            });
        }
        Ok((s[0] >> 1) & 0x03)
    }

    /// Get the RETAIN flag (bit 0 of byte 0).
    pub fn retain(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let s = self.slice(buf);
        if s.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 1,
                have: 0,
            });
        }
        Ok(s[0] & 0x01 == 1)
    }

    /// Get the remaining length (variable-length integer starting at byte 1).
    pub fn remaining_length(&self, buf: &[u8]) -> Result<u32, FieldError> {
        let s = self.slice(buf);
        if s.len() < 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 1,
                need: 1,
                have: s.len().saturating_sub(1),
            });
        }
        let (val, _consumed) = decode_variable_length(s, 1)?;
        Ok(val)
    }

    /// Compute the fixed header length (1 byte type/flags + N bytes remaining length).
    #[must_use]
    pub fn fixed_header_len(&self, buf: &[u8]) -> usize {
        let s = self.slice(buf);
        if s.len() < 2 {
            return MQTT_MIN_HEADER_LEN;
        }
        match decode_variable_length(s, 1) {
            Ok((_val, consumed)) => 1 + consumed,
            Err(_) => MQTT_MIN_HEADER_LEN,
        }
    }

    /// Compute the variable header start offset within the full buffer.
    fn var_header_offset(&self, buf: &[u8]) -> usize {
        self.index.start + self.fixed_header_len(buf)
    }

    // ========================================================================
    // PUBLISH field accessors
    // ========================================================================

    /// Get the topic length for a PUBLISH message (2-byte big-endian at variable header start).
    pub fn topic_len(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.var_header_offset(buf);
        if off + 2 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        Ok(u16::from_be_bytes([buf[off], buf[off + 1]]))
    }

    /// Get the topic string for a PUBLISH message.
    pub fn topic(&self, buf: &[u8]) -> Result<String, FieldError> {
        let off = self.var_header_offset(buf);
        if off + 2 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        let tlen = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        let topic_start = off + 2;
        if topic_start + tlen > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: topic_start,
                need: tlen,
                have: buf.len().saturating_sub(topic_start),
            });
        }
        String::from_utf8(buf[topic_start..topic_start + tlen].to_vec())
            .map_err(|e| FieldError::InvalidValue(format!("invalid UTF-8 topic: {e}")))
    }

    /// Get the message ID for PUBLISH (`QoS` > 0), PUBACK, PUBREC, PUBREL, PUBCOMP,
    /// SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK messages.
    ///
    /// For PUBLISH: message ID follows the topic (2 bytes `topic_len` + topic bytes).
    /// For others: message ID is at the start of the variable header.
    pub fn msgid(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let mt = self.msg_type(buf)?;
        let off = self.var_header_offset(buf);

        match mt {
            PUBLISH => {
                // msg_id is after topic_len(2) + topic(N)
                if off + 2 > buf.len() {
                    return Err(FieldError::BufferTooShort {
                        offset: off,
                        need: 2,
                        have: buf.len().saturating_sub(off),
                    });
                }
                let tlen = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
                let msgid_off = off + 2 + tlen;
                if msgid_off + 2 > buf.len() {
                    return Err(FieldError::BufferTooShort {
                        offset: msgid_off,
                        need: 2,
                        have: buf.len().saturating_sub(msgid_off),
                    });
                }
                Ok(u16::from_be_bytes([buf[msgid_off], buf[msgid_off + 1]]))
            },
            PUBACK | PUBREC | PUBREL | PUBCOMP | SUBSCRIBE | SUBACK | UNSUBSCRIBE | UNSUBACK => {
                if off + 2 > buf.len() {
                    return Err(FieldError::BufferTooShort {
                        offset: off,
                        need: 2,
                        have: buf.len().saturating_sub(off),
                    });
                }
                Ok(u16::from_be_bytes([buf[off], buf[off + 1]]))
            },
            _ => Err(FieldError::InvalidValue(format!(
                "message type {mt} does not have a msgid field"
            ))),
        }
    }

    /// Get the payload value for a PUBLISH message (bytes after topic + optional msgid).
    pub fn value(&self, buf: &[u8]) -> Result<Vec<u8>, FieldError> {
        let off = self.var_header_offset(buf);
        let rem_len = self.remaining_length(buf)? as usize;
        let fixed_hdr = self.fixed_header_len(buf);
        let payload_end = self.index.start + fixed_hdr + rem_len;
        let payload_end = payload_end.min(buf.len());

        if off + 2 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        let tlen = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        let mut value_start = off + 2 + tlen;

        // If QoS > 0, skip the 2-byte message ID
        let qos = self.qos(buf)?;
        if qos > 0 {
            value_start += 2;
        }

        if value_start > payload_end {
            return Ok(Vec::new());
        }
        Ok(buf[value_start..payload_end].to_vec())
    }

    // ========================================================================
    // CONNECT field accessors
    // ========================================================================

    /// Get the protocol name from a CONNECT message (e.g., "MQTT" or "`MQIsdp`").
    pub fn proto_name(&self, buf: &[u8]) -> Result<String, FieldError> {
        let off = self.var_header_offset(buf);
        if off + 2 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        let name_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        let name_start = off + 2;
        if name_start + name_len > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: name_start,
                need: name_len,
                have: buf.len().saturating_sub(name_start),
            });
        }
        String::from_utf8(buf[name_start..name_start + name_len].to_vec())
            .map_err(|e| FieldError::InvalidValue(format!("invalid UTF-8 proto_name: {e}")))
    }

    /// Get the protocol level/version byte from a CONNECT message.
    pub fn proto_level(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.var_header_offset(buf);
        if off + 2 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        let name_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        let level_off = off + 2 + name_len;
        if level_off >= buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: level_off,
                need: 1,
                have: 0,
            });
        }
        Ok(buf[level_off])
    }

    /// Get the connect flags byte from a CONNECT message.
    pub fn connect_flags(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.var_header_offset(buf);
        if off + 2 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        let name_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        let flags_off = off + 2 + name_len + 1;
        if flags_off >= buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: flags_off,
                need: 1,
                have: 0,
            });
        }
        Ok(buf[flags_off])
    }

    /// Get the username flag from CONNECT flags (bit 7).
    pub fn usernameflag(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let flags = self.connect_flags(buf)?;
        Ok((flags >> 7) & 0x01 == 1)
    }

    /// Get the password flag from CONNECT flags (bit 6).
    pub fn passwordflag(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let flags = self.connect_flags(buf)?;
        Ok((flags >> 6) & 0x01 == 1)
    }

    /// Get the will retain flag from CONNECT flags (bit 5).
    pub fn willretainflag(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let flags = self.connect_flags(buf)?;
        Ok((flags >> 5) & 0x01 == 1)
    }

    /// Get the will `QoS` from CONNECT flags (bits 4-3).
    pub fn will_qosflag(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let flags = self.connect_flags(buf)?;
        Ok((flags >> 3) & 0x03)
    }

    /// Get the will flag from CONNECT flags (bit 2).
    pub fn willflag(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let flags = self.connect_flags(buf)?;
        Ok((flags >> 2) & 0x01 == 1)
    }

    /// Get the clean session flag from CONNECT flags (bit 1).
    pub fn cleansess(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let flags = self.connect_flags(buf)?;
        Ok((flags >> 1) & 0x01 == 1)
    }

    /// Get the keep alive value from a CONNECT message (2-byte big-endian).
    pub fn klive(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.var_header_offset(buf);
        if off + 2 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        let name_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        let klive_off = off + 2 + name_len + 2; // after proto_name + proto_level + connect_flags
        if klive_off + 2 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: klive_off,
                need: 2,
                have: buf.len().saturating_sub(klive_off),
            });
        }
        Ok(u16::from_be_bytes([buf[klive_off], buf[klive_off + 1]]))
    }

    /// Compute the offset to the start of the CONNECT payload (after variable header).
    fn connect_payload_offset(&self, buf: &[u8]) -> Result<usize, FieldError> {
        let off = self.var_header_offset(buf);
        if off + 2 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        let name_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        // variable header = proto_name_len(2) + proto_name(N) + proto_level(1) + connect_flags(1) + keep_alive(2)
        Ok(off + 2 + name_len + 1 + 1 + 2)
    }

    /// Get the client ID from a CONNECT message.
    pub fn client_id(&self, buf: &[u8]) -> Result<String, FieldError> {
        let off = self.connect_payload_offset(buf)?;
        if off + 2 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        let cid_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        let cid_start = off + 2;
        if cid_start + cid_len > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: cid_start,
                need: cid_len,
                have: buf.len().saturating_sub(cid_start),
            });
        }
        String::from_utf8(buf[cid_start..cid_start + cid_len].to_vec())
            .map_err(|e| FieldError::InvalidValue(format!("invalid UTF-8 client_id: {e}")))
    }

    // ========================================================================
    // CONNACK field accessors
    // ========================================================================

    /// Get the session present flag from a CONNACK message (byte 0 of variable header).
    pub fn sess_present_flag(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.var_header_offset(buf);
        if off >= buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: 0,
            });
        }
        Ok(buf[off] & 0x01)
    }

    /// Get the return code from a CONNACK message (byte 1 of variable header).
    pub fn retcode(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.var_header_offset(buf);
        if off + 2 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: off + 1,
                need: 1,
                have: buf.len().saturating_sub(off + 1),
            });
        }
        Ok(buf[off + 1])
    }

    // ========================================================================
    // SUBACK field accessors
    // ========================================================================

    /// Get the return codes from a SUBACK message (bytes after the 2-byte msgid).
    pub fn retcodes(&self, buf: &[u8]) -> Result<Vec<u8>, FieldError> {
        let off = self.var_header_offset(buf);
        let rem_len = self.remaining_length(buf)? as usize;
        let fixed_hdr = self.fixed_header_len(buf);
        let payload_end = self.index.start + fixed_hdr + rem_len;
        let payload_end = payload_end.min(buf.len());

        let retcodes_start = off + 2; // after msgid
        if retcodes_start > payload_end {
            return Ok(Vec::new());
        }
        Ok(buf[retcodes_start..payload_end].to_vec())
    }

    // ========================================================================
    // Summary / display
    // ========================================================================

    /// Generate a one-line summary of this MQTT layer.
    #[must_use]
    pub fn summary(&self, buf: &[u8]) -> String {
        let mt = match self.msg_type(buf) {
            Ok(t) => t,
            Err(_) => return "MQTT".to_string(),
        };
        let type_name = message_type_name(mt);

        match mt {
            PUBLISH => {
                let topic = self.topic(buf).unwrap_or_else(|_| "?".to_string());
                let qos = self.qos(buf).unwrap_or(0);
                format!("MQTT {type_name} topic={topic} QOS={qos}")
            },
            CONNECT => {
                let cid = self.client_id(buf).unwrap_or_else(|_| "?".to_string());
                format!("MQTT {type_name} clientId={cid}")
            },
            CONNACK => {
                let rc = self.retcode(buf).unwrap_or(0);
                format!("MQTT {type_name} retcode={rc}")
            },
            SUBSCRIBE | UNSUBSCRIBE => {
                let mid = self.msgid(buf).unwrap_or(0);
                format!("MQTT {type_name} msgid={mid}")
            },
            SUBACK => {
                let mid = self.msgid(buf).unwrap_or(0);
                format!("MQTT {type_name} msgid={mid}")
            },
            PUBACK | PUBREC | PUBREL | PUBCOMP | UNSUBACK => {
                let mid = self.msgid(buf).unwrap_or(0);
                format!("MQTT {type_name} msgid={mid}")
            },
            _ => format!("MQTT {type_name}"),
        }
    }

    /// Compute the total MQTT message length (fixed header + remaining length).
    fn compute_header_len(&self, buf: &[u8]) -> usize {
        let fixed_hdr = self.fixed_header_len(buf);
        let rem_len = self.remaining_length(buf).unwrap_or(0) as usize;
        fixed_hdr + rem_len
    }

    // ========================================================================
    // Field access API
    // ========================================================================

    /// Get the field names for this layer.
    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        MQTT_FIELD_NAMES
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "msg_type" => Some(self.msg_type(buf).map(FieldValue::U8)),
            "dup" => Some(self.dup(buf).map(FieldValue::Bool)),
            "qos" => Some(self.qos(buf).map(FieldValue::U8)),
            "retain" => Some(self.retain(buf).map(FieldValue::Bool)),
            "remaining_length" => Some(self.remaining_length(buf).map(FieldValue::U32)),
            "topic_len" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == PUBLISH {
                    Some(self.topic_len(buf).map(FieldValue::U16))
                } else {
                    None
                }
            },
            "topic" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == PUBLISH {
                    Some(self.topic(buf).map(FieldValue::Str))
                } else {
                    None
                }
            },
            "msgid" => {
                let mt = self.msg_type(buf).ok()?;
                match mt {
                    PUBLISH => {
                        let qos = self.qos(buf).ok()?;
                        if qos > 0 {
                            Some(self.msgid(buf).map(FieldValue::U16))
                        } else {
                            None
                        }
                    },
                    PUBACK | PUBREC | PUBREL | PUBCOMP | SUBSCRIBE | SUBACK | UNSUBSCRIBE
                    | UNSUBACK => Some(self.msgid(buf).map(FieldValue::U16)),
                    _ => None,
                }
            },
            "value" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == PUBLISH {
                    Some(self.value(buf).map(FieldValue::Bytes))
                } else {
                    None
                }
            },
            "proto_name" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNECT {
                    Some(self.proto_name(buf).map(FieldValue::Str))
                } else {
                    None
                }
            },
            "proto_level" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNECT {
                    Some(self.proto_level(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "connect_flags" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNECT {
                    Some(self.connect_flags(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "klive" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNECT {
                    Some(self.klive(buf).map(FieldValue::U16))
                } else {
                    None
                }
            },
            "client_id" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNECT {
                    Some(self.client_id(buf).map(FieldValue::Str))
                } else {
                    None
                }
            },
            "usernameflag" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNECT {
                    Some(self.usernameflag(buf).map(FieldValue::Bool))
                } else {
                    None
                }
            },
            "passwordflag" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNECT {
                    Some(self.passwordflag(buf).map(FieldValue::Bool))
                } else {
                    None
                }
            },
            "willretainflag" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNECT {
                    Some(self.willretainflag(buf).map(FieldValue::Bool))
                } else {
                    None
                }
            },
            "willQOSflag" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNECT {
                    Some(self.will_qosflag(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "willflag" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNECT {
                    Some(self.willflag(buf).map(FieldValue::Bool))
                } else {
                    None
                }
            },
            "cleansess" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNECT {
                    Some(self.cleansess(buf).map(FieldValue::Bool))
                } else {
                    None
                }
            },
            "sess_present_flag" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNACK {
                    Some(self.sess_present_flag(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "retcode" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == CONNACK {
                    Some(self.retcode(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "retcodes" => {
                let mt = self.msg_type(buf).ok()?;
                if mt == SUBACK {
                    Some(self.retcodes(buf).map(FieldValue::Bytes))
                } else {
                    None
                }
            },
            _ => None,
        }
    }

    /// Set a field value by name (limited support for MQTT).
    pub fn set_field(
        &self,
        _buf: &mut [u8],
        _name: &str,
        _value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        // MQTT fields are variable-length and setting them in-place is not
        // straightforward. Use the builder for constructing new packets.
        None
    }
}

impl Layer for MqttLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Mqtt
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.compute_header_len(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        MQTT_FIELD_NAMES
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Variable-length encoding/decoding tests ----

    #[test]
    fn test_decode_variable_length_single_byte() {
        // Value 0
        let buf = [0x00];
        let (val, consumed) = decode_variable_length(&buf, 0).unwrap();
        assert_eq!(val, 0);
        assert_eq!(consumed, 1);

        // Value 127
        let buf = [0x7F];
        let (val, consumed) = decode_variable_length(&buf, 0).unwrap();
        assert_eq!(val, 127);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_variable_length_two_bytes() {
        // Value 128 = 0x00 + 0x80 first byte, 0x01 second byte
        let buf = [0x80, 0x01];
        let (val, consumed) = decode_variable_length(&buf, 0).unwrap();
        assert_eq!(val, 128);
        assert_eq!(consumed, 2);

        // Value 16383
        let buf = [0xFF, 0x7F];
        let (val, consumed) = decode_variable_length(&buf, 0).unwrap();
        assert_eq!(val, 16383);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_decode_variable_length_four_bytes() {
        // Value 268,435,455 (max)
        let buf = [0xFF, 0xFF, 0xFF, 0x7F];
        let (val, consumed) = decode_variable_length(&buf, 0).unwrap();
        assert_eq!(val, 268_435_455);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_encode_variable_length_roundtrip() {
        for &val in &[0u32, 1, 127, 128, 16383, 16384, 2_097_151, 268_435_455] {
            let encoded = encode_variable_length(val);
            let (decoded, consumed) = decode_variable_length(&encoded, 0).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {}", val);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn test_encode_variable_length_zero() {
        let encoded = encode_variable_length(0);
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn test_encode_variable_length_single_byte() {
        let encoded = encode_variable_length(10);
        assert_eq!(encoded, vec![0x0a]);
    }

    // ---- Detection ----

    #[test]
    fn test_is_mqtt_payload_valid() {
        // PINGREQ: 0xC0 0x00
        assert!(is_mqtt_payload(&[0xC0, 0x00]));
        // CONNECT
        assert!(is_mqtt_payload(&[0x10, 0x1f]));
        // PUBLISH QoS 0
        assert!(is_mqtt_payload(&[0x30, 0x0a, 0x00, 0x04]));
    }

    #[test]
    fn test_is_mqtt_payload_invalid() {
        // Too short
        assert!(!is_mqtt_payload(&[0x30]));
        // Type 0 is reserved/invalid
        assert!(!is_mqtt_payload(&[0x00, 0x00]));
    }

    // ---- PUBLISH parsing ----

    #[test]
    fn test_parse_publish_qos0() {
        // PUBLISH QoS0: \x30\x0a\x00\x04test\x00test (but wait... let me
        // recalculate the value: fixed header = 0x30 (type=3, dup=0, qos=0, retain=0)
        // remaining length = 0x0a = 10
        // variable header: topic_len=0x0004, topic="test" (4 bytes)
        // payload: remaining = 10 - (2+4) = 4 bytes => but we need 6 bytes for "test"?
        // No: rem_len=10 = 2(topic_len) + 4(topic) + 4(value) = 10 correct.
        // So value = last 4 bytes.
        // Full packet: 0x30 0x0a 0x00 0x04 't' 'e' 's' 't' 't' 'e' 's' 't'
        let data: Vec<u8> = vec![
            0x30, 0x0a, 0x00, 0x04, b't', b'e', b's', b't', b't', b'e', b's', b't',
        ];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&data).unwrap(), PUBLISH);
        assert!(!mqtt.dup(&data).unwrap());
        assert_eq!(mqtt.qos(&data).unwrap(), 0);
        assert!(!mqtt.retain(&data).unwrap());
        assert_eq!(mqtt.remaining_length(&data).unwrap(), 10);
        assert_eq!(mqtt.fixed_header_len(&data), 2);
        assert_eq!(mqtt.topic_len(&data).unwrap(), 4);
        assert_eq!(mqtt.topic(&data).unwrap(), "test");
        assert_eq!(mqtt.value(&data).unwrap(), b"test");
    }

    #[test]
    fn test_parse_publish_qos1() {
        // PUBLISH QoS1 with msg_id:
        // type=3, dup=0, qos=1, retain=0 => 0x32
        // remaining_length=12 => topic_len(2) + topic(4) + msgid(2) + value(4)
        let data: Vec<u8> = vec![
            0x32, 0x0c, 0x00, 0x04, b't', b'e', b's', b't', 0x00, 0x0a, b'd', b'a', b't', b'a',
        ];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&data).unwrap(), PUBLISH);
        assert_eq!(mqtt.qos(&data).unwrap(), 1);
        assert_eq!(mqtt.topic(&data).unwrap(), "test");
        assert_eq!(mqtt.msgid(&data).unwrap(), 10);
        assert_eq!(mqtt.value(&data).unwrap(), b"data");
    }

    // ---- CONNECT parsing ----

    #[test]
    fn test_parse_connect() {
        // CONNECT: \x10\x1f\x00\x06MQIsdp\x03\x02\x00\x3c\x00\x11mosqpub/1440-kali
        let data: Vec<u8> = vec![
            0x10, 0x1f, // fixed header: CONNECT, remaining_length=31
            0x00, 0x06, // proto_name length = 6
            b'M', b'Q', b'I', b's', b'd', b'p', // proto_name = "MQIsdp"
            0x03, // proto_level = 3
            0x02, // connect_flags = 0x02 (clean session)
            0x00, 0x3c, // keep_alive = 60
            0x00, 0x11, // client_id length = 17
            b'm', b'o', b's', b'q', b'p', b'u', b'b', b'/', b'1', b'4', b'4', b'0', b'-', b'k',
            b'a', b'l', b'i',
        ];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&data).unwrap(), CONNECT);
        assert_eq!(mqtt.remaining_length(&data).unwrap(), 31);
        assert_eq!(mqtt.proto_name(&data).unwrap(), "MQIsdp");
        assert_eq!(mqtt.proto_level(&data).unwrap(), 3);
        assert_eq!(mqtt.connect_flags(&data).unwrap(), 0x02);
        assert!(mqtt.cleansess(&data).unwrap());
        assert!(!mqtt.usernameflag(&data).unwrap());
        assert!(!mqtt.passwordflag(&data).unwrap());
        assert!(!mqtt.willflag(&data).unwrap());
        assert_eq!(mqtt.klive(&data).unwrap(), 60);
        assert_eq!(mqtt.client_id(&data).unwrap(), "mosqpub/1440-kali");
    }

    // ---- CONNACK parsing ----

    #[test]
    fn test_parse_connack() {
        // CONNACK: \x20\x02\x00\x00
        let data: Vec<u8> = vec![0x20, 0x02, 0x00, 0x00];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&data).unwrap(), CONNACK);
        assert_eq!(mqtt.remaining_length(&data).unwrap(), 2);
        assert_eq!(mqtt.sess_present_flag(&data).unwrap(), 0);
        assert_eq!(mqtt.retcode(&data).unwrap(), 0);
    }

    // ---- SUBSCRIBE parsing ----

    #[test]
    fn test_parse_subscribe() {
        // SUBSCRIBE: \x82\x09\x00\x01\x00\x04test\x01
        // type=8, flags=0x02 (reserved), rem_len=9
        // msgid=0x0001, topic_filter_len=4, topic="test", qos=1
        let data: Vec<u8> = vec![
            0x82, 0x09, 0x00, 0x01, 0x00, 0x04, b't', b'e', b's', b't', 0x01,
        ];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&data).unwrap(), SUBSCRIBE);
        assert_eq!(mqtt.remaining_length(&data).unwrap(), 9);
        assert_eq!(mqtt.msgid(&data).unwrap(), 1);
    }

    // ---- SUBACK parsing ----

    #[test]
    fn test_parse_suback() {
        // SUBACK: \x90\x03\x00\x01\x00
        // type=9, rem_len=3, msgid=1, retcodes=[0x00]
        let data: Vec<u8> = vec![0x90, 0x03, 0x00, 0x01, 0x00];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&data).unwrap(), SUBACK);
        assert_eq!(mqtt.remaining_length(&data).unwrap(), 3);
        assert_eq!(mqtt.msgid(&data).unwrap(), 1);
        assert_eq!(mqtt.retcodes(&data).unwrap(), vec![0x00]);
    }

    // ---- PINGREQ / PINGRESP ----

    #[test]
    fn test_parse_pingreq() {
        let data: Vec<u8> = vec![0xC0, 0x00];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&data).unwrap(), PINGREQ);
        assert_eq!(mqtt.remaining_length(&data).unwrap(), 0);
    }

    #[test]
    fn test_parse_pingresp() {
        let data: Vec<u8> = vec![0xD0, 0x00];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&data).unwrap(), PINGRESP);
        assert_eq!(mqtt.remaining_length(&data).unwrap(), 0);
    }

    // ---- DISCONNECT ----

    #[test]
    fn test_parse_disconnect() {
        let data: Vec<u8> = vec![0xE0, 0x00];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&data).unwrap(), DISCONNECT);
        assert_eq!(mqtt.remaining_length(&data).unwrap(), 0);
    }

    // ---- Message type names ----

    #[test]
    fn test_message_type_names() {
        assert_eq!(message_type_name(CONNECT), "CONNECT");
        assert_eq!(message_type_name(CONNACK), "CONNACK");
        assert_eq!(message_type_name(PUBLISH), "PUBLISH");
        assert_eq!(message_type_name(PUBACK), "PUBACK");
        assert_eq!(message_type_name(PUBREC), "PUBREC");
        assert_eq!(message_type_name(PUBREL), "PUBREL");
        assert_eq!(message_type_name(PUBCOMP), "PUBCOMP");
        assert_eq!(message_type_name(SUBSCRIBE), "SUBSCRIBE");
        assert_eq!(message_type_name(SUBACK), "SUBACK");
        assert_eq!(message_type_name(UNSUBSCRIBE), "UNSUBSCRIBE");
        assert_eq!(message_type_name(UNSUBACK), "UNSUBACK");
        assert_eq!(message_type_name(PINGREQ), "PINGREQ");
        assert_eq!(message_type_name(PINGRESP), "PINGRESP");
        assert_eq!(message_type_name(DISCONNECT), "DISCONNECT");
        assert_eq!(message_type_name(AUTH), "AUTH");
        assert_eq!(message_type_name(0), "UNKNOWN");
    }

    // ---- Summary ----

    #[test]
    fn test_summary_publish() {
        let data: Vec<u8> = vec![
            0x30, 0x0a, 0x00, 0x04, b't', b'e', b's', b't', b't', b'e', b's', b't',
        ];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);
        let s = mqtt.summary(&data);
        assert!(s.contains("PUBLISH"));
        assert!(s.contains("topic=test"));
        assert!(s.contains("QOS=0"));
    }

    #[test]
    fn test_summary_connect() {
        let data: Vec<u8> = vec![
            0x10, 0x1f, 0x00, 0x06, b'M', b'Q', b'I', b's', b'd', b'p', 0x03, 0x02, 0x00, 0x3c,
            0x00, 0x11, b'm', b'o', b's', b'q', b'p', b'u', b'b', b'/', b'1', b'4', b'4', b'0',
            b'-', b'k', b'a', b'l', b'i',
        ];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);
        let s = mqtt.summary(&data);
        assert!(s.contains("CONNECT"));
        assert!(s.contains("clientId=mosqpub/1440-kali"));
    }

    // ---- get_field ----

    #[test]
    fn test_get_field_msg_type() {
        let data: Vec<u8> = vec![0xC0, 0x00];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);
        let val = mqtt.get_field(&data, "msg_type").unwrap().unwrap();
        assert_eq!(val, FieldValue::U8(PINGREQ));
    }

    #[test]
    fn test_get_field_unknown() {
        let data: Vec<u8> = vec![0xC0, 0x00];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);
        assert!(mqtt.get_field(&data, "nonexistent").is_none());
    }

    // ---- Layer trait ----

    #[test]
    fn test_layer_trait_kind() {
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, 2);
        let mqtt = MqttLayer::new(idx);
        assert_eq!(mqtt.kind(), LayerKind::Mqtt);
    }

    #[test]
    fn test_layer_trait_header_len() {
        // PUBLISH with rem_len=10 => total = 2 (fixed header) + 10 = 12
        let data: Vec<u8> = vec![
            0x30, 0x0a, 0x00, 0x04, b't', b'e', b's', b't', b't', b'e', b's', b't',
        ];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);
        assert_eq!(Layer::header_len(&mqtt, &data), 12);
    }

    // ---- PUBACK ----

    #[test]
    fn test_parse_puback() {
        // PUBACK: type=4, rem_len=2, msgid=0x000a
        let data: Vec<u8> = vec![0x40, 0x02, 0x00, 0x0a];
        let idx = LayerIndex::new(LayerKind::Mqtt, 0, data.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&data).unwrap(), PUBACK);
        assert_eq!(mqtt.msgid(&data).unwrap(), 10);
    }

    // ---- Builder round-trip ----

    #[test]
    fn test_builder_roundtrip_publish() {
        let built = MqttBuilder::new()
            .publish()
            .topic(b"test")
            .payload(b"hello")
            .build();

        let idx = LayerIndex::new(LayerKind::Mqtt, 0, built.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&built).unwrap(), PUBLISH);
        assert_eq!(mqtt.qos(&built).unwrap(), 0);
        assert_eq!(mqtt.topic(&built).unwrap(), "test");
        assert_eq!(mqtt.value(&built).unwrap(), b"hello");
    }

    #[test]
    fn test_builder_roundtrip_connect() {
        let built = MqttBuilder::new()
            .connect()
            .client_id(b"myclient")
            .keep_alive(120)
            .clean_session(true)
            .build();

        let idx = LayerIndex::new(LayerKind::Mqtt, 0, built.len());
        let mqtt = MqttLayer::new(idx);

        assert_eq!(mqtt.msg_type(&built).unwrap(), CONNECT);
        assert_eq!(mqtt.proto_name(&built).unwrap(), "MQTT");
        assert_eq!(mqtt.proto_level(&built).unwrap(), 4);
        assert!(mqtt.cleansess(&built).unwrap());
        assert_eq!(mqtt.klive(&built).unwrap(), 120);
        assert_eq!(mqtt.client_id(&built).unwrap(), "myclient");
    }
}
