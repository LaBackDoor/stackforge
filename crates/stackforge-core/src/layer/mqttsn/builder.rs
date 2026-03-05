//! MQTT-SN packet builder.
//!
//! Provides a fluent API for constructing MQTT-SN v1.2 packets.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::mqttsn::builder::MqttSnBuilder;
//!
//! // Simple PINGRESP
//! let pkt = MqttSnBuilder::pingresp().build();
//! assert_eq!(pkt, b"\x02\x17");
//!
//! // CONNECT with client ID
//! let pkt = MqttSnBuilder::connect()
//!     .cleansess(true)
//!     .duration(30)
//!     .client_id(b"test")
//!     .build();
//! assert_eq!(&pkt[0..2], &[0x0a, 0x04]); // length=10, type=CONNECT
//! ```

use super::{
    ADVERTISE, CONNACK, CONNECT, DISCONNECT, GWINFO, PINGREQ, PINGRESP, PUBACK, PUBCOMP, PUBLISH,
    PUBREC, PUBREL, RC_ACCEPTED, REGACK, REGISTER, SEARCHGW, SUBACK, SUBSCRIBE, TID_PREDEF,
    TID_SHORT, UNSUBACK, UNSUBSCRIBE, WILLMSG, WILLMSGREQ, WILLMSGRESP, WILLMSGUPD, WILLTOPIC,
    WILLTOPICREQ, WILLTOPICRESP, WILLTOPICUPD,
};

/// Builder for MQTT-SN packets.
///
/// The builder produces a complete MQTT-SN message with the appropriate
/// length prefix (1-byte or 3-byte extended).
#[derive(Debug, Clone)]
pub struct MqttSnBuilder {
    /// Message type byte
    msg_type: u8,

    // ----- Flags byte fields -----
    dup: bool,
    qos: u8,
    retain: bool,
    will: bool,
    cleansess: bool,
    tid_type: u8,

    // ----- Message-specific fields -----
    gw_id: u8,
    duration: u16,
    radius: u8,
    gw_addr: Vec<u8>,
    prot_id: u8,
    client_id: Vec<u8>,
    return_code: u8,
    tid: u16,
    mid: u16,
    data: Vec<u8>,
    topic_name: Vec<u8>,
    will_topic: Vec<u8>,
    will_msg: Vec<u8>,
}

impl Default for MqttSnBuilder {
    fn default() -> Self {
        Self {
            msg_type: CONNECT,
            dup: false,
            qos: 0,
            retain: false,
            will: false,
            cleansess: false,
            tid_type: 0,
            gw_id: 0,
            duration: 0,
            radius: 0,
            gw_addr: Vec::new(),
            prot_id: 0x01,
            client_id: Vec::new(),
            return_code: RC_ACCEPTED,
            tid: 0,
            mid: 0,
            data: Vec::new(),
            topic_name: Vec::new(),
            will_topic: Vec::new(),
            will_msg: Vec::new(),
        }
    }
}

impl MqttSnBuilder {
    /// Create a new builder with CONNECT defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // Convenience constructors
    // ========================================================================

    /// ADVERTISE message builder.
    #[must_use]
    pub fn advertise() -> Self {
        Self {
            msg_type: ADVERTISE,
            ..Default::default()
        }
    }

    /// SEARCHGW message builder.
    #[must_use]
    pub fn searchgw() -> Self {
        Self {
            msg_type: SEARCHGW,
            ..Default::default()
        }
    }

    /// GWINFO message builder.
    #[must_use]
    pub fn gwinfo() -> Self {
        Self {
            msg_type: GWINFO,
            ..Default::default()
        }
    }

    /// CONNECT message builder.
    #[must_use]
    pub fn connect() -> Self {
        Self {
            msg_type: CONNECT,
            ..Default::default()
        }
    }

    /// CONNACK message builder.
    #[must_use]
    pub fn connack() -> Self {
        Self {
            msg_type: CONNACK,
            ..Default::default()
        }
    }

    /// WILLTOPICREQ message builder.
    #[must_use]
    pub fn willtopicreq() -> Self {
        Self {
            msg_type: WILLTOPICREQ,
            ..Default::default()
        }
    }

    /// WILLTOPIC message builder.
    #[must_use]
    pub fn willtopic() -> Self {
        Self {
            msg_type: WILLTOPIC,
            ..Default::default()
        }
    }

    /// WILLMSGREQ message builder.
    #[must_use]
    pub fn willmsgreq() -> Self {
        Self {
            msg_type: WILLMSGREQ,
            ..Default::default()
        }
    }

    /// WILLMSG message builder.
    #[must_use]
    pub fn willmsg() -> Self {
        Self {
            msg_type: WILLMSG,
            ..Default::default()
        }
    }

    /// REGISTER message builder.
    #[must_use]
    pub fn register() -> Self {
        Self {
            msg_type: REGISTER,
            ..Default::default()
        }
    }

    /// REGACK message builder.
    #[must_use]
    pub fn regack() -> Self {
        Self {
            msg_type: REGACK,
            ..Default::default()
        }
    }

    /// PUBLISH message builder.
    #[must_use]
    pub fn publish() -> Self {
        Self {
            msg_type: PUBLISH,
            ..Default::default()
        }
    }

    /// PUBACK message builder.
    #[must_use]
    pub fn puback() -> Self {
        Self {
            msg_type: PUBACK,
            ..Default::default()
        }
    }

    /// PUBCOMP message builder.
    #[must_use]
    pub fn pubcomp() -> Self {
        Self {
            msg_type: PUBCOMP,
            ..Default::default()
        }
    }

    /// PUBREC message builder.
    #[must_use]
    pub fn pubrec() -> Self {
        Self {
            msg_type: PUBREC,
            ..Default::default()
        }
    }

    /// PUBREL message builder.
    #[must_use]
    pub fn pubrel() -> Self {
        Self {
            msg_type: PUBREL,
            ..Default::default()
        }
    }

    /// SUBSCRIBE message builder.
    #[must_use]
    pub fn subscribe() -> Self {
        Self {
            msg_type: SUBSCRIBE,
            ..Default::default()
        }
    }

    /// SUBACK message builder.
    #[must_use]
    pub fn suback() -> Self {
        Self {
            msg_type: SUBACK,
            ..Default::default()
        }
    }

    /// UNSUBSCRIBE message builder.
    #[must_use]
    pub fn unsubscribe() -> Self {
        Self {
            msg_type: UNSUBSCRIBE,
            ..Default::default()
        }
    }

    /// UNSUBACK message builder.
    #[must_use]
    pub fn unsuback() -> Self {
        Self {
            msg_type: UNSUBACK,
            ..Default::default()
        }
    }

    /// PINGREQ message builder.
    #[must_use]
    pub fn pingreq() -> Self {
        Self {
            msg_type: PINGREQ,
            ..Default::default()
        }
    }

    /// PINGRESP message builder.
    #[must_use]
    pub fn pingresp() -> Self {
        Self {
            msg_type: PINGRESP,
            ..Default::default()
        }
    }

    /// DISCONNECT message builder.
    #[must_use]
    pub fn disconnect() -> Self {
        Self {
            msg_type: DISCONNECT,
            ..Default::default()
        }
    }

    /// WILLTOPICUPD message builder.
    #[must_use]
    pub fn willtopicupd() -> Self {
        Self {
            msg_type: WILLTOPICUPD,
            ..Default::default()
        }
    }

    /// WILLTOPICRESP message builder.
    #[must_use]
    pub fn willtopicresp() -> Self {
        Self {
            msg_type: WILLTOPICRESP,
            ..Default::default()
        }
    }

    /// WILLMSGUPD message builder.
    #[must_use]
    pub fn willmsgupd() -> Self {
        Self {
            msg_type: WILLMSGUPD,
            ..Default::default()
        }
    }

    /// WILLMSGRESP message builder.
    #[must_use]
    pub fn willmsgresp() -> Self {
        Self {
            msg_type: WILLMSGRESP,
            ..Default::default()
        }
    }

    // ========================================================================
    // Fluent setters
    // ========================================================================

    /// Set the message type byte directly.
    #[must_use]
    pub fn msg_type(mut self, v: u8) -> Self {
        self.msg_type = v;
        self
    }

    /// Set the DUP flag.
    #[must_use]
    pub fn dup(mut self, v: bool) -> Self {
        self.dup = v;
        self
    }

    /// Set the `QoS` level (0-3).
    #[must_use]
    pub fn qos(mut self, v: u8) -> Self {
        self.qos = v & 0x03;
        self
    }

    /// Set the Retain flag.
    #[must_use]
    pub fn retain(mut self, v: bool) -> Self {
        self.retain = v;
        self
    }

    /// Set the Will flag.
    #[must_use]
    pub fn will(mut self, v: bool) -> Self {
        self.will = v;
        self
    }

    /// Set the `CleanSession` flag.
    #[must_use]
    pub fn cleansess(mut self, v: bool) -> Self {
        self.cleansess = v;
        self
    }

    /// Set the `TopicIdType` (0-3).
    #[must_use]
    pub fn tid_type(mut self, v: u8) -> Self {
        self.tid_type = v & 0x03;
        self
    }

    /// Set the Gateway ID.
    #[must_use]
    pub fn gw_id(mut self, v: u8) -> Self {
        self.gw_id = v;
        self
    }

    /// Set the Duration.
    #[must_use]
    pub fn duration(mut self, v: u16) -> Self {
        self.duration = v;
        self
    }

    /// Set the Radius.
    #[must_use]
    pub fn radius(mut self, v: u8) -> Self {
        self.radius = v;
        self
    }

    /// Set the Gateway Address.
    #[must_use]
    pub fn gw_addr(mut self, v: &[u8]) -> Self {
        self.gw_addr = v.to_vec();
        self
    }

    /// Set the Protocol ID.
    #[must_use]
    pub fn prot_id(mut self, v: u8) -> Self {
        self.prot_id = v;
        self
    }

    /// Set the Client ID (byte slice).
    #[must_use]
    pub fn client_id(mut self, v: &[u8]) -> Self {
        self.client_id = v.to_vec();
        self
    }

    /// Set the Client ID from a string.
    #[must_use]
    pub fn client_id_str(mut self, v: &str) -> Self {
        self.client_id = v.as_bytes().to_vec();
        self
    }

    /// Set the Return Code.
    #[must_use]
    pub fn return_code(mut self, v: u8) -> Self {
        self.return_code = v;
        self
    }

    /// Set the Topic ID.
    #[must_use]
    pub fn tid(mut self, v: u16) -> Self {
        self.tid = v;
        self
    }

    /// Set the Message ID.
    #[must_use]
    pub fn mid(mut self, v: u16) -> Self {
        self.mid = v;
        self
    }

    /// Set the Data / payload bytes.
    #[must_use]
    pub fn data(mut self, v: &[u8]) -> Self {
        self.data = v.to_vec();
        self
    }

    /// Set the Topic Name.
    #[must_use]
    pub fn topic_name(mut self, v: &[u8]) -> Self {
        self.topic_name = v.to_vec();
        self
    }

    /// Set the Topic Name from a string.
    #[must_use]
    pub fn topic_name_str(mut self, v: &str) -> Self {
        self.topic_name = v.as_bytes().to_vec();
        self
    }

    /// Set the Will Topic.
    #[must_use]
    pub fn will_topic_bytes(mut self, v: &[u8]) -> Self {
        self.will_topic = v.to_vec();
        self
    }

    /// Set the Will Topic from a string.
    #[must_use]
    pub fn will_topic_str(mut self, v: &str) -> Self {
        self.will_topic = v.as_bytes().to_vec();
        self
    }

    /// Set the Will Message.
    #[must_use]
    pub fn will_msg_bytes(mut self, v: &[u8]) -> Self {
        self.will_msg = v.to_vec();
        self
    }

    // ========================================================================
    // Build helpers
    // ========================================================================

    /// Build the flags byte from the individual flag fields.
    fn build_flags(&self) -> u8 {
        let mut flags: u8 = 0;
        if self.dup {
            flags |= 1 << 7;
        }
        flags |= (self.qos & 0x03) << 5;
        if self.retain {
            flags |= 1 << 4;
        }
        if self.will {
            flags |= 1 << 3;
        }
        if self.cleansess {
            flags |= 1 << 2;
        }
        flags |= self.tid_type & 0x03;
        flags
    }

    /// Build the body bytes (everything after the length + `msg_type` header).
    fn build_body(&self) -> Vec<u8> {
        let mut body = Vec::new();

        match self.msg_type {
            ADVERTISE => {
                body.push(self.gw_id);
                body.extend_from_slice(&self.duration.to_be_bytes());
            },
            SEARCHGW => {
                body.push(self.radius);
            },
            GWINFO => {
                body.push(self.gw_id);
                body.extend_from_slice(&self.gw_addr);
            },
            CONNECT => {
                body.push(self.build_flags());
                body.push(self.prot_id);
                body.extend_from_slice(&self.duration.to_be_bytes());
                body.extend_from_slice(&self.client_id);
            },
            CONNACK => {
                body.push(self.return_code);
            },
            WILLTOPICREQ | WILLMSGREQ => {
                // Empty body -- only length + msg_type
            },
            WILLTOPIC | WILLTOPICUPD => {
                body.push(self.build_flags());
                body.extend_from_slice(&self.will_topic);
            },
            WILLMSG | WILLMSGUPD => {
                body.extend_from_slice(&self.will_msg);
            },
            REGISTER => {
                body.extend_from_slice(&self.tid.to_be_bytes());
                body.extend_from_slice(&self.mid.to_be_bytes());
                body.extend_from_slice(&self.topic_name);
            },
            REGACK => {
                body.extend_from_slice(&self.tid.to_be_bytes());
                body.extend_from_slice(&self.mid.to_be_bytes());
                body.push(self.return_code);
            },
            PUBLISH => {
                body.push(self.build_flags());
                body.extend_from_slice(&self.tid.to_be_bytes());
                body.extend_from_slice(&self.mid.to_be_bytes());
                body.extend_from_slice(&self.data);
            },
            PUBACK => {
                body.extend_from_slice(&self.tid.to_be_bytes());
                body.extend_from_slice(&self.mid.to_be_bytes());
                body.push(self.return_code);
            },
            PUBCOMP | PUBREC | PUBREL => {
                body.extend_from_slice(&self.mid.to_be_bytes());
            },
            SUBSCRIBE => {
                body.push(self.build_flags());
                body.extend_from_slice(&self.mid.to_be_bytes());
                // topic: if tid_type is TID_SHORT (2), topic is 2-byte short topic
                // if tid_type is TID_PREDEF (1), topic is 2-byte predefined ID
                // else: UTF-8 topic name
                match self.tid_type {
                    TID_PREDEF => body.extend_from_slice(&self.tid.to_be_bytes()),
                    TID_SHORT => body.extend_from_slice(&self.tid.to_be_bytes()),
                    _ => body.extend_from_slice(&self.topic_name),
                }
            },
            SUBACK => {
                body.push(self.build_flags());
                body.extend_from_slice(&self.tid.to_be_bytes());
                body.extend_from_slice(&self.mid.to_be_bytes());
                body.push(self.return_code);
            },
            UNSUBSCRIBE => {
                body.push(self.build_flags());
                body.extend_from_slice(&self.mid.to_be_bytes());
                match self.tid_type {
                    TID_PREDEF => body.extend_from_slice(&self.tid.to_be_bytes()),
                    TID_SHORT => body.extend_from_slice(&self.tid.to_be_bytes()),
                    _ => body.extend_from_slice(&self.topic_name),
                }
            },
            UNSUBACK => {
                body.extend_from_slice(&self.mid.to_be_bytes());
            },
            PINGREQ => {
                if !self.client_id.is_empty() {
                    body.extend_from_slice(&self.client_id);
                }
            },
            PINGRESP => {
                // Empty body
            },
            DISCONNECT => {
                if self.duration > 0 {
                    body.extend_from_slice(&self.duration.to_be_bytes());
                }
            },
            WILLTOPICRESP | WILLMSGRESP => {
                body.push(self.return_code);
            },
            _ => {},
        }

        body
    }

    // ========================================================================
    // Build
    // ========================================================================

    /// Serialize the MQTT-SN message into bytes.
    ///
    /// Automatically selects 1-byte or 3-byte extended length encoding:
    /// - If total length < 256 and >= 2: single byte
    /// - If total length >= 256: 0x01 prefix + 2-byte BE u16
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let body = self.build_body();
        // Total = length_header + msg_type(1) + body
        // Try 1-byte length first: total = 1 + 1 + body.len()
        let total_short = 2 + body.len();

        if total_short < 256 {
            let mut pkt = Vec::with_capacity(total_short);
            pkt.push(total_short as u8);
            pkt.push(self.msg_type);
            pkt.extend_from_slice(&body);
            pkt
        } else {
            // Extended: 0x01 + 2-byte BE u16 total + msg_type + body
            let total_ext = 3 + 1 + body.len();
            let mut pkt = Vec::with_capacity(total_ext);
            pkt.push(0x01);
            pkt.extend_from_slice(&(total_ext as u16).to_be_bytes());
            pkt.push(self.msg_type);
            pkt.extend_from_slice(&body);
            pkt
        }
    }

    /// Serialize into an existing buffer. Returns the number of bytes written.
    pub fn build_into(&self, buf: &mut Vec<u8>) -> usize {
        let pkt = self.build();
        let len = pkt.len();
        buf.extend_from_slice(&pkt);
        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::mqttsn::{MqttSnLayer, RC_REJ_CONGESTION, RC_REJ_INVALID_TID, TID_NORMAL};
    use crate::layer::{LayerIndex, LayerKind};

    fn make_layer(buf: &[u8]) -> MqttSnLayer {
        let idx = LayerIndex::new(LayerKind::MqttSn, 0, buf.len());
        MqttSnLayer::new(idx)
    }

    // ========================================================================
    // Basic build tests
    // ========================================================================

    #[test]
    fn test_build_advertise() {
        let pkt = MqttSnBuilder::advertise()
            .gw_id(0x98)
            .duration(0x2b9a)
            .build();
        assert_eq!(pkt, b"\x05\x00\x98\x2b\x9a");
    }

    #[test]
    fn test_build_searchgw() {
        let pkt = MqttSnBuilder::searchgw().radius(0xcc).build();
        assert_eq!(pkt, b"\x03\x01\xcc");
    }

    #[test]
    fn test_build_gwinfo() {
        let pkt = MqttSnBuilder::gwinfo()
            .gw_id(0x42)
            .gw_addr(&[192, 168, 1, 1])
            .build();
        assert_eq!(pkt.len(), 7); // 1 + 1 + 1 + 4
        assert_eq!(pkt[0], 7);
        assert_eq!(pkt[1], GWINFO);
        assert_eq!(pkt[2], 0x42);
        assert_eq!(&pkt[3..], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_build_connect() {
        let pkt = MqttSnBuilder::connect()
            .cleansess(true)
            .prot_id(0x1a)
            .duration(0x775b)
            .client_id(b"test")
            .build();
        assert_eq!(pkt, b"\x0a\x04\x04\x1a\x77\x5b\x74\x65\x73\x74");
    }

    #[test]
    fn test_build_connack() {
        let pkt = MqttSnBuilder::connack()
            .return_code(RC_REJ_INVALID_TID)
            .build();
        assert_eq!(pkt, b"\x03\x05\x02");
    }

    #[test]
    fn test_build_publish() {
        let pkt = MqttSnBuilder::publish()
            .qos(2)
            .tid(0x197f)
            .mid(0x6a26)
            .data(b"test")
            .build();
        assert_eq!(
            pkt,
            &[
                0x0b, 0x0c, 0x40, 0x19, 0x7f, 0x6a, 0x26, b't', b'e', b's', b't'
            ]
        );
    }

    #[test]
    fn test_build_puback() {
        let pkt = MqttSnBuilder::puback()
            .tid(0x0001)
            .mid(0x0002)
            .return_code(RC_ACCEPTED)
            .build();
        assert_eq!(pkt.len(), 7);
        assert_eq!(pkt[0], 7);
        assert_eq!(pkt[1], PUBACK);
        assert_eq!(&pkt[2..4], &[0x00, 0x01]); // tid
        assert_eq!(&pkt[4..6], &[0x00, 0x02]); // mid
        assert_eq!(pkt[6], RC_ACCEPTED);
    }

    #[test]
    fn test_build_pubcomp() {
        let pkt = MqttSnBuilder::pubcomp().mid(0x1234).build();
        assert_eq!(pkt.len(), 4);
        assert_eq!(pkt[0], 4);
        assert_eq!(pkt[1], PUBCOMP);
        assert_eq!(&pkt[2..4], &[0x12, 0x34]);
    }

    #[test]
    fn test_build_register() {
        let pkt = MqttSnBuilder::register()
            .tid(0x0001)
            .mid(0x0002)
            .topic_name(b"test/topic")
            .build();
        assert_eq!(pkt.len(), 16); // 1 + 1 + 2 + 2 + 10
        assert_eq!(pkt[0], 16);
        assert_eq!(pkt[1], REGISTER);
        assert_eq!(&pkt[2..4], &[0x00, 0x01]); // tid
        assert_eq!(&pkt[4..6], &[0x00, 0x02]); // mid
        assert_eq!(&pkt[6..], b"test/topic");
    }

    #[test]
    fn test_build_regack() {
        let pkt = MqttSnBuilder::regack()
            .tid(0x0010)
            .mid(0x0020)
            .return_code(RC_ACCEPTED)
            .build();
        assert_eq!(pkt.len(), 7);
        assert_eq!(pkt[0], 7);
        assert_eq!(pkt[1], REGACK);
        assert_eq!(&pkt[2..4], &[0x00, 0x10]); // tid
        assert_eq!(&pkt[4..6], &[0x00, 0x20]); // mid
        assert_eq!(pkt[6], RC_ACCEPTED);
    }

    #[test]
    fn test_build_subscribe_normal_topic() {
        let pkt = MqttSnBuilder::subscribe()
            .qos(1)
            .tid_type(TID_NORMAL)
            .mid(0x0001)
            .topic_name(b"sensors/temp")
            .build();
        assert_eq!(pkt[1], SUBSCRIBE);
        let flags = pkt[2];
        assert_eq!((flags >> 5) & 0x03, 1); // QoS=1
        assert_eq!(flags & 0x03, TID_NORMAL);
        assert_eq!(&pkt[3..5], &[0x00, 0x01]); // mid
        assert_eq!(&pkt[5..], b"sensors/temp");
    }

    #[test]
    fn test_build_subscribe_predef_tid() {
        let pkt = MqttSnBuilder::subscribe()
            .qos(1)
            .tid_type(TID_PREDEF)
            .mid(0x0001)
            .tid(0x0042)
            .build();
        assert_eq!(pkt[1], SUBSCRIBE);
        let flags = pkt[2];
        assert_eq!(flags & 0x03, TID_PREDEF);
        assert_eq!(&pkt[5..7], &[0x00, 0x42]); // predefined tid
    }

    #[test]
    fn test_build_subscribe_short_topic() {
        // Short topic is encoded as a 2-byte value in the tid field
        let short = u16::from_be_bytes([b'a', b'b']);
        let pkt = MqttSnBuilder::subscribe()
            .qos(0)
            .tid_type(TID_SHORT)
            .mid(0x0005)
            .tid(short)
            .build();
        assert_eq!(pkt[1], SUBSCRIBE);
        let flags = pkt[2];
        assert_eq!(flags & 0x03, TID_SHORT);
        assert_eq!(&pkt[5..7], &[b'a', b'b']);
    }

    #[test]
    fn test_build_suback() {
        let pkt = MqttSnBuilder::suback()
            .qos(1)
            .tid(0x0001)
            .mid(0x0002)
            .return_code(RC_ACCEPTED)
            .build();
        assert_eq!(pkt.len(), 8);
        assert_eq!(pkt[0], 8);
        assert_eq!(pkt[1], SUBACK);
        // flags, tid(2), mid(2), rc
        let flags = pkt[2];
        assert_eq!((flags >> 5) & 0x03, 1);
        assert_eq!(&pkt[3..5], &[0x00, 0x01]); // tid
        assert_eq!(&pkt[5..7], &[0x00, 0x02]); // mid
        assert_eq!(pkt[7], RC_ACCEPTED);
    }

    #[test]
    fn test_build_unsubscribe_normal() {
        let pkt = MqttSnBuilder::unsubscribe()
            .tid_type(TID_NORMAL)
            .mid(0x0003)
            .topic_name(b"test/t")
            .build();
        assert_eq!(pkt[1], UNSUBSCRIBE);
        let flags = pkt[2];
        assert_eq!(flags & 0x03, TID_NORMAL);
        assert_eq!(&pkt[3..5], &[0x00, 0x03]); // mid
        assert_eq!(&pkt[5..], b"test/t");
    }

    #[test]
    fn test_build_unsuback() {
        let pkt = MqttSnBuilder::unsuback().mid(0x0003).build();
        assert_eq!(pkt.len(), 4);
        assert_eq!(pkt[0], 4);
        assert_eq!(pkt[1], UNSUBACK);
        assert_eq!(&pkt[2..4], &[0x00, 0x03]);
    }

    #[test]
    fn test_build_pingreq_with_client_id() {
        let pkt = MqttSnBuilder::pingreq().client_id(b"sensor1").build();
        assert_eq!(pkt[0] as usize, pkt.len());
        assert_eq!(pkt[1], PINGREQ);
        assert_eq!(&pkt[2..], b"sensor1");
    }

    #[test]
    fn test_build_pingresp() {
        let pkt = MqttSnBuilder::pingresp().build();
        assert_eq!(pkt, b"\x02\x17");
    }

    #[test]
    fn test_build_disconnect_no_duration() {
        let pkt = MqttSnBuilder::disconnect().build();
        assert_eq!(pkt, b"\x02\x18");
    }

    #[test]
    fn test_build_disconnect_with_duration() {
        let pkt = MqttSnBuilder::disconnect().duration(0x0312).build();
        assert_eq!(pkt, b"\x04\x18\x03\x12");
    }

    #[test]
    fn test_build_willtopic() {
        let pkt = MqttSnBuilder::willtopic()
            .qos(1)
            .retain(true)
            .will_topic_str("lastwill")
            .build();
        assert_eq!(pkt[1], WILLTOPIC);
        let flags = pkt[2];
        assert_eq!((flags >> 5) & 0x03, 1); // QoS=1
        assert_eq!((flags >> 4) & 1, 1); // Retain=true
        assert_eq!(&pkt[3..], b"lastwill");
    }

    #[test]
    fn test_build_willmsg() {
        let pkt = MqttSnBuilder::willmsg().will_msg_bytes(b"goodbye").build();
        assert_eq!(pkt[1], WILLMSG);
        assert_eq!(&pkt[2..], b"goodbye");
    }

    #[test]
    fn test_build_willtopicresp() {
        let pkt = MqttSnBuilder::willtopicresp()
            .return_code(RC_ACCEPTED)
            .build();
        assert_eq!(pkt.len(), 3);
        assert_eq!(pkt[0], 3);
        assert_eq!(pkt[1], WILLTOPICRESP);
        assert_eq!(pkt[2], RC_ACCEPTED);
    }

    #[test]
    fn test_build_willmsgresp() {
        let pkt = MqttSnBuilder::willmsgresp()
            .return_code(RC_REJ_CONGESTION)
            .build();
        assert_eq!(pkt.len(), 3);
        assert_eq!(pkt[0], 3);
        assert_eq!(pkt[1], WILLMSGRESP);
        assert_eq!(pkt[2], RC_REJ_CONGESTION);
    }

    // ========================================================================
    // Round-trip tests (build then parse)
    // ========================================================================

    #[test]
    fn test_roundtrip_connect() {
        let pkt = MqttSnBuilder::connect()
            .cleansess(true)
            .will(true)
            .prot_id(0x01)
            .duration(60)
            .client_id(b"mydevice")
            .build();
        let layer = make_layer(&pkt);
        assert_eq!(layer.msg_type(&pkt).unwrap(), CONNECT);
        assert_eq!(layer.cleansess(&pkt).unwrap(), true);
        assert_eq!(layer.will(&pkt).unwrap(), true);
        assert_eq!(layer.prot_id(&pkt).unwrap(), 0x01);
        assert_eq!(layer.duration(&pkt).unwrap(), 60);
        assert_eq!(layer.client_id(&pkt).unwrap(), "mydevice");
    }

    #[test]
    fn test_roundtrip_publish() {
        let pkt = MqttSnBuilder::publish()
            .dup(true)
            .qos(1)
            .retain(true)
            .tid(0xBEEF)
            .mid(0xCAFE)
            .data(b"hello world")
            .build();
        let layer = make_layer(&pkt);
        assert_eq!(layer.msg_type(&pkt).unwrap(), PUBLISH);
        assert_eq!(layer.dup(&pkt).unwrap(), true);
        assert_eq!(layer.qos(&pkt).unwrap(), 1);
        assert_eq!(layer.retain(&pkt).unwrap(), true);
        assert_eq!(layer.tid(&pkt).unwrap(), 0xBEEF);
        assert_eq!(layer.mid(&pkt).unwrap(), 0xCAFE);
        assert_eq!(layer.data(&pkt).unwrap(), b"hello world");
    }

    #[test]
    fn test_roundtrip_register() {
        let pkt = MqttSnBuilder::register()
            .tid(0x0042)
            .mid(0x0001)
            .topic_name(b"sensors/temp")
            .build();
        let layer = make_layer(&pkt);
        assert_eq!(layer.msg_type(&pkt).unwrap(), REGISTER);
        assert_eq!(layer.tid(&pkt).unwrap(), 0x0042);
        assert_eq!(layer.mid(&pkt).unwrap(), 0x0001);
        assert_eq!(layer.topic_name(&pkt).unwrap(), "sensors/temp");
    }

    #[test]
    fn test_roundtrip_suback() {
        let pkt = MqttSnBuilder::suback()
            .qos(2)
            .tid(0x0010)
            .mid(0x0020)
            .return_code(RC_ACCEPTED)
            .build();
        let layer = make_layer(&pkt);
        assert_eq!(layer.msg_type(&pkt).unwrap(), SUBACK);
        assert_eq!(layer.qos(&pkt).unwrap(), 2);
        assert_eq!(layer.tid(&pkt).unwrap(), 0x0010);
        assert_eq!(layer.mid(&pkt).unwrap(), 0x0020);
        assert_eq!(layer.return_code(&pkt).unwrap(), RC_ACCEPTED);
    }

    #[test]
    fn test_extended_length_builder() {
        // Build a message with a large payload that requires extended length
        let big_data = vec![0xAA; 300];
        let pkt = MqttSnBuilder::publish()
            .qos(0)
            .tid(0x0001)
            .mid(0x0001)
            .data(&big_data)
            .build();
        // Should use extended length encoding (0x01 prefix)
        assert_eq!(pkt[0], 0x01);
        let total_len = u16::from_be_bytes([pkt[1], pkt[2]]);
        assert_eq!(total_len as usize, pkt.len());
        assert_eq!(pkt[3], PUBLISH);
        let layer = make_layer(&pkt);
        assert_eq!(layer.msg_type(&pkt).unwrap(), PUBLISH);
        assert_eq!(layer.data(&pkt).unwrap().len(), 300);
    }

    #[test]
    fn test_flags_all_set() {
        let pkt = MqttSnBuilder::publish()
            .dup(true)
            .qos(3)
            .retain(true)
            .tid_type(TID_SHORT)
            .tid(0x4142) // "AB"
            .mid(0x0001)
            .data(b"x")
            .build();
        let layer = make_layer(&pkt);
        let flags = layer.flags(&pkt).unwrap();
        // DUP=1(bit7), QoS=3(bits6-5), Retain=1(bit4), Will=0(bit3), CleanSess=0(bit2), TidType=2(bits1-0)
        assert_eq!(flags & 0x80, 0x80); // DUP
        assert_eq!((flags >> 5) & 0x03, 3); // QoS
        assert_eq!(flags & 0x10, 0x10); // Retain
        assert_eq!(flags & 0x03, TID_SHORT); // TidType
    }

    #[test]
    fn test_build_into() {
        let builder = MqttSnBuilder::pingresp();
        let mut buf = Vec::new();
        let written = builder.build_into(&mut buf);
        assert_eq!(written, 2);
        assert_eq!(buf, b"\x02\x17");
    }
}
