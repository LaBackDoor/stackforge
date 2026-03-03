//! MQTT packet builder.
//!
//! Provides a fluent API for constructing MQTT packets.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::mqtt::builder::MqttBuilder;
//!
//! // Default: PINGREQ
//! let pkt = MqttBuilder::new().build();
//! assert_eq!(pkt, b"\xc0\x00");
//!
//! // PUBLISH QoS 0
//! let pkt = MqttBuilder::new()
//!     .publish()
//!     .topic(b"test")
//!     .payload(b"hello")
//!     .build();
//! ```

use super::{CONNACK, CONNECT, PUBLISH, SUBACK, SUBSCRIBE, encode_variable_length};

/// Builder for MQTT packets.
///
/// By default, builds a PINGREQ message (`\xC0\x00`).
#[derive(Debug, Clone)]
pub struct MqttBuilder {
    /// MQTT message type (1-15).
    msg_type: u8,
    /// DUP flag.
    dup: bool,
    /// QoS level (0, 1, or 2).
    qos: u8,
    /// RETAIN flag.
    retain: bool,

    // -- CONNECT fields --
    /// Protocol name (default: "MQTT").
    proto_name: Vec<u8>,
    /// Protocol level (default: 4 for MQTT 3.1.1).
    proto_level: u8,
    /// Clean session flag.
    clean_session: bool,
    /// Will flag.
    will_flag: bool,
    /// Will QoS.
    will_qos: u8,
    /// Will retain flag.
    will_retain: bool,
    /// Username flag.
    username_flag: bool,
    /// Password flag.
    password_flag: bool,
    /// Keep alive (seconds).
    keep_alive: u16,
    /// Client ID.
    client_id: Vec<u8>,
    /// Will topic.
    will_topic: Vec<u8>,
    /// Will message.
    will_msg: Vec<u8>,
    /// Username.
    username: Vec<u8>,
    /// Password.
    password: Vec<u8>,

    // -- PUBLISH fields --
    /// Topic for PUBLISH.
    topic: Vec<u8>,
    /// Message ID (used by PUBLISH QoS>0, SUBSCRIBE, SUBACK, etc.).
    msg_id: u16,

    // -- SUBSCRIBE fields --
    /// Topic filters with requested QoS for SUBSCRIBE.
    topics: Vec<(Vec<u8>, u8)>,

    // -- SUBACK fields --
    /// Return codes for SUBACK.
    retcodes: Vec<u8>,

    // -- CONNACK fields --
    /// Session present flag for CONNACK.
    sess_present: u8,
    /// Return code for CONNACK.
    ret_code: u8,

    // -- Generic payload --
    /// Payload/value bytes (used for PUBLISH payload, etc.).
    value: Vec<u8>,
}

impl Default for MqttBuilder {
    fn default() -> Self {
        Self {
            msg_type: 12, // PINGREQ
            dup: false,
            qos: 0,
            retain: false,
            proto_name: b"MQTT".to_vec(),
            proto_level: 4,
            clean_session: false,
            will_flag: false,
            will_qos: 0,
            will_retain: false,
            username_flag: false,
            password_flag: false,
            keep_alive: 0,
            client_id: Vec::new(),
            will_topic: Vec::new(),
            will_msg: Vec::new(),
            username: Vec::new(),
            password: Vec::new(),
            topic: Vec::new(),
            msg_id: 0,
            topics: Vec::new(),
            retcodes: Vec::new(),
            sess_present: 0,
            ret_code: 0,
            value: Vec::new(),
        }
    }
}

impl MqttBuilder {
    /// Create a new MQTT builder. Defaults to PINGREQ (`\xC0\x00`).
    pub fn new() -> Self {
        Self::default()
    }

    // ========== Message type setters ==========

    /// Set message type to CONNECT (1).
    pub fn connect(mut self) -> Self {
        self.msg_type = CONNECT;
        self
    }

    /// Set message type to CONNACK (2).
    pub fn connack(mut self) -> Self {
        self.msg_type = CONNACK;
        self
    }

    /// Set message type to PUBLISH (3).
    pub fn publish(mut self) -> Self {
        self.msg_type = PUBLISH;
        self
    }

    /// Set message type to PUBACK (4).
    pub fn puback(mut self) -> Self {
        self.msg_type = super::PUBACK;
        self
    }

    /// Set message type to PUBREC (5).
    pub fn pubrec(mut self) -> Self {
        self.msg_type = super::PUBREC;
        self
    }

    /// Set message type to PUBREL (6).
    pub fn pubrel(mut self) -> Self {
        self.msg_type = super::PUBREL;
        self
    }

    /// Set message type to PUBCOMP (7).
    pub fn pubcomp(mut self) -> Self {
        self.msg_type = super::PUBCOMP;
        self
    }

    /// Set message type to SUBSCRIBE (8).
    pub fn subscribe(mut self) -> Self {
        self.msg_type = SUBSCRIBE;
        self
    }

    /// Set message type to SUBACK (9).
    pub fn suback(mut self) -> Self {
        self.msg_type = SUBACK;
        self
    }

    /// Set message type to UNSUBSCRIBE (10).
    pub fn unsubscribe(mut self) -> Self {
        self.msg_type = super::UNSUBSCRIBE;
        self
    }

    /// Set message type to UNSUBACK (11).
    pub fn unsuback(mut self) -> Self {
        self.msg_type = super::UNSUBACK;
        self
    }

    /// Set message type to PINGREQ (12, the default).
    pub fn pingreq(mut self) -> Self {
        self.msg_type = super::PINGREQ;
        self
    }

    /// Set message type to PINGRESP (13).
    pub fn pingresp(mut self) -> Self {
        self.msg_type = super::PINGRESP;
        self
    }

    /// Set message type to DISCONNECT (14).
    pub fn disconnect(mut self) -> Self {
        self.msg_type = super::DISCONNECT;
        self
    }

    /// Set the raw message type value.
    pub fn msg_type(mut self, t: u8) -> Self {
        self.msg_type = t;
        self
    }

    // ========== Flag setters ==========

    /// Set the DUP flag.
    pub fn dup(mut self, val: bool) -> Self {
        self.dup = val;
        self
    }

    /// Set the QoS level.
    pub fn qos(mut self, val: u8) -> Self {
        self.qos = val;
        self
    }

    /// Set the RETAIN flag.
    pub fn retain(mut self, val: bool) -> Self {
        self.retain = val;
        self
    }

    // ========== CONNECT field setters ==========

    /// Set the protocol name (default: "MQTT").
    pub fn proto_name<T: Into<Vec<u8>>>(mut self, name: T) -> Self {
        self.proto_name = name.into();
        self
    }

    /// Set the protocol level (default: 4 for MQTT 3.1.1).
    pub fn proto_level(mut self, level: u8) -> Self {
        self.proto_level = level;
        self
    }

    /// Set the clean session flag.
    pub fn clean_session(mut self, val: bool) -> Self {
        self.clean_session = val;
        self
    }

    /// Set the will flag and optionally will topic/message.
    pub fn will(mut self, topic: &[u8], msg: &[u8], qos: u8, retain: bool) -> Self {
        self.will_flag = true;
        self.will_topic = topic.to_vec();
        self.will_msg = msg.to_vec();
        self.will_qos = qos;
        self.will_retain = retain;
        self
    }

    /// Set the username.
    pub fn username<T: Into<Vec<u8>>>(mut self, name: T) -> Self {
        self.username_flag = true;
        self.username = name.into();
        self
    }

    /// Set the password.
    pub fn password<T: Into<Vec<u8>>>(mut self, pass: T) -> Self {
        self.password_flag = true;
        self.password = pass.into();
        self
    }

    /// Set the keep alive value (seconds).
    pub fn keep_alive(mut self, secs: u16) -> Self {
        self.keep_alive = secs;
        self
    }

    /// Set the client ID.
    pub fn client_id<T: Into<Vec<u8>>>(mut self, id: T) -> Self {
        self.client_id = id.into();
        self
    }

    // ========== PUBLISH field setters ==========

    /// Set the topic for PUBLISH.
    pub fn topic<T: Into<Vec<u8>>>(mut self, t: T) -> Self {
        self.topic = t.into();
        self
    }

    /// Set the message ID.
    pub fn msg_id(mut self, id: u16) -> Self {
        self.msg_id = id;
        self
    }

    /// Set the payload/value bytes.
    pub fn payload<T: Into<Vec<u8>>>(mut self, data: T) -> Self {
        self.value = data.into();
        self
    }

    // ========== SUBSCRIBE field setters ==========

    /// Add a topic filter with requested QoS for SUBSCRIBE.
    pub fn add_topic(mut self, filter: &[u8], qos: u8) -> Self {
        self.topics.push((filter.to_vec(), qos));
        self
    }

    // ========== SUBACK field setters ==========

    /// Set the return codes for SUBACK.
    pub fn retcodes<T: Into<Vec<u8>>>(mut self, codes: T) -> Self {
        self.retcodes = codes.into();
        self
    }

    // ========== CONNACK field setters ==========

    /// Set the session present flag for CONNACK.
    pub fn sess_present(mut self, val: u8) -> Self {
        self.sess_present = val;
        self
    }

    /// Set the return code for CONNACK.
    pub fn ret_code(mut self, code: u8) -> Self {
        self.ret_code = code;
        self
    }

    // ========== Size helpers ==========

    /// Compute the size of the variable header + payload (the remaining length).
    pub fn remaining_size(&self) -> usize {
        match self.msg_type {
            CONNECT => {
                // proto_name_len(2) + proto_name(N) + proto_level(1) + connect_flags(1) + keep_alive(2)
                let var_header = 2 + self.proto_name.len() + 1 + 1 + 2;
                // payload: client_id_len(2) + client_id(N)
                let mut payload_len = 2 + self.client_id.len();
                // optional will topic + message
                if self.will_flag {
                    payload_len += 2 + self.will_topic.len() + 2 + self.will_msg.len();
                }
                // optional username
                if self.username_flag {
                    payload_len += 2 + self.username.len();
                }
                // optional password
                if self.password_flag {
                    payload_len += 2 + self.password.len();
                }
                var_header + payload_len
            },
            CONNACK => 2, // session_present(1) + return_code(1)
            PUBLISH => {
                // topic_len(2) + topic(N) + optional msgid(2) + value(N)
                let mut len = 2 + self.topic.len();
                if self.qos > 0 {
                    len += 2; // msg_id
                }
                len += self.value.len();
                len
            },
            super::PUBACK | super::PUBREC | super::PUBREL | super::PUBCOMP | super::UNSUBACK => {
                2 // msg_id(2)
            },
            SUBSCRIBE => {
                // msg_id(2) + topic_filters
                let mut len = 2;
                for (filter, _qos) in &self.topics {
                    len += 2 + filter.len() + 1; // filter_len(2) + filter(N) + qos(1)
                }
                len
            },
            SUBACK => {
                // msg_id(2) + retcodes(N)
                2 + self.retcodes.len()
            },
            super::UNSUBSCRIBE => {
                // msg_id(2) + topic_filters (no qos byte)
                let mut len = 2;
                for (filter, _qos) in &self.topics {
                    len += 2 + filter.len();
                }
                len
            },
            // PINGREQ, PINGRESP, DISCONNECT, AUTH: no variable header or payload
            _ => 0,
        }
    }

    /// Compute the total header size (fixed header bytes only).
    pub fn header_size(&self) -> usize {
        let rem = self.remaining_size() as u32;
        1 + encode_variable_length(rem).len()
    }

    /// Compute the total packet size.
    pub fn packet_size(&self) -> usize {
        self.header_size() + self.remaining_size()
    }

    // ========== Build ==========

    /// Serialize the MQTT packet into bytes.
    pub fn build(&self) -> Vec<u8> {
        let remaining = self.remaining_size();
        let rem_encoded = encode_variable_length(remaining as u32);
        let total = 1 + rem_encoded.len() + remaining;
        let mut buf = Vec::with_capacity(total);

        // Fixed header byte 0: [type(4)] [dup(1)] [qos(2)] [retain(1)]
        let mut byte0: u8 = (self.msg_type & 0x0F) << 4;
        if self.dup {
            byte0 |= 0x08;
        }
        byte0 |= (self.qos & 0x03) << 1;
        if self.retain {
            byte0 |= 0x01;
        }
        // Special fixed flags for SUBSCRIBE (0x02), UNSUBSCRIBE (0x02), PUBREL (0x02)
        match self.msg_type {
            SUBSCRIBE | super::UNSUBSCRIBE | super::PUBREL => {
                byte0 = (self.msg_type << 4) | 0x02;
            },
            _ => {},
        }
        buf.push(byte0);

        // Remaining length
        buf.extend_from_slice(&rem_encoded);

        // Variable header + payload
        match self.msg_type {
            CONNECT => self.build_connect(&mut buf),
            CONNACK => self.build_connack(&mut buf),
            PUBLISH => self.build_publish(&mut buf),
            super::PUBACK | super::PUBREC | super::PUBREL | super::PUBCOMP | super::UNSUBACK => {
                buf.extend_from_slice(&self.msg_id.to_be_bytes());
            },
            SUBSCRIBE => self.build_subscribe(&mut buf),
            SUBACK => self.build_suback(&mut buf),
            super::UNSUBSCRIBE => {
                buf.extend_from_slice(&self.msg_id.to_be_bytes());
                for (filter, _qos) in &self.topics {
                    buf.extend_from_slice(&(filter.len() as u16).to_be_bytes());
                    buf.extend_from_slice(filter);
                }
            },
            // PINGREQ, PINGRESP, DISCONNECT, AUTH: nothing to add
            _ => {},
        }

        buf
    }

    fn build_connect(&self, buf: &mut Vec<u8>) {
        // Protocol name
        buf.extend_from_slice(&(self.proto_name.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.proto_name);

        // Protocol level
        buf.push(self.proto_level);

        // Connect flags
        let mut flags: u8 = 0;
        if self.username_flag {
            flags |= 0x80;
        }
        if self.password_flag {
            flags |= 0x40;
        }
        if self.will_retain {
            flags |= 0x20;
        }
        flags |= (self.will_qos & 0x03) << 3;
        if self.will_flag {
            flags |= 0x04;
        }
        if self.clean_session {
            flags |= 0x02;
        }
        buf.push(flags);

        // Keep alive
        buf.extend_from_slice(&self.keep_alive.to_be_bytes());

        // Payload: client ID
        buf.extend_from_slice(&(self.client_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.client_id);

        // Optional will topic + message
        if self.will_flag {
            buf.extend_from_slice(&(self.will_topic.len() as u16).to_be_bytes());
            buf.extend_from_slice(&self.will_topic);
            buf.extend_from_slice(&(self.will_msg.len() as u16).to_be_bytes());
            buf.extend_from_slice(&self.will_msg);
        }

        // Optional username
        if self.username_flag {
            buf.extend_from_slice(&(self.username.len() as u16).to_be_bytes());
            buf.extend_from_slice(&self.username);
        }

        // Optional password
        if self.password_flag {
            buf.extend_from_slice(&(self.password.len() as u16).to_be_bytes());
            buf.extend_from_slice(&self.password);
        }
    }

    fn build_connack(&self, buf: &mut Vec<u8>) {
        buf.push(self.sess_present & 0x01);
        buf.push(self.ret_code);
    }

    fn build_publish(&self, buf: &mut Vec<u8>) {
        // Topic
        buf.extend_from_slice(&(self.topic.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.topic);

        // Message ID (only if QoS > 0)
        if self.qos > 0 {
            buf.extend_from_slice(&self.msg_id.to_be_bytes());
        }

        // Payload
        buf.extend_from_slice(&self.value);
    }

    fn build_subscribe(&self, buf: &mut Vec<u8>) {
        // Message ID
        buf.extend_from_slice(&self.msg_id.to_be_bytes());

        // Topic filters
        for (filter, qos) in &self.topics {
            buf.extend_from_slice(&(filter.len() as u16).to_be_bytes());
            buf.extend_from_slice(filter);
            buf.push(*qos);
        }
    }

    fn build_suback(&self, buf: &mut Vec<u8>) {
        // Message ID
        buf.extend_from_slice(&self.msg_id.to_be_bytes());

        // Return codes
        buf.extend_from_slice(&self.retcodes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_pingreq() {
        let pkt = MqttBuilder::new().build();
        assert_eq!(pkt, b"\xc0\x00", "default PINGREQ should be 0xC0 0x00");
    }

    #[test]
    fn test_pingresp() {
        let pkt = MqttBuilder::new().pingresp().build();
        assert_eq!(pkt, b"\xd0\x00");
    }

    #[test]
    fn test_disconnect() {
        let pkt = MqttBuilder::new().disconnect().build();
        assert_eq!(pkt, b"\xe0\x00");
    }

    #[test]
    fn test_connack() {
        let pkt = MqttBuilder::new()
            .connack()
            .sess_present(0)
            .ret_code(0)
            .build();
        assert_eq!(pkt, b"\x20\x02\x00\x00");
    }

    #[test]
    fn test_connack_with_retcode() {
        let pkt = MqttBuilder::new().connack().ret_code(5).build();
        assert_eq!(pkt.len(), 4);
        assert_eq!(pkt[0], 0x20); // CONNACK
        assert_eq!(pkt[1], 0x02); // remaining length = 2
        assert_eq!(pkt[2], 0x00); // session present = 0
        assert_eq!(pkt[3], 0x05); // return code = 5 (not authorized)
    }

    #[test]
    fn test_publish_qos0() {
        let pkt = MqttBuilder::new()
            .publish()
            .topic(b"test".to_vec())
            .payload(b"test".to_vec())
            .build();
        // Fixed header: 0x30 (PUBLISH, QoS0, no dup, no retain)
        // Remaining length: 10 (2 + 4 + 4)
        // Variable header: 00 04 "test"
        // Payload: "test"
        assert_eq!(pkt, b"\x30\x0a\x00\x04test\x74\x65\x73\x74");
        // That is: 0x30, 0x0a, 0x00, 0x04, t, e, s, t, t, e, s, t
        assert_eq!(pkt[0], 0x30);
        assert_eq!(pkt[1], 0x0a);
        assert_eq!(pkt.len(), 12);
    }

    #[test]
    fn test_publish_qos1() {
        let pkt = MqttBuilder::new()
            .publish()
            .qos(1)
            .topic(b"test".to_vec())
            .msg_id(10)
            .payload(b"data".to_vec())
            .build();
        // Fixed header: 0x32 (PUBLISH, QoS1)
        // Remaining length: 12 = 2 + 4 + 2 + 4
        assert_eq!(pkt[0], 0x32);
        assert_eq!(pkt[1], 12);
        // Topic: 00 04 "test"
        assert_eq!(&pkt[2..4], &[0x00, 0x04]);
        assert_eq!(&pkt[4..8], b"test");
        // Message ID: 00 0a
        assert_eq!(&pkt[8..10], &[0x00, 0x0a]);
        // Payload: "data"
        assert_eq!(&pkt[10..14], b"data");
    }

    #[test]
    fn test_connect_default() {
        let pkt = MqttBuilder::new()
            .connect()
            .client_id(b"test")
            .clean_session(true)
            .keep_alive(60)
            .build();

        // byte 0: 0x10 (CONNECT)
        assert_eq!(pkt[0], 0x10);
        // remaining length: 2(proto_name_len) + 4("MQTT") + 1(level) + 1(flags) + 2(keepalive) + 2(client_id_len) + 4("test") = 16
        assert_eq!(pkt[1], 16);
        // proto name
        assert_eq!(&pkt[2..4], &[0x00, 0x04]);
        assert_eq!(&pkt[4..8], b"MQTT");
        // proto level
        assert_eq!(pkt[8], 4);
        // connect flags: clean session = 0x02
        assert_eq!(pkt[9], 0x02);
        // keep alive: 60 = 0x003c
        assert_eq!(&pkt[10..12], &[0x00, 0x3c]);
        // client id
        assert_eq!(&pkt[12..14], &[0x00, 0x04]);
        assert_eq!(&pkt[14..18], b"test");
    }

    #[test]
    fn test_connect_mqisdp() {
        // MQIsdp v3
        let pkt = MqttBuilder::new()
            .connect()
            .proto_name(b"MQIsdp".to_vec())
            .proto_level(3)
            .clean_session(true)
            .keep_alive(60)
            .client_id(b"mosqpub/1440-kali".to_vec())
            .build();

        assert_eq!(pkt[0], 0x10); // CONNECT
        // rem len = 2+6+1+1+2+2+17 = 31 = 0x1f
        assert_eq!(pkt[1], 0x1f);
        assert_eq!(&pkt[2..4], &[0x00, 0x06]);
        assert_eq!(&pkt[4..10], b"MQIsdp");
        assert_eq!(pkt[10], 3); // proto level
        assert_eq!(pkt[11], 0x02); // clean session
        assert_eq!(&pkt[12..14], &[0x00, 0x3c]); // keep alive 60
        assert_eq!(&pkt[14..16], &[0x00, 0x11]); // client id len 17
        assert_eq!(&pkt[16..33], b"mosqpub/1440-kali");
    }

    #[test]
    fn test_subscribe() {
        let pkt = MqttBuilder::new()
            .subscribe()
            .msg_id(1)
            .add_topic(b"test", 1)
            .build();
        // Fixed header: 0x82 (SUBSCRIBE with reserved bits 0x02)
        assert_eq!(pkt[0], 0x82);
        // Remaining length: 2(msgid) + 2(filter_len) + 4("test") + 1(qos) = 9
        assert_eq!(pkt[1], 9);
        // Message ID: 0x0001
        assert_eq!(&pkt[2..4], &[0x00, 0x01]);
        // Topic filter len: 4
        assert_eq!(&pkt[4..6], &[0x00, 0x04]);
        // Topic filter: "test"
        assert_eq!(&pkt[6..10], b"test");
        // QoS: 1
        assert_eq!(pkt[10], 0x01);
    }

    #[test]
    fn test_suback() {
        let pkt = MqttBuilder::new()
            .suback()
            .msg_id(1)
            .retcodes(vec![0x00])
            .build();
        // SUBACK: \x90\x03\x00\x01\x00
        assert_eq!(pkt, b"\x90\x03\x00\x01\x00");
    }

    #[test]
    fn test_puback() {
        let pkt = MqttBuilder::new().puback().msg_id(10).build();
        assert_eq!(pkt, b"\x40\x02\x00\x0a");
    }

    #[test]
    fn test_packet_size() {
        let b = MqttBuilder::new(); // PINGREQ
        assert_eq!(b.packet_size(), 2);
        assert_eq!(b.header_size(), 2);
        assert_eq!(b.remaining_size(), 0);
    }
}
