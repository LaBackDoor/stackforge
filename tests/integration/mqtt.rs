//! MQTT protocol integration tests.
//!
//! Tests MQTT parsing, building, full-stack packet handling, and field access
//! for CONNECT, CONNACK, PUBLISH, SUBSCRIBE, PINGREQ, and DISCONNECT messages.

use stackforge_core::layer::mqtt::{
    CONNACK, CONNECT, DISCONNECT, MQTT_FIELD_NAMES, MQTT_MIN_HEADER_LEN, MqttBuilder, MqttLayer,
    PINGREQ, PUBLISH, SUBSCRIBE, is_mqtt_payload, message_type_name,
};
use stackforge_core::layer::stack::{LayerStack, LayerStackEntry};
use stackforge_core::layer::tcp::builder::TcpBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerIndex, LayerKind};
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

// ============================================================================
// Helper: wrap MQTT bytes in an Eth/IP/TCP/MQTT full-stack packet
// ============================================================================

fn build_mqtt_stack_packet(mqtt_builder: MqttBuilder) -> Packet {
    let raw = LayerStack::new()
        .push(LayerStackEntry::Ethernet(
            EthernetBuilder::new()
                .dst(MacAddress::BROADCAST)
                .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        ))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(192, 168, 1, 10))
                .dst(Ipv4Addr::new(192, 168, 1, 20))
                .ttl(64),
        ))
        .push(LayerStackEntry::Tcp(
            TcpBuilder::new().src_port(54321).dst_port(1883),
        ))
        .push(LayerStackEntry::Mqtt(mqtt_builder))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    pkt
}

// ============================================================================
// PUBLISH build-parse roundtrip
// ============================================================================

#[test]
fn test_mqtt_publish_build_parse_roundtrip() {
    let pkt = build_mqtt_stack_packet(
        MqttBuilder::new()
            .publish()
            .topic(b"sensor/temperature".to_vec())
            .payload(b"22.5".to_vec()),
    );

    // All layers should be present
    assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
    assert!(pkt.get_layer(LayerKind::Ipv4).is_some());
    assert!(pkt.get_layer(LayerKind::Tcp).is_some());
    assert!(pkt.get_layer(LayerKind::Mqtt).is_some());

    let mqtt = pkt.mqtt().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(mqtt.msg_type(buf).unwrap(), PUBLISH);
    assert_eq!(mqtt.qos(buf).unwrap(), 0);
    assert!(!mqtt.dup(buf).unwrap());
    assert!(!mqtt.retain(buf).unwrap());
    assert_eq!(mqtt.topic(buf).unwrap(), "sensor/temperature");
    assert_eq!(mqtt.value(buf).unwrap(), b"22.5");
}

// ============================================================================
// CONNECT build-parse roundtrip
// ============================================================================

#[test]
fn test_mqtt_connect_build_parse_roundtrip() {
    let pkt = build_mqtt_stack_packet(
        MqttBuilder::new()
            .connect()
            .proto_name(b"MQTT".to_vec())
            .proto_level(4)
            .clean_session(true)
            .keep_alive(60)
            .client_id(b"stackforge-client".to_vec()),
    );

    assert!(pkt.get_layer(LayerKind::Mqtt).is_some());

    let mqtt = pkt.mqtt().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(mqtt.msg_type(buf).unwrap(), CONNECT);
    assert_eq!(mqtt.proto_name(buf).unwrap(), "MQTT");
    assert_eq!(mqtt.proto_level(buf).unwrap(), 4);
    assert!(mqtt.cleansess(buf).unwrap());
    assert_eq!(mqtt.klive(buf).unwrap(), 60);
    assert_eq!(mqtt.client_id(buf).unwrap(), "stackforge-client");
}

// ============================================================================
// CONNACK parse from raw bytes
// ============================================================================

#[test]
fn test_mqtt_connack_parse() {
    // CONNACK: 0x20 0x02 0x00 0x00 (session present=0, return code=0)
    let raw = vec![0x20, 0x02, 0x00, 0x00];
    assert!(is_mqtt_payload(&raw));

    let idx = LayerIndex::new(LayerKind::Mqtt, 0, raw.len());
    let layer = MqttLayer::new(idx);
    assert_eq!(layer.msg_type(&raw).unwrap(), CONNACK);
    assert_eq!(layer.remaining_length(&raw).unwrap(), 2);
    assert_eq!(layer.sess_present_flag(&raw).unwrap(), 0);
    assert_eq!(layer.retcode(&raw).unwrap(), 0);
}

// ============================================================================
// SUBSCRIBE parse from raw bytes
// ============================================================================

#[test]
fn test_mqtt_subscribe_parse() {
    // Build a SUBSCRIBE packet via the builder, then parse it
    let raw = MqttBuilder::new()
        .subscribe()
        .msg_id(42)
        .add_topic(b"home/+/temp", 1)
        .build();

    let idx = LayerIndex::new(LayerKind::Mqtt, 0, raw.len());
    let layer = MqttLayer::new(idx);
    assert_eq!(layer.msg_type(&raw).unwrap(), SUBSCRIBE);
    assert_eq!(layer.msgid(&raw).unwrap(), 42);
}

// ============================================================================
// PINGREQ parse
// ============================================================================

#[test]
fn test_mqtt_pingreq_parse() {
    let raw: Vec<u8> = vec![0xC0, 0x00];
    assert!(is_mqtt_payload(&raw));

    let idx = LayerIndex::new(LayerKind::Mqtt, 0, raw.len());
    let layer = MqttLayer::new(idx);
    assert_eq!(layer.msg_type(&raw).unwrap(), PINGREQ);
    assert_eq!(layer.remaining_length(&raw).unwrap(), 0);
}

// ============================================================================
// DISCONNECT parse
// ============================================================================

#[test]
fn test_mqtt_disconnect_parse() {
    let raw: Vec<u8> = vec![0xE0, 0x00];
    assert!(is_mqtt_payload(&raw));

    let idx = LayerIndex::new(LayerKind::Mqtt, 0, raw.len());
    let layer = MqttLayer::new(idx);
    assert_eq!(layer.msg_type(&raw).unwrap(), DISCONNECT);
    assert_eq!(layer.remaining_length(&raw).unwrap(), 0);
}

// ============================================================================
// Field access via typed accessor
// ============================================================================

#[test]
fn test_mqtt_field_access() {
    let pkt = build_mqtt_stack_packet(
        MqttBuilder::new()
            .publish()
            .qos(1)
            .dup(true)
            .retain(true)
            .topic(b"test/topic".to_vec())
            .msg_id(100)
            .payload(b"payload".to_vec()),
    );

    let mqtt = pkt.mqtt().unwrap();
    let buf = pkt.as_bytes();

    assert_eq!(mqtt.msg_type(buf).unwrap(), PUBLISH);
    assert!(mqtt.dup(buf).unwrap());
    assert_eq!(mqtt.qos(buf).unwrap(), 1);
    assert!(mqtt.retain(buf).unwrap());
    assert_eq!(mqtt.topic(buf).unwrap(), "test/topic");
    assert_eq!(mqtt.topic_len(buf).unwrap(), 10);
    assert_eq!(mqtt.msgid(buf).unwrap(), 100);
    assert_eq!(mqtt.value(buf).unwrap(), b"payload");
}

// ============================================================================
// Layer detection on port 1883
// ============================================================================

#[test]
fn test_mqtt_layer_detection() {
    let pkt = build_mqtt_stack_packet(MqttBuilder::new().pingreq());

    assert!(pkt.get_layer(LayerKind::Mqtt).is_some());

    let tcp = pkt.tcp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(tcp.dst_port(buf).unwrap(), 1883);
}

// ============================================================================
// Builder raw bytes verification
// ============================================================================

#[test]
fn test_mqtt_builder_raw_bytes() {
    // Default builder produces PINGREQ
    let default_pkt = MqttBuilder::new().build();
    assert_eq!(default_pkt, b"\xC0\x00");

    // PUBLISH QoS0
    let pub_pkt = MqttBuilder::new()
        .publish()
        .topic(b"test".to_vec())
        .payload(b"hello".to_vec())
        .build();

    // Fixed header: 0x30 (PUBLISH, QoS0)
    assert_eq!(pub_pkt[0], 0x30);
    // Remaining length: 2 (topic_len) + 4 (topic) + 5 (payload) = 11
    assert_eq!(pub_pkt[1], 11);
    // Topic length: 0x00 0x04
    assert_eq!(&pub_pkt[2..4], &[0x00, 0x04]);
    // Topic: "test"
    assert_eq!(&pub_pkt[4..8], b"test");
    // Payload: "hello"
    assert_eq!(&pub_pkt[8..13], b"hello");
}

// ============================================================================
// MQTT_FIELD_NAMES contains expected names
// ============================================================================

#[test]
fn test_mqtt_field_names() {
    assert!(MQTT_FIELD_NAMES.contains(&"msg_type"));
    assert!(MQTT_FIELD_NAMES.contains(&"dup"));
    assert!(MQTT_FIELD_NAMES.contains(&"qos"));
    assert!(MQTT_FIELD_NAMES.contains(&"retain"));
    assert!(MQTT_FIELD_NAMES.contains(&"remaining_length"));
    assert!(MQTT_FIELD_NAMES.contains(&"topic"));
    assert!(MQTT_FIELD_NAMES.contains(&"proto_name"));
    assert!(MQTT_FIELD_NAMES.contains(&"proto_level"));
    assert!(MQTT_FIELD_NAMES.contains(&"klive"));
    assert!(MQTT_FIELD_NAMES.contains(&"client_id"));
    assert!(MQTT_FIELD_NAMES.contains(&"cleansess"));
}

// ============================================================================
// PUBLISH with QoS 1 includes message ID
// ============================================================================

#[test]
fn test_mqtt_publish_qos1_msgid() {
    let raw = MqttBuilder::new()
        .publish()
        .qos(1)
        .topic(b"q1".to_vec())
        .msg_id(7)
        .payload(b"v".to_vec())
        .build();

    let idx = LayerIndex::new(LayerKind::Mqtt, 0, raw.len());
    let layer = MqttLayer::new(idx);
    assert_eq!(layer.msg_type(&raw).unwrap(), PUBLISH);
    assert_eq!(layer.qos(&raw).unwrap(), 1);
    assert_eq!(layer.topic(&raw).unwrap(), "q1");
    assert_eq!(layer.msgid(&raw).unwrap(), 7);
    assert_eq!(layer.value(&raw).unwrap(), b"v");
}

// ============================================================================
// CONNECT with MQIsdp v3 protocol name
// ============================================================================

#[test]
fn test_mqtt_connect_mqisdp_v3() {
    let raw = MqttBuilder::new()
        .connect()
        .proto_name(b"MQIsdp".to_vec())
        .proto_level(3)
        .clean_session(true)
        .keep_alive(60)
        .client_id(b"old-client".to_vec())
        .build();

    let idx = LayerIndex::new(LayerKind::Mqtt, 0, raw.len());
    let layer = MqttLayer::new(idx);
    assert_eq!(layer.msg_type(&raw).unwrap(), CONNECT);
    assert_eq!(layer.proto_name(&raw).unwrap(), "MQIsdp");
    assert_eq!(layer.proto_level(&raw).unwrap(), 3);
    assert!(layer.cleansess(&raw).unwrap());
    assert_eq!(layer.klive(&raw).unwrap(), 60);
    assert_eq!(layer.client_id(&raw).unwrap(), "old-client");
}

// ============================================================================
// CONNACK with non-zero return code
// ============================================================================

#[test]
fn test_mqtt_connack_refused() {
    let raw = MqttBuilder::new().connack().ret_code(5).build();

    let idx = LayerIndex::new(LayerKind::Mqtt, 0, raw.len());
    let layer = MqttLayer::new(idx);
    assert_eq!(layer.msg_type(&raw).unwrap(), CONNACK);
    assert_eq!(layer.retcode(&raw).unwrap(), 5);
}

// ============================================================================
// Summary strings
// ============================================================================

#[test]
fn test_mqtt_summary_publish() {
    let raw = MqttBuilder::new()
        .publish()
        .topic(b"status".to_vec())
        .build();

    let idx = LayerIndex::new(LayerKind::Mqtt, 0, raw.len());
    let layer = MqttLayer::new(idx);
    let summary = layer.summary(&raw);
    assert!(summary.contains("MQTT"));
    assert!(summary.contains("PUBLISH"));
    assert!(summary.contains("status"));
}

// ============================================================================
// Message type name function
// ============================================================================

#[test]
fn test_mqtt_message_type_names() {
    assert_eq!(message_type_name(1), "CONNECT");
    assert_eq!(message_type_name(2), "CONNACK");
    assert_eq!(message_type_name(3), "PUBLISH");
    assert_eq!(message_type_name(8), "SUBSCRIBE");
    assert_eq!(message_type_name(12), "PINGREQ");
    assert_eq!(message_type_name(14), "DISCONNECT");
    assert_eq!(message_type_name(0), "UNKNOWN");
}

// ============================================================================
// is_mqtt_payload detection
// ============================================================================

#[test]
fn test_mqtt_payload_detection() {
    // Valid PINGREQ
    assert!(is_mqtt_payload(&[0xC0, 0x00]));

    // Valid CONNECT header
    let connect = MqttBuilder::new().connect().client_id(b"test").build();
    assert!(is_mqtt_payload(&connect));

    // Too short
    assert!(!is_mqtt_payload(&[0xC0]));

    // Invalid message type (type = 0)
    assert!(!is_mqtt_payload(&[0x00, 0x00]));
}

// ============================================================================
// MQTT minimum header length constant
// ============================================================================

#[test]
fn test_mqtt_min_header_len() {
    assert_eq!(MQTT_MIN_HEADER_LEN, 2);
}
