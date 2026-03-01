//! QUIC protocol integration tests.
//!
//! Tests QUIC varint encoding/decoding, long/short header parsing,
//! packet building, frame parsing, and field access.

use stackforge_core::FieldValue;
use stackforge_core::layer::LayerKind;
use stackforge_core::layer::quic::{
    QuicBuilder, QuicLayer,
    frames::{FrameType, parse_frames},
    headers::{QuicLongHeader, QuicPacketType, QuicShortHeader, packet_type},
    varint,
};

// ============================================================================
// Varint encode/decode — 1-byte (6-bit value, max 63)
// ============================================================================

#[test]
fn test_varint_encode_1byte_zero() {
    let encoded = varint::encode(0);
    assert_eq!(encoded, vec![0x00]);
}

#[test]
fn test_varint_encode_1byte_max() {
    let encoded = varint::encode(63);
    assert_eq!(encoded.len(), 1);
    let (v, n) = varint::decode(&encoded).unwrap();
    assert_eq!(v, 63);
    assert_eq!(n, 1);
}

#[test]
fn test_varint_decode_1byte() {
    let buf = [0x25u8]; // 0b00100101 = 37
    let (val, len) = varint::decode(&buf).unwrap();
    assert_eq!(val, 37);
    assert_eq!(len, 1);
}

// ============================================================================
// Varint encode/decode — 2-byte (14-bit value, max 16383)
// ============================================================================

#[test]
fn test_varint_encode_2byte_min() {
    let encoded = varint::encode(64);
    assert_eq!(encoded.len(), 2);
    let (v, n) = varint::decode(&encoded).unwrap();
    assert_eq!(v, 64);
    assert_eq!(n, 2);
}

#[test]
fn test_varint_encode_2byte_max() {
    let encoded = varint::encode(16383);
    assert_eq!(encoded.len(), 2);
    let (v, n) = varint::decode(&encoded).unwrap();
    assert_eq!(v, 16383);
    assert_eq!(n, 2);
}

#[test]
fn test_varint_decode_2bytes() {
    let buf = [0x40u8, 0x01u8]; // 2-byte encoding of value 1
    let (val, len) = varint::decode(&buf).unwrap();
    assert_eq!(val, 1);
    assert_eq!(len, 2);
}

// ============================================================================
// Varint encode/decode — 4-byte (30-bit value, max 1073741823)
// ============================================================================

#[test]
fn test_varint_encode_4byte_min() {
    let encoded = varint::encode(16384);
    assert_eq!(encoded.len(), 4);
    let (v, n) = varint::decode(&encoded).unwrap();
    assert_eq!(v, 16384);
    assert_eq!(n, 4);
}

#[test]
fn test_varint_decode_4bytes() {
    let v = 494_878_333u32;
    let encoded = (v | 0x8000_0000u32).to_be_bytes();
    let (val, len) = varint::decode(&encoded).unwrap();
    assert_eq!(val, v as u64);
    assert_eq!(len, 4);
}

// ============================================================================
// Varint encode/decode — 8-byte (62-bit value, max 4611686018427387903)
// ============================================================================

#[test]
fn test_varint_encode_8byte() {
    let v = 1_073_741_824u64; // first value requiring 8-byte encoding
    let encoded = varint::encode(v);
    assert_eq!(encoded.len(), 8);
    let (decoded, n) = varint::decode(&encoded).unwrap();
    assert_eq!(decoded, v);
    assert_eq!(n, 8);
}

#[test]
fn test_varint_encode_decode_max_value() {
    let v = varint::VARINT_MAX;
    let encoded = varint::encode(v);
    assert_eq!(encoded.len(), 8);
    let (decoded, _) = varint::decode(&encoded).unwrap();
    assert_eq!(decoded, v);
}

// ============================================================================
// Varint roundtrip for boundary values
// ============================================================================

#[test]
fn test_varint_roundtrip_boundary_values() {
    let values = [
        0u64,
        1,
        63,
        64,
        16383,
        16384,
        1_073_741_823,
        1_073_741_824,
        varint::VARINT_MAX,
    ];
    for &v in &values {
        let encoded = varint::encode(v);
        let (decoded, _) = varint::decode(&encoded).unwrap();
        assert_eq!(decoded, v, "roundtrip failed for {}", v);
    }
}

#[test]
fn test_varint_decode_empty() {
    assert!(varint::decode(&[]).is_none());
}

#[test]
fn test_varint_decode_too_short_2byte() {
    assert!(varint::decode(&[0x40]).is_none()); // 2-byte prefix but only 1 byte
}

#[test]
fn test_varint_decode_too_short_4byte() {
    assert!(varint::decode(&[0x80, 0x01]).is_none()); // 4-byte prefix but only 2 bytes
}

// ============================================================================
// QUIC long header parse — Initial packet
// ============================================================================

#[test]
fn test_quic_long_header_parse_initial() {
    let buf = QuicBuilder::initial()
        .version(1)
        .dst_conn_id(vec![0x01, 0x02, 0x03, 0x04])
        .src_conn_id(vec![])
        .payload(vec![])
        .build();

    let hdr = QuicLongHeader::parse(&buf).unwrap();
    assert_eq!(hdr.packet_type, QuicPacketType::Initial);
    assert_eq!(hdr.version, 1);
    assert_eq!(hdr.dst_conn_id, vec![0x01, 0x02, 0x03, 0x04]);
    assert_eq!(hdr.src_conn_id, vec![]);
}

#[test]
fn test_quic_long_header_parse_version() {
    let buf = QuicBuilder::initial()
        .version(0x51474F4F) // QUIC/Go test version
        .build();
    let hdr = QuicLongHeader::parse(&buf).unwrap();
    assert_eq!(hdr.version, 0x51474F4F);
}

#[test]
fn test_quic_long_header_parse_with_src_conn_id() {
    let buf = QuicBuilder::initial()
        .dst_conn_id(vec![0xDE, 0xAD, 0xBE, 0xEF])
        .src_conn_id(vec![0x11, 0x22])
        .build();
    let hdr = QuicLongHeader::parse(&buf).unwrap();
    assert_eq!(hdr.dst_conn_id, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(hdr.src_conn_id, vec![0x11, 0x22]);
}

#[test]
fn test_quic_long_header_too_short_returns_none() {
    assert!(QuicLongHeader::parse(&[0xC0u8, 0x00, 0x00]).is_none());
}

// ============================================================================
// QUIC short header parse — 1-RTT packet
// ============================================================================

#[test]
fn test_quic_short_header_parse() {
    let buf = QuicBuilder::one_rtt()
        .payload(vec![0x01]) // PING frame
        .build();

    let hdr = QuicShortHeader::parse(&buf).unwrap();
    assert_eq!(hdr.dst_conn_id, vec![]);
    assert_eq!(hdr.header_len, 1);
}

#[test]
fn test_quic_short_header_with_conn_id() {
    let buf = vec![0x40u8, 0xAA, 0xBB, 0xCC, 0xDD]; // short header + 4-byte conn id
    let hdr = QuicShortHeader::parse_with_conn_id_len(&buf, 4).unwrap();
    assert_eq!(hdr.dst_conn_id, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(hdr.header_len, 5);
}

#[test]
fn test_quic_long_header_rejected_as_short() {
    let buf = QuicBuilder::initial().build();
    assert!(QuicShortHeader::parse(&buf).is_none());
}

#[test]
fn test_quic_short_header_bit7_is_zero() {
    let buf = QuicBuilder::one_rtt().payload(vec![]).build();
    assert_eq!(buf[0] & 0x80, 0x00); // header form = 0
    assert_eq!(buf[0] & 0x40, 0x40); // fixed bit = 1
}

// ============================================================================
// QUIC builder Initial packet build + parse back
// ============================================================================

#[test]
fn test_quic_initial_build_parse_roundtrip() {
    let bytes = QuicBuilder::initial()
        .version(1)
        .dst_conn_id(vec![0x01, 0x02, 0x03, 0x04])
        .src_conn_id(vec![0xAA, 0xBB])
        .build();

    let layer = QuicLayer::new(0, bytes.len());
    assert!(layer.is_long_header(&bytes));
    assert_eq!(layer.packet_type(&bytes), Some(QuicPacketType::Initial));
    assert_eq!(layer.version(&bytes), Some(1));
}

#[test]
fn test_quic_initial_build_long_header_bit() {
    let bytes = QuicBuilder::initial().build();
    assert_eq!(bytes[0] & 0x80, 0x80); // long header bit = 1
    assert_eq!(bytes[0] & 0x40, 0x40); // fixed bit = 1
    assert_eq!((bytes[0] & 0x30) >> 4, 0x00); // packet type = Initial (0)
}

#[test]
fn test_quic_handshake_build() {
    let bytes = QuicBuilder::handshake()
        .dst_conn_id(vec![0x01])
        .payload(vec![0x06, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF])
        .build();

    let hdr = QuicLongHeader::parse(&bytes).unwrap();
    assert_eq!(hdr.packet_type, QuicPacketType::Handshake);
}

// ============================================================================
// QUIC frame parse — PADDING, PING, ACK, STREAM
// ============================================================================

#[test]
fn test_quic_frame_parse_padding() {
    let buf = [0x00u8]; // one PADDING frame
    let frames = parse_frames(&buf);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::Padding);
    assert_eq!(frames[0].length, 1);
}

#[test]
fn test_quic_frame_parse_ping() {
    let buf = [0x01u8]; // PING frame
    let frames = parse_frames(&buf);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::Ping);
    assert_eq!(frames[0].length, 1);
}

#[test]
fn test_quic_frame_parse_padding_then_ping() {
    let buf = [0x00u8, 0x00, 0x01]; // 2x PADDING + PING
    let frames = parse_frames(&buf);
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].frame_type, FrameType::Padding);
    assert_eq!(frames[1].frame_type, FrameType::Padding);
    assert_eq!(frames[2].frame_type, FrameType::Ping);
}

#[test]
fn test_quic_frame_parse_stream_with_length() {
    // STREAM type 0x0A: OFF=0, LEN=1, FIN=0
    // stream_id=1(1 byte), length=2(1 byte), data=0xAA,0xBB
    let buf = [0x0Au8, 0x01, 0x02, 0xAA, 0xBB];
    let frames = parse_frames(&buf);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::Stream);
    assert_eq!(frames[0].length, 5);
}

#[test]
fn test_quic_frame_parse_handshake_done() {
    let buf = [0x1Eu8]; // HANDSHAKE_DONE
    let frames = parse_frames(&buf);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::HandshakeDone);
}

#[test]
fn test_quic_frame_parse_crypto() {
    // CRYPTO: type=0x06, offset=0(varint=0x00), length=4(varint=0x04), data
    let buf = [0x06u8, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
    let frames = parse_frames(&buf);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::Crypto);
    assert_eq!(frames[0].length, 7);
}

#[test]
fn test_quic_frame_stops_on_unknown() {
    let buf = [0x01u8, 0xFF]; // PING, then Unknown
    let frames = parse_frames(&buf);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::Ping);
}

#[test]
fn test_quic_frame_type_names() {
    assert_eq!(FrameType::Padding.name(), "PADDING");
    assert_eq!(FrameType::Ping.name(), "PING");
    assert_eq!(FrameType::Ack.name(), "ACK");
    assert_eq!(FrameType::Stream.name(), "STREAM");
    assert_eq!(FrameType::Crypto.name(), "CRYPTO");
    assert_eq!(FrameType::HandshakeDone.name(), "HANDSHAKE_DONE");
    assert_eq!(FrameType::Unknown(0xFF).name(), "UNKNOWN");
}

// ============================================================================
// QUIC layer kind check
// ============================================================================

#[test]
fn test_quic_layer_kind() {
    use stackforge_core::layer::Layer;
    let buf = QuicBuilder::initial().build();
    let layer = QuicLayer::new(0, buf.len());
    assert_eq!(layer.kind(), LayerKind::Quic);
}

// ============================================================================
// QUIC header_form field access
// ============================================================================

#[test]
fn test_quic_header_form_long() {
    let buf = QuicBuilder::initial().build();
    let layer = QuicLayer::new(0, buf.len());
    assert!(layer.is_long_header(&buf));

    if let Some(Ok(FieldValue::U8(v))) = layer.get_field(&buf, "header_form") {
        assert_eq!(v, 1); // long header
    } else {
        panic!("expected header_form field");
    }
}

#[test]
fn test_quic_header_form_short() {
    let buf = QuicBuilder::one_rtt().payload(vec![0x01]).build();
    let layer = QuicLayer::new(0, buf.len());
    assert!(!layer.is_long_header(&buf));

    if let Some(Ok(FieldValue::U8(v))) = layer.get_field(&buf, "header_form") {
        assert_eq!(v, 0); // short header
    } else {
        panic!("expected header_form field");
    }
}

// ============================================================================
// QUIC packet_type field access
// ============================================================================

#[test]
fn test_quic_packet_type_initial() {
    let buf = QuicBuilder::initial().build();
    let layer = QuicLayer::new(0, buf.len());
    assert_eq!(layer.packet_type(&buf), Some(QuicPacketType::Initial));

    if let Some(Ok(FieldValue::U8(v))) = layer.get_field(&buf, "packet_type") {
        assert_eq!(v, 0x00); // Initial = 0
    } else {
        panic!("expected packet_type field");
    }
}

#[test]
fn test_quic_packet_type_handshake() {
    let buf = QuicBuilder::handshake().build();
    let layer = QuicLayer::new(0, buf.len());
    assert_eq!(layer.packet_type(&buf), Some(QuicPacketType::Handshake));
}

#[test]
fn test_quic_packet_type_one_rtt() {
    let buf = QuicBuilder::one_rtt().payload(vec![0x01]).build();
    let layer = QuicLayer::new(0, buf.len());
    assert_eq!(layer.packet_type(&buf), Some(QuicPacketType::OneRtt));
}

// ============================================================================
// QUIC version field access
// ============================================================================

#[test]
fn test_quic_version_field_v1() {
    let buf = QuicBuilder::initial().version(1).build();
    let layer = QuicLayer::new(0, buf.len());
    assert_eq!(layer.version(&buf), Some(1));

    if let Some(Ok(FieldValue::U32(v))) = layer.get_field(&buf, "version") {
        assert_eq!(v, 1);
    } else {
        panic!("expected version field");
    }
}

#[test]
fn test_quic_version_field_custom() {
    let buf = QuicBuilder::initial().version(2).build();
    let layer = QuicLayer::new(0, buf.len());
    assert_eq!(layer.version(&buf), Some(2));
}

#[test]
fn test_quic_version_none_for_short_header() {
    let buf = QuicBuilder::one_rtt().payload(vec![0x01]).build();
    let layer = QuicLayer::new(0, buf.len());
    assert_eq!(layer.version(&buf), None);
}

// ============================================================================
// QUIC set_field
// ============================================================================

#[test]
fn test_quic_set_field_version() {
    let mut buf = QuicBuilder::initial().version(1).build();
    let layer = QuicLayer::new(0, buf.len());
    layer
        .set_field(&mut buf, "version", FieldValue::U32(99))
        .unwrap()
        .unwrap();
    assert_eq!(layer.version(&buf), Some(99));
}

#[test]
fn test_quic_set_field_fixed_bit() {
    let mut buf = QuicBuilder::initial().build();
    let layer = QuicLayer::new(0, buf.len());
    // clear fixed bit
    layer
        .set_field(&mut buf, "fixed_bit", FieldValue::U8(0))
        .unwrap()
        .unwrap();
    if let Some(Ok(FieldValue::U8(v))) = layer.get_field(&buf, "fixed_bit") {
        assert_eq!(v, 0);
    }
}

// ============================================================================
// QUIC field_names
// ============================================================================

#[test]
fn test_quic_field_names() {
    let names = QuicLayer::field_names();
    assert!(names.contains(&"header_form"));
    assert!(names.contains(&"fixed_bit"));
    assert!(names.contains(&"packet_type"));
    assert!(names.contains(&"version"));
}

// ============================================================================
// QUIC summary
// ============================================================================

#[test]
fn test_quic_summary_initial() {
    let buf = QuicBuilder::initial().build();
    let layer = QuicLayer::new(0, buf.len());
    let s = layer.summary(&buf);
    assert!(s.contains("QUIC"));
    assert!(s.contains("Initial"));
}

#[test]
fn test_quic_summary_one_rtt() {
    let buf = QuicBuilder::one_rtt().payload(vec![0x01]).build();
    let layer = QuicLayer::new(0, buf.len());
    let s = layer.summary(&buf);
    assert!(s.contains("QUIC"));
    assert!(s.contains("1-RTT"));
}

// ============================================================================
// packet_type function
// ============================================================================

#[test]
fn test_quic_packet_type_function_short_header() {
    assert_eq!(packet_type(0x40, 0), QuicPacketType::OneRtt);
}

#[test]
fn test_quic_packet_type_function_version_neg() {
    assert_eq!(packet_type(0x80, 0), QuicPacketType::VersionNeg);
}

#[test]
fn test_quic_packet_type_function_initial() {
    assert_eq!(packet_type(0xC0, 1), QuicPacketType::Initial);
}

#[test]
fn test_quic_packet_type_function_handshake() {
    assert_eq!(packet_type(0xE0, 1), QuicPacketType::Handshake);
}
