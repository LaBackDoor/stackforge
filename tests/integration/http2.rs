//! Integration tests for the HTTP/2 protocol layer.
//!
//! Tests cover:
//! - HPACK integer encoding/decoding
//! - HPACK string literal encoding/decoding
//! - Huffman encode/decode roundtrips
//! - HpackDecoder / HpackEncoder roundtrips
//! - Frame parsing (all major frame types)
//! - Multi-frame parsing with and without preface
//! - Http2FrameBuilder factories
//! - Http2Builder (connection builder)
//! - Http2Layer methods (summary, header_len, get_field, set_field)
//! - is_http2_payload detection helper
//! - End-to-end request/response encoding and decoding

use stackforge_core::layer::field::FieldValue;
use stackforge_core::layer::http2::builder::{
    Http2Builder, Http2FrameBuilder, build_get_request, build_response_200,
};
use stackforge_core::layer::http2::frames::{
    HTTP2_FRAME_HEADER_LEN, HTTP2_PREFACE, Http2Frame, Http2FrameType, error_codes, flags,
    parse_all_frames, parse_goaway, parse_rst_stream, parse_settings, parse_window_update,
    settings_id,
};
use stackforge_core::layer::http2::hpack::{
    HpackDecoder, HpackEncoder, STATIC_TABLE, decode_integer, decode_string, encode_integer,
    encode_string_literal, huffman_decode, huffman_encode,
};
use stackforge_core::layer::http2::{Http2Layer, is_http2_payload};

// ============================================================================
// Helper: build a raw frame
// ============================================================================

fn make_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::new();
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push((len & 0xFF) as u8);
    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7FFFFFFF).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// ============================================================================
// HPACK Integer Codec Tests
// ============================================================================

#[test]
fn test_hpack_integer_zero() {
    let encoded = encode_integer(0, 5, 0x00);
    let (val, consumed) = decode_integer(&encoded, 5).unwrap();
    assert_eq!(val, 0);
    assert_eq!(consumed, 1);
}

#[test]
fn test_hpack_integer_prefix_boundary() {
    // 5-bit prefix max = 31; value 30 fits in prefix
    let encoded = encode_integer(30, 5, 0x00);
    assert_eq!(encoded.len(), 1);
    let (val, _) = decode_integer(&encoded, 5).unwrap();
    assert_eq!(val, 30);
}

#[test]
fn test_hpack_integer_at_prefix_limit() {
    // value == prefix_max triggers continuation
    let encoded = encode_integer(31, 5, 0x00);
    assert!(encoded.len() > 1);
    let (val, _) = decode_integer(&encoded, 5).unwrap();
    assert_eq!(val, 31);
}

#[test]
fn test_hpack_integer_rfc_example_1337() {
    // RFC 7541 Section 5.1, example: 1337 with 5-bit prefix
    let encoded = encode_integer(1337, 5, 0x00);
    assert_eq!(encoded, vec![0b00011111, 0x9A, 0x0A]);
    let (val, consumed) = decode_integer(&encoded, 5).unwrap();
    assert_eq!(val, 1337);
    assert_eq!(consumed, 3);
}

#[test]
fn test_hpack_integer_roundtrip_all_prefix_sizes() {
    let values = [
        0u64, 1, 127, 128, 255, 256, 1023, 1024, 65535, 65536, 100000,
    ];
    for &val in &values {
        for prefix in 1u8..=7 {
            let encoded = encode_integer(val, prefix, 0x00);
            let (decoded, _) = decode_integer(&encoded, prefix).unwrap();
            assert_eq!(
                val, decoded,
                "Roundtrip failed for val={val} prefix={prefix}"
            );
        }
    }
}

#[test]
fn test_hpack_integer_with_prefix_byte() {
    // Indexed header field: prefix_byte = 0x80, prefix_bits = 7
    let encoded = encode_integer(5, 7, 0x80);
    assert_eq!(encoded[0], 0x85); // 0x80 | 5
    let (val, _) = decode_integer(&encoded, 7).unwrap();
    assert_eq!(val, 5);
}

#[test]
fn test_hpack_decode_integer_empty_buffer() {
    let result = decode_integer(&[], 5);
    assert!(result.is_none());
}

// ============================================================================
// HPACK String Literal Tests
// ============================================================================

#[test]
fn test_decode_string_simple_ascii() {
    let mut buf = vec![0x0au8]; // H=0, length=10
    buf.extend_from_slice(b"custom-key");
    let (bytes, consumed) = decode_string(&buf).unwrap();
    assert_eq!(bytes, b"custom-key");
    assert_eq!(consumed, 11);
}

#[test]
fn test_decode_string_empty() {
    let buf = vec![0x00u8]; // H=0, length=0
    let (bytes, consumed) = decode_string(&buf).unwrap();
    assert!(bytes.is_empty());
    assert_eq!(consumed, 1);
}

#[test]
fn test_decode_string_huffman_flag() {
    let original = b"custom-header";
    let encoded_huff = huffman_encode(original);
    let mut buf = encode_integer(encoded_huff.len() as u64, 7, 0x80); // H=1
    buf.extend_from_slice(&encoded_huff);
    let (decoded, _) = decode_string(&buf).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_encode_string_literal_roundtrip() {
    let data = b"x-request-id";
    let encoded = encode_string_literal(data);
    let (decoded, consumed) = decode_string(&encoded).unwrap();
    assert_eq!(decoded, data);
    assert_eq!(consumed, encoded.len());
}

// ============================================================================
// Huffman Codec Tests
// ============================================================================

#[test]
fn test_huffman_roundtrip_empty() {
    let encoded = huffman_encode(b"");
    assert!(encoded.is_empty());
    let decoded = huffman_decode(&encoded).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn test_huffman_roundtrip_single_byte() {
    for b in 0u8..=127 {
        let original = [b];
        let encoded = huffman_encode(&original);
        let decoded = huffman_decode(&encoded).unwrap();
        assert_eq!(decoded, &original[..], "Roundtrip failed for byte={b}");
    }
}

#[test]
fn test_huffman_roundtrip_all_printable_ascii() {
    let original: Vec<u8> = (32u8..=126u8).collect();
    let encoded = huffman_encode(&original);
    let decoded = huffman_decode(&encoded).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_huffman_rfc7541_www_example_com() {
    // RFC 7541 Appendix C.4.1: "www.example.com"
    let original = b"www.example.com";
    let encoded = huffman_encode(original);
    let decoded = huffman_decode(&encoded).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_huffman_rfc7541_no_cache() {
    // RFC 7541 Appendix C.4.1: "no-cache"
    let original = b"no-cache";
    let encoded = huffman_encode(original);
    let decoded = huffman_decode(&encoded).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_huffman_decode_known_vector() {
    // Known good vector from RFC 7541 Appendix C.4.1
    // "www.example.com" encodes to f1e3c2e5f23a6ba0ab90f4ff
    let encoded = [
        0xf1u8, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    let decoded = huffman_decode(&encoded).unwrap();
    assert_eq!(decoded, b"www.example.com");
}

#[test]
fn test_huffman_encode_produces_compression() {
    // For typical HTTP headers, Huffman should be <= original size
    let original = b"custom-key: custom-header-value";
    let encoded = huffman_encode(original);
    // Huffman encoding of HTTP strings should compress
    assert!(encoded.len() <= original.len());
}

// ============================================================================
// HPACK Static Table Tests
// ============================================================================

#[test]
fn test_static_table_length() {
    assert_eq!(
        STATIC_TABLE.len(),
        61,
        "Static table must have exactly 61 entries (RFC 7541 Appendix A)"
    );
}

#[test]
fn test_static_table_index_1() {
    assert_eq!(STATIC_TABLE[0], (":authority", ""));
}

#[test]
fn test_static_table_index_2() {
    assert_eq!(STATIC_TABLE[1], (":method", "GET"));
}

#[test]
fn test_static_table_index_3() {
    assert_eq!(STATIC_TABLE[2], (":method", "POST"));
}

#[test]
fn test_static_table_index_4() {
    assert_eq!(STATIC_TABLE[3], (":path", "/"));
}

#[test]
fn test_static_table_index_8() {
    assert_eq!(STATIC_TABLE[7], (":status", "200"));
}

#[test]
fn test_static_table_last_entry() {
    assert_eq!(STATIC_TABLE[60], ("www-authenticate", ""));
}

// ============================================================================
// HpackDecoder Tests
// ============================================================================

#[test]
fn test_decoder_empty_input() {
    let mut decoder = HpackDecoder::new();
    let headers = decoder.decode(&[]).unwrap();
    assert!(headers.is_empty());
}

#[test]
fn test_decoder_indexed_header_method_get() {
    // RFC 7541: index 2 = ":method: GET"
    let buf = [0x82u8]; // 1000_0010 = indexed, index=2
    let mut decoder = HpackDecoder::new();
    let headers = decoder.decode(&buf).unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
}

#[test]
fn test_decoder_indexed_header_path() {
    // Index 4 = ":path: /"
    let buf = [0x84u8]; // indexed, index=4
    let mut decoder = HpackDecoder::new();
    let headers = decoder.decode(&buf).unwrap();
    assert_eq!(headers[0], (":path".to_string(), "/".to_string()));
}

#[test]
fn test_decoder_literal_with_incremental_indexing_new_name() {
    // Literal with incremental indexing, new name: 01_000000 + name + value
    let mut buf = vec![0x40u8]; // pattern: 01 + index=0 (new name)
    buf.extend_from_slice(&encode_string_literal(b"x-custom-header"));
    buf.extend_from_slice(&encode_string_literal(b"custom-value"));

    let mut decoder = HpackDecoder::new();
    let headers = decoder.decode(&buf).unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0, "x-custom-header");
    assert_eq!(headers[0].1, "custom-value");

    // Entry should have been added to dynamic table
    assert_eq!(decoder.dynamic_table_len(), 1);
}

#[test]
fn test_decoder_literal_without_indexing() {
    // Pattern: 0000_0000 (no indexing, new name)
    let mut buf = vec![0x00u8];
    buf.extend_from_slice(&encode_string_literal(b"x-never-cache"));
    buf.extend_from_slice(&encode_string_literal(b"secret-value"));

    let mut decoder = HpackDecoder::new();
    let headers = decoder.decode(&buf).unwrap();
    assert_eq!(headers[0].0, "x-never-cache");
    assert_eq!(headers[0].1, "secret-value");

    // Entry should NOT be in dynamic table
    assert_eq!(decoder.dynamic_table_len(), 0);
}

#[test]
fn test_decoder_never_indexed() {
    // Pattern: 0001_0000 (never indexed, new name)
    let mut buf = vec![0x10u8];
    buf.extend_from_slice(&encode_string_literal(b"authorization"));
    buf.extend_from_slice(&encode_string_literal(b"Bearer token"));

    let mut decoder = HpackDecoder::new();
    let headers = decoder.decode(&buf).unwrap();
    assert_eq!(headers[0].0, "authorization");

    // Entry should NOT be in dynamic table
    assert_eq!(decoder.dynamic_table_len(), 0);
}

#[test]
fn test_decoder_dynamic_table_ordering() {
    // The most recently added entry should be at index 62
    let mut decoder = HpackDecoder::new();

    // Add first entry
    let mut buf = vec![0x40u8];
    buf.extend_from_slice(&encode_string_literal(b"x-first"));
    buf.extend_from_slice(&encode_string_literal(b"1"));
    decoder.decode(&buf).unwrap();

    // Add second entry
    let mut buf2 = vec![0x40u8];
    buf2.extend_from_slice(&encode_string_literal(b"x-second"));
    buf2.extend_from_slice(&encode_string_literal(b"2"));
    decoder.decode(&buf2).unwrap();

    // Dynamic table should have 2 entries, most recent first
    let entries = decoder.dynamic_table_entries();
    assert_eq!(entries[0].0, "x-second");
    assert_eq!(entries[1].0, "x-first");

    // Index 62 should be x-second (most recent)
    let buf3 = [0xBE]; // indexed, index=62 (0x80 | 62)
    let headers = decoder.decode(&buf3).unwrap();
    assert_eq!(headers[0].0, "x-second");
}

#[test]
fn test_decoder_multiple_headers() {
    let mut decoder = HpackDecoder::new();

    let mut buf = Vec::new();
    buf.push(0x82); // :method GET
    buf.push(0x84); // :path /
    buf.push(0x86); // :scheme http
    buf.push(0x87); // :status 200 ... wait, 0x87 = index 7
    // Let's just do method, path, scheme
    let headers = decoder.decode(&buf[..3]).unwrap();
    assert_eq!(headers.len(), 3);
    assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
    assert_eq!(headers[1], (":path".to_string(), "/".to_string()));
    assert_eq!(headers[2], (":scheme".to_string(), "http".to_string()));
}

#[test]
fn test_decoder_invalid_index() {
    // Index 0 is invalid in HPACK indexed representation
    let buf = [0x80u8]; // indexed, index=0
    let mut decoder = HpackDecoder::new();
    // Should return an error since index 0 is invalid
    assert!(decoder.decode(&buf).is_err());
}

// ============================================================================
// HpackEncoder Tests
// ============================================================================

#[test]
fn test_encoder_empty() {
    let encoder = HpackEncoder::new();
    let encoded = encoder.encode(&[]);
    assert!(encoded.is_empty());
}

#[test]
fn test_encoder_static_exact_match() {
    let encoder = HpackEncoder::new();
    // ":method: GET" = static index 2 → 0x82
    let encoded = encoder.encode(&[(":method", "GET")]);
    assert_eq!(encoded, vec![0x82]);
}

#[test]
fn test_encoder_static_name_match_post() {
    let encoder = HpackEncoder::new();
    // ":method: POST" = static index 3 → 0x83
    let encoded = encoder.encode(&[(":method", "POST")]);
    assert_eq!(encoded, vec![0x83]);
}

#[test]
fn test_encoder_static_name_match_delete() {
    let encoder = HpackEncoder::new();
    // ":method" exists at index 2, "DELETE" is not a static value
    // Should use literal with name index
    let encoded = encoder.encode(&[(":method", "DELETE")]);
    // First byte: 0x40 | 2 = 0x42 (literal with incremental indexing, name idx=2)
    assert_eq!(encoded[0], 0x42);
}

#[test]
fn test_encoder_decode_roundtrip() {
    let encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let headers = vec![
        (":method", "GET"),
        (":path", "/"),
        (":scheme", "https"),
        (":authority", "example.com"),
        ("user-agent", "test/1.0"),
        ("accept", "text/html"),
        ("x-custom", "value"),
    ];

    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();

    assert_eq!(decoded.len(), headers.len());
    for (i, &(name, value)) in headers.iter().enumerate() {
        assert_eq!(decoded[i].0, name, "Name mismatch at index {i}");
        assert_eq!(decoded[i].1, value, "Value mismatch at index {i}");
    }
}

#[test]
fn test_encoder_huffman_roundtrip() {
    let encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let headers = vec![
        (":method", "GET"),
        (":path", "/api/resource"),
        ("content-type", "application/json"),
        ("x-trace-id", "abc-123-def-456"),
    ];

    let encoded = encoder.encode_huffman(&headers);
    let decoded = decoder.decode(&encoded).unwrap();

    for (i, &(name, value)) in headers.iter().enumerate() {
        assert_eq!(decoded[i].0, name);
        assert_eq!(decoded[i].1, value);
    }
}

// ============================================================================
// Frame Parsing Tests
// ============================================================================

#[test]
fn test_parse_frame_header_only() {
    let frame_bytes = make_frame(4, 0, 0, &[]); // SETTINGS, empty
    let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();

    assert_eq!(frame.length, 0);
    assert_eq!(frame.frame_type, Http2FrameType::Settings);
    assert_eq!(frame.flags, 0);
    assert_eq!(frame.stream_id, 0);
    assert_eq!(frame.total_size, 9);
}

#[test]
fn test_parse_frame_with_payload() {
    let payload = b"test_payload_data";
    let frame_bytes = make_frame(0, 0, 1, payload);
    let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();

    assert_eq!(frame.length, payload.len() as u32);
    assert_eq!(frame.frame_type, Http2FrameType::Data);
    assert_eq!(frame.stream_id, 1);
    assert_eq!(frame.payload(&frame_bytes), payload);
}

#[test]
fn test_parse_frame_stream_id_r_bit_masked() {
    // Set the R bit (0x80000000) in the stream ID field — should be ignored
    let mut frame_bytes = make_frame(0, 0, 1, &[]);
    frame_bytes[5] |= 0x80; // Set R bit
    let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();
    assert_eq!(frame.stream_id, 1); // R bit should be masked out
}

#[test]
fn test_parse_frame_type_all_known() {
    for type_byte in 0u8..=9 {
        let frame_bytes = make_frame(type_byte, 0, 0, &[0u8; 8]); // Ping-like (8 bytes)
        let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();
        assert_ne!(frame.frame_type, Http2FrameType::Unknown(type_byte));
    }
}

#[test]
fn test_parse_frame_unknown_type() {
    let frame_bytes = make_frame(0xfe, 0, 0, &[]);
    let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();
    assert_eq!(frame.frame_type, Http2FrameType::Unknown(0xfe));
}

#[test]
fn test_parse_frame_returns_none_too_short() {
    let buf = [0u8; 8]; // Only 8 bytes, need 9
    assert!(Http2Frame::parse_at(&buf, 0).is_none());
}

#[test]
fn test_parse_frame_returns_none_truncated_payload() {
    let mut buf = [0u8; 9];
    buf[0] = 0x00; // length[0]
    buf[1] = 0x00; // length[1]
    buf[2] = 0x64; // length[2] = 100 bytes payload
    buf[3] = 0x00; // type = DATA
    // No payload follows
    assert!(Http2Frame::parse_at(&buf, 0).is_none());
}

#[test]
fn test_parse_frame_at_offset() {
    let mut buf = vec![0u8; 10]; // 10 bytes garbage at start
    buf.extend_from_slice(&make_frame(4, 0, 0, &[]));
    let frame = Http2Frame::parse_at(&buf, 10).unwrap();
    assert_eq!(frame.frame_type, Http2FrameType::Settings);
}

#[test]
fn test_parse_all_frames_with_preface() {
    let mut buf = Vec::new();
    buf.extend_from_slice(HTTP2_PREFACE);
    buf.extend_from_slice(&make_frame(4, 0, 0, &[])); // SETTINGS
    buf.extend_from_slice(&make_frame(4, flags::SETTINGS_ACK, 0, &[])); // SETTINGS ACK

    let frames = parse_all_frames(&buf);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].frame_type, Http2FrameType::Settings);
    assert!(!frames[0].is_ack());
    assert_eq!(frames[1].frame_type, Http2FrameType::Settings);
    assert!(frames[1].is_ack());
}

#[test]
fn test_parse_all_frames_no_preface() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&make_frame(1, flags::HEADERS_END_HEADERS, 1, &[0x82]));
    buf.extend_from_slice(&make_frame(0, flags::DATA_END_STREAM, 1, b"body"));

    let frames = parse_all_frames(&buf);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].frame_type, Http2FrameType::Headers);
    assert_eq!(frames[1].frame_type, Http2FrameType::Data);
}

#[test]
fn test_parse_frame_flags_end_stream() {
    let frame_bytes = make_frame(0, flags::DATA_END_STREAM, 1, b"data");
    let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();
    assert!(frame.is_end_stream());
    assert!(!frame.is_end_headers());
}

#[test]
fn test_parse_frame_flags_end_headers() {
    let frame_bytes = make_frame(1, flags::HEADERS_END_HEADERS, 1, &[0x82]);
    let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();
    assert!(frame.is_end_headers());
    assert!(!frame.is_end_stream());
}

#[test]
fn test_parse_frame_flags_padded() {
    let frame_bytes = make_frame(0, flags::DATA_PADDED, 1, &[0x02, b'a', b'b', 0xff, 0xff]);
    let frame = Http2Frame::parse_at(&frame_bytes, 0).unwrap();
    assert!(frame.is_padded());
}

// ============================================================================
// Frame-specific payload parsers
// ============================================================================

#[test]
fn test_parse_settings_empty() {
    let settings = parse_settings(&[]);
    assert!(settings.is_empty());
}

#[test]
fn test_parse_settings_multiple_params() {
    let mut payload = Vec::new();
    let entries: &[(u16, u32)] = &[
        (settings_id::HEADER_TABLE_SIZE, 4096),
        (settings_id::ENABLE_PUSH, 0),
        (settings_id::MAX_CONCURRENT_STREAMS, 100),
        (settings_id::INITIAL_WINDOW_SIZE, 65535),
        (settings_id::MAX_FRAME_SIZE, 16384),
        (settings_id::MAX_HEADER_LIST_SIZE, 8192),
    ];
    for &(id, val) in entries {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&val.to_be_bytes());
    }
    let settings = parse_settings(&payload);
    assert_eq!(settings.len(), 6);
    assert_eq!(settings[0], (settings_id::HEADER_TABLE_SIZE, 4096));
    assert_eq!(settings[1], (settings_id::ENABLE_PUSH, 0));
    assert_eq!(settings[4], (settings_id::MAX_FRAME_SIZE, 16384));
}

#[test]
fn test_parse_settings_ignores_partial_entry() {
    // 5 bytes: one full entry (6 bytes) minus 1 = partial, should be ignored
    let mut payload = Vec::new();
    payload.extend_from_slice(&settings_id::HEADER_TABLE_SIZE.to_be_bytes());
    payload.extend_from_slice(&4096u32.to_be_bytes());
    payload.push(0xFF); // incomplete second entry
    let settings = parse_settings(&payload);
    assert_eq!(settings.len(), 1); // Only the complete entry
}

#[test]
fn test_parse_goaway() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&5u32.to_be_bytes()); // last_stream_id=5
    payload.extend_from_slice(&error_codes::PROTOCOL_ERROR.to_be_bytes());
    let (last_id, err) = parse_goaway(&payload).unwrap();
    assert_eq!(last_id, 5);
    assert_eq!(err, error_codes::PROTOCOL_ERROR);
}

#[test]
fn test_parse_goaway_r_bit_masked() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0x80000003u32.to_be_bytes()); // R bit set, stream=3
    payload.extend_from_slice(&0u32.to_be_bytes());
    let (last_id, _) = parse_goaway(&payload).unwrap();
    assert_eq!(last_id, 3); // R bit masked out
}

#[test]
fn test_parse_goaway_too_short() {
    assert!(parse_goaway(&[0u8; 7]).is_none());
}

#[test]
fn test_parse_window_update_connection_level() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&65535u32.to_be_bytes());
    let increment = parse_window_update(&payload).unwrap();
    assert_eq!(increment, 65535);
}

#[test]
fn test_parse_window_update_r_bit_masked() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0x80010000u32.to_be_bytes()); // R bit + 65536
    let increment = parse_window_update(&payload).unwrap();
    assert_eq!(increment, 65536); // R bit masked
}

#[test]
fn test_parse_rst_stream() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&error_codes::CANCEL.to_be_bytes());
    let err = parse_rst_stream(&payload).unwrap();
    assert_eq!(err, error_codes::CANCEL);
}

// ============================================================================
// Http2FrameBuilder Tests
// ============================================================================

#[test]
fn test_builder_settings() {
    let bytes = Http2FrameBuilder::settings().build();
    assert_eq!(bytes.len(), 9);
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert_eq!(frame.frame_type, Http2FrameType::Settings);
    assert_eq!(frame.stream_id, 0);
    assert_eq!(frame.length, 0);
    assert!(!frame.is_ack());
}

#[test]
fn test_builder_settings_ack() {
    let bytes = Http2FrameBuilder::settings_ack().build();
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert!(frame.is_ack());
    assert_eq!(frame.length, 0);
}

#[test]
fn test_builder_ping() {
    let data = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04u8];
    let bytes = Http2FrameBuilder::ping(data).build();
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert_eq!(frame.frame_type, Http2FrameType::Ping);
    assert!(!frame.is_ack());
    assert_eq!(frame.payload(&bytes), &data);
}

#[test]
fn test_builder_ping_ack() {
    let data = [0u8; 8];
    let bytes = Http2FrameBuilder::ping_ack(data).build();
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert!(frame.is_ack());
}

#[test]
fn test_builder_goaway_no_error() {
    let bytes = Http2FrameBuilder::goaway(1, error_codes::NO_ERROR).build();
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert_eq!(frame.frame_type, Http2FrameType::GoAway);
    let (last_id, err) = parse_goaway(frame.payload(&bytes)).unwrap();
    assert_eq!(last_id, 1);
    assert_eq!(err, error_codes::NO_ERROR);
}

#[test]
fn test_builder_window_update() {
    let bytes = Http2FrameBuilder::window_update(65535, 0).build();
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert_eq!(frame.frame_type, Http2FrameType::WindowUpdate);
    let inc = parse_window_update(frame.payload(&bytes)).unwrap();
    assert_eq!(inc, 65535);
}

#[test]
fn test_builder_rst_stream() {
    let bytes = Http2FrameBuilder::rst_stream(3, error_codes::CANCEL).build();
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert_eq!(frame.frame_type, Http2FrameType::RstStream);
    assert_eq!(frame.stream_id, 3);
    let err = parse_rst_stream(frame.payload(&bytes)).unwrap();
    assert_eq!(err, error_codes::CANCEL);
}

#[test]
fn test_builder_headers_frame_end_headers() {
    let hpack = vec![0x82u8]; // :method GET
    let bytes = Http2FrameBuilder::headers_frame(1, hpack.clone()).build();
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert_eq!(frame.frame_type, Http2FrameType::Headers);
    assert!(frame.is_end_headers());
    assert!(!frame.is_end_stream());
    assert_eq!(frame.payload(&bytes), &hpack);
}

#[test]
fn test_builder_headers_frame_final() {
    let hpack = vec![0x82u8];
    let bytes = Http2FrameBuilder::headers_frame_final(1, hpack).build();
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert!(frame.is_end_headers());
    assert!(frame.is_end_stream());
}

#[test]
fn test_builder_data_frame() {
    let data = b"request body content";
    let bytes = Http2FrameBuilder::data_frame(1, data.to_vec()).build();
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert_eq!(frame.frame_type, Http2FrameType::Data);
    assert!(!frame.is_end_stream());
    assert_eq!(frame.payload(&bytes), data);
}

#[test]
fn test_builder_data_frame_final() {
    let bytes = Http2FrameBuilder::data_frame_final(1, b"last".to_vec()).build();
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert!(frame.is_end_stream());
}

#[test]
fn test_builder_settings_with_params() {
    let params = [
        (settings_id::INITIAL_WINDOW_SIZE, 65535u32),
        (settings_id::MAX_FRAME_SIZE, 16384u32),
    ];
    let bytes = Http2FrameBuilder::settings_with_params(&params).build();
    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert_eq!(frame.length, 12); // 2 entries * 6 bytes each

    let parsed = parse_settings(frame.payload(&bytes));
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0], (settings_id::INITIAL_WINDOW_SIZE, 65535));
    assert_eq!(parsed[1], (settings_id::MAX_FRAME_SIZE, 16384));
}

// ============================================================================
// Http2Builder Tests
// ============================================================================

#[test]
fn test_connection_builder_preface() {
    let bytes = Http2Builder::new()
        .frame(Http2FrameBuilder::settings())
        .build();

    assert!(bytes.starts_with(HTTP2_PREFACE));
    let frames = parse_all_frames(&bytes);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, Http2FrameType::Settings);
}

#[test]
fn test_connection_builder_no_preface() {
    let bytes = Http2Builder::without_preface()
        .frame(Http2FrameBuilder::settings_ack())
        .build();

    assert!(!bytes.starts_with(HTTP2_PREFACE));
}

#[test]
fn test_connection_builder_multiple_frames() {
    let bytes = Http2Builder::new()
        .frame(Http2FrameBuilder::settings())
        .frame(Http2FrameBuilder::settings_ack())
        .frame(Http2FrameBuilder::headers_frame(1, vec![0x82]))
        .frame(Http2FrameBuilder::data_frame_final(1, b"hello".to_vec()))
        .build();

    let frames = parse_all_frames(&bytes);
    assert_eq!(frames.len(), 4);
    assert_eq!(frames[0].frame_type, Http2FrameType::Settings);
    assert_eq!(frames[1].frame_type, Http2FrameType::Settings);
    assert!(frames[1].is_ack());
    assert_eq!(frames[2].frame_type, Http2FrameType::Headers);
    assert_eq!(frames[3].frame_type, Http2FrameType::Data);
    assert!(frames[3].is_end_stream());
}

#[test]
fn test_connection_builder_header_size() {
    // preface(24) + settings(9) + settings_ack(9) = 42
    let builder = Http2Builder::new()
        .frame(Http2FrameBuilder::settings())
        .frame(Http2FrameBuilder::settings_ack());

    assert_eq!(builder.header_size(), 42);
    assert_eq!(builder.build().len(), 42);
}

#[test]
fn test_connection_builder_empty() {
    let bytes = Http2Builder::without_preface().build();
    assert!(bytes.is_empty());
}

// ============================================================================
// Http2Layer Tests
// ============================================================================

#[test]
fn test_layer_new_no_preface() {
    let bytes = Http2FrameBuilder::settings().build();
    let layer = Http2Layer::new(0, bytes.len(), false);
    assert!(!layer.has_preface);
    assert_eq!(layer.index.start, 0);
    assert_eq!(layer.index.end, bytes.len());
}

#[test]
fn test_layer_new_with_preface() {
    let bytes = Http2Builder::new()
        .frame(Http2FrameBuilder::settings())
        .build();
    let layer = Http2Layer::new(0, bytes.len(), true);
    assert!(layer.has_preface);
}

#[test]
fn test_layer_has_preface_at() {
    let bytes = Http2Builder::new()
        .frame(Http2FrameBuilder::settings())
        .build();
    assert!(Http2Layer::has_preface_at(&bytes, 0));
    assert!(!Http2Layer::has_preface_at(&bytes, 1));
}

#[test]
fn test_layer_first_frame_with_preface() {
    let bytes = Http2Builder::new()
        .frame(Http2FrameBuilder::settings())
        .build();
    let layer = Http2Layer::new(0, bytes.len(), true);
    let frame = layer.first_frame(&bytes).unwrap();
    assert_eq!(frame.frame_type, Http2FrameType::Settings);
}

#[test]
fn test_layer_first_frame_no_preface() {
    let bytes = Http2FrameBuilder::settings_ack().build();
    let layer = Http2Layer::new(0, bytes.len(), false);
    let frame = layer.first_frame(&bytes).unwrap();
    assert!(frame.is_ack());
}

#[test]
fn test_layer_all_frames() {
    let bytes = Http2Builder::new()
        .frame(Http2FrameBuilder::settings())
        .frame(Http2FrameBuilder::settings_ack())
        .frame(Http2FrameBuilder::headers_frame(1, vec![0x82]))
        .build();
    let layer = Http2Layer::new(0, bytes.len(), true);
    let frames = layer.all_frames(&bytes);
    assert_eq!(frames.len(), 3);
}

#[test]
fn test_layer_summary_with_preface() {
    let bytes = Http2Builder::new()
        .frame(Http2FrameBuilder::settings())
        .build();
    let layer = Http2Layer::new(0, bytes.len(), true);
    let summary = layer.summary(&bytes);
    assert!(summary.contains("HTTP/2"), "Expected HTTP/2 in: {summary}");
    assert!(
        summary.contains("Preface"),
        "Expected Preface in: {summary}"
    );
    assert!(
        summary.contains("SETTINGS"),
        "Expected SETTINGS in: {summary}"
    );
}

#[test]
fn test_layer_summary_headers_frame() {
    let hpack = vec![0x82u8];
    let bytes = Http2FrameBuilder::headers_frame(3, hpack).build();
    let layer = Http2Layer::new(0, bytes.len(), false);
    let summary = layer.summary(&bytes);
    assert!(summary.contains("HTTP/2"), "Expected HTTP/2 in: {summary}");
    assert!(
        summary.contains("HEADERS"),
        "Expected HEADERS in: {summary}"
    );
    assert!(
        summary.contains("stream=3"),
        "Expected stream=3 in: {summary}"
    );
}

#[test]
fn test_layer_header_len_preface_and_frame() {
    let bytes = Http2Builder::new()
        .frame(Http2FrameBuilder::settings())
        .build();
    let layer = Http2Layer::new(0, bytes.len(), true);
    // 24 bytes preface + 9 bytes frame header = 33
    assert_eq!(layer.header_len(&bytes), 33);
}

#[test]
fn test_layer_header_len_frame_only() {
    let bytes = Http2FrameBuilder::settings().build();
    let layer = Http2Layer::new(0, bytes.len(), false);
    assert_eq!(layer.header_len(&bytes), 9);
}

#[test]
fn test_layer_header_len_preface_only() {
    // Buffer is exactly the preface with no room for a frame header
    let mut bytes = HTTP2_PREFACE.to_vec();
    bytes.extend_from_slice(&[0u8; 8]); // Only 8 bytes (less than frame header)
    let layer = Http2Layer::new(0, bytes.len(), true);
    // Not enough room for a frame header after preface → return 24
    assert_eq!(layer.header_len(&bytes), 24);
}

#[test]
fn test_layer_get_field_frame_type() {
    let bytes = Http2FrameBuilder::headers_frame(1, vec![0x82]).build();
    let layer = Http2Layer::new(0, bytes.len(), false);
    let val = layer.get_field(&bytes, "frame_type").unwrap().unwrap();
    assert_eq!(val, FieldValue::U8(1)); // HEADERS = 1
}

#[test]
fn test_layer_get_field_stream_id() {
    let bytes = Http2FrameBuilder::headers_frame(5, vec![0x82]).build();
    let layer = Http2Layer::new(0, bytes.len(), false);
    let val = layer.get_field(&bytes, "stream_id").unwrap().unwrap();
    assert_eq!(val, FieldValue::U32(5));
}

#[test]
fn test_layer_get_field_flags() {
    let bytes = Http2FrameBuilder::headers_frame_final(1, vec![0x82]).build();
    let layer = Http2Layer::new(0, bytes.len(), false);
    let val = layer.get_field(&bytes, "flags").unwrap().unwrap();
    assert_eq!(
        val,
        FieldValue::U8(flags::HEADERS_END_HEADERS | flags::HEADERS_END_STREAM)
    );
}

#[test]
fn test_layer_get_field_length() {
    let payload = vec![0x82u8, 0x84, 0x86]; // 3 HPACK bytes
    let bytes = Http2FrameBuilder::headers_frame(1, payload).build();
    let layer = Http2Layer::new(0, bytes.len(), false);
    let val = layer.get_field(&bytes, "length").unwrap().unwrap();
    assert_eq!(val, FieldValue::U32(3));
}

#[test]
fn test_layer_get_field_unknown() {
    let bytes = Http2FrameBuilder::settings().build();
    let layer = Http2Layer::new(0, bytes.len(), false);
    assert!(layer.get_field(&bytes, "nonexistent_field").is_none());
}

#[test]
fn test_layer_set_field_stream_id() {
    let mut bytes = Http2FrameBuilder::headers_frame(1, vec![0x82]).build();
    let layer = Http2Layer::new(0, bytes.len(), false);

    layer
        .set_field(&mut bytes, "stream_id", FieldValue::U32(7))
        .unwrap()
        .unwrap();

    let new_val = layer.get_field(&bytes, "stream_id").unwrap().unwrap();
    assert_eq!(new_val, FieldValue::U32(7));
}

#[test]
fn test_layer_set_field_flags() {
    let mut bytes = Http2FrameBuilder::data_frame(1, b"data".to_vec()).build();
    let layer = Http2Layer::new(0, bytes.len(), false);

    layer
        .set_field(&mut bytes, "flags", FieldValue::U8(flags::DATA_END_STREAM))
        .unwrap()
        .unwrap();

    let frame = Http2Frame::parse_at(&bytes, 0).unwrap();
    assert!(frame.is_end_stream());
}

// ============================================================================
// is_http2_payload Tests
// ============================================================================

#[test]
fn test_is_http2_preface_detected() {
    let bytes = Http2Builder::new()
        .frame(Http2FrameBuilder::settings())
        .build();
    assert!(is_http2_payload(&bytes));
}

#[test]
fn test_is_http2_frame_detected() {
    let bytes = Http2FrameBuilder::settings_ack().build();
    assert!(is_http2_payload(&bytes));
}

#[test]
fn test_is_http2_headers_frame_detected() {
    let bytes = Http2FrameBuilder::headers_frame(1, vec![0x82]).build();
    assert!(is_http2_payload(&bytes));
}

#[test]
fn test_is_http2_not_http1() {
    assert!(!is_http2_payload(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ));
    assert!(!is_http2_payload(b"HTTP/1.1 200 OK\r\n\r\n"));
}

#[test]
fn test_is_http2_not_empty() {
    assert!(!is_http2_payload(&[]));
}

#[test]
fn test_is_http2_not_too_short() {
    assert!(!is_http2_payload(&[0x00, 0x00, 0x00]));
}

// ============================================================================
// End-to-End Tests
// ============================================================================

#[test]
fn test_e2e_get_request_decode() {
    let bytes = build_get_request("www.example.com", "/index.html", 1);

    assert!(bytes.starts_with(HTTP2_PREFACE));

    let frames = parse_all_frames(&bytes);
    assert!(frames.len() >= 2);

    // First frame should be SETTINGS
    assert_eq!(frames[0].frame_type, Http2FrameType::Settings);

    // Second frame should be HEADERS with END_STREAM
    let headers_frame = &frames[1];
    assert_eq!(headers_frame.frame_type, Http2FrameType::Headers);
    assert!(headers_frame.is_end_headers());
    assert!(headers_frame.is_end_stream());
    assert_eq!(headers_frame.stream_id, 1);

    // Decode HPACK
    let hpack_data = headers_frame.payload(&bytes);
    let mut decoder = HpackDecoder::new();
    let headers = decoder.decode(hpack_data).unwrap();

    let find = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };

    assert_eq!(find(":method"), Some("GET"));
    assert_eq!(find(":path"), Some("/index.html"));
    assert_eq!(find(":scheme"), Some("https"));
    assert_eq!(find(":authority"), Some("www.example.com"));
}

#[test]
fn test_e2e_response_200_with_body() {
    let body = b"{\"status\": \"ok\"}";
    let bytes = build_response_200(1, Some(body));

    let frames = parse_all_frames(&bytes);
    assert!(frames.len() >= 3);

    // SETTINGS ACK
    assert_eq!(frames[0].frame_type, Http2FrameType::Settings);
    assert!(frames[0].is_ack());

    // HEADERS with :status 200
    assert_eq!(frames[1].frame_type, Http2FrameType::Headers);
    assert!(frames[1].is_end_headers());
    assert!(!frames[1].is_end_stream());

    let mut decoder = HpackDecoder::new();
    let headers = decoder.decode(frames[1].payload(&bytes)).unwrap();
    let status = headers
        .iter()
        .find(|(n, _)| n == ":status")
        .map(|(_, v)| v.as_str());
    assert_eq!(status, Some("200"));

    // DATA frame with body
    assert_eq!(frames[2].frame_type, Http2FrameType::Data);
    assert!(frames[2].is_end_stream());
    assert_eq!(frames[2].payload(&bytes), body);
}

#[test]
fn test_e2e_response_200_no_body() {
    let bytes = build_response_200(1, None);

    let frames = parse_all_frames(&bytes);
    assert_eq!(frames.len(), 2); // SETTINGS ACK + HEADERS(END_STREAM)

    assert_eq!(frames[1].frame_type, Http2FrameType::Headers);
    assert!(frames[1].is_end_headers());
    assert!(frames[1].is_end_stream());
}

#[test]
fn test_e2e_hpack_compression_large_header_set() {
    let encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let headers = vec![
        (":method", "POST"),
        (":path", "/api/v2/resources"),
        (":scheme", "https"),
        (":authority", "api.example.com"),
        ("content-type", "application/json"),
        ("content-length", "256"),
        (
            "authorization",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ),
        ("user-agent", "stackforge/1.0"),
        ("accept", "application/json"),
        ("x-request-id", "req-abc-123-def-456-ghi"),
    ];

    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();

    assert_eq!(decoded.len(), headers.len());
    for (i, &(name, value)) in headers.iter().enumerate() {
        assert_eq!(decoded[i].0, name, "Name mismatch at index {i}");
        assert_eq!(decoded[i].1, value, "Value mismatch at index {i}");
    }
}

#[test]
fn test_e2e_full_http2_exchange() {
    // Simulate: client preface + SETTINGS + HEADERS(GET) → server SETTINGS ACK + HEADERS(200) + DATA

    // Client
    let client_bytes = Http2Builder::new()
        .frame(Http2FrameBuilder::settings_with_params(&[(
            settings_id::INITIAL_WINDOW_SIZE,
            65535,
        )]))
        .frame(Http2FrameBuilder::headers_frame_final(
            1,
            HpackEncoder::new().encode(&[
                (":method", "GET"),
                (":path", "/"),
                (":scheme", "https"),
                (":authority", "example.com"),
            ]),
        ))
        .build();

    assert!(client_bytes.starts_with(HTTP2_PREFACE));
    let client_frames = parse_all_frames(&client_bytes);
    assert_eq!(client_frames.len(), 2);

    // Server
    let server_bytes = build_response_200(1, Some(b"Hello, HTTP/2!"));
    let server_frames = parse_all_frames(&server_bytes);

    // Decode server response headers
    let mut decoder = HpackDecoder::new();
    let resp_headers = decoder
        .decode(server_frames[1].payload(&server_bytes))
        .unwrap();
    let status = resp_headers
        .iter()
        .find(|(n, _)| n == ":status")
        .map(|(_, v)| v.as_str());
    assert_eq!(status, Some("200"));

    // Verify DATA frame
    assert_eq!(server_frames[2].payload(&server_bytes), b"Hello, HTTP/2!");
}

#[test]
fn test_preface_constant() {
    assert_eq!(HTTP2_PREFACE.len(), 24);
    assert_eq!(HTTP2_PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
}

#[test]
fn test_frame_header_len_constant() {
    assert_eq!(HTTP2_FRAME_HEADER_LEN, 9);
}

#[test]
fn test_frame_type_display() {
    assert_eq!(Http2FrameType::Data.name(), "DATA");
    assert_eq!(Http2FrameType::Headers.name(), "HEADERS");
    assert_eq!(Http2FrameType::Priority.name(), "PRIORITY");
    assert_eq!(Http2FrameType::RstStream.name(), "RST_STREAM");
    assert_eq!(Http2FrameType::Settings.name(), "SETTINGS");
    assert_eq!(Http2FrameType::PushPromise.name(), "PUSH_PROMISE");
    assert_eq!(Http2FrameType::Ping.name(), "PING");
    assert_eq!(Http2FrameType::GoAway.name(), "GOAWAY");
    assert_eq!(Http2FrameType::WindowUpdate.name(), "WINDOW_UPDATE");
    assert_eq!(Http2FrameType::Continuation.name(), "CONTINUATION");
}

#[test]
fn test_error_codes_all() {
    let known_codes = [
        (error_codes::NO_ERROR, "NO_ERROR"),
        (error_codes::PROTOCOL_ERROR, "PROTOCOL_ERROR"),
        (error_codes::INTERNAL_ERROR, "INTERNAL_ERROR"),
        (error_codes::FLOW_CONTROL_ERROR, "FLOW_CONTROL_ERROR"),
        (error_codes::SETTINGS_TIMEOUT, "SETTINGS_TIMEOUT"),
        (error_codes::STREAM_CLOSED, "STREAM_CLOSED"),
        (error_codes::FRAME_SIZE_ERROR, "FRAME_SIZE_ERROR"),
        (error_codes::REFUSED_STREAM, "REFUSED_STREAM"),
        (error_codes::CANCEL, "CANCEL"),
        (error_codes::COMPRESSION_ERROR, "COMPRESSION_ERROR"),
        (error_codes::CONNECT_ERROR, "CONNECT_ERROR"),
        (error_codes::ENHANCE_YOUR_CALM, "ENHANCE_YOUR_CALM"),
        (error_codes::INADEQUATE_SECURITY, "INADEQUATE_SECURITY"),
        (error_codes::HTTP_1_1_REQUIRED, "HTTP_1_1_REQUIRED"),
    ];
    for (code, expected_name) in known_codes {
        assert_eq!(error_codes::name(code), expected_name);
    }
}
