//! IPv6 protocol integration tests.
//!
//! Tests IPv6 header parsing, building, field access, extension headers,
//! and full-stack packet handling.

use stackforge_core::layer::ipv6::ext_headers::{ExtHeaderKind, parse_ext_headers};
use stackforge_core::layer::{LayerIndex, LayerKind};
use stackforge_core::{IPV6_HEADER_LEN, Ipv6Builder, Ipv6Layer};
use std::net::Ipv6Addr;

// ============================================================================
// Helper: build a minimal IPv6 header buffer
// ============================================================================

fn make_ipv6_buf(src: Ipv6Addr, dst: Ipv6Addr, nh: u8, payload_len: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 40];
    buf[0] = 0x60; // version=6, TC=0, FL=0
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = (payload_len >> 8) as u8;
    buf[5] = (payload_len & 0xFF) as u8;
    buf[6] = nh;
    buf[7] = 64; // hop_limit
    buf[8..24].copy_from_slice(&src.octets());
    buf[24..40].copy_from_slice(&dst.octets());
    buf
}

// ============================================================================
// Basic header parsing
// ============================================================================

#[test]
fn test_ipv6_version_is_6() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let buf = make_ipv6_buf(src, dst, 58, 0);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.version(&buf).unwrap(), 6);
}

#[test]
fn test_ipv6_src_address() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let buf = make_ipv6_buf(src, dst, 58, 0);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.src(&buf).unwrap(), src);
}

#[test]
fn test_ipv6_dst_address() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let buf = make_ipv6_buf(src, dst, 17, 8);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.dst(&buf).unwrap(), dst);
}

#[test]
fn test_ipv6_hop_limit_default() {
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 58, 0);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.hop_limit(&buf).unwrap(), 64);
}

#[test]
fn test_ipv6_hop_limit_custom() {
    let mut buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 58, 0);
    buf[7] = 128;
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.hop_limit(&buf).unwrap(), 128);
}

#[test]
fn test_ipv6_next_header_icmpv6() {
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 58, 8);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.next_header(&buf).unwrap(), 58); // ICMPv6
}

#[test]
fn test_ipv6_next_header_tcp() {
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 6, 20);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.next_header(&buf).unwrap(), 6); // TCP
}

#[test]
fn test_ipv6_next_header_udp() {
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 17, 8);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.next_header(&buf).unwrap(), 17); // UDP
}

#[test]
fn test_ipv6_payload_len() {
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 58, 40);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.payload_len(&buf).unwrap(), 40);
}

#[test]
fn test_ipv6_payload_len_zero() {
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 59, 0);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.payload_len(&buf).unwrap(), 0);
}

// ============================================================================
// Builder tests
// ============================================================================

#[test]
fn test_ipv6_builder_basic_length() {
    let bytes = Ipv6Builder::new()
        .src(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        .dst(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
        .hop_limit(64)
        .next_header(58)
        .build();
    assert_eq!(bytes.len(), IPV6_HEADER_LEN);
}

#[test]
fn test_ipv6_builder_version_field() {
    let bytes = Ipv6Builder::new().build();
    assert_eq!((bytes[0] >> 4) & 0x0F, 6);
}

#[test]
fn test_ipv6_builder_src_dst_roundtrip() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let bytes = Ipv6Builder::new().src(src).dst(dst).build();
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.src(&bytes).unwrap(), src);
    assert_eq!(layer.dst(&bytes).unwrap(), dst);
}

#[test]
fn test_ipv6_builder_hop_limit() {
    let bytes = Ipv6Builder::new().hop_limit(128).build();
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.hop_limit(&bytes).unwrap(), 128);
}

#[test]
fn test_ipv6_builder_hop_limit_255() {
    let bytes = Ipv6Builder::new().hop_limit(255).build();
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.hop_limit(&bytes).unwrap(), 255);
}

#[test]
fn test_ipv6_builder_next_header() {
    let bytes = Ipv6Builder::new().next_header(17).build();
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.next_header(&bytes).unwrap(), 17);
}

#[test]
fn test_ipv6_builder_traffic_class() {
    let bytes = Ipv6Builder::new().traffic_class(0xAB).build();
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.traffic_class(&bytes).unwrap(), 0xAB);
}

#[test]
fn test_ipv6_builder_flow_label() {
    let bytes = Ipv6Builder::new().flow_label(0x12345).build();
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.flow_label(&bytes).unwrap(), 0x12345);
}

#[test]
fn test_ipv6_builder_with_payload() {
    let payload = b"hello ipv6";
    let bytes = Ipv6Builder::new()
        .src(Ipv6Addr::LOCALHOST)
        .dst(Ipv6Addr::LOCALHOST)
        .payload(payload.as_ref())
        .build();
    assert_eq!(bytes.len(), IPV6_HEADER_LEN + payload.len());
    assert_eq!(&bytes[IPV6_HEADER_LEN..], payload.as_ref());
}

#[test]
fn test_ipv6_auto_length_calculation() {
    let payload = vec![0u8; 32];
    let bytes = Ipv6Builder::new().payload(payload.clone()).build();
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.payload_len(&bytes).unwrap(), 32);
}

#[test]
fn test_ipv6_manual_payload_len_override() {
    let bytes = Ipv6Builder::new()
        .payload(vec![0u8; 10])
        .payload_len(99) // override with manual value
        .build();
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.payload_len(&bytes).unwrap(), 99);
}

// ============================================================================
// Field setters
// ============================================================================

#[test]
fn test_ipv6_set_hop_limit() {
    let mut buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 6, 0);
    let layer = Ipv6Layer::at_start();
    layer.set_hop_limit(&mut buf, 42).unwrap();
    assert_eq!(layer.hop_limit(&buf).unwrap(), 42);
}

#[test]
fn test_ipv6_set_traffic_class() {
    let src = Ipv6Addr::LOCALHOST;
    let dst = Ipv6Addr::LOCALHOST;
    let mut buf = make_ipv6_buf(src, dst, 6, 0);
    let layer = Ipv6Layer::at_start();
    layer.set_traffic_class(&mut buf, 0xC0).unwrap();
    assert_eq!(layer.traffic_class(&buf).unwrap(), 0xC0);
}

#[test]
fn test_ipv6_set_flow_label() {
    let mut buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 6, 0);
    let layer = Ipv6Layer::at_start();
    layer.set_flow_label(&mut buf, 0xABCDE).unwrap();
    assert_eq!(layer.flow_label(&buf).unwrap(), 0xABCDE);
}

#[test]
fn test_ipv6_set_src_address() {
    let mut buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 6, 0);
    let layer = Ipv6Layer::at_start();
    let new_src = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4);
    layer.set_src(&mut buf, new_src).unwrap();
    assert_eq!(layer.src(&buf).unwrap(), new_src);
}

#[test]
fn test_ipv6_set_dst_address() {
    let mut buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 6, 0);
    let layer = Ipv6Layer::at_start();
    let new_dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 255);
    layer.set_dst(&mut buf, new_dst).unwrap();
    assert_eq!(layer.dst(&buf).unwrap(), new_dst);
}

#[test]
fn test_ipv6_set_next_header() {
    let mut buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 6, 0);
    let layer = Ipv6Layer::at_start();
    layer.set_next_header(&mut buf, 58).unwrap();
    assert_eq!(layer.next_header(&buf).unwrap(), 58);
}

// ============================================================================
// Address types
// ============================================================================

#[test]
fn test_ipv6_loopback_address() {
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 58, 0);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.src(&buf).unwrap(), Ipv6Addr::LOCALHOST);
}

#[test]
fn test_ipv6_link_local_address() {
    let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0200, 0x5EFF, 0xFE12, 0x3456);
    let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    let buf = make_ipv6_buf(src, dst, 58, 0);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.src(&buf).unwrap(), src);
    assert_eq!(layer.dst(&buf).unwrap(), dst);
}

#[test]
fn test_ipv6_unspecified_address() {
    let buf = Ipv6Builder::new()
        .src(Ipv6Addr::UNSPECIFIED)
        .dst(Ipv6Addr::UNSPECIFIED)
        .build();
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.src(&buf).unwrap(), Ipv6Addr::UNSPECIFIED);
    assert_eq!(layer.dst(&buf).unwrap(), Ipv6Addr::UNSPECIFIED);
}

// ============================================================================
// Layer kind and header length
// ============================================================================

#[test]
fn test_ipv6_layer_kind() {
    use stackforge_core::layer::Layer;
    let _buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 58, 0);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.kind(), LayerKind::Ipv6);
}

#[test]
fn test_ipv6_header_len_constant() {
    assert_eq!(IPV6_HEADER_LEN, 40);
}

#[test]
fn test_ipv6_header_len_method() {
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 58, 0);
    let layer = Ipv6Layer::at_start();
    assert_eq!(layer.header_len(&buf), 40);
}

// ============================================================================
// field_names
// ============================================================================

#[test]
fn test_ipv6_field_names() {
    let names = Ipv6Layer::field_names();
    assert!(names.contains(&"version"));
    assert!(names.contains(&"tc"));
    assert!(names.contains(&"fl"));
    assert!(names.contains(&"plen"));
    assert!(names.contains(&"nh"));
    assert!(names.contains(&"hlim"));
    assert!(names.contains(&"src"));
    assert!(names.contains(&"dst"));
}

// ============================================================================
// summary()
// ============================================================================

#[test]
fn test_ipv6_summary_contains_ipv6() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let buf = make_ipv6_buf(src, dst, 58, 0);
    let layer = Ipv6Layer::at_start();
    let s = layer.summary(&buf);
    assert!(s.contains("IPv6"));
}

#[test]
fn test_ipv6_summary_contains_addresses() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let buf = make_ipv6_buf(src, dst, 58, 0);
    let layer = Ipv6Layer::at_start();
    let s = layer.summary(&buf);
    assert!(s.contains("2001:db8::1"));
    assert!(s.contains("2001:db8::2"));
}

// ============================================================================
// Dynamic field access (get_field / set_field)
// ============================================================================

#[test]
fn test_ipv6_get_field_version() {
    use stackforge_core::FieldValue;
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 17, 0);
    let layer = Ipv6Layer::at_start();
    if let Some(Ok(FieldValue::U8(v))) = layer.get_field(&buf, "version") {
        assert_eq!(v, 6);
    } else {
        panic!("expected version = 6");
    }
}

#[test]
fn test_ipv6_get_field_nh() {
    use stackforge_core::FieldValue;
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 17, 0);
    let layer = Ipv6Layer::at_start();
    if let Some(Ok(FieldValue::U8(v))) = layer.get_field(&buf, "nh") {
        assert_eq!(v, 17);
    } else {
        panic!("expected nh = 17");
    }
}

#[test]
fn test_ipv6_get_field_hlim() {
    use stackforge_core::FieldValue;
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 17, 0);
    let layer = Ipv6Layer::at_start();
    if let Some(Ok(FieldValue::U8(v))) = layer.get_field(&buf, "hlim") {
        assert_eq!(v, 64);
    } else {
        panic!("expected hlim = 64");
    }
}

#[test]
fn test_ipv6_get_field_unknown_returns_none() {
    let buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 17, 0);
    let layer = Ipv6Layer::at_start();
    assert!(layer.get_field(&buf, "nonexistent_field").is_none());
}

#[test]
fn test_ipv6_set_field_hlim() {
    use stackforge_core::FieldValue;
    let mut buf = make_ipv6_buf(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 6, 0);
    let layer = Ipv6Layer::at_start();
    layer
        .set_field(&mut buf, "hlim", FieldValue::U8(200))
        .unwrap()
        .unwrap();
    assert_eq!(layer.hop_limit(&buf).unwrap(), 200);
}

// ============================================================================
// Extension headers
// ============================================================================

#[test]
fn test_ext_header_icmpv6_terminal() {
    // NH=58 = ICMPv6 — immediately terminal, no extension header
    let buf = vec![0u8; 8]; // 8 bytes of "ICMPv6"
    let headers = parse_ext_headers(&buf, 0, 58);
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].kind, ExtHeaderKind::Icmpv6);
}

#[test]
fn test_ext_header_hop_by_hop_then_icmpv6() {
    // Hop-by-Hop (8 bytes, next=58), then ICMPv6 (8 bytes)
    let mut buf = vec![0u8; 16];
    buf[0] = 58; // next header = ICMPv6
    buf[1] = 0; // Hdr Ext Len=0 => (0+1)*8 = 8 bytes
    // buf[2..8] = padding
    // buf[8..16] = ICMPv6 payload
    let headers = parse_ext_headers(&buf, 0, 0); // start with HopByHop (NH=0)
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].kind, ExtHeaderKind::HopByHop);
    assert_eq!(headers[0].start, 0);
    assert_eq!(headers[0].end, 8);
    assert_eq!(headers[1].kind, ExtHeaderKind::Icmpv6);
    assert_eq!(headers[1].start, 8);
}

#[test]
fn test_ext_header_fragment_then_udp() {
    // Fragment header (8 bytes, next=17), then UDP (8 bytes)
    let mut buf = vec![0u8; 16];
    buf[0] = 17; // next header = UDP
    // Fragment header is always exactly 8 bytes
    let headers = parse_ext_headers(&buf, 0, 44); // start with Fragment (NH=44)
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].kind, ExtHeaderKind::Fragment);
    assert_eq!(headers[0].len(), 8);
    assert_eq!(headers[1].kind, ExtHeaderKind::Udp);
}

#[test]
fn test_ext_header_routing_then_tcp() {
    // Routing header (16 bytes, len=1), then TCP
    let mut buf = vec![0u8; 36];
    buf[0] = 6; // next header = TCP
    buf[1] = 1; // Hdr Ext Len=1 => (1+1)*8 = 16 bytes
    let headers = parse_ext_headers(&buf, 0, 43); // start with Routing (NH=43)
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].kind, ExtHeaderKind::Routing);
    assert_eq!(headers[0].len(), 16);
    assert_eq!(headers[1].kind, ExtHeaderKind::Tcp);
}

#[test]
fn test_ext_header_destination_options() {
    // Destination Options header (8 bytes), then NoNextHeader
    let mut buf = vec![0u8; 12];
    buf[0] = 59; // next header = NoNextHeader
    buf[1] = 0; // Hdr Ext Len=0 => 8 bytes
    let headers = parse_ext_headers(&buf, 0, 60); // DestinationOptions (NH=60)
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].kind, ExtHeaderKind::DestinationOptions);
    assert_eq!(headers[1].kind, ExtHeaderKind::NoNextHeader);
}

#[test]
fn test_ext_header_no_next_header() {
    let buf = vec![0u8; 4];
    let headers = parse_ext_headers(&buf, 0, 59); // NoNextHeader
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].kind, ExtHeaderKind::NoNextHeader);
}

#[test]
fn test_ext_header_kind_from_nh_tcp() {
    assert_eq!(ExtHeaderKind::from_nh(6), Some(ExtHeaderKind::Tcp));
}

#[test]
fn test_ext_header_kind_from_nh_unknown() {
    assert_eq!(ExtHeaderKind::from_nh(200), None);
}

#[test]
fn test_ext_header_tcp_is_terminal() {
    assert!(ExtHeaderKind::Tcp.is_terminal());
    assert!(ExtHeaderKind::Udp.is_terminal());
    assert!(ExtHeaderKind::Icmpv6.is_terminal());
    assert!(ExtHeaderKind::NoNextHeader.is_terminal());
    assert!(!ExtHeaderKind::HopByHop.is_terminal());
    assert!(!ExtHeaderKind::Routing.is_terminal());
    assert!(!ExtHeaderKind::Fragment.is_terminal());
    assert!(!ExtHeaderKind::DestinationOptions.is_terminal());
}

// ============================================================================
// Layer offset access
// ============================================================================

#[test]
fn test_ipv6_at_offset() {
    // Build a buffer with an Ethernet header (14 bytes) prepended
    let mut buf = vec![0u8; 14 + 40];
    // Set some bytes in the IPv6 region
    buf[14] = 0x60; // version=6
    let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    buf[22..38].copy_from_slice(&src.octets()); // start + 8 = 22
    let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    buf[38..54].copy_from_slice(&dst.octets()); // start + 24 = 38
    buf[14 + 7] = 64; // hop limit

    let layer = Ipv6Layer::at_offset(14);
    assert_eq!(layer.version(&buf).unwrap(), 6);
    assert_eq!(layer.src(&buf).unwrap(), src);
    assert_eq!(layer.dst(&buf).unwrap(), dst);
    assert_eq!(layer.hop_limit(&buf).unwrap(), 64);
}

// ============================================================================
// Hashret and answers
// ============================================================================

#[test]
fn test_ipv6_hashret_length() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let buf = make_ipv6_buf(src, dst, 58, 0);
    let layer = Ipv6Layer::at_start();
    let hash = layer.hashret(&buf);
    // hashret = XOR of src+dst octets (16 bytes) + next_header (1 byte)
    assert_eq!(hash.len(), 17);
}

#[test]
fn test_ipv6_answers() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let req_buf = make_ipv6_buf(src, dst, 58, 0);
    let rep_buf = make_ipv6_buf(dst, src, 58, 0); // reversed src/dst

    let req_layer = Ipv6Layer::at_start();
    let rep_layer = Ipv6Layer::at_start();

    // Response (dst->src) should answer the request (src->dst)
    assert!(rep_layer.answers(&rep_buf, &req_layer, &req_buf));
}

#[test]
fn test_ipv6_answers_wrong_addresses() {
    let a = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let b = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let c = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3);
    let req_buf = make_ipv6_buf(a, b, 58, 0);
    let rep_buf = make_ipv6_buf(c, a, 58, 0); // wrong source

    let req_layer = Ipv6Layer::at_start();
    let rep_layer = Ipv6Layer::at_start();
    assert!(!rep_layer.answers(&rep_buf, &req_layer, &req_buf));
}

// ============================================================================
// LayerIndex integration
// ============================================================================

#[test]
fn test_ipv6_layer_index_from_new() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let buf = make_ipv6_buf(src, dst, 58, 0);
    let index = LayerIndex::new(LayerKind::Ipv6, 0, buf.len());
    let layer = Ipv6Layer { index };
    assert_eq!(layer.version(&buf).unwrap(), 6);
}
