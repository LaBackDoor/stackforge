//! DHCP (Dynamic Host Configuration Protocol) integration tests.
//!
//! Tests DHCP parsing, building, full-stack packet handling, and field access
//! for BOOTP header fields and DHCP options.

use stackforge_core::layer::dhcp::{
    DHCP_CLIENT_PORT, DHCP_FIELD_NAMES, DHCP_MIN_HEADER_LEN, DHCP_SERVER_PORT, DhcpBuilder,
    DhcpLayer, is_dhcp_payload,
    options::{DhcpOption, code, msg_type},
};
use stackforge_core::layer::field::MacAddress;
use stackforge_core::layer::stack::{LayerStack, LayerStackEntry};
use stackforge_core::layer::udp::builder::UdpBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerIndex, LayerKind};
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

// ============================================================================
// Helper: wrap DHCP bytes in Eth/IP/UDP full-stack packet
// ============================================================================

fn build_dhcp_packet(dhcp_payload: Vec<u8>, sport: u16, dport: u16) -> Packet {
    let raw = LayerStack::new()
        .push(LayerStackEntry::Ethernet(
            EthernetBuilder::new()
                .dst(MacAddress::BROADCAST)
                .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        ))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(0, 0, 0, 0))
                .dst(Ipv4Addr::new(255, 255, 255, 255))
                .ttl(64),
        ))
        .push(LayerStackEntry::Udp(
            UdpBuilder::new().src_port(sport).dst_port(dport),
        ))
        .push(LayerStackEntry::Raw(dhcp_payload))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    pkt
}

fn make_layer(data: &[u8]) -> DhcpLayer {
    DhcpLayer::new(LayerIndex::new(LayerKind::Dhcp, 0, data.len()))
}

// ============================================================================
// Constants
// ============================================================================

#[test]
fn test_dhcp_constants() {
    assert_eq!(DHCP_SERVER_PORT, 67);
    assert_eq!(DHCP_CLIENT_PORT, 68);
    assert!(DHCP_MIN_HEADER_LEN >= 240);
}

#[test]
fn test_dhcp_field_names() {
    let names = DHCP_FIELD_NAMES;
    assert!(names.contains(&"op"));
    assert!(names.contains(&"xid"));
    assert!(names.contains(&"chaddr"));
    assert!(names.contains(&"msg_type"));
    assert!(names.contains(&"server_id"));
    assert!(names.contains(&"lease_time"));
    assert!(names.contains(&"subnet_mask"));
    assert!(names.contains(&"router"));
    assert!(names.contains(&"dns"));
}

// ============================================================================
// Builder tests
// ============================================================================

#[test]
fn test_builder_discover() {
    let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let data = DhcpBuilder::discover(mac, 0xdeadbeef).build();

    let layer = make_layer(&data);
    assert_eq!(layer.op(&data).unwrap(), 1);
    assert_eq!(layer.htype(&data).unwrap(), 1);
    assert_eq!(layer.hlen(&data).unwrap(), 6);
    assert_eq!(layer.hops(&data).unwrap(), 0);
    assert_eq!(layer.xid(&data).unwrap(), 0xdeadbeef);
    assert_eq!(layer.flags(&data).unwrap(), 0x8000); // broadcast
    assert_eq!(
        layer.chaddr(&data).unwrap(),
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    );
    assert_eq!(layer.msg_type(&data), Some(msg_type::DISCOVER));
    assert!(layer.is_request(&data));
    assert!(!layer.is_reply(&data));
}

#[test]
fn test_builder_offer() {
    let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let data = DhcpBuilder::offer(
        0x12345678,
        mac,
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(192, 168, 1, 1),
    )
    .lease_time(3600)
    .subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
    .router(Ipv4Addr::new(192, 168, 1, 1))
    .dns(&[Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)])
    .build();

    let layer = make_layer(&data);
    assert_eq!(layer.op(&data).unwrap(), 2);
    assert_eq!(layer.xid(&data).unwrap(), 0x12345678);
    assert_eq!(
        layer.yiaddr(&data).unwrap(),
        Ipv4Addr::new(192, 168, 1, 100)
    );
    assert_eq!(layer.siaddr(&data).unwrap(), Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(layer.msg_type(&data), Some(msg_type::OFFER));
    assert_eq!(layer.server_id(&data), Some(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(layer.lease_time(&data), Some(3600));
    assert_eq!(
        layer.subnet_mask(&data),
        Some(Ipv4Addr::new(255, 255, 255, 0))
    );
    assert_eq!(layer.router(&data), Some(Ipv4Addr::new(192, 168, 1, 1)));
    let dns_servers = layer.dns(&data);
    assert_eq!(dns_servers.len(), 2);
    assert_eq!(dns_servers[0], Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(dns_servers[1], Ipv4Addr::new(8, 8, 4, 4));
    assert!(layer.is_reply(&data));
}

#[test]
fn test_builder_request() {
    let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let data = DhcpBuilder::request(
        mac,
        0xaabbccdd,
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(192, 168, 1, 1),
    )
    .build();

    let layer = make_layer(&data);
    assert_eq!(layer.op(&data).unwrap(), 1);
    assert_eq!(layer.xid(&data).unwrap(), 0xaabbccdd);
    assert_eq!(layer.msg_type(&data), Some(msg_type::REQUEST));
    assert_eq!(
        layer.requested_ip(&data),
        Some(Ipv4Addr::new(192, 168, 1, 100))
    );
    assert_eq!(layer.server_id(&data), Some(Ipv4Addr::new(192, 168, 1, 1)));
}

#[test]
fn test_builder_ack() {
    let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let data = DhcpBuilder::ack(
        0x11223344,
        mac,
        Ipv4Addr::new(10, 0, 0, 50),
        Ipv4Addr::new(10, 0, 0, 1),
    )
    .lease_time(86400)
    .subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
    .router(Ipv4Addr::new(10, 0, 0, 1))
    .dns(&[Ipv4Addr::new(8, 8, 8, 8)])
    .domain_name("example.com")
    .build();

    let layer = make_layer(&data);
    assert_eq!(layer.op(&data).unwrap(), 2);
    assert_eq!(layer.msg_type(&data), Some(msg_type::ACK));
    assert_eq!(layer.yiaddr(&data).unwrap(), Ipv4Addr::new(10, 0, 0, 50));
    assert_eq!(layer.server_id(&data), Some(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(layer.lease_time(&data), Some(86400));
}

#[test]
fn test_builder_nak() {
    let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let data = DhcpBuilder::nak(0x55667788, mac, Ipv4Addr::new(10, 0, 0, 1)).build();

    let layer = make_layer(&data);
    assert_eq!(layer.op(&data).unwrap(), 2);
    assert_eq!(layer.msg_type(&data), Some(msg_type::NAK));
    assert_eq!(layer.server_id(&data), Some(Ipv4Addr::new(10, 0, 0, 1)));
}

// ============================================================================
// Summary tests
// ============================================================================

#[test]
fn test_summary_all_types() {
    let mac = MacAddress::new([0x00; 6]);

    let discover = DhcpBuilder::discover(mac, 1).build();
    assert_eq!(make_layer(&discover).summary(&discover), "DHCP Discover");

    let offer = DhcpBuilder::offer(1, mac, Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST).build();
    assert_eq!(make_layer(&offer).summary(&offer), "DHCP Offer");

    let request = DhcpBuilder::request(mac, 1, Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST).build();
    assert_eq!(make_layer(&request).summary(&request), "DHCP Request");

    let ack = DhcpBuilder::ack(1, mac, Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST).build();
    assert_eq!(make_layer(&ack).summary(&ack), "DHCP ACK");

    let nak = DhcpBuilder::nak(1, mac, Ipv4Addr::LOCALHOST).build();
    assert_eq!(make_layer(&nak).summary(&nak), "DHCP NAK");
}

// ============================================================================
// Options tests
// ============================================================================

#[test]
fn test_options_parsing() {
    let mac = MacAddress::new([0x00; 6]);
    let data = DhcpBuilder::offer(
        1,
        mac,
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(192, 168, 1, 1),
    )
    .lease_time(3600)
    .subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
    .router(Ipv4Addr::new(192, 168, 1, 1))
    .dns(&[Ipv4Addr::new(8, 8, 8, 8)])
    .domain_name("example.com")
    .build();

    let layer = make_layer(&data);
    let opts = layer.options(&data);

    // Should have: msg_type, server_id, lease_time, subnet_mask, router, dns, domain_name
    assert!(opts.len() >= 7);

    // Find message type
    let mt = opts.iter().find(|o| o.code == code::MESSAGE_TYPE).unwrap();
    assert_eq!(mt.as_message_type(), Some(msg_type::OFFER));

    // Find server_id
    let sid = opts.iter().find(|o| o.code == code::SERVER_ID).unwrap();
    assert_eq!(sid.as_ipv4(), Some(Ipv4Addr::new(192, 168, 1, 1)));

    // Find domain name
    let dn = opts.iter().find(|o| o.code == code::DOMAIN_NAME).unwrap();
    assert_eq!(&dn.data, b"example.com");
}

#[test]
fn test_option_serialize_roundtrip() {
    let opt = DhcpOption::lease_time(7200);
    let bytes = opt.to_bytes();
    assert_eq!(bytes[0], code::LEASE_TIME);
    assert_eq!(bytes[1], 4); // length
    assert_eq!(
        u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
        7200
    );
}

#[test]
fn test_options_empty_for_short_buffer() {
    let data = vec![0u8; 100]; // too short for DHCP
    let layer = make_layer(&data);
    assert!(layer.options(&data).is_empty());
}

#[test]
fn test_options_empty_for_bad_cookie() {
    let mut data = vec![0u8; 300];
    // Set wrong magic cookie
    data[236] = 0;
    data[237] = 0;
    data[238] = 0;
    data[239] = 0;
    let layer = make_layer(&data);
    assert!(layer.options(&data).is_empty());
}

// ============================================================================
// is_dhcp_payload
// ============================================================================

#[test]
fn test_is_dhcp_payload_valid() {
    let mac = MacAddress::new([0x00; 6]);
    let data = DhcpBuilder::discover(mac, 1).build();
    assert!(is_dhcp_payload(&data));
}

#[test]
fn test_is_dhcp_payload_too_short() {
    assert!(!is_dhcp_payload(&[0u8; 10]));
    assert!(!is_dhcp_payload(&[0u8; 243]));
}

#[test]
fn test_is_dhcp_payload_bad_cookie() {
    let mut data = vec![0u8; 300];
    data[236] = 99;
    data[237] = 130;
    data[238] = 83;
    data[239] = 99;
    assert!(is_dhcp_payload(&data));

    data[236] = 0;
    assert!(!is_dhcp_payload(&data));
}

// ============================================================================
// Full-stack packet parsing (Eth/IP/UDP/DHCP)
// ============================================================================

#[test]
fn test_full_stack_discover() {
    let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let dhcp_data = DhcpBuilder::discover(mac, 0xcafebabe).build();
    let pkt = build_dhcp_packet(dhcp_data, DHCP_CLIENT_PORT, DHCP_SERVER_PORT);

    assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
    assert!(pkt.get_layer(LayerKind::Ipv4).is_some());
    assert!(pkt.get_layer(LayerKind::Udp).is_some());
    assert!(pkt.get_layer(LayerKind::Dhcp).is_some());

    // Verify DHCP layer parsed correctly
    let dhcp_idx = pkt.get_layer(LayerKind::Dhcp).unwrap();
    let layer = DhcpLayer::new(*dhcp_idx);
    let buf = pkt.as_bytes();
    assert_eq!(layer.op(buf).unwrap(), 1);
    assert_eq!(layer.xid(buf).unwrap(), 0xcafebabe);
    assert_eq!(layer.msg_type(buf), Some(msg_type::DISCOVER));
}

#[test]
fn test_full_stack_offer() {
    let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let dhcp_data = DhcpBuilder::offer(
        0xdeadbeef,
        mac,
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(192, 168, 1, 1),
    )
    .lease_time(3600)
    .build();

    let pkt = build_dhcp_packet(dhcp_data, DHCP_SERVER_PORT, DHCP_CLIENT_PORT);
    assert!(pkt.get_layer(LayerKind::Dhcp).is_some());

    let dhcp_idx = pkt.get_layer(LayerKind::Dhcp).unwrap();
    let layer = DhcpLayer::new(*dhcp_idx);
    let buf = pkt.as_bytes();
    assert_eq!(layer.msg_type(buf), Some(msg_type::OFFER));
    assert_eq!(layer.yiaddr(buf).unwrap(), Ipv4Addr::new(192, 168, 1, 100));
}

// ============================================================================
// get_field / set_field tests
// ============================================================================

#[test]
fn test_get_field_bootp_fields() {
    let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let data = DhcpBuilder::discover(mac, 0x12345678).build();
    let layer = make_layer(&data);

    use stackforge_core::layer::field::FieldValue;

    assert_eq!(layer.get_field(&data, "op"), Some(Ok(FieldValue::U8(1))));
    assert_eq!(layer.get_field(&data, "htype"), Some(Ok(FieldValue::U8(1))));
    assert_eq!(layer.get_field(&data, "hlen"), Some(Ok(FieldValue::U8(6))));
    assert_eq!(
        layer.get_field(&data, "xid"),
        Some(Ok(FieldValue::U32(0x12345678)))
    );
    assert_eq!(
        layer.get_field(&data, "flags"),
        Some(Ok(FieldValue::U16(0x8000)))
    );
    assert_eq!(
        layer.get_field(&data, "chaddr"),
        Some(Ok(FieldValue::Mac(MacAddress::new([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55
        ]))))
    );
    assert_eq!(layer.get_field(&data, "nonexistent"), None);
}

#[test]
fn test_get_field_option_fields() {
    let mac = MacAddress::new([0x00; 6]);
    let data = DhcpBuilder::offer(
        1,
        mac,
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(192, 168, 1, 1),
    )
    .lease_time(7200)
    .subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
    .router(Ipv4Addr::new(192, 168, 1, 1))
    .dns(&[Ipv4Addr::new(8, 8, 8, 8)])
    .build();

    let layer = make_layer(&data);
    use stackforge_core::layer::field::FieldValue;

    assert_eq!(
        layer.get_field(&data, "msg_type"),
        Some(Ok(FieldValue::U8(msg_type::OFFER)))
    );
    assert_eq!(
        layer.get_field(&data, "server_id"),
        Some(Ok(FieldValue::Ipv4(Ipv4Addr::new(192, 168, 1, 1))))
    );
    assert_eq!(
        layer.get_field(&data, "lease_time"),
        Some(Ok(FieldValue::U32(7200)))
    );
    assert_eq!(
        layer.get_field(&data, "subnet_mask"),
        Some(Ok(FieldValue::Ipv4(Ipv4Addr::new(255, 255, 255, 0))))
    );
    assert_eq!(
        layer.get_field(&data, "router"),
        Some(Ok(FieldValue::Ipv4(Ipv4Addr::new(192, 168, 1, 1))))
    );
    assert_eq!(
        layer.get_field(&data, "dns"),
        Some(Ok(FieldValue::Str("8.8.8.8".to_string())))
    );
}

#[test]
fn test_set_field_op() {
    let mac = MacAddress::new([0x00; 6]);
    let mut data = DhcpBuilder::discover(mac, 1).build();
    let layer = make_layer(&data);

    use stackforge_core::layer::field::FieldValue;

    assert_eq!(layer.op(&data).unwrap(), 1);
    layer
        .set_field(&mut data, "op", FieldValue::U8(2))
        .unwrap()
        .unwrap();
    assert_eq!(layer.op(&data).unwrap(), 2);
}

#[test]
fn test_set_field_xid() {
    let mac = MacAddress::new([0x00; 6]);
    let mut data = DhcpBuilder::discover(mac, 0x11111111).build();
    let layer = make_layer(&data);

    use stackforge_core::layer::field::FieldValue;

    layer
        .set_field(&mut data, "xid", FieldValue::U32(0x99999999))
        .unwrap()
        .unwrap();
    assert_eq!(layer.xid(&data).unwrap(), 0x99999999);
}

// ============================================================================
// IP address fields
// ============================================================================

#[test]
fn test_ciaddr_giaddr() {
    let mac = MacAddress::new([0x00; 6]);
    let data = DhcpBuilder::discover(mac, 1).build();
    let layer = make_layer(&data);

    assert_eq!(layer.ciaddr(&data).unwrap(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(layer.giaddr(&data).unwrap(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(layer.secs(&data).unwrap(), 0);
}

// ============================================================================
// Layer trait implementation
// ============================================================================

#[test]
fn test_layer_kind() {
    let mac = MacAddress::new([0x00; 6]);
    let data = DhcpBuilder::discover(mac, 1).build();
    let layer = make_layer(&data);
    use stackforge_core::layer::Layer;
    assert_eq!(layer.kind(), LayerKind::Dhcp);
}

#[test]
fn test_header_len_equals_data_len() {
    let mac = MacAddress::new([0x00; 6]);
    let data = DhcpBuilder::discover(mac, 1).build();
    let layer = make_layer(&data);
    use stackforge_core::layer::Layer;
    assert_eq!(layer.header_len(&data), data.len());
}
