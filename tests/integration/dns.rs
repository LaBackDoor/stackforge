//! DNS protocol integration tests
//!
//! Tests DNS parsing, building, name compression, and full-stack packet handling.

use stackforge_core::layer::dns::DnsLayer;
use stackforge_core::layer::dns::builder::DnsBuilder;
use stackforge_core::layer::dns::query::DnsQuestion;
use stackforge_core::layer::dns::rdata::DnsRData;
use stackforge_core::layer::dns::rr::DnsResourceRecord;
use stackforge_core::layer::dns::types;
use stackforge_core::layer::field_ext::DnsName;
use stackforge_core::layer::stack::{LayerStack, LayerStackEntry};
use stackforge_core::layer::udp::builder::UdpBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerKind};
use stackforge_core::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

// ============================================================================
// Helper: Build a DNS query packet (Ether/IP/UDP/DNS)
// ============================================================================

fn build_dns_query_packet(qname: &str, qtype: u16) -> Vec<u8> {
    let stack = LayerStack::new()
        .push(LayerStackEntry::Ethernet(
            EthernetBuilder::new()
                .dst(MacAddress::BROADCAST)
                .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        ))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(192, 168, 1, 100))
                .dst(Ipv4Addr::new(8, 8, 8, 8))
                .ttl(64),
        ))
        .push(LayerStackEntry::Udp(
            UdpBuilder::new().src_port(12345).dst_port(53),
        ))
        .push(LayerStackEntry::Dns(
            DnsBuilder::query(qname, qtype).id(0xAAAA),
        ));

    stack.build()
}

// ============================================================================
// DNS Header Parsing
// ============================================================================

#[test]
fn test_dns_header_fields() {
    let dns_bytes = DnsBuilder::new()
        .id(0x1234)
        .qr(true)
        .opcode(0)
        .aa(true)
        .tc(false)
        .rd(true)
        .ra(true)
        .z(false)
        .ad(true)
        .cd(false)
        .rcode(0)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    assert_eq!(layer.id(&dns_bytes).unwrap(), 0x1234);
    assert!(layer.qr(&dns_bytes).unwrap());
    assert_eq!(layer.opcode(&dns_bytes).unwrap(), 0);
    assert!(layer.aa(&dns_bytes).unwrap());
    assert!(!layer.tc(&dns_bytes).unwrap());
    assert!(layer.rd(&dns_bytes).unwrap());
    assert!(layer.ra(&dns_bytes).unwrap());
    assert!(!layer.z(&dns_bytes).unwrap());
    assert!(layer.ad(&dns_bytes).unwrap());
    assert!(!layer.cd(&dns_bytes).unwrap());
    assert_eq!(layer.rcode(&dns_bytes).unwrap(), 0);
}

#[test]
fn test_dns_section_counts() {
    let q1 = DnsQuestion::from_name("example.com").unwrap();
    let q2 = DnsQuestion::from_name("test.com").unwrap();
    let mut a1 = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::A,
        DnsRData::A(Ipv4Addr::new(93, 184, 216, 34)),
    );
    a1.ttl = 300;

    let dns_bytes = DnsBuilder::new()
        .id(0x5678)
        .qr(true)
        .question(q1)
        .question(q2)
        .answer(a1)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    assert_eq!(layer.qdcount(&dns_bytes).unwrap(), 2);
    assert_eq!(layer.ancount(&dns_bytes).unwrap(), 1);
    assert_eq!(layer.nscount(&dns_bytes).unwrap(), 0);
    assert_eq!(layer.arcount(&dns_bytes).unwrap(), 0);
}

// ============================================================================
// DNS Question Parsing
// ============================================================================

#[test]
fn test_dns_question_parse_roundtrip() {
    let dns_bytes = DnsBuilder::query("www.example.com", types::rr_type::A)
        .id(0x1111)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let questions = layer.questions(&dns_bytes).unwrap();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].qname.to_string(), "www.example.com.");
    assert_eq!(questions[0].qtype, types::rr_type::A);
    assert_eq!(questions[0].qclass, types::dns_class::IN);
}

#[test]
fn test_dns_question_aaaa() {
    let mut q = DnsQuestion::from_name("ipv6.example.com").unwrap();
    q.qtype = types::rr_type::AAAA;

    let dns_bytes = DnsBuilder::new().id(0x2222).question(q).build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let questions = layer.questions(&dns_bytes).unwrap();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].qtype, types::rr_type::AAAA);
    assert_eq!(questions[0].qname.to_string(), "ipv6.example.com.");
}

#[test]
fn test_dns_question_mx() {
    let mut q = DnsQuestion::from_name("example.com").unwrap();
    q.qtype = types::rr_type::MX;

    let dns_bytes = DnsBuilder::new().id(0x3333).question(q).build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let questions = layer.questions(&dns_bytes).unwrap();
    assert_eq!(questions[0].qtype, types::rr_type::MX);
}

// ============================================================================
// DNS Answer Parsing
// ============================================================================

#[test]
fn test_dns_answer_a_record() {
    let q = DnsQuestion::from_name("example.com").unwrap();
    let mut a = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::A,
        DnsRData::A(Ipv4Addr::new(93, 184, 216, 34)),
    );
    a.ttl = 3600;

    let dns_bytes = DnsBuilder::new()
        .id(0x4444)
        .qr(true)
        .aa(true)
        .question(q)
        .answer(a)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let answers = layer.answers_rr(&dns_bytes).unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].rtype, types::rr_type::A);
    assert_eq!(answers[0].ttl, 3600);
    match &answers[0].rdata {
        DnsRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
        _ => panic!("Expected A record"),
    }
}

#[test]
fn test_dns_answer_aaaa_record() {
    let q = DnsQuestion::from_name("example.com").unwrap();
    let mut a = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::AAAA,
        DnsRData::AAAA(Ipv6Addr::new(
            0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946,
        )),
    );
    a.ttl = 3600;

    let dns_bytes = DnsBuilder::new()
        .id(0x5555)
        .qr(true)
        .question(q)
        .answer(a)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let answers = layer.answers_rr(&dns_bytes).unwrap();
    assert_eq!(answers.len(), 1);
    match &answers[0].rdata {
        DnsRData::AAAA(ip) => {
            assert_eq!(
                *ip,
                Ipv6Addr::new(
                    0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946
                )
            );
        },
        _ => panic!("Expected AAAA record"),
    }
}

#[test]
fn test_dns_answer_cname_record() {
    let q = DnsQuestion::from_name("www.example.com").unwrap();
    let mut cname = DnsResourceRecord::new(
        DnsName::from("www.example.com"),
        types::rr_type::CNAME,
        DnsRData::CNAME(DnsName::from("example.com")),
    );
    cname.ttl = 3600;
    let mut a = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::A,
        DnsRData::A(Ipv4Addr::new(93, 184, 216, 34)),
    );
    a.ttl = 3600;

    let dns_bytes = DnsBuilder::new()
        .id(0x6666)
        .qr(true)
        .question(q)
        .answer(cname)
        .answer(a)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let answers = layer.answers_rr(&dns_bytes).unwrap();
    assert_eq!(answers.len(), 2);
    match &answers[0].rdata {
        DnsRData::CNAME(name) => assert_eq!(name.to_string(), "example.com."),
        _ => panic!("Expected CNAME record"),
    }
    match &answers[1].rdata {
        DnsRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
        _ => panic!("Expected A record"),
    }
}

#[test]
fn test_dns_answer_mx_record() {
    let q = DnsQuestion::from_name("example.com").unwrap();
    let mut mx = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::MX,
        DnsRData::MX {
            preference: 10,
            exchange: DnsName::from("mail.example.com"),
        },
    );
    mx.ttl = 3600;

    let dns_bytes = DnsBuilder::new()
        .id(0x7777)
        .qr(true)
        .question(q)
        .answer(mx)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let answers = layer.answers_rr(&dns_bytes).unwrap();
    assert_eq!(answers.len(), 1);
    match &answers[0].rdata {
        DnsRData::MX {
            preference,
            exchange,
        } => {
            assert_eq!(*preference, 10);
            assert_eq!(exchange.to_string(), "mail.example.com.");
        },
        _ => panic!("Expected MX record"),
    }
}

#[test]
fn test_dns_answer_ns_record() {
    let q = DnsQuestion::from_name("example.com").unwrap();
    let mut ns1 = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::NS,
        DnsRData::NS(DnsName::from("ns1.example.com")),
    );
    ns1.ttl = 172800;
    let mut ns2 = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::NS,
        DnsRData::NS(DnsName::from("ns2.example.com")),
    );
    ns2.ttl = 172800;

    let dns_bytes = DnsBuilder::new()
        .id(0x8888)
        .qr(true)
        .question(q)
        .authority(ns1)
        .authority(ns2)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    assert_eq!(layer.nscount(&dns_bytes).unwrap(), 2);
    let authorities = layer.authorities(&dns_bytes).unwrap();
    assert_eq!(authorities.len(), 2);
    match &authorities[0].rdata {
        DnsRData::NS(name) => assert_eq!(name.to_string(), "ns1.example.com."),
        _ => panic!("Expected NS record"),
    }
}

#[test]
fn test_dns_answer_soa_record() {
    let q = DnsQuestion::from_name("example.com").unwrap();
    let mut soa = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::SOA,
        DnsRData::SOA {
            mname: DnsName::from("ns1.example.com"),
            rname: DnsName::from("admin.example.com"),
            serial: 2024010101,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: 86400,
        },
    );
    soa.ttl = 3600;

    let dns_bytes = DnsBuilder::new()
        .id(0x9999)
        .qr(true)
        .question(q)
        .authority(soa)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let authorities = layer.authorities(&dns_bytes).unwrap();
    assert_eq!(authorities.len(), 1);
    match &authorities[0].rdata {
        DnsRData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            assert_eq!(mname.to_string(), "ns1.example.com.");
            assert_eq!(rname.to_string(), "admin.example.com.");
            assert_eq!(*serial, 2024010101);
            assert_eq!(*refresh, 3600);
            assert_eq!(*retry, 900);
            assert_eq!(*expire, 604800);
            assert_eq!(*minimum, 86400);
        },
        _ => panic!("Expected SOA record"),
    }
}

#[test]
fn test_dns_answer_txt_record() {
    let q = DnsQuestion::from_name("example.com").unwrap();
    let mut txt = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::TXT,
        DnsRData::TXT(vec![b"v=spf1 include:_spf.google.com ~all".to_vec()]),
    );
    txt.ttl = 3600;

    let dns_bytes = DnsBuilder::new()
        .id(0xAAAA)
        .qr(true)
        .question(q)
        .answer(txt)
        .compress(false) // TXT records don't benefit from compression
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let answers = layer.answers_rr(&dns_bytes).unwrap();
    assert_eq!(answers.len(), 1);
    match &answers[0].rdata {
        DnsRData::TXT(strings) => {
            assert_eq!(strings.len(), 1);
            assert_eq!(
                String::from_utf8_lossy(&strings[0]),
                "v=spf1 include:_spf.google.com ~all"
            );
        },
        _ => panic!("Expected TXT record"),
    }
}

#[test]
fn test_dns_answer_srv_record() {
    let q = DnsQuestion::from_name("_sip._tcp.example.com").unwrap();
    let mut srv = DnsResourceRecord::new(
        DnsName::from("_sip._tcp.example.com"),
        types::rr_type::SRV,
        DnsRData::SRV {
            priority: 10,
            weight: 60,
            port: 5060,
            target: DnsName::from("sip.example.com"),
        },
    );
    srv.ttl = 3600;

    let dns_bytes = DnsBuilder::new()
        .id(0xBBBB)
        .qr(true)
        .question(q)
        .answer(srv)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let answers = layer.answers_rr(&dns_bytes).unwrap();
    assert_eq!(answers.len(), 1);
    match &answers[0].rdata {
        DnsRData::SRV {
            priority,
            weight,
            port,
            target,
        } => {
            assert_eq!(*priority, 10);
            assert_eq!(*weight, 60);
            assert_eq!(*port, 5060);
            assert_eq!(target.to_string(), "sip.example.com.");
        },
        _ => panic!("Expected SRV record"),
    }
}

#[test]
fn test_dns_answer_ptr_record() {
    let mut q = DnsQuestion::from_name("34.216.184.93.in-addr.arpa").unwrap();
    q.qtype = types::rr_type::PTR;
    let mut ptr = DnsResourceRecord::new(
        DnsName::from("34.216.184.93.in-addr.arpa"),
        types::rr_type::PTR,
        DnsRData::PTR(DnsName::from("example.com")),
    );
    ptr.ttl = 3600;

    let dns_bytes = DnsBuilder::new()
        .id(0xCCCC)
        .qr(true)
        .question(q)
        .answer(ptr)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let answers = layer.answers_rr(&dns_bytes).unwrap();
    assert_eq!(answers.len(), 1);
    match &answers[0].rdata {
        DnsRData::PTR(name) => assert_eq!(name.to_string(), "example.com."),
        _ => panic!("Expected PTR record"),
    }
}

// ============================================================================
// DNS Name Compression
// ============================================================================

#[test]
fn test_dns_name_compression_reduces_size() {
    let q = DnsQuestion::from_name("www.example.com").unwrap();
    let mut a = DnsResourceRecord::new(
        DnsName::from("www.example.com"),
        types::rr_type::A,
        DnsRData::A(Ipv4Addr::new(1, 2, 3, 4)),
    );
    a.ttl = 300;

    let compressed = DnsBuilder::new()
        .question(q.clone())
        .answer(a.clone())
        .compress(true)
        .build();

    let uncompressed = DnsBuilder::new()
        .question(q)
        .answer(a)
        .compress(false)
        .build();

    // Compressed should be smaller because the answer rrname "www.example.com"
    // can reference the pointer to the question's qname
    assert!(compressed.len() < uncompressed.len());
}

#[test]
fn test_dns_name_compression_multiple_shared_suffixes() {
    let q1 = DnsQuestion::from_name("www.example.com").unwrap();
    let q2 = DnsQuestion::from_name("mail.example.com").unwrap();
    let q3 = DnsQuestion::from_name("ftp.example.com").unwrap();

    let compressed = DnsBuilder::new()
        .question(q1.clone())
        .question(q2.clone())
        .question(q3.clone())
        .compress(true)
        .build();

    let uncompressed = DnsBuilder::new()
        .question(q1)
        .question(q2)
        .question(q3)
        .compress(false)
        .build();

    // With 3 questions sharing "example.com", compression should save significant space
    assert!(compressed.len() < uncompressed.len());

    // Verify all three questions are still parseable
    let layer = DnsLayer::new(0, compressed.len());
    let questions = layer.questions(&compressed).unwrap();
    assert_eq!(questions.len(), 3);
    assert_eq!(questions[0].qname.to_string(), "www.example.com.");
    assert_eq!(questions[1].qname.to_string(), "mail.example.com.");
    assert_eq!(questions[2].qname.to_string(), "ftp.example.com.");
}

// ============================================================================
// DNS Build-Parse Round-trip
// ============================================================================

#[test]
fn test_dns_query_build_parse_roundtrip() {
    let original = DnsBuilder::query("www.google.com", types::rr_type::A)
        .id(0xDEAD)
        .rd(true);

    let bytes = original.build();

    let layer = DnsLayer::new(0, bytes.len());
    assert_eq!(layer.id(&bytes).unwrap(), 0xDEAD);
    assert!(!layer.qr(&bytes).unwrap()); // Query
    assert!(layer.rd(&bytes).unwrap());
    assert_eq!(layer.qdcount(&bytes).unwrap(), 1);

    let questions = layer.questions(&bytes).unwrap();
    assert_eq!(questions[0].qname.to_string(), "www.google.com.");
    assert_eq!(questions[0].qtype, types::rr_type::A);
}

#[test]
fn test_dns_response_build_parse_roundtrip() {
    let q = DnsQuestion::from_name("example.com").unwrap();
    let mut a1 = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::A,
        DnsRData::A(Ipv4Addr::new(93, 184, 216, 34)),
    );
    a1.ttl = 300;
    let mut a2 = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::A,
        DnsRData::A(Ipv4Addr::new(93, 184, 216, 35)),
    );
    a2.ttl = 300;

    let original = DnsBuilder::response()
        .id(0xBEEF)
        .aa(true)
        .question(q)
        .answer(a1)
        .answer(a2);

    let bytes = original.build();

    let layer = DnsLayer::new(0, bytes.len());
    assert_eq!(layer.id(&bytes).unwrap(), 0xBEEF);
    assert!(layer.qr(&bytes).unwrap()); // Response
    assert!(layer.aa(&bytes).unwrap());
    assert_eq!(layer.qdcount(&bytes).unwrap(), 1);
    assert_eq!(layer.ancount(&bytes).unwrap(), 2);

    let answers = layer.answers_rr(&bytes).unwrap();
    assert_eq!(answers.len(), 2);
    match &answers[0].rdata {
        DnsRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
        _ => panic!("Expected A record"),
    }
    match &answers[1].rdata {
        DnsRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 35)),
        _ => panic!("Expected A record"),
    }
}

// ============================================================================
// Full Stack: Ether/IP/UDP/DNS
// ============================================================================

#[test]
fn test_dns_full_stack_query() {
    let bytes = build_dns_query_packet("example.com", types::rr_type::A);

    let mut pkt = Packet::from_bytes(bytes);
    pkt.parse().unwrap();

    // Verify all layers exist
    assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
    assert!(pkt.get_layer(LayerKind::Ipv4).is_some());
    assert!(pkt.get_layer(LayerKind::Udp).is_some());
    assert!(pkt.get_layer(LayerKind::Dns).is_some());

    // Verify DNS layer
    let dns = pkt.dns().unwrap();
    assert_eq!(dns.id(pkt.as_bytes()).unwrap(), 0xAAAA);
    assert!(!dns.qr(pkt.as_bytes()).unwrap());

    let questions = dns.questions(pkt.as_bytes()).unwrap();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].qname.to_string(), "example.com.");
    assert_eq!(questions[0].qtype, types::rr_type::A);
}

#[test]
fn test_dns_full_stack_udp_port_53_binding() {
    // When DNS is stacked on UDP, dport should be auto-set to 53
    let stack = LayerStack::new()
        .push(LayerStackEntry::Ethernet(EthernetBuilder::new()))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(10, 0, 0, 1))
                .dst(Ipv4Addr::new(8, 8, 8, 8)),
        ))
        .push(LayerStackEntry::Udp(UdpBuilder::new().src_port(54321)))
        .push(LayerStackEntry::Dns(DnsBuilder::query(
            "test.com",
            types::rr_type::A,
        )));

    let bytes = stack.build();

    // Parse and check UDP dport was auto-set to 53
    let mut pkt = Packet::from_bytes(bytes);
    pkt.parse().unwrap();

    let udp = pkt.udp().unwrap();
    assert_eq!(udp.dst_port(pkt.as_bytes()).unwrap(), 53);
}

#[test]
fn test_dns_mdns_port_5353_detection() {
    // Build a packet on port 5353 (mDNS)
    let stack = LayerStack::new()
        .push(LayerStackEntry::Ethernet(EthernetBuilder::new()))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(192, 168, 1, 100))
                .dst(Ipv4Addr::new(224, 0, 0, 251)),
        ))
        .push(LayerStackEntry::Udp(
            UdpBuilder::new().src_port(5353).dst_port(5353),
        ))
        .push(LayerStackEntry::Dns(DnsBuilder::query(
            "_http._tcp.local",
            types::rr_type::PTR,
        )));

    let bytes = stack.build();

    let mut pkt = Packet::from_bytes(bytes);
    pkt.parse().unwrap();

    // mDNS on port 5353 should be detected as DNS
    assert!(pkt.get_layer(LayerKind::Dns).is_some());
    let dns = pkt.dns().unwrap();
    let questions = dns.questions(pkt.as_bytes()).unwrap();
    assert_eq!(questions[0].qname.to_string(), "_http._tcp.local.");
}

// ============================================================================
// DNS Dynamic Field Access
// ============================================================================

#[test]
fn test_dns_get_field() {
    let dns_bytes = DnsBuilder::new()
        .id(0x4242)
        .qr(true)
        .rd(true)
        .ra(true)
        .rcode(3) // NXDOMAIN
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());

    // Test get_field for various field types
    match layer.get_field(&dns_bytes, "id").unwrap().unwrap() {
        FieldValue::U16(v) => assert_eq!(v, 0x4242),
        _ => panic!("Expected U16"),
    }

    match layer.get_field(&dns_bytes, "qr").unwrap().unwrap() {
        FieldValue::Bool(v) => assert!(v),
        _ => panic!("Expected Bool"),
    }

    match layer.get_field(&dns_bytes, "rcode").unwrap().unwrap() {
        FieldValue::U8(v) => assert_eq!(v, 3),
        _ => panic!("Expected U8"),
    }

    // Unknown field should return None
    assert!(layer.get_field(&dns_bytes, "nonexistent").is_none());
}

#[test]
fn test_dns_set_field() {
    let mut dns_bytes = DnsBuilder::new().id(0x1111).build();

    let layer = DnsLayer::new(0, dns_bytes.len());

    // Modify ID
    layer
        .set_field(&mut dns_bytes, "id", FieldValue::U16(0x9999))
        .unwrap()
        .unwrap();
    assert_eq!(layer.id(&dns_bytes).unwrap(), 0x9999);

    // Modify QR flag
    layer
        .set_field(&mut dns_bytes, "qr", FieldValue::Bool(true))
        .unwrap()
        .unwrap();
    assert!(layer.qr(&dns_bytes).unwrap());
}

// ============================================================================
// DNS Summary
// ============================================================================

#[test]
fn test_dns_summary_query() {
    let dns_bytes = DnsBuilder::query("example.com", types::rr_type::A)
        .id(0x1234)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let summary = layer.summary(&dns_bytes);
    assert!(summary.contains("DNS"));
    assert!(summary.contains("QUERY") || summary.contains("example.com"));
}

#[test]
fn test_dns_summary_response() {
    let dns_bytes = DnsBuilder::response()
        .id(0x1234)
        .rcode(0) // NOERROR
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let summary = layer.summary(&dns_bytes);
    assert!(summary.contains("DNS"));
}

// ============================================================================
// DNS parse_all
// ============================================================================

#[test]
fn test_dns_parse_all_sections() {
    let q = DnsQuestion::from_name("example.com").unwrap();
    let mut a = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::A,
        DnsRData::A(Ipv4Addr::new(1, 2, 3, 4)),
    );
    a.ttl = 300;
    let mut ns = DnsResourceRecord::new(
        DnsName::from("example.com"),
        types::rr_type::NS,
        DnsRData::NS(DnsName::from("ns1.example.com")),
    );
    ns.ttl = 172800;
    let mut additional = DnsResourceRecord::new(
        DnsName::from("ns1.example.com"),
        types::rr_type::A,
        DnsRData::A(Ipv4Addr::new(198, 51, 100, 1)),
    );
    additional.ttl = 172800;

    let dns_bytes = DnsBuilder::new()
        .id(0xFFFF)
        .qr(true)
        .aa(true)
        .question(q)
        .answer(a)
        .authority(ns)
        .additional(additional)
        .build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let (questions, answers, authorities, additionals) = layer.parse_all(&dns_bytes).unwrap();

    assert_eq!(questions.len(), 1);
    assert_eq!(answers.len(), 1);
    assert_eq!(authorities.len(), 1);
    assert_eq!(additionals.len(), 1);

    assert_eq!(questions[0].qname.to_string(), "example.com.");
    match &answers[0].rdata {
        DnsRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(1, 2, 3, 4)),
        _ => panic!("Expected A record"),
    }
    match &authorities[0].rdata {
        DnsRData::NS(name) => assert_eq!(name.to_string(), "ns1.example.com."),
        _ => panic!("Expected NS record"),
    }
    match &additionals[0].rdata {
        DnsRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(198, 51, 100, 1)),
        _ => panic!("Expected A record"),
    }
}

// ============================================================================
// DNS Hashret (transaction ID for matching)
// ============================================================================

#[test]
fn test_dns_hashret() {
    use stackforge_core::layer::Layer;

    let dns_bytes = DnsBuilder::new().id(0xABCD).build();
    let layer = DnsLayer::new(0, dns_bytes.len());
    let hashret = layer.hashret(&dns_bytes);
    assert_eq!(hashret, vec![0xAB, 0xCD]);
}

// ============================================================================
// DNS Type Constants
// ============================================================================

#[test]
fn test_dns_type_constants() {
    assert_eq!(types::rr_type::A, 1);
    assert_eq!(types::rr_type::NS, 2);
    assert_eq!(types::rr_type::CNAME, 5);
    assert_eq!(types::rr_type::SOA, 6);
    assert_eq!(types::rr_type::PTR, 12);
    assert_eq!(types::rr_type::MX, 15);
    assert_eq!(types::rr_type::TXT, 16);
    assert_eq!(types::rr_type::AAAA, 28);
    assert_eq!(types::rr_type::SRV, 33);
    assert_eq!(types::rr_type::DNSKEY, 48);
    assert_eq!(types::rr_type::OPT, 41);
}

#[test]
fn test_dns_class_constants() {
    assert_eq!(types::dns_class::IN, 1);
    assert_eq!(types::dns_class::CH, 3);
    assert_eq!(types::dns_class::ANY, 255);
}

#[test]
fn test_dns_rcode_constants() {
    assert_eq!(types::rcode::NOERROR, 0);
    assert_eq!(types::rcode::FORMERR, 1);
    assert_eq!(types::rcode::SERVFAIL, 2);
    assert_eq!(types::rcode::NXDOMAIN, 3);
    assert_eq!(types::rcode::NOTIMP, 4);
    assert_eq!(types::rcode::REFUSED, 5);
}

// ============================================================================
// DNS Name Edge Cases
// ============================================================================

#[test]
fn test_dns_root_name() {
    let q = DnsQuestion::from_name(".").unwrap();
    let dns_bytes = DnsBuilder::new().question(q).build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let questions = layer.questions(&dns_bytes).unwrap();
    assert_eq!(questions[0].qname.to_string(), ".");
}

#[test]
fn test_dns_single_label_name() {
    let q = DnsQuestion::from_name("localhost").unwrap();
    let dns_bytes = DnsBuilder::new().question(q).build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    let questions = layer.questions(&dns_bytes).unwrap();
    assert_eq!(questions[0].qname.to_string(), "localhost.");
}

// ============================================================================
// Malformed Packet Handling
// ============================================================================

#[test]
fn test_dns_truncated_header() {
    // Only 6 bytes (less than 12-byte DNS header)
    let short_data = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x01];
    let layer = DnsLayer::new(0, short_data.len());

    // Header field access should fail gracefully
    assert!(layer.qdcount(&short_data).is_err() || layer.arcount(&short_data).is_err());
}

#[test]
fn test_dns_zero_counts_valid() {
    // Valid header with all zeros (no questions, no answers)
    let dns_bytes = DnsBuilder::new().id(0x0000).build();

    let layer = DnsLayer::new(0, dns_bytes.len());
    assert_eq!(layer.qdcount(&dns_bytes).unwrap(), 0);
    assert_eq!(layer.ancount(&dns_bytes).unwrap(), 0);

    let questions = layer.questions(&dns_bytes).unwrap();
    assert!(questions.is_empty());
}

// ============================================================================
// DNS LayerEnum Integration
// ============================================================================

#[test]
fn test_dns_layer_enum_show_fields() {
    let bytes = build_dns_query_packet("example.com", types::rr_type::A);

    let mut pkt = Packet::from_bytes(bytes);
    pkt.parse().unwrap();

    let dns_idx = pkt.get_layer(LayerKind::Dns).unwrap();
    let layer_enum = pkt.layer_enum(dns_idx);

    let fields = layer_enum.show_fields(pkt.as_bytes());
    // Should have at least the 15 header fields
    assert!(fields.len() >= 15);

    // Check some field names exist
    let field_names: Vec<&str> = fields.iter().map(|(name, _)| *name).collect();
    assert!(field_names.contains(&"id"));
    assert!(field_names.contains(&"qr"));
    assert!(field_names.contains(&"rd"));
    assert!(field_names.contains(&"qdcount"));
}

#[test]
fn test_dns_layer_enum_field_names() {
    let bytes = build_dns_query_packet("example.com", types::rr_type::A);

    let mut pkt = Packet::from_bytes(bytes);
    pkt.parse().unwrap();

    let dns_idx = pkt.get_layer(LayerKind::Dns).unwrap();
    let layer_enum = pkt.layer_enum(dns_idx);

    let names = layer_enum.field_names();
    assert!(names.contains(&"id"));
    assert!(names.contains(&"qr"));
    assert!(names.contains(&"opcode"));
    assert!(names.contains(&"rcode"));
    assert!(names.contains(&"qdcount"));
    assert!(names.contains(&"ancount"));
    assert!(names.contains(&"nscount"));
    assert!(names.contains(&"arcount"));
}
