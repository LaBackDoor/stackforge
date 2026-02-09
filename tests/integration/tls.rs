//! Integration tests for TLS protocol layer.

use stackforge_core::layer::tls::builder::{TlsAlertBuilder, TlsCcsBuilder, TlsRecordBuilder};
use stackforge_core::layer::tls::handshake::{ClientHello, Handshake, ServerHello};
use stackforge_core::layer::tls::is_tls_payload;
use stackforge_core::layer::tls::record::TlsLayer;
use stackforge_core::layer::tls::session::TlsSession;
use stackforge_core::layer::tls::sslv2::{Sslv2ClientHello, is_sslv2};
use stackforge_core::layer::tls::types::{ExtensionType, HandshakeType, TlsContentType};
use stackforge_core::layer::{LayerIndex, LayerKind};
use stackforge_core::{LayerStack, LayerStackEntry, Packet};

// ============================================================================
// Record Layer Tests
// ============================================================================

#[test]
fn test_parse_tls_record_in_packet() {
    // Build Ethernet + IPv4 + TCP + TLS record
    let mut data = Vec::new();
    // Ethernet header (14 bytes)
    data.extend_from_slice(&[0xff; 6]); // dst
    data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
    data.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 header (20 bytes)
    data.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x00, // version/ihl, tos, total len (filled later)
        0x00, 0x01, 0x40, 0x00, // id, flags
        0x40, 0x06, 0x00, 0x00, // ttl=64, proto=TCP, checksum
        192, 168, 1, 1, // src
        192, 168, 1, 2, // dst
    ]);

    // TCP header (20 bytes) - port 443
    data.extend_from_slice(&[
        0x01, 0xBB, // sport = 443 (HTTPS)
        0xC0, 0x00, // dport = 49152
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, 0xFF, 0xFF, // data offset=5, flags=SYN, window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent
    ]);

    // TLS record: Handshake, TLS 1.2, 5 bytes of fragment
    data.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x05]);
    data.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00]); // ClientHello stub

    // Fix IP total length
    let ip_total_len = (data.len() - 14) as u16;
    data[16] = (ip_total_len >> 8) as u8;
    data[17] = (ip_total_len & 0xFF) as u8;

    let mut pkt = Packet::from_bytes(data);
    pkt.parse().unwrap();

    assert!(pkt.get_layer(LayerKind::Tls).is_some());
    assert!(pkt.get_layer(LayerKind::Tcp).is_some());

    let layers = pkt.layer_enums();
    let tls = layers.iter().find(|l| l.kind() == LayerKind::Tls).unwrap();
    let summary = tls.summary(pkt.as_bytes());
    assert!(summary.contains("TLS"));
}

#[test]
fn test_tls_record_builder_roundtrip() {
    let fragment = vec![0x01, 0x00, 0x00, 0x01, 0x00]; // ClientHello stub
    let record = TlsRecordBuilder::new()
        .content_type(TlsContentType::Handshake)
        .version(0x0303)
        .fragment(fragment.clone())
        .build();

    assert_eq!(record.len(), 10); // 5 header + 5 fragment
    assert_eq!(record[0], 0x16); // Handshake
    assert_eq!(record[1..3], [0x03, 0x03]); // TLS 1.2

    let layer = TlsLayer {
        index: LayerIndex::new(LayerKind::Tls, 0, record.len()),
    };
    assert_eq!(
        layer.content_type(&record).unwrap(),
        TlsContentType::Handshake
    );
    assert_eq!(layer.version(&record).unwrap(), 0x0303);
    assert_eq!(layer.length(&record).unwrap(), 5);
    assert_eq!(layer.fragment(&record), &fragment);
}

#[test]
fn test_tls_alert_builder() {
    let alert = TlsAlertBuilder::new()
        .level(2) // fatal
        .description(40) // handshake_failure
        .version(0x0303)
        .build();

    assert_eq!(alert[0], 0x15); // Alert content type
    assert_eq!(alert[5], 2); // fatal level
    assert_eq!(alert[6], 40); // handshake_failure
}

#[test]
fn test_tls_ccs_builder() {
    let ccs = TlsCcsBuilder::new().version(0x0303).build();

    assert_eq!(ccs[0], 0x14); // ChangeCipherSpec
    assert_eq!(ccs[5], 0x01); // CCS message
}

// ============================================================================
// Handshake Tests
// ============================================================================

#[test]
fn test_client_hello_build_parse_roundtrip() {
    let ch = ClientHello {
        version: 0x0303,
        random: [0xAB; 32],
        session_id: vec![],
        cipher_suites: vec![0x1301, 0x1302, 0x1303, 0x00FF],
        compression_methods: vec![0x00],
        extensions: vec![],
    };

    let bytes = ch.build();
    let parsed = ClientHello::parse(&bytes).unwrap();

    assert_eq!(parsed.version, 0x0303);
    assert_eq!(parsed.random, [0xAB; 32]);
    assert_eq!(parsed.cipher_suites, vec![0x1301, 0x1302, 0x1303, 0x00FF]);
    assert_eq!(parsed.compression_methods, vec![0x00]);
}

#[test]
fn test_server_hello_build_parse_roundtrip() {
    let sh = ServerHello {
        version: 0x0303,
        random: [0xCD; 32],
        session_id: vec![0x01, 0x02, 0x03, 0x04],
        cipher_suite: 0x1301,
        compression_method: 0x00,
        extensions: vec![],
    };

    let bytes = sh.build();
    let parsed = ServerHello::parse(&bytes).unwrap();

    assert_eq!(parsed.version, 0x0303);
    assert_eq!(parsed.cipher_suite, 0x1301);
    assert_eq!(parsed.session_id, vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn test_handshake_wrapper() {
    let ch = ClientHello {
        version: 0x0303,
        random: [0x00; 32],
        session_id: vec![],
        cipher_suites: vec![0x1301],
        compression_methods: vec![0x00],
        extensions: vec![],
    };

    let ch_bytes = ch.build();
    let hs = Handshake {
        msg_type: HandshakeType::CLIENT_HELLO,
        length: 0, // auto
        body: ch_bytes,
    };

    let bytes = hs.build();
    assert_eq!(bytes[0], 0x01); // ClientHello type
    // Length is 3 bytes at offset 1..4
    let length = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
    assert!(length > 0);
}

// ============================================================================
// Extension Tests
// ============================================================================

#[test]
fn test_sni_extension_roundtrip() {
    use stackforge_core::layer::tls::extensions::sni;

    let hostname = "example.com";
    let ext = sni::build_sni(hostname);

    assert_eq!(ext.ext_type, ExtensionType::SERVER_NAME.0);
    let parsed_hostnames = sni::parse_sni(&ext.data);
    assert_eq!(
        parsed_hostnames.first().map(|s| s.as_str()),
        Some("example.com")
    );
}

#[test]
fn test_supported_versions_extension() {
    use stackforge_core::layer::tls::extensions::supported_versions;

    let versions = vec![0x0304u16, 0x0303];
    let ext = supported_versions::build_supported_versions_client(&versions);
    let parsed = supported_versions::parse_supported_versions_client(&ext.data);
    assert_eq!(parsed, versions);
}

// ============================================================================
// TLS Detection Tests
// ============================================================================

#[test]
fn test_is_tls_payload_detection() {
    // Valid TLS 1.2 Handshake
    assert!(is_tls_payload(&[0x16, 0x03, 0x03, 0x00, 0x05]));
    // Valid TLS 1.0 Alert
    assert!(is_tls_payload(&[0x15, 0x03, 0x01, 0x00, 0x02]));
    // Valid CCS
    assert!(is_tls_payload(&[0x14, 0x03, 0x03, 0x00, 0x01]));
    // Application Data
    assert!(is_tls_payload(&[0x17, 0x03, 0x03, 0x00, 0x03]));
    // Invalid content type
    assert!(!is_tls_payload(&[0x19, 0x03, 0x03, 0x00, 0x05]));
    // Too short
    assert!(!is_tls_payload(&[0x16, 0x03, 0x03, 0x00]));
    // HTTP data
    assert!(!is_tls_payload(b"HTTP/1.1 200 OK\r\n"));
    // SSLv2 detection
    assert!(is_tls_payload(&[0x80, 0x2e, 0x01, 0x00, 0x02]));
}

// ============================================================================
// SSLv2 Tests
// ============================================================================

#[test]
fn test_sslv2_client_hello_parse() {
    // SSLv2 ClientHello from the .uts file
    let ch_bytes: Vec<u8> = vec![
        0x80, 0x2e, 0x01, 0x00, 0x02, 0x00, 0x15, 0x00, 0x00, 0x00, 0x10, 0x07, 0x00, 0xc0, 0x05,
        0x00, 0x80, 0x03, 0x00, 0x80, 0x01, 0x00, 0x80, 0x06, 0x00, 0x40, 0x04, 0x00, 0x80, 0x02,
        0x00, 0x80, 0x1a, 0xfb, 0x2f, 0x9c, 0xa3, 0xd1, 0x29, 0x34, 0x54, 0xa3, 0x15, 0x28, 0x21,
        0xff, 0xd1, 0x0c,
    ];

    assert!(is_sslv2(&ch_bytes));

    // Parse the SSLv2 record
    let parsed = stackforge_core::layer::tls::sslv2::record::parse_sslv2_record(&ch_bytes);
    assert!(parsed.is_some());
    let (record, _consumed) = parsed.unwrap();
    assert!(!record.data.is_empty());
    assert_eq!(record.data[0], 1); // ClientHello msg_type

    // Parse the ClientHello (parse skips the msg_type byte if present)
    let client_hello = Sslv2ClientHello::parse(&record.data);
    assert!(client_hello.is_some());
    let client_hello = client_hello.unwrap();
    assert_eq!(client_hello.version, 0x0002);
    assert_eq!(client_hello.cipher_specs.len(), 7);
    assert_eq!(client_hello.challenge.len(), 16);
}

// ============================================================================
// Session Tests
// ============================================================================

#[test]
fn test_session_creation_and_transcript() {
    let mut session = TlsSession::new_client();
    assert_eq!(session.version, 0x0303);
    assert!(!session.handshake_complete);

    session.update_transcript(b"hello");
    session.update_transcript(b" world");
    assert_eq!(session.transcript, b"hello world");
}

#[test]
fn test_nss_key_log_parsing() {
    use stackforge_core::layer::tls::session::parse_nss_key_log;

    let content = "# SSL/TLS secrets log file
CLIENT_RANDOM 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 aabbccdd
CLIENT_HANDSHAKE_TRAFFIC_SECRET 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 eeff0011
";
    let entries = parse_nss_key_log(content);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].label, "CLIENT_RANDOM");
    assert_eq!(entries[0].client_random.len(), 32);
    assert_eq!(entries[0].secret, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    assert_eq!(entries[1].label, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
}

// ============================================================================
// TLS 1.3 ClientHello from .uts test data
// ============================================================================

#[test]
fn test_parse_tls13_client_hello_from_uts() {
    // Real TLS 1.3 ClientHello from tls13.uts
    let data = hex_to_bytes(
        "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d \
         ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 \
         03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 \
         ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 \
         01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 \
         38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae \
         4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e \
         04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 \
         04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01",
    );

    // Skip the handshake header (type:1 + length:3) and parse ClientHello
    let ch = ClientHello::parse(&data[4..]).unwrap();

    assert_eq!(ch.version, 0x0303); // TLS 1.2 (legacy in TLS 1.3)
    assert_eq!(ch.cipher_suites, vec![0x1301, 0x1303, 0x1302]);
    assert_eq!(ch.compression_methods, vec![0x00]);

    // Check for SNI extension
    let sni_name = ch.sni();
    assert_eq!(sni_name.as_deref(), Some("server"));

    // Check for supported_versions extension
    let versions = ch.supported_versions();
    assert_eq!(versions, vec![0x0304u16]); // TLS 1.3
}

#[test]
fn test_parse_tls13_server_hello_from_uts() {
    // Real TLS 1.3 ServerHello from tls13.uts
    let data = hex_to_bytes(
        "02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 \
         93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e \
         00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 \
         72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 \
         03 04",
    );

    // Skip handshake header (type:1 + length:3)
    let sh = ServerHello::parse(&data[4..]).unwrap();

    assert_eq!(sh.version, 0x0303); // legacy
    assert_eq!(sh.cipher_suite, 0x1301); // TLS_AES_128_GCM_SHA256
    assert_eq!(sh.session_id.len(), 0);

    // Check selected_version extension
    let selected_version = sh.selected_version();
    assert_eq!(selected_version, 0x0304u16); // TLS 1.3
}

// ============================================================================
// Layer Stack Tests
// ============================================================================

#[test]
fn test_tls_layer_stacking() {
    use stackforge_core::layer::field::MacAddress;
    use stackforge_core::{EthernetBuilder, Ipv4Builder, TcpBuilder, TlsRecordBuilder};
    use std::net::Ipv4Addr;

    let stack = LayerStack::new()
        .push(LayerStackEntry::Ethernet(
            EthernetBuilder::new()
                .dst(MacAddress::BROADCAST)
                .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        ))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(192, 168, 1, 1))
                .dst(Ipv4Addr::new(192, 168, 1, 2))
                .ttl(64),
        ))
        .push(LayerStackEntry::Tcp(
            TcpBuilder::new().src_port(12345).dst_port(443),
        ))
        .push(LayerStackEntry::Tls(
            TlsRecordBuilder::new()
                .content_type(TlsContentType::Handshake)
                .version(0x0301)
                .fragment(vec![0x01, 0x00, 0x00, 0x01, 0x00]),
        ));

    let bytes = stack.build();

    // Parse and verify
    let mut pkt = Packet::from_bytes(bytes);
    pkt.parse().unwrap();
    assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
    assert!(pkt.get_layer(LayerKind::Ipv4).is_some());
    assert!(pkt.get_layer(LayerKind::Tcp).is_some());
    assert!(pkt.get_layer(LayerKind::Tls).is_some());
}

// ============================================================================
// Certificate Tests
// ============================================================================

#[test]
fn test_certificate_pem_loading() {
    use stackforge_core::layer::tls::cert::parse_pem_chain;

    let pem = std::fs::read_to_string("tests/uts/tls/pki/srv_cert.pem");
    if let Ok(pem_str) = pem {
        let certs = parse_pem_chain(&pem_str);
        assert!(!certs.is_empty(), "Should parse at least one certificate");
        assert!(!certs[0].is_empty(), "Certificate should not be empty");

        // Try to extract CN
        if let Some(cn) = certs[0].subject_cn() {
            assert!(!cn.is_empty(), "CN should not be empty");
        }
    }
}

// ============================================================================
// TLS 1.3 Full Record Parsing from tls13.uts
// ============================================================================

#[test]
fn test_parse_tls13_client_hello_full_record_from_uts() {
    // Full TLS record (including 5-byte record header) from tls13.uts
    let full_record = hex_to_bytes(
        "16 03 01 00 c4 01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da \
         cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 \
         13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 \
         65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 \
         01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 \
         38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d \
         54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 \
         05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 \
         02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01",
    );

    // Verify TLS record header (matches tls13.uts assertions)
    let layer = TlsLayer {
        index: LayerIndex::new(LayerKind::Tls, 0, full_record.len()),
    };
    assert_eq!(
        layer.content_type(&full_record).unwrap(),
        TlsContentType::Handshake
    );
    assert_eq!(layer.version(&full_record).unwrap(), 0x0301); // TLS 1.0 in record
    assert_eq!(layer.length(&full_record).unwrap(), 196); // matches t1.len == 196

    // Parse the ClientHello from the fragment
    let fragment = layer.fragment(&full_record);
    let (hs, _) = Handshake::parse(fragment).unwrap();
    assert_eq!(hs.msg_type, HandshakeType::CLIENT_HELLO);
    assert_eq!(hs.length, 192); // matches ch.msglen == 192

    let ch = ClientHello::parse(&hs.body).unwrap();
    assert_eq!(ch.version, 0x0303); // matches ch.version == 0x0303
    assert_eq!(ch.session_id.len(), 0); // matches ch.sidlen == 0
    assert_eq!(ch.cipher_suites, vec![0x1301, 0x1303, 0x1302]); // [4865, 4867, 4866]
    assert_eq!(ch.compression_methods, vec![0x00]); // matches ch.comp == [0]

    // Verify 9 extensions (matches len(ext) == 9 from .uts)
    assert_eq!(ch.extensions.len(), 9);

    // Verify SNI = "server" (from .uts: ext[0].servernames[0].servername == b"server")
    assert_eq!(ch.sni().as_deref(), Some("server"));

    // Verify supported versions = [0x0304] (from .uts: ext[5].versions == [772])
    assert_eq!(ch.supported_versions(), vec![0x0304u16]);
}

#[test]
fn test_parse_tls13_server_hello_full_record_from_uts() {
    // Full TLS record from tls13.uts
    let full_record = hex_to_bytes(
        "16 03 03 00 5a 02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 \
         9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 \
         00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db \
         f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 \
         02 03 04",
    );

    // Verify TLS record header
    let layer = TlsLayer {
        index: LayerIndex::new(LayerKind::Tls, 0, full_record.len()),
    };
    assert_eq!(
        layer.content_type(&full_record).unwrap(),
        TlsContentType::Handshake
    );
    assert_eq!(layer.version(&full_record).unwrap(), 0x0303);

    // Parse ServerHello from fragment
    let fragment = layer.fragment(&full_record);
    let (hs, _) = Handshake::parse(fragment).unwrap();
    assert_eq!(hs.msg_type, HandshakeType::SERVER_HELLO);

    let sh = ServerHello::parse(&hs.body).unwrap();
    assert_eq!(sh.cipher_suite, 0x1301); // TLS_AES_128_GCM_SHA256
    assert_eq!(sh.session_id.len(), 0);

    // Verify 2 extensions (from .uts: len(sh.ext) == 2)
    assert_eq!(sh.extensions.len(), 2);

    // Verify selected version = 0x0304
    assert_eq!(sh.selected_version(), 0x0304u16);
}

#[test]
fn test_tls13_encrypted_record_header_from_uts() {
    // Encrypted handshake from tls13.uts (serverEncHS) - just verify record header
    let record_start = hex_to_bytes("17 03 03 02 a2");

    let layer = TlsLayer {
        index: LayerIndex::new(LayerKind::Tls, 0, 5),
    };
    assert_eq!(
        layer.content_type(&record_start).unwrap(),
        TlsContentType::ApplicationData
    );
    assert_eq!(layer.version(&record_start).unwrap(), 0x0303);
    assert_eq!(layer.length(&record_start).unwrap(), 674);
}

// ============================================================================
// SSLv2 Tests from sslv2.uts
// ============================================================================

#[test]
fn test_sslv2_client_hello_cipher_specs_from_uts() {
    // From sslv2.uts: ch.ciphers == [0x0700c0, 0x050080, 0x030080, 0x010080,
    //                                 0x060040, 0x040080, 0x020080]
    let ch_bytes: Vec<u8> = vec![
        0x80, 0x2e, 0x01, 0x00, 0x02, 0x00, 0x15, 0x00, 0x00, 0x00, 0x10, 0x07, 0x00, 0xc0, 0x05,
        0x00, 0x80, 0x03, 0x00, 0x80, 0x01, 0x00, 0x80, 0x06, 0x00, 0x40, 0x04, 0x00, 0x80, 0x02,
        0x00, 0x80, 0x1a, 0xfb, 0x2f, 0x9c, 0xa3, 0xd1, 0x29, 0x34, 0x54, 0xa3, 0x15, 0x28, 0x21,
        0xff, 0xd1, 0x0c,
    ];

    let (record, consumed) =
        stackforge_core::layer::tls::sslv2::record::parse_sslv2_record(&ch_bytes).unwrap();
    assert_eq!(record.length, 46); // matches t.len == 46 from .uts
    assert_eq!(consumed, ch_bytes.len());

    let client_hello = Sslv2ClientHello::parse(&record.data).unwrap();
    assert_eq!(client_hello.version, 0x0002); // matches ch.version == 0x0002

    // Verify exact cipher specs from .uts
    let expected_ciphers: Vec<u32> = vec![
        0x0700c0, 0x050080, 0x030080, 0x010080, 0x060040, 0x040080, 0x020080,
    ];
    assert_eq!(client_hello.cipher_specs, expected_ciphers);

    // Verify challenge from .uts
    let expected_challenge = hex_to_bytes("1a fb 2f 9c a3 d1 29 34 54 a3 15 28 21 ff d1 0c");
    assert_eq!(client_hello.challenge, expected_challenge);
}

// ============================================================================
// HMAC Tests from tls.uts (RFC 2202 test vectors)
// ============================================================================

#[test]
fn test_hmac_md5_rfc2202_from_uts() {
    use stackforge_core::layer::tls::crypto::hash::TlsHash;
    use stackforge_core::layer::tls::crypto::hmac_tls::TlsHmac;

    // Test 1 from tls.uts: Hmac_MD5(b'\x0b'*16).digest("Hi There")
    let hmac = TlsHmac::new(TlsHash::Md5, &[0x0b; 16]);
    let result = hmac.digest(b"Hi There");
    assert_eq!(
        result,
        hex_to_bytes("92 94 72 7a 36 38 bb 1c 13 f4 8e f8 15 8b fc 9d")
    );

    // Test 2: Hmac_MD5('Jefe').digest("what do ya want for nothing?")
    let hmac = TlsHmac::new(TlsHash::Md5, b"Jefe");
    let result = hmac.digest(b"what do ya want for nothing?");
    assert_eq!(
        result,
        hex_to_bytes("75 0c 78 3e 6a b0 b5 03 ea a8 6e 31 0a 5d b7 38")
    );

    // Test 3: Hmac_MD5(b'\xaa'*16).digest(b'\xdd'*50)
    let hmac = TlsHmac::new(TlsHash::Md5, &[0xaa; 16]);
    let result = hmac.digest(&[0xdd; 50]);
    assert_eq!(
        result,
        hex_to_bytes("56 be 34 52 1d 14 4c 88 db b8 c7 33 f0 e8 b3 f6")
    );
}

#[test]
fn test_hmac_sha1_rfc2202_from_uts() {
    use stackforge_core::layer::tls::crypto::hash::TlsHash;
    use stackforge_core::layer::tls::crypto::hmac_tls::TlsHmac;

    // Test 1 from tls.uts: Hmac_SHA(b'\x0b'*20).digest("Hi There")
    let hmac = TlsHmac::new(TlsHash::Sha1, &[0x0b; 20]);
    let result = hmac.digest(b"Hi There");
    assert_eq!(
        result,
        hex_to_bytes("b6 17 31 86 55 05 72 64 e2 8b c0 b6 fb 37 8c 8e f1 46 be 00")
    );

    // Test 2: Hmac_SHA('Jefe').digest("what do ya want for nothing?")
    let hmac = TlsHmac::new(TlsHash::Sha1, b"Jefe");
    let result = hmac.digest(b"what do ya want for nothing?");
    assert_eq!(
        result,
        hex_to_bytes("ef fc df 6a e5 eb 2f a2 d2 74 16 d5 f1 84 df 9c 25 9a 7c 79")
    );
}

#[test]
fn test_hmac_sha256_rfc4231_from_uts() {
    use stackforge_core::layer::tls::crypto::hash::TlsHash;
    use stackforge_core::layer::tls::crypto::hmac_tls::TlsHmac;

    // Test case 1 from tls.uts (RFC 4231)
    let hmac = TlsHmac::new(TlsHash::Sha256, &[0x0b; 20]);
    let result = hmac.digest(b"Hi There");
    assert_eq!(
        result,
        hex_to_bytes(
            "b0 34 4c 61 d8 db 38 53 5c a8 af ce af 0b f1 2b \
             88 1d c2 00 c9 83 3d a7 26 e9 37 6c 2e 32 cf f7"
        )
    );

    // Test case 2: key = "Jefe"
    let hmac = TlsHmac::new(TlsHash::Sha256, b"Jefe");
    let result = hmac.digest(b"what do ya want for nothing?");
    assert_eq!(
        result,
        hex_to_bytes(
            "5b dc c1 46 bf 60 75 4e 6a 04 24 26 08 95 75 c7 \
             5a 00 3f 08 9d 27 39 83 9d ec 58 b9 64 ec 38 43"
        )
    );
}

// ============================================================================
// TLS 1.3 Key Schedule Tests from tls13.uts (RFC 8448)
// ============================================================================

#[test]
fn test_tls13_key_schedule_from_uts() {
    use stackforge_core::layer::tls::crypto::hash::TlsHash;
    use stackforge_core::layer::tls::crypto::hkdf_tls13::Tls13KeySchedule;

    let mut ks = Tls13KeySchedule::new(TlsHash::Sha256);

    // Early secret (no PSK)
    let early = ks.derive_early_secret(None);
    assert_eq!(
        early,
        &hex_to_bytes(
            "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 \
             10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a"
        )
    );

    // ECDHE shared secret from the test session
    let ecdhe_secret = hex_to_bytes(
        "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d \
         35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d",
    );

    // Handshake secret
    let hs_secret = ks.derive_handshake_secret(&ecdhe_secret);
    assert_eq!(
        hs_secret,
        &hex_to_bytes(
            "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 \
             04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac"
        )
    );

    // Client/Server handshake traffic secrets need the transcript hash
    // For a complete test, we'd need the exact transcript bytes from the .uts session.
    // Here we verify the key schedule structure is correct.
    let master = ks.derive_master_secret();
    assert_eq!(
        master,
        &hex_to_bytes(
            "18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 \
             80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19"
        )
    );
}

// ============================================================================
// PKI Certificate Tests from tests/uts/tls/pki/
// ============================================================================

#[test]
fn test_pki_server_cert_pem() {
    use stackforge_core::layer::tls::cert::parse_pem_chain;

    let pem = std::fs::read_to_string("tests/uts/tls/pki/srv_cert.pem")
        .expect("srv_cert.pem should exist");
    let certs = parse_pem_chain(&pem);
    assert_eq!(certs.len(), 1);
    assert!(!certs[0].is_empty());

    // From sslv2.uts: sh.cert.subject_str == '/C=MN/L=Ulaanbaatar/OU=Scapy Test PKI/CN=Scapy Test Server'
    if let Some(cn) = certs[0].subject_cn() {
        assert_eq!(cn, "Scapy Test Server");
    }
}

#[test]
fn test_pki_client_cert_pem() {
    use stackforge_core::layer::tls::cert::parse_pem_chain;

    let pem = std::fs::read_to_string("tests/uts/tls/pki/cli_cert.pem")
        .expect("cli_cert.pem should exist");
    let certs = parse_pem_chain(&pem);
    assert_eq!(certs.len(), 1);
    assert!(!certs[0].is_empty());

    // From sslv2.uts: cc.certdata.subject_str == '/C=MN/L=Ulaanbaatar/OU=Scapy Test PKI/CN=Scapy Test Client'
    if let Some(cn) = certs[0].subject_cn() {
        assert_eq!(cn, "Scapy Test Client");
    }
}

#[test]
fn test_pki_ca_cert_pem() {
    use stackforge_core::layer::tls::cert::parse_pem_chain;

    let pem =
        std::fs::read_to_string("tests/uts/tls/pki/ca_cert.pem").expect("ca_cert.pem should exist");
    let certs = parse_pem_chain(&pem);
    assert_eq!(certs.len(), 1);
    assert!(!certs[0].is_empty());

    if let Some(cn) = certs[0].subject_cn() {
        assert_eq!(cn, "Scapy Test CA");
    }
}

#[test]
fn test_pki_ed25519_cert_pem() {
    use stackforge_core::layer::tls::cert::parse_pem_chain;

    let pem = std::fs::read_to_string("tests/uts/tls/pki/srv_cert_ed25519.pem")
        .expect("srv_cert_ed25519.pem should exist");
    let certs = parse_pem_chain(&pem);
    assert_eq!(certs.len(), 1);
    assert!(!certs[0].is_empty());

    if let Some(cn) = certs[0].subject_cn() {
        assert_eq!(cn, "Scapy Test Server");
    }
}

// ============================================================================
// Cipher Suite Registry Tests
// ============================================================================

#[test]
fn test_cipher_suite_lookup() {
    use stackforge_core::layer::tls::crypto::suites::{
        find_suite, find_suite_by_name, tls13_suites,
    };

    // TLS 1.3 suites
    let suite = find_suite(0x1301).expect("TLS_AES_128_GCM_SHA256 should exist");
    assert_eq!(suite.name, "TLS_AES_128_GCM_SHA256");

    let suite = find_suite(0x1302).expect("TLS_AES_256_GCM_SHA384 should exist");
    assert_eq!(suite.name, "TLS_AES_256_GCM_SHA384");

    let suite = find_suite(0x1303).expect("TLS_CHACHA20_POLY1305_SHA256 should exist");
    assert_eq!(suite.name, "TLS_CHACHA20_POLY1305_SHA256");

    // By name
    let suite = find_suite_by_name("TLS_AES_128_GCM_SHA256");
    assert!(suite.is_some());
    assert_eq!(suite.unwrap().id, 0x1301);

    // TLS 1.3 suites iterator
    let tls13: Vec<_> = tls13_suites().collect();
    assert!(tls13.len() >= 3);
}

// ============================================================================
// Key Exchange Tests
// ============================================================================

#[test]
fn test_ecdhe_key_exchange_full_roundtrip() {
    use stackforge_core::layer::tls::keyexchange::ecdhe::{
        build_key_share_entry, kx_for_group, parse_key_share_entry,
    };

    // X25519 full exchange
    let mut client_kx = kx_for_group(0x001D).unwrap();
    let mut server_kx = kx_for_group(0x001D).unwrap();

    let client_pub = client_kx.generate();
    let server_pub = server_kx.generate();

    // Build and parse key share entries (TLS 1.3 format)
    let client_entry = build_key_share_entry(0x001D, &client_pub);
    let (group, parsed_pub) = parse_key_share_entry(&client_entry).unwrap();
    assert_eq!(group, 0x001D);
    assert_eq!(parsed_pub, client_pub);

    // Compute shared secrets
    let client_shared = client_kx.compute_shared_secret(&server_pub).unwrap();
    let server_shared = server_kx.compute_shared_secret(&client_pub).unwrap();
    assert_eq!(client_shared, server_shared);
    assert_eq!(client_shared.len(), 32);

    // P-256 full exchange
    let mut client_kx = kx_for_group(0x0017).unwrap();
    let mut server_kx = kx_for_group(0x0017).unwrap();

    let client_pub = client_kx.generate();
    let server_pub = server_kx.generate();

    let client_shared = client_kx.compute_shared_secret(&server_pub).unwrap();
    let server_shared = server_kx.compute_shared_secret(&client_pub).unwrap();
    assert_eq!(client_shared, server_shared);
    assert_eq!(client_shared.len(), 32);
}

// ============================================================================
// Hash Tests
// ============================================================================

#[test]
fn test_tls_hash_digests() {
    use stackforge_core::layer::tls::crypto::hash::TlsHash;

    // SHA-256 empty hash (used in TLS 1.3 key schedule)
    let empty_sha256 = TlsHash::Sha256.digest(b"");
    assert_eq!(empty_sha256.len(), 32);
    assert_eq!(
        empty_sha256,
        hex_to_bytes(
            "e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55"
        )
    );

    // SHA-256 hash lengths
    assert_eq!(TlsHash::Sha256.hash_len(), 32);
    assert_eq!(TlsHash::Sha384.hash_len(), 48);
    assert_eq!(TlsHash::Sha1.hash_len(), 20);
    assert_eq!(TlsHash::Md5.hash_len(), 16);
}

// ============================================================================
// Helper
// ============================================================================

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect()
}
