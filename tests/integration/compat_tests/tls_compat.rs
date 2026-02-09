//! TLS compatibility tests with Scapy.
//!
//! Verifies that Stackforge TLS record builders produce byte-identical
//! output to Scapy's TLS layer.

use super::{compare_bytes, scapy_build};
use stackforge_core::layer::tls::builder::{TlsAlertBuilder, TlsCcsBuilder, TlsRecordBuilder};
use stackforge_core::layer::tls::types::TlsContentType;

#[test]
fn test_tls_handshake_record_vs_scapy() {
    // Build a TLS record with Scapy
    let scapy_bytes = scapy_build(
        r#"__import__("scapy.layers.tls.record", fromlist=["TLS"]).TLS(type=22, version=0x0303, len=5) / __import__("scapy.packet", fromlist=["Raw"]).Raw(load=b"\x01\x00\x00\x01\x00")"#,
    );

    // Build with Stackforge
    let sf_bytes = TlsRecordBuilder::new()
        .content_type(TlsContentType::Handshake)
        .version(0x0303)
        .fragment(vec![0x01, 0x00, 0x00, 0x01, 0x00])
        .build();

    compare_bytes(&sf_bytes, &scapy_bytes).unwrap_or_else(|e| {
        panic!("TLS Handshake record mismatch:\n{}", e);
    });
}

#[test]
fn test_tls_alert_record_vs_scapy() {
    // Build a TLS Alert with Scapy
    let scapy_bytes = scapy_build(
        r#"__import__("scapy.layers.tls.record", fromlist=["TLS"]).TLS(type=21, version=0x0303, len=2) / __import__("scapy.packet", fromlist=["Raw"]).Raw(load=b"\x02\x28")"#,
    );

    // Build with Stackforge (fatal handshake_failure)
    let sf_bytes = TlsAlertBuilder::new()
        .level(2)
        .description(40)
        .version(0x0303)
        .build();

    compare_bytes(&sf_bytes, &scapy_bytes).unwrap_or_else(|e| {
        panic!("TLS Alert record mismatch:\n{}", e);
    });
}

#[test]
fn test_tls_ccs_record_vs_scapy() {
    // Build a TLS ChangeCipherSpec with Scapy
    let scapy_bytes = scapy_build(
        r#"__import__("scapy.layers.tls.record", fromlist=["TLS"]).TLS(type=20, version=0x0303, len=1) / __import__("scapy.packet", fromlist=["Raw"]).Raw(load=b"\x01")"#,
    );

    // Build with Stackforge
    let sf_bytes = TlsCcsBuilder::new().version(0x0303).build();

    compare_bytes(&sf_bytes, &scapy_bytes).unwrap_or_else(|e| {
        panic!("TLS CCS record mismatch:\n{}", e);
    });
}

#[test]
fn test_tls_application_data_vs_scapy() {
    let payload = b"Hello, TLS!";

    // Build a TLS Application Data record with Scapy
    let scapy_bytes = scapy_build(
        r#"__import__("scapy.layers.tls.record", fromlist=["TLS"]).TLS(type=23, version=0x0303, len=11) / __import__("scapy.packet", fromlist=["Raw"]).Raw(load=b"Hello, TLS!")"#,
    );

    // Build with Stackforge
    let sf_bytes = TlsRecordBuilder::new()
        .content_type(TlsContentType::ApplicationData)
        .version(0x0303)
        .fragment(payload.to_vec())
        .build();

    compare_bytes(&sf_bytes, &scapy_bytes).unwrap_or_else(|e| {
        panic!("TLS Application Data record mismatch:\n{}", e);
    });
}

#[test]
fn test_tls_record_header_format() {
    // Verify our 5-byte TLS record header format matches the spec exactly
    let record = TlsRecordBuilder::new()
        .content_type_raw(0x16)
        .version(0x0301)
        .fragment(vec![0xAA; 10])
        .build();

    // content_type: 1 byte
    assert_eq!(record[0], 0x16);
    // version: 2 bytes big-endian
    assert_eq!(record[1], 0x03);
    assert_eq!(record[2], 0x01);
    // length: 2 bytes big-endian
    assert_eq!(record[3], 0x00);
    assert_eq!(record[4], 0x0A);
    // fragment
    assert_eq!(&record[5..], &[0xAA; 10]);
}
