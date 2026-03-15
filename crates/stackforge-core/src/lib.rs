//! # Stackforge Core
//!
//! High-performance, zero-copy network packet manipulation library.
//!
//! This crate provides the core networking primitives for the Stackforge
//! framework, implementing a "Lazy Zero-Copy View" architecture for efficient
//! packet processing.
//!
//! ## Architecture
//!
//! Unlike traditional packet parsing libraries that eagerly deserialize all
//! fields into objects, Stackforge Core uses a lazy evaluation model:
//!
//! 1. **Zero-Copy Buffers**: Packets are stored as contiguous byte buffers
//!    using the `bytes` crate's reference-counted `Bytes` type.
//!
//! 2. **Index-Only Parsing**: When parsing a packet, we only identify layer
//!    boundaries (where each protocol header starts and ends).
//!
//! 3. **On-Demand Access**: Field values are read directly from the buffer
//!    only when explicitly requested.
//!
//! 4. **Copy-on-Write**: Mutation triggers buffer cloning only when shared.
//!
//! ## Example
//!
//! ```rust
//! use stackforge_core::{Packet, LayerKind, EthernetLayer, ArpBuilder};
//! use stackforge_core::layer::field::MacAddress;
//! use std::net::Ipv4Addr;
//!
//! // Build an ARP request
//! let arp = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 100))
//!     .hwsrc(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
//!     .psrc(Ipv4Addr::new(192, 168, 1, 1))
//!     .build();
//!
//! // Parse an existing packet
//! let raw_bytes = vec![
//!     0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // Destination MAC (broadcast)
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Source MAC
//!     0x08, 0x06,                          // EtherType: ARP
//! ];
//!
//! let eth = EthernetLayer::at_start();
//! assert_eq!(eth.ethertype(&raw_bytes).unwrap(), 0x0806);
//! ```

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

#[cfg(feature = "anonymize")]
pub mod anonymize;
pub mod error;
pub mod flow;
pub mod layer;
pub mod packet;
pub mod parallel;
pub mod pcap;
pub mod sniffer;
pub mod utils;

// Re-export commonly used types at the crate root
pub use error::{PacketError, Result};
pub use layer::arp::{ARP_FIXED_HEADER_LEN, ARP_HEADER_LEN, ArpRoute, HardwareAddr, ProtocolAddr};
pub use layer::bindings::{
    BindingRegistry, apply_binding, expected_upper_layers, find_binding, find_bindings_from,
    find_bindings_to, infer_upper_layer,
};
pub use layer::coap::{COAP_FIELD_NAMES, COAP_MIN_HEADER_LEN, COAP_PORT, CoapBuilder, CoapLayer};
pub use layer::cotp::{COTP_FIELD_NAMES, COTP_MIN_HEADER_LEN, CotpBuilder, CotpLayer};
pub use layer::dnp3::{DNP3_FIELD_NAMES, DNP3_MIN_HEADER_LEN, DNP3_PORT, Dnp3Builder, Dnp3Layer};
pub use layer::ethernet::{
    DOT3_MAX_LENGTH, ETHERNET_HEADER_LEN, EthernetFrameType, dispatch_hook, is_dot3, is_ethernet_ii,
};
pub use layer::ftp::{
    FTP_CONTROL_PORT, FTP_DATA_PORT, FTP_FIELD_NAMES, FTP_MIN_HEADER_LEN, FtpBuilder, FtpLayer,
};
pub use layer::iec104::{
    IEC104_FIELD_NAMES, IEC104_MIN_HEADER_LEN, IEC104_PORT, Iec104Builder, Iec104Layer,
};
pub use layer::imap::{IMAP_FIELD_NAMES, IMAP_MIN_HEADER_LEN, IMAP_PORT, ImapBuilder, ImapLayer};
pub use layer::modbus::{
    MODBUS_FIELD_NAMES, MODBUS_MIN_HEADER_LEN, MODBUS_TCP_PORT, ModbusBuilder, ModbusLayer,
};
pub use layer::mqtt::{MQTT_FIELD_NAMES, MQTT_MIN_HEADER_LEN, MQTT_PORT, MqttBuilder, MqttLayer};
pub use layer::mqttsn::{
    MQTTSN_FIELD_NAMES, MQTTSN_MIN_HEADER_LEN, MQTTSN_PORT, MqttSnBuilder, MqttSnLayer,
};
pub use layer::neighbor::{
    ArpCache, CacheEntry, NdpCache, ipv4_multicast_mac, ipv6_multicast_mac, is_ipv4_multicast,
    is_ipv6_multicast, solicited_node_multicast,
};
pub use layer::pop3::{POP3_FIELD_NAMES, POP3_MIN_HEADER_LEN, POP3_PORT, Pop3Builder, Pop3Layer};
pub use layer::quic::builder::QuicBuilder;
pub use layer::s7comm::{S7COMM_FIELD_NAMES, S7COMM_MIN_HEADER_LEN, S7CommBuilder, S7CommLayer};
pub use layer::smtp::{SMTP_FIELD_NAMES, SMTP_MIN_HEADER_LEN, SMTP_PORT, SmtpBuilder, SmtpLayer};
pub use layer::tftp::{TFTP_MIN_HEADER_LEN, TFTP_PORT, TftpBuilder, TftpLayer};
pub use layer::tpkt::{TPKT_FIELD_NAMES, TPKT_MIN_HEADER_LEN, TPKT_PORT, TpktBuilder, TpktLayer};
pub use layer::zwave::{
    ZWAVE_FIELD_NAMES, ZWAVE_HEADER_LEN, ZWAVE_MIN_HEADER_LEN, ZWaveBuilder, ZWaveLayer,
};
pub use layer::{
    // Builders
    ArpBuilder,
    // Layer types
    ArpLayer,
    // Field types
    BytesField,
    DnsLayer,
    Dot3Builder,
    Dot3Layer,
    EthernetBuilder,
    EthernetLayer,
    Field,
    FieldDesc,
    FieldError,
    FieldType,
    FieldValue,
    Http2Builder,
    Http2FrameBuilder,
    HttpRequestBuilder,
    HttpResponseBuilder,
    ICMPV6_MIN_HEADER_LEN,
    IPV6_HEADER_LEN,
    IcmpBuilder,
    IcmpLayer,
    Icmpv6Builder,
    Icmpv6Layer,
    // Stacking
    IntoLayerStackEntry,
    Ipv4Builder,
    Ipv4Flags,
    Ipv4Layer,
    Ipv6Builder,
    Ipv6Layer,
    L2TP_FIELD_NAMES,
    L2TP_MIN_HEADER_LEN,
    L2TP_PORT,
    L2tpBuilder,
    L2tpLayer,
    LAYER_BINDINGS,
    // Core traits and enums
    Layer,
    // Bindings
    LayerBinding,
    LayerEnum,
    LayerIndex,
    LayerKind,
    LayerStack,
    LayerStackEntry,
    MacAddress,
    // Neighbor resolution
    NeighborCache,
    NeighborResolver,
    RAW_FIELDS,
    RawBuilder,
    RawLayer,
    SSH_BINARY_HEADER_LEN,
    SSH_PORT,
    SshBuilder,
    SshLayer,
    TcpBuilder,
    TcpFlags,
    TcpLayer,
    TlsRecordBuilder,
    UdpBuilder,
    UdpLayer,
    icmpv6_checksum,
    verify_icmpv6_checksum,
};
pub use packet::Packet;
pub use pcap::{
    CaptureFormat, CaptureIterator, CapturedPacket, LinkType, MmapPcapReader, PcapIterator,
    PcapMetadata, PcapNgIterator, PcapNgStreamWriter, rdpcap, wrpcap, wrpcap_packets, wrpcapng,
    wrpcapng_packets,
};

// Flow extraction re-exports
pub use flow::{
    CanonicalKey, ConversationState, ConversationStatus, ConversationTable, DirectionStats,
    FlowConfig, FlowDirection, FlowError, ProtocolState, TransportProtocol, ZWaveFlowState,
    ZWaveKey, extract_flows, extract_flows_from_file, extract_flows_streaming,
    extract_flows_with_config, extract_zwave_flows,
};

// Sniffer re-exports
pub use sniffer::{
    CaptureStats, InterfaceInfo, ParsedPacket, RawPacket, SnifferConfig, SnifferError,
    SnifferHandle, WorkerPoolConfig, WorkerPoolSniffer, list_interfaces, validate_filter,
};

// Utils re-exports
pub use utils::{
    align_to, ethernet_min_frame, extract_bits, hexdump, hexstr, hexstr_sep, internet_checksum,
    pad_to, parse_hex, set_bits, transport_checksum, verify_checksum,
};

/// Protocol constants for `EtherType` field.
pub mod ethertype {
    pub use crate::layer::ethertype::*;
}

/// Protocol constants for IP protocol numbers.
pub mod ip_protocol {
    pub use crate::layer::ip_protocol::*;
}

/// ARP operation codes.
pub mod arp_opcode {
    pub use crate::layer::arp::opcode::*;
}

/// ARP hardware types.
pub mod arp_hardware {
    pub use crate::layer::arp::hardware_type::*;
}

/// ARP protocol types.
pub mod arp_protocol {
    pub use crate::layer::arp::protocol_type::*;
}

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::arp_hardware;
    pub use crate::arp_opcode;
    pub use crate::ethertype;
    pub use crate::{
        ARP_HEADER_LEN,
        ArpBuilder,
        ArpCache,
        // ARP
        ArpLayer,
        BindingRegistry,
        BytesField,
        Dot3Builder,
        Dot3Layer,
        ETHERNET_HEADER_LEN,
        EthernetBuilder,
        // Ethernet
        EthernetLayer,
        Field,
        FieldDesc,
        FieldError,
        FieldType,
        FieldValue,
        HardwareAddr,
        // Stacking
        IntoLayerStackEntry,
        Ipv4Builder,
        Ipv4Flags,
        Layer,
        // Bindings
        LayerBinding,
        LayerEnum,
        LayerIndex,
        LayerKind,
        LayerStack,
        LayerStackEntry,
        // Fields
        MacAddress,
        NdpCache,
        // Neighbor
        NeighborCache,
        // Core types
        Packet,
        PacketError,
        ProtocolAddr,
        // Raw
        RawBuilder,
        RawLayer,
        Result,
        TcpBuilder,
        TcpFlags,
        apply_binding,
        find_binding,
        ipv4_multicast_mac,
        ipv6_multicast_mac,
        is_dot3,
        is_ethernet_ii,
    };
    pub use std::net::{Ipv4Addr, Ipv6Addr};
}

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get library version
#[must_use]
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn test_basic_packet_creation() {
        // Build Ethernet header
        let eth = EthernetBuilder::new()
            .dst(MacAddress::BROADCAST)
            .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
            .build_with_payload(LayerKind::Arp);

        // Build ARP payload
        let arp = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 100))
            .hwsrc(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
            .psrc(Ipv4Addr::new(192, 168, 1, 1))
            .build();

        // Combine
        let mut packet_data = eth;
        packet_data.extend_from_slice(&arp);

        // Parse and verify
        let mut packet = Packet::from_bytes(packet_data);
        packet.parse().unwrap();

        assert_eq!(packet.layer_count(), 2);

        let eth_layer = packet.ethernet().unwrap();
        assert_eq!(
            eth_layer.ethertype(packet.as_bytes()).unwrap(),
            ethertype::ARP
        );

        let arp_layer = packet.arp().unwrap();
        assert!(arp_layer.is_request(packet.as_bytes()));
    }

    #[test]
    fn test_layer_bindings() {
        // Test that bindings are correctly defined
        let binding = find_binding(LayerKind::Ethernet, LayerKind::Arp);
        assert!(binding.is_some());
        assert_eq!(binding.unwrap().field_value, 0x0806);

        // Test apply_binding helper
        let (field, value) = apply_binding(LayerKind::Ethernet, LayerKind::Ipv4).unwrap();
        assert_eq!(field, "type");
        assert_eq!(value, 0x0800);
    }

    #[test]
    fn test_neighbor_resolution() {
        let _cache = NeighborCache::new();

        // Test multicast resolution
        let mcast_ip = Ipv4Addr::new(224, 0, 0, 1);
        let mcast_mac = ipv4_multicast_mac(mcast_ip);
        assert!(mcast_mac.is_multicast());
        assert!(mcast_mac.is_ipv4_multicast());
    }

    #[test]
    fn test_frame_type_dispatch() {
        // Ethernet II frame (type > 1500)
        let eth2 = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08,
            0x00, // IPv4 = 0x0800
        ];
        assert!(!is_dot3(&eth2, 0));
        assert!(is_ethernet_ii(&eth2, 0));

        // 802.3 frame (length <= 1500)
        let dot3 = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00,
            0x64, // Length = 100
        ];
        assert!(is_dot3(&dot3, 0));
        assert!(!is_ethernet_ii(&dot3, 0));
    }
}
