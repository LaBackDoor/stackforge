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

pub mod error;
pub mod layer;
pub mod packet;
pub mod pcap;
pub mod utils;

// Re-export commonly used types at the crate root
pub use error::{PacketError, Result};
pub use layer::arp::{ARP_FIXED_HEADER_LEN, ARP_HEADER_LEN, ArpRoute, HardwareAddr, ProtocolAddr};
pub use layer::bindings::{
    BindingRegistry, apply_binding, expected_upper_layers, find_binding, find_bindings_from,
    find_bindings_to, infer_upper_layer,
};
pub use layer::ethernet::{
    DOT3_MAX_LENGTH, ETHERNET_HEADER_LEN, EthernetFrameType, dispatch_hook, is_dot3, is_ethernet_ii,
};
pub use layer::neighbor::{
    ArpCache, CacheEntry, NdpCache, ipv4_multicast_mac, ipv6_multicast_mac, is_ipv4_multicast,
    is_ipv6_multicast, solicited_node_multicast,
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
    IcmpBuilder,
    IcmpLayer,
    Icmpv6Layer,
    // Stacking
    IntoLayerStackEntry,
    Ipv4Builder,
    Ipv4Flags,
    Ipv4Layer,
    Ipv6Layer,
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
};
pub use packet::Packet;
pub use pcap::{
    CapturedPacket, LinkType, PcapIterator, PcapMetadata, rdpcap, wrpcap, wrpcap_packets,
};

// Utils re-exports
pub use utils::{
    align_to, ethernet_min_frame, extract_bits, hexdump, hexstr, hexstr_sep, internet_checksum,
    pad_to, parse_hex, set_bits, transport_checksum, verify_checksum,
};

/// Protocol constants for EtherType field.
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
