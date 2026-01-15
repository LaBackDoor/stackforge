use stackforge_core::infer_upper_layer;
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

#[test]
fn test_layer_bindings() {
    // Ethernet -> ARP
    let binding = find_binding(LayerKind::Ethernet, LayerKind::Arp);
    assert!(binding.is_some());
    assert_eq!(binding.unwrap().field_value, ethertype::ARP);

    // Ethernet -> IPv4
    let binding = find_binding(LayerKind::Ethernet, LayerKind::Ipv4);
    assert!(binding.is_some());
    assert_eq!(binding.unwrap().field_value, ethertype::IPV4);

    // Apply binding helper
    let (field, value) = apply_binding(LayerKind::Ethernet, LayerKind::Ipv6).unwrap();
    assert_eq!(field, "type");
    assert_eq!(value, ethertype::IPV6);
}

#[test]
fn test_infer_upper_layer() {
    assert_eq!(
        infer_upper_layer(LayerKind::Ethernet, "type", ethertype::ARP),
        Some(LayerKind::Arp)
    );
    assert_eq!(
        infer_upper_layer(LayerKind::Ethernet, "type", ethertype::IPV4),
        Some(LayerKind::Ipv4)
    );
    assert_eq!(infer_upper_layer(LayerKind::Ethernet, "type", 0x9999), None);
}

// ============================================================================
// Neighbor Resolution Tests
// ============================================================================

#[test]
fn test_neighbor_cache() {
    let cache = NeighborCache::new();

    let ip = Ipv4Addr::new(192, 168, 1, 1);
    let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    cache.cache_arp(ip, mac);
    assert_eq!(cache.lookup_arp(&ip), Some(mac));
}

#[test]
fn test_multicast_mac_generation() {
    // IPv4 multicast
    let ip = Ipv4Addr::new(224, 0, 0, 1);
    let mac = ipv4_multicast_mac(ip);
    assert!(mac.is_multicast());
    assert!(mac.is_ipv4_multicast());
    assert_eq!(mac.0[0], 0x01);
    assert_eq!(mac.0[1], 0x00);
    assert_eq!(mac.0[2], 0x5e);

    // IPv6 multicast
    let ip6 = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    let mac6 = ipv6_multicast_mac(ip6);
    assert!(mac6.is_multicast());
    assert!(mac6.is_ipv6_multicast());
    assert_eq!(mac6.0[0], 0x33);
    assert_eq!(mac6.0[1], 0x33);
}
