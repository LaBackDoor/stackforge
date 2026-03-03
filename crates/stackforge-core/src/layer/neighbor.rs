//! Neighbor resolution system for automatic MAC address lookup.
//!
//! which automatically resolves destination MAC addresses based on
//! the network layer protocol being used.
//!
//! For example:
//! - ARP requests should use broadcast MAC (ff:ff:ff:ff:ff:ff)
//! - IP packets need ARP resolution to find the destination MAC
//! - Multicast IPs map to specific multicast MACs

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::layer::LayerKind;
use crate::layer::field::MacAddress;

/// A resolver function type for determining destination MAC addresses.
pub type ResolverFn = fn(&NeighborCache, &[u8], &[u8]) -> Option<MacAddress>;

/// Neighbor cache entry with expiration.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub mac: MacAddress,
    pub expires: Instant,
}

impl CacheEntry {
    #[must_use]
    pub fn new(mac: MacAddress, ttl: Duration) -> Self {
        Self {
            mac,
            expires: Instant::now() + ttl,
        }
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires
    }
}

/// ARP cache for storing resolved MAC addresses.
#[derive(Debug, Clone, Default)]
pub struct ArpCache {
    entries: HashMap<Ipv4Addr, CacheEntry>,
    ttl: Duration,
}

impl ArpCache {
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(120)) // 2 minute default like Scapy
    }

    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
        }
    }

    /// Get a cached MAC address for an IP.
    #[must_use]
    pub fn get(&self, ip: &Ipv4Addr) -> Option<MacAddress> {
        self.entries.get(ip).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.mac)
            }
        })
    }

    /// Store a MAC address for an IP.
    pub fn put(&mut self, ip: Ipv4Addr, mac: MacAddress) {
        self.entries.insert(ip, CacheEntry::new(mac, self.ttl));
    }

    /// Remove expired entries.
    pub fn cleanup(&mut self) {
        self.entries.retain(|_, entry| !entry.is_expired());
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// IPv6 neighbor cache.
#[derive(Debug, Clone, Default)]
pub struct NdpCache {
    entries: HashMap<Ipv6Addr, CacheEntry>,
    ttl: Duration,
}

impl NdpCache {
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(120))
    }

    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
        }
    }

    #[must_use]
    pub fn get(&self, ip: &Ipv6Addr) -> Option<MacAddress> {
        self.entries.get(ip).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.mac)
            }
        })
    }

    pub fn put(&mut self, ip: Ipv6Addr, mac: MacAddress) {
        self.entries.insert(ip, CacheEntry::new(mac, self.ttl));
    }

    pub fn cleanup(&mut self) {
        self.entries.retain(|_, entry| !entry.is_expired());
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Trait for neighbor resolution.
pub trait NeighborResolver {
    /// Resolve the destination MAC for a given L2/L3 layer combination.
    fn resolve(&self, l2_data: &[u8], l3_data: &[u8]) -> Option<MacAddress>;
}

/// Registry for neighbor resolvers.
#[derive(Clone)]
pub struct NeighborCache {
    /// Registered resolvers for (L2, L3) pairs
    resolvers: HashMap<(LayerKind, LayerKind), ResolverFn>,
    /// ARP cache for IPv4
    arp_cache: Arc<RwLock<ArpCache>>,
    /// NDP cache for IPv6
    ndp_cache: Arc<RwLock<NdpCache>>,
}

impl Default for NeighborCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NeighborCache {
    #[must_use]
    pub fn new() -> Self {
        let mut cache = Self {
            resolvers: HashMap::new(),
            arp_cache: Arc::new(RwLock::new(ArpCache::new())),
            ndp_cache: Arc::new(RwLock::new(NdpCache::new())),
        };
        cache.register_defaults();
        cache
    }

    /// Register default resolvers.
    fn register_defaults(&mut self) {
        self.register_l3(LayerKind::Ethernet, LayerKind::Arp, resolve_ether_arp);
        self.register_l3(LayerKind::Ethernet, LayerKind::Ipv4, resolve_ether_ipv4);
        self.register_l3(LayerKind::Ethernet, LayerKind::Ipv6, resolve_ether_ipv6);
    }

    /// Register a resolver for a L2/L3 combination.
    pub fn register_l3(&mut self, l2: LayerKind, l3: LayerKind, resolver: ResolverFn) {
        self.resolvers.insert((l2, l3), resolver);
    }

    /// Resolve destination MAC for the given layer data.
    #[must_use]
    pub fn resolve(
        &self,
        l2: LayerKind,
        l3: LayerKind,
        l2_data: &[u8],
        l3_data: &[u8],
    ) -> Option<MacAddress> {
        self.resolvers
            .get(&(l2, l3))
            .and_then(|resolver| resolver(self, l2_data, l3_data))
    }

    /// Get the ARP cache.
    #[must_use]
    pub fn arp_cache(&self) -> &Arc<RwLock<ArpCache>> {
        &self.arp_cache
    }

    /// Get the NDP cache.
    #[must_use]
    pub fn ndp_cache(&self) -> &Arc<RwLock<NdpCache>> {
        &self.ndp_cache
    }

    /// Cache an ARP entry.
    pub fn cache_arp(&self, ip: Ipv4Addr, mac: MacAddress) {
        if let Ok(mut cache) = self.arp_cache.write() {
            cache.put(ip, mac);
        }
    }

    /// Lookup an ARP entry.
    #[must_use]
    pub fn lookup_arp(&self, ip: &Ipv4Addr) -> Option<MacAddress> {
        self.arp_cache.read().ok()?.get(ip)
    }

    /// Cache an NDP entry.
    pub fn cache_ndp(&self, ip: Ipv6Addr, mac: MacAddress) {
        if let Ok(mut cache) = self.ndp_cache.write() {
            cache.put(ip, mac);
        }
    }

    /// Lookup an NDP entry.
    #[must_use]
    pub fn lookup_ndp(&self, ip: &Ipv6Addr) -> Option<MacAddress> {
        self.ndp_cache.read().ok()?.get(ip)
    }
}

impl std::fmt::Debug for NeighborCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NeighborCache")
            .field("resolvers", &self.resolvers.keys().collect::<Vec<_>>())
            .finish()
    }
}

// ============================================================================
// Default Resolver Implementations
// ============================================================================

/// Resolve MAC for Ethernet + ARP.
fn resolve_ether_arp(
    _cache: &NeighborCache,
    _l2_data: &[u8],
    l3_data: &[u8],
) -> Option<MacAddress> {
    if l3_data.len() < 8 {
        return None;
    }

    // ARP Request (op=1) -> Broadcast
    let op = u16::from_be_bytes([l3_data[6], l3_data[7]]);
    if op == 1 {
        Some(MacAddress::BROADCAST)
    } else {
        None
    }
}

/// Resolve MAC for Ethernet + IPv4.
fn resolve_ether_ipv4(
    cache: &NeighborCache,
    _l2_data: &[u8],
    l3_data: &[u8],
) -> Option<MacAddress> {
    if l3_data.len() < 20 {
        return None;
    }

    let dst_ip = Ipv4Addr::new(l3_data[16], l3_data[17], l3_data[18], l3_data[19]);

    if dst_ip.is_multicast() {
        return Some(MacAddress::from_ipv4_multicast(dst_ip));
    }
    if dst_ip.is_broadcast() || dst_ip == Ipv4Addr::BROADCAST {
        return Some(MacAddress::BROADCAST);
    }

    let interfaces = pnet_datalink::interfaces();
    let mut next_hop = dst_ip;
    let mut is_local = false;

    for iface in &interfaces {
        if !iface.is_up() {
            continue;
        }
        for ip_net in &iface.ips {
            if let IpAddr::V4(local_ip) = ip_net.ip()
                && local_ip == dst_ip
            {
                is_local = true;
                break;
            }
            if ip_net.contains(IpAddr::V4(dst_ip)) {
                is_local = true;
                break;
            }
        }
    }

    if !is_local
        && let Ok(gw) = default_net::get_default_gateway()
        && let IpAddr::V4(gw_ip) = gw.ip_addr
    {
        next_hop = gw_ip;
    }

    cache.lookup_arp(&next_hop)
}

/// Resolve MAC for Ethernet + IPv6.
fn resolve_ether_ipv6(
    cache: &NeighborCache,
    _l2_data: &[u8],
    l3_data: &[u8],
) -> Option<MacAddress> {
    if l3_data.len() < 40 {
        return None;
    }

    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&l3_data[24..40]);
    let dst_ip = Ipv6Addr::from(dst_bytes);

    if dst_ip.segments()[0] >> 8 == 0xff {
        return Some(MacAddress::from_ipv6_multicast(dst_ip));
    }

    let interfaces = pnet_datalink::interfaces();
    let mut next_hop = dst_ip;
    let mut is_local = false;

    for iface in &interfaces {
        if !iface.is_up() {
            continue;
        }
        for ip_net in &iface.ips {
            if ip_net.contains(IpAddr::V6(dst_ip)) {
                is_local = true;
                break;
            }
        }
    }

    if !is_local
        && let Ok(gw) = default_net::get_default_gateway()
        && let IpAddr::V6(gw_ip) = gw.ip_addr
    {
        next_hop = gw_ip;
    }

    cache.lookup_ndp(&next_hop)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get multicast MAC for IPv4 multicast address.
#[must_use]
pub fn ipv4_multicast_mac(ip: Ipv4Addr) -> MacAddress {
    MacAddress::from_ipv4_multicast(ip)
}

/// Get multicast MAC for IPv6 multicast address.
#[must_use]
pub fn ipv6_multicast_mac(ip: Ipv6Addr) -> MacAddress {
    MacAddress::from_ipv6_multicast(ip)
}

/// Check if an IPv4 address is multicast.
#[must_use]
pub fn is_ipv4_multicast(ip: Ipv4Addr) -> bool {
    ip.is_multicast()
}

/// Check if an IPv6 address is multicast.
#[must_use]
pub fn is_ipv6_multicast(ip: Ipv6Addr) -> bool {
    ip.segments()[0] >> 8 == 0xff
}

/// Solicited-node multicast address for IPv6.
#[must_use]
pub fn solicited_node_multicast(ip: Ipv6Addr) -> Ipv6Addr {
    let octets = ip.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(octets[13]),
        (u16::from(octets[14]) << 8) | u16::from(octets[15]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_cache() {
        let mut cache = ArpCache::new();
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        cache.put(ip, mac);
        assert_eq!(cache.get(&ip), Some(mac));
    }

    #[test]
    fn test_arp_cache_expiration() {
        let mut cache = ArpCache::with_ttl(Duration::from_millis(1));
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        cache.put(ip, mac);
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(cache.get(&ip), None);
    }

    #[test]
    fn test_resolve_ether_arp() {
        let cache = NeighborCache::new(); // Create dummy cache for signature

        // ARP request (op=1)
        let arp_request = vec![
            0x00, 0x01, // hwtype
            0x08, 0x00, // ptype
            0x06, 0x04, // hwlen, plen
            0x00, 0x01, // op = request
        ];

        // FIXED: Pass &cache as first argument
        let result = resolve_ether_arp(&cache, &[], &arp_request);
        assert_eq!(result, Some(MacAddress::BROADCAST));

        // ARP reply (op=2)
        let arp_reply = vec![
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, // op = reply
        ];

        // FIXED: Pass &cache as first argument
        let result = resolve_ether_arp(&cache, &[], &arp_reply);
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_ether_ipv4_multicast() {
        let cache = NeighborCache::new();

        // IPv4 header with multicast destination (224.0.0.1)
        let mut ipv4 = vec![0u8; 20];
        ipv4[16] = 224;
        ipv4[17] = 0;
        ipv4[18] = 0;
        ipv4[19] = 1;

        // FIXED: Pass &cache as first argument
        let result = resolve_ether_ipv4(&cache, &[], &ipv4);
        assert!(result.is_some());
        let mac = result.unwrap();
        assert!(mac.is_ipv4_multicast());
    }

    #[test]
    fn test_resolve_ether_ipv4_broadcast() {
        let cache = NeighborCache::new();

        let mut ipv4 = vec![0u8; 20];
        ipv4[16] = 255;
        ipv4[17] = 255;
        ipv4[18] = 255;
        ipv4[19] = 255;

        // FIXED: Pass &cache as first argument
        let result = resolve_ether_ipv4(&cache, &[], &ipv4);
        assert_eq!(result, Some(MacAddress::BROADCAST));
    }

    #[test]
    fn test_ipv4_multicast_mac() {
        let ip = Ipv4Addr::new(224, 0, 0, 1);
        let mac = ipv4_multicast_mac(ip);
        assert_eq!(mac.0[0], 0x01);
        assert_eq!(mac.0[1], 0x00);
        assert_eq!(mac.0[2], 0x5e);
    }

    #[test]
    fn test_ipv6_multicast_mac() {
        let ip = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let mac = ipv6_multicast_mac(ip);
        assert_eq!(mac.0[0], 0x33);
        assert_eq!(mac.0[1], 0x33);
    }

    #[test]
    fn test_neighbor_cache() {
        let cache = NeighborCache::new();

        // Test ARP caching
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let mac = MacAddress::new([0xaa; 6]);
        cache.cache_arp(ip, mac);
        assert_eq!(cache.lookup_arp(&ip), Some(mac));
    }

    #[test]
    fn test_solicited_node_multicast() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1234);
        let snm = solicited_node_multicast(ip);

        // Should be ff02::1:ff00:1234
        assert_eq!(snm.segments()[0], 0xff02);
        assert_eq!(snm.segments()[5], 1);
    }
}
