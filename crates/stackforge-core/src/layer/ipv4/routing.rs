//! IPv4 routing utilities.
//!
//! Provides routing table lookup and interface selection for IPv4 packets.
//! This is used to determine which interface to send packets on and what
//! the next-hop address should be.

use std::net::Ipv4Addr;

/// Routing information for an IPv4 destination.
#[derive(Debug, Clone, Default)]
pub struct Ipv4Route {
    /// The outgoing interface name.
    pub interface: Option<String>,
    /// The source IP address to use.
    pub source: Option<Ipv4Addr>,
    /// The next-hop gateway IP (if not on local network).
    pub gateway: Option<Ipv4Addr>,
    /// Whether the destination is on the local network.
    pub is_local: bool,
    /// The network mask (prefix length).
    pub prefix_len: u8,
    /// Route metric (lower is better).
    pub metric: u32,
}

impl Ipv4Route {
    /// Create an empty route (no routing info available).
    pub fn none() -> Self {
        Self::default()
    }

    /// Create a route for a local destination.
    pub fn local(interface: String, source: Ipv4Addr) -> Self {
        Self {
            interface: Some(interface),
            source: Some(source),
            gateway: None,
            is_local: true,
            prefix_len: 32,
            metric: 0,
        }
    }

    /// Create a route via a gateway.
    pub fn via_gateway(interface: String, source: Ipv4Addr, gateway: Ipv4Addr) -> Self {
        Self {
            interface: Some(interface),
            source: Some(source),
            gateway: Some(gateway),
            is_local: false,
            prefix_len: 0,
            metric: 0,
        }
    }

    /// Check if this route is valid (has interface).
    pub fn is_valid(&self) -> bool {
        self.interface.is_some()
    }

    /// Get the next-hop address (gateway or destination if local).
    pub fn next_hop(&self, dst: Ipv4Addr) -> Ipv4Addr {
        self.gateway.unwrap_or(dst)
    }
}

/// A router that can look up routes for destinations.
pub trait Ipv4Router {
    /// Look up the route for a destination.
    fn route(&self, dst: Ipv4Addr) -> Ipv4Route;
}

/// Get routing information for a destination address.
///
/// This uses the system routing table to determine the interface,
/// source address, and gateway for reaching a destination.
pub fn get_route(dst: Ipv4Addr) -> Ipv4Route {
    // Handle special addresses
    if dst.is_loopback() {
        return Ipv4Route::local("lo".to_string(), Ipv4Addr::LOCALHOST);
    }

    if dst.is_broadcast() || dst == Ipv4Addr::BROADCAST {
        return get_default_route()
            .map(|r| Ipv4Route {
                is_local: true,
                ..r
            })
            .unwrap_or_default();
    }

    if dst.is_multicast() {
        // Multicast uses the default route interface
        return get_default_route()
            .map(|r| Ipv4Route {
                gateway: None,
                is_local: true,
                ..r
            })
            .unwrap_or_default();
    }

    // Try to find a matching interface
    let interfaces = pnet_datalink::interfaces();

    // First, check for direct connectivity
    for iface in &interfaces {
        if !iface.is_up() || iface.is_loopback() {
            continue;
        }

        for ip_network in &iface.ips {
            if let std::net::IpAddr::V4(ip) = ip_network.ip() {
                // Check if destination is in this subnet
                if ip_network.contains(std::net::IpAddr::V4(dst)) {
                    return Ipv4Route {
                        interface: Some(iface.name.clone()),
                        source: Some(ip),
                        gateway: None,
                        is_local: true,
                        prefix_len: ip_network.prefix(),
                        metric: 0,
                    };
                }
            }
        }
    }

    // Use default gateway
    if let Some(route) = get_default_route() {
        return route;
    }

    Ipv4Route::none()
}

/// Get the default route (gateway).
pub fn get_default_route() -> Option<Ipv4Route> {
    // Try to get default interface using default-net crate
    let default_iface = default_net::get_default_interface().ok()?;
    let gateway = default_net::get_default_gateway().ok()?;

    let interfaces = pnet_datalink::interfaces();
    let iface = interfaces.iter().find(|i| i.name == default_iface.name)?;

    // Find IPv4 address on this interface
    let source = iface.ips.iter().find_map(|ip| {
        if let std::net::IpAddr::V4(v4) = ip.ip() {
            Some(v4)
        } else {
            None
        }
    })?;

    let gw_ip = match gateway.ip_addr {
        std::net::IpAddr::V4(v4) => v4,
        _ => return None,
    };

    Some(Ipv4Route {
        interface: Some(iface.name.clone()),
        source: Some(source),
        gateway: Some(gw_ip),
        is_local: false,
        prefix_len: 0,
        metric: 0,
    })
}

/// Get the source IP address for a destination.
///
/// This performs a routing lookup and returns the appropriate source.
pub fn get_source_for_dst(dst: Ipv4Addr) -> Option<Ipv4Addr> {
    get_route(dst).source
}

/// Get the interface name for a destination.
pub fn get_interface_for_dst(dst: Ipv4Addr) -> Option<String> {
    get_route(dst).interface
}

/// Check if a destination is on the local network.
pub fn is_local_destination(dst: Ipv4Addr) -> bool {
    get_route(dst).is_local
}

/// Get all available IPv4 interfaces.
pub fn get_ipv4_interfaces() -> Vec<Ipv4Interface> {
    pnet_datalink::interfaces()
        .into_iter()
        .filter_map(|iface| {
            if !iface.is_up() {
                return None;
            }

            let addrs: Vec<_> = iface
                .ips
                .iter()
                .filter_map(|ip| {
                    if let std::net::IpAddr::V4(v4) = ip.ip() {
                        Some(Ipv4InterfaceAddr {
                            address: v4,
                            prefix_len: ip.prefix(),
                            // Fix for `and_then` error: match directly on IpAddr
                            broadcast: match ip.broadcast() {
                                std::net::IpAddr::V4(v4) => Some(v4),
                                _ => None,
                            },
                        })
                    } else {
                        None
                    }
                })
                .collect();

            if addrs.is_empty() {
                return None;
            }

            // Fix for "Value used after being moved":
            // Extract boolean flags BEFORE moving `iface.name`
            let is_loopback = iface.is_loopback();
            let is_up = iface.is_up();
            let is_running = iface.is_running();
            let is_multicast = iface.is_multicast();
            let is_broadcast = iface.is_broadcast();

            Some(Ipv4Interface {
                name: iface.name, // Move occurs here
                index: iface.index,
                mac: iface.mac.map(|m| m.octets()),
                addresses: addrs,
                is_loopback,
                is_up,
                is_running,
                is_multicast,
                is_broadcast,
                mtu: None, // Not available from pnet
            })
        })
        .collect()
}

/// Information about an IPv4-capable interface.
#[derive(Debug, Clone)]
pub struct Ipv4Interface {
    /// Interface name (e.g., "eth0", "en0").
    pub name: String,
    /// Interface index.
    pub index: u32,
    /// MAC address (if available).
    pub mac: Option<[u8; 6]>,
    /// IPv4 addresses on this interface.
    pub addresses: Vec<Ipv4InterfaceAddr>,
    /// Whether this is a loopback interface.
    pub is_loopback: bool,
    /// Whether the interface is up.
    pub is_up: bool,
    /// Whether the interface is running.
    pub is_running: bool,
    /// Whether multicast is enabled.
    pub is_multicast: bool,
    /// Whether broadcast is supported.
    pub is_broadcast: bool,
    /// Interface MTU.
    pub mtu: Option<u32>,
}

impl Ipv4Interface {
    /// Get the first (primary) IPv4 address.
    pub fn primary_address(&self) -> Option<Ipv4Addr> {
        self.addresses.first().map(|a| a.address)
    }

    /// Check if an address is on this interface's network.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        self.addresses.iter().any(|a| {
            let mask = prefix_to_mask(a.prefix_len);
            (u32::from(a.address) & mask) == (u32::from(addr) & mask)
        })
    }
}

/// An IPv4 address on an interface.
#[derive(Debug, Clone)]
pub struct Ipv4InterfaceAddr {
    /// The IPv4 address.
    pub address: Ipv4Addr,
    /// Network prefix length (e.g., 24 for /24).
    pub prefix_len: u8,
    /// Broadcast address (if applicable).
    pub broadcast: Option<Ipv4Addr>,
}

impl Ipv4InterfaceAddr {
    /// Get the network address.
    pub fn network(&self) -> Ipv4Addr {
        let mask = prefix_to_mask(self.prefix_len);
        Ipv4Addr::from(u32::from(self.address) & mask)
    }

    /// Get the subnet mask.
    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(prefix_to_mask(self.prefix_len))
    }
}

/// Convert a prefix length to a subnet mask.
pub fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix >= 32 {
        0xFFFFFFFF
    } else if prefix == 0 {
        0
    } else {
        !((1u32 << (32 - prefix)) - 1)
    }
}

/// Convert a subnet mask to a prefix length.
pub fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    let mask_u32 = u32::from(mask);
    mask_u32.leading_ones() as u8
}

/// Check if an IP address matches a network/prefix.
pub fn ip_in_network(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = prefix_to_mask(prefix);
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

/// Calculate the broadcast address for a network.
pub fn broadcast_address(network: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = prefix_to_mask(prefix);
    Ipv4Addr::from(u32::from(network) | !mask)
}

/// Calculate the number of hosts in a network.
pub fn network_host_count(prefix: u8) -> u32 {
    if prefix >= 31 {
        // /31 has 2 hosts, /32 has 1
        2u32.saturating_sub(prefix as u32 - 30)
    } else {
        (1u32 << (32 - prefix)) - 2 // Subtract network and broadcast
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_to_mask() {
        assert_eq!(prefix_to_mask(0), 0x00000000);
        assert_eq!(prefix_to_mask(8), 0xFF000000);
        assert_eq!(prefix_to_mask(16), 0xFFFF0000);
        assert_eq!(prefix_to_mask(24), 0xFFFFFF00);
        assert_eq!(prefix_to_mask(32), 0xFFFFFFFF);
    }

    #[test]
    fn test_mask_to_prefix() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn test_ip_in_network() {
        let network = Ipv4Addr::new(192, 168, 1, 0);
        assert!(ip_in_network(Ipv4Addr::new(192, 168, 1, 100), network, 24));
        assert!(ip_in_network(Ipv4Addr::new(192, 168, 1, 255), network, 24));
        assert!(!ip_in_network(Ipv4Addr::new(192, 168, 2, 1), network, 24));
    }

    #[test]
    fn test_broadcast_address() {
        assert_eq!(
            broadcast_address(Ipv4Addr::new(192, 168, 1, 0), 24),
            Ipv4Addr::new(192, 168, 1, 255)
        );
        assert_eq!(
            broadcast_address(Ipv4Addr::new(10, 0, 0, 0), 8),
            Ipv4Addr::new(10, 255, 255, 255)
        );
    }

    #[test]
    fn test_network_host_count() {
        assert_eq!(network_host_count(24), 254);
        assert_eq!(network_host_count(16), 65534);
        assert_eq!(network_host_count(8), 16777214);
    }

    #[test]
    fn test_route_loopback() {
        let route = get_route(Ipv4Addr::LOCALHOST);
        assert!(route.is_local);
        assert_eq!(route.interface, Some("lo".to_string()));
    }

    #[test]
    fn test_ipv4_route() {
        let route = Ipv4Route::local("eth0".to_string(), Ipv4Addr::new(192, 168, 1, 100));
        assert!(route.is_valid());
        assert!(route.is_local);
        assert_eq!(
            route.next_hop(Ipv4Addr::new(192, 168, 1, 200)),
            Ipv4Addr::new(192, 168, 1, 200)
        );

        let route = Ipv4Route::via_gateway(
            "eth0".to_string(),
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        assert!(!route.is_local);
        assert_eq!(
            route.next_hop(Ipv4Addr::new(8, 8, 8, 8)),
            Ipv4Addr::new(192, 168, 1, 1)
        );
    }

    #[test]
    fn test_get_ipv4_interfaces() {
        let interfaces = get_ipv4_interfaces();
        for iface in &interfaces {
            assert!(!iface.name.is_empty());
            assert!(!iface.addresses.is_empty());
        }
    }

    #[test]
    fn test_interface_addr() {
        let addr = Ipv4InterfaceAddr {
            address: Ipv4Addr::new(192, 168, 1, 100),
            prefix_len: 24,
            broadcast: Some(Ipv4Addr::new(192, 168, 1, 255)),
        };

        assert_eq!(addr.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(addr.netmask(), Ipv4Addr::new(255, 255, 255, 0));
    }
}
