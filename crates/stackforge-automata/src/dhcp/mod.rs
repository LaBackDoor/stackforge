pub mod lease;

use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::time::Duration;

use stackforge_core::layer::dhcp::options::{code, msg_type, DhcpOption};
use stackforge_core::layer::dhcp::{DhcpBuilder, DhcpLayer, DHCP_SERVER_PORT};
use stackforge_core::layer::field::MacAddress;
use stackforge_core::{
    EthernetBuilder, Ipv4Builder, LayerKind, Packet, UdpBuilder,
};

use crate::traits::Automaton;

use self::lease::{LeaseTable, PoolConfig};

/// Full-featured DHCP server automaton.
///
/// Implements the complete DHCP protocol (RFC 2131):
/// - DORA handshake (Discover → Offer → Request → ACK)
/// - DHCPNAK for invalid requests
/// - DHCPRELEASE to free leases
/// - DHCPDECLINE to mark addresses as unusable
/// - DHCPINFORM to provide configuration without lease
/// - Periodic lease sweep via `on_tick()`
/// - Relay agent (giaddr) support
/// - Configurable pool, gateway, DNS, subnet, domain, lease time, T1/T2
///
/// Uses interior mutability (`RefCell`) because the `Automaton` trait
/// requires `&self` on `make_reply`, but we need to mutate the lease table.
pub struct DhcpServer {
    /// Server MAC address (for building Ethernet frames).
    server_mac: MacAddress,
    /// Lease table with interior mutability.
    leases: RefCell<LeaseTable>,
    /// Lease sweep interval.
    sweep_interval: Duration,
}

impl DhcpServer {
    /// Create a new DHCP server with the given configuration.
    pub fn new(server_mac: MacAddress, pool_config: PoolConfig) -> Self {
        Self {
            server_mac,
            leases: RefCell::new(LeaseTable::new(pool_config)),
            sweep_interval: Duration::from_secs(60),
        }
    }

    /// Set the lease sweep interval (default: 60 seconds).
    #[must_use]
    pub fn sweep_interval(mut self, interval: Duration) -> Self {
        self.sweep_interval = interval;
        self
    }

    /// Extract DHCP fields from a parsed packet.
    /// Returns None if the packet doesn't contain a DHCP layer.
    fn extract_dhcp_info(&self, pkt: &Packet) -> Option<DhcpInfo> {
        let buf = pkt.as_bytes();
        let dhcp_idx = pkt.get_layer(LayerKind::Dhcp)?;
        let dhcp = DhcpLayer::new(*dhcp_idx);

        let op = dhcp.op(buf).ok()?;
        let xid = dhcp.xid(buf).ok()?;
        let flags = dhcp.flags(buf).ok()?;
        let ciaddr = dhcp.ciaddr(buf).ok()?;
        let giaddr = dhcp.giaddr(buf).ok()?;
        let client_mac = dhcp.chaddr(buf).ok()?;

        let msg_type = dhcp.msg_type(buf)?;
        let requested_ip = dhcp.requested_ip(buf);
        let server_id = dhcp.server_id(buf);
        let hostname = dhcp
            .get_option(buf, code::HOSTNAME)
            .and_then(|o| String::from_utf8(o.data).ok());

        Some(DhcpInfo {
            op,
            xid,
            flags,
            ciaddr,
            giaddr,
            client_mac,
            msg_type,
            requested_ip,
            server_id,
            hostname,
        })
    }

    /// Build a full Ethernet/IPv4/UDP/DHCP reply frame.
    fn build_reply_frame(
        &self,
        dhcp_payload: Vec<u8>,
        client_mac: [u8; 6],
        flags: u16,
        giaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
    ) -> Vec<u8> {
        let table = self.leases.borrow();
        let config = table.config();

        // Determine destination: relay agent, broadcast, or unicast
        let (dst_mac, dst_ip) = if giaddr != Ipv4Addr::UNSPECIFIED {
            // Relay agent — send back to relay
            // We don't know relay MAC, so broadcast on our segment
            (MacAddress::new([0xff; 6]), giaddr)
        } else if flags & 0x8000 != 0 || yiaddr == Ipv4Addr::UNSPECIFIED {
            // Broadcast flag set or no assigned IP yet
            (
                MacAddress::new([0xff; 6]),
                Ipv4Addr::new(255, 255, 255, 255),
            )
        } else {
            // Unicast to client
            (MacAddress::new(client_mac), yiaddr)
        };

        // Build layers from bottom up
        let udp = UdpBuilder::dhcp_server().payload(dhcp_payload).build();

        let ip = Ipv4Builder::udp()
            .src(config.server_ip)
            .dst(dst_ip)
            .ttl(128)
            .payload(udp)
            .build();

        let eth = EthernetBuilder::new()
            .src(self.server_mac)
            .dst(dst_mac)
            .build_with_payload(LayerKind::Ipv4);

        let mut frame = eth;
        frame.extend_from_slice(&ip);
        frame
    }

    /// Handle DHCP Discover — respond with Offer.
    fn handle_discover(&self, info: &DhcpInfo) -> Option<Vec<u8>> {
        let mut table = self.leases.borrow_mut();
        let offered_ip = table.allocate(info.client_mac, info.requested_ip)?;
        let config = table.config().clone();

        let mut builder = DhcpBuilder::offer(
            info.xid,
            MacAddress::new(info.client_mac),
            offered_ip,
            config.server_ip,
        )
        .lease_time(config.lease_time)
        .subnet_mask(config.subnet_mask)
        .router(config.gateway)
        .dns(&config.dns_servers);

        // Add renewal/rebinding times
        builder = builder.option(DhcpOption::new(
            code::RENEWAL_TIME,
            config.effective_renewal_time().to_be_bytes().to_vec(),
        ));
        builder = builder.option(DhcpOption::new(
            code::REBINDING_TIME,
            config.effective_rebinding_time().to_be_bytes().to_vec(),
        ));

        if let Some(ref domain) = config.domain {
            builder = builder.domain_name(domain);
        }

        // If request came via relay, set giaddr
        if info.giaddr != Ipv4Addr::UNSPECIFIED {
            builder = builder.giaddr(info.giaddr);
        }

        let dhcp_payload = builder.build();
        drop(table);

        Some(self.build_reply_frame(
            dhcp_payload,
            info.client_mac,
            info.flags,
            info.giaddr,
            offered_ip,
        ))
    }

    /// Handle DHCP Request — respond with ACK or NAK.
    fn handle_request(&self, info: &DhcpInfo) -> Option<Vec<u8>> {
        let mut table = self.leases.borrow_mut();
        let config = table.config().clone();

        // If server_id is present and doesn't match us, ignore
        if let Some(sid) = info.server_id {
            if sid != config.server_ip {
                return None;
            }
        }

        // Determine requested IP: from option 50 or ciaddr
        let requested = info
            .requested_ip
            .or(if info.ciaddr != Ipv4Addr::UNSPECIFIED {
                Some(info.ciaddr)
            } else {
                None
            });

        let requested_ip = match requested {
            Some(ip) => ip,
            None => {
                // No requested IP — NAK
                let dhcp_payload =
                    DhcpBuilder::nak(info.xid, MacAddress::new(info.client_mac), config.server_ip)
                        .build();
                drop(table);
                return Some(self.build_reply_frame(
                    dhcp_payload,
                    info.client_mac,
                    info.flags,
                    info.giaddr,
                    Ipv4Addr::UNSPECIFIED,
                ));
            }
        };

        // Try to allocate/confirm the requested IP
        let allocated = table.allocate(info.client_mac, Some(requested_ip));
        match allocated {
            Some(ip) if ip == requested_ip => {
                // Commit the lease
                table.commit(info.client_mac, ip, info.hostname.clone());

                let mut builder = DhcpBuilder::ack(
                    info.xid,
                    MacAddress::new(info.client_mac),
                    ip,
                    config.server_ip,
                )
                .lease_time(config.lease_time)
                .subnet_mask(config.subnet_mask)
                .router(config.gateway)
                .dns(&config.dns_servers);

                builder = builder.option(DhcpOption::new(
                    code::RENEWAL_TIME,
                    config.effective_renewal_time().to_be_bytes().to_vec(),
                ));
                builder = builder.option(DhcpOption::new(
                    code::REBINDING_TIME,
                    config.effective_rebinding_time().to_be_bytes().to_vec(),
                ));

                if let Some(ref domain) = config.domain {
                    builder = builder.domain_name(domain);
                }

                if info.giaddr != Ipv4Addr::UNSPECIFIED {
                    builder = builder.giaddr(info.giaddr);
                }

                let dhcp_payload = builder.build();
                drop(table);

                Some(self.build_reply_frame(
                    dhcp_payload,
                    info.client_mac,
                    info.flags,
                    info.giaddr,
                    ip,
                ))
            }
            _ => {
                // Can't grant requested IP — NAK
                let dhcp_payload =
                    DhcpBuilder::nak(info.xid, MacAddress::new(info.client_mac), config.server_ip)
                        .build();
                drop(table);
                Some(self.build_reply_frame(
                    dhcp_payload,
                    info.client_mac,
                    info.flags,
                    info.giaddr,
                    Ipv4Addr::UNSPECIFIED,
                ))
            }
        }
    }

    /// Handle DHCP Release — free the lease.
    fn handle_release(&self, info: &DhcpInfo) {
        let mut table = self.leases.borrow_mut();
        table.release(&info.client_mac);
    }

    /// Handle DHCP Decline — mark IP as unusable.
    fn handle_decline(&self, info: &DhcpInfo) {
        if let Some(ip) = info.requested_ip {
            let mut table = self.leases.borrow_mut();
            table.decline(ip, &info.client_mac);
        }
    }

    /// Handle DHCP Inform — provide configuration without lease.
    fn handle_inform(&self, info: &DhcpInfo) -> Option<Vec<u8>> {
        let table = self.leases.borrow();
        let config = table.config().clone();
        drop(table);

        // ACK without yiaddr or lease time
        let mut builder = DhcpBuilder::ack(
            info.xid,
            MacAddress::new(info.client_mac),
            Ipv4Addr::UNSPECIFIED, // no yiaddr for INFORM
            config.server_ip,
        )
        .subnet_mask(config.subnet_mask)
        .router(config.gateway)
        .dns(&config.dns_servers);

        if let Some(ref domain) = config.domain {
            builder = builder.domain_name(domain);
        }

        // For INFORM, ciaddr should be set, use it as destination
        let dhcp_payload = builder.build();

        Some(self.build_reply_frame(
            dhcp_payload,
            info.client_mac,
            0, // unicast for INFORM responses
            info.giaddr,
            info.ciaddr,
        ))
    }

    /// Get the number of active leases.
    pub fn active_lease_count(&self) -> usize {
        self.leases.borrow().active_leases().len()
    }

    /// Get total leases (including expired).
    pub fn total_lease_count(&self) -> usize {
        self.leases.borrow().len()
    }
}

/// Extracted DHCP packet information.
struct DhcpInfo {
    #[allow(dead_code)]
    op: u8,
    xid: u32,
    flags: u16,
    ciaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    client_mac: [u8; 6],
    msg_type: u8,
    requested_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
    hostname: Option<String>,
}

impl Automaton for DhcpServer {
    fn bpf_filter(&self) -> Option<String> {
        Some(format!(
            "udp dst port {} and udp src port 68",
            DHCP_SERVER_PORT
        ))
    }

    fn is_request(&self, pkt: &Packet) -> bool {
        let buf = pkt.as_bytes();
        // Quick check: must be large enough for Ethernet(14) + IP(20) + UDP(8) + BOOTP(236) + cookie(4)
        if buf.len() < 282 {
            return false;
        }
        pkt.get_layer(LayerKind::Dhcp).is_some()
    }

    fn make_reply(&self, request: &Packet) -> Option<Vec<u8>> {
        let info = self.extract_dhcp_info(request)?;

        match info.msg_type {
            msg_type::DISCOVER => self.handle_discover(&info),
            msg_type::REQUEST => self.handle_request(&info),
            msg_type::RELEASE => {
                self.handle_release(&info);
                None // no reply for release
            }
            msg_type::DECLINE => {
                self.handle_decline(&info);
                None // no reply for decline
            }
            msg_type::INFORM => self.handle_inform(&info),
            _ => None,
        }
    }

    fn tick_interval(&self) -> Option<Duration> {
        Some(self.sweep_interval)
    }

    fn on_tick(&mut self) -> Option<Vec<Vec<u8>>> {
        let swept = self.leases.borrow_mut().sweep_expired();
        if swept > 0 {
            // Could log here; no packets to send on sweep
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stackforge_core::layer::dhcp::options::msg_type;

    fn test_config() -> PoolConfig {
        PoolConfig {
            pool_start: Ipv4Addr::new(10, 0, 0, 10),
            pool_end: Ipv4Addr::new(10, 0, 0, 20),
            server_ip: Ipv4Addr::new(10, 0, 0, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            domain: Some("test.local".to_string()),
            lease_time: 3600,
            renewal_time: None,
            rebinding_time: None,
        }
    }

    fn server_mac() -> MacAddress {
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    }

    fn build_dhcp_request_frame(
        msg_type_val: u8,
        client_mac: [u8; 6],
        xid: u32,
        flags: u16,
        ciaddr: Ipv4Addr,
        requested_ip: Option<Ipv4Addr>,
        server_id: Option<Ipv4Addr>,
    ) -> Vec<u8> {
        let mut builder = DhcpBuilder::new()
            .op(1) // BOOTREQUEST
            .xid(xid)
            .flags(flags)
            .ciaddr(ciaddr)
            .chaddr_mac(MacAddress::new(client_mac))
            .option(DhcpOption::message_type(msg_type_val));

        if let Some(ip) = requested_ip {
            builder =
                builder.option(DhcpOption::new(code::REQUESTED_IP, ip.octets().to_vec()));
        }
        if let Some(sid) = server_id {
            builder = builder.option(DhcpOption::server_id(sid));
        }

        let dhcp_payload = builder.build();

        // Wrap in Eth/IP/UDP
        let udp = UdpBuilder::dhcp_client().payload(dhcp_payload).build();
        let ip = Ipv4Builder::udp()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::new(255, 255, 255, 255))
            .ttl(128)
            .payload(udp)
            .build();
        let eth = EthernetBuilder::new()
            .src(MacAddress::new(client_mac))
            .dst(MacAddress::new([0xff; 6]))
            .build_with_payload(LayerKind::Ipv4);

        let mut frame = eth;
        frame.extend_from_slice(&ip);
        frame
    }

    fn parse_reply_dhcp(reply: &[u8]) -> (u8, Ipv4Addr) {
        // Parse the reply to get msg_type and yiaddr
        let mut pkt = Packet::from_bytes(reply.to_vec());
        pkt.parse().unwrap();
        let dhcp_idx = pkt.get_layer(LayerKind::Dhcp).unwrap();
        let dhcp = DhcpLayer::new(*dhcp_idx);
        let buf = pkt.as_bytes();
        let mt = dhcp.msg_type(buf).unwrap_or(0);
        let yiaddr = dhcp.yiaddr(buf).unwrap_or(Ipv4Addr::UNSPECIFIED);
        (mt, yiaddr)
    }

    #[test]
    fn test_discover_offer() {
        let server = DhcpServer::new(server_mac(), test_config());
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let frame = build_dhcp_request_frame(
            msg_type::DISCOVER,
            client_mac,
            0x12345678,
            0x8000,
            Ipv4Addr::UNSPECIFIED,
            None,
            None,
        );

        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();

        assert!(server.is_request(&pkt));
        let reply = server.make_reply(&pkt).unwrap();
        let (mt, yiaddr) = parse_reply_dhcp(&reply);
        assert_eq!(mt, msg_type::OFFER);
        assert_eq!(yiaddr, Ipv4Addr::new(10, 0, 0, 10));
    }

    #[test]
    fn test_request_ack() {
        let server = DhcpServer::new(server_mac(), test_config());
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let server_ip = Ipv4Addr::new(10, 0, 0, 1);

        // First, discover
        let frame = build_dhcp_request_frame(
            msg_type::DISCOVER,
            client_mac,
            0x1234,
            0x8000,
            Ipv4Addr::UNSPECIFIED,
            None,
            None,
        );
        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();
        server.make_reply(&pkt).unwrap();

        // Then request
        let frame = build_dhcp_request_frame(
            msg_type::REQUEST,
            client_mac,
            0x1234,
            0x8000,
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(10, 0, 0, 10)),
            Some(server_ip),
        );
        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();
        let reply = server.make_reply(&pkt).unwrap();

        let (mt, yiaddr) = parse_reply_dhcp(&reply);
        assert_eq!(mt, msg_type::ACK);
        assert_eq!(yiaddr, Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(server.active_lease_count(), 1);
    }

    #[test]
    fn test_request_nak_wrong_ip() {
        let server = DhcpServer::new(server_mac(), test_config());
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let server_ip = Ipv4Addr::new(10, 0, 0, 1);

        // Request an IP outside the pool
        let frame = build_dhcp_request_frame(
            msg_type::REQUEST,
            client_mac,
            0x1234,
            0x8000,
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(192, 168, 1, 1)), // out of pool
            Some(server_ip),
        );
        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();
        let reply = server.make_reply(&pkt).unwrap();

        let (mt, _) = parse_reply_dhcp(&reply);
        assert_eq!(mt, msg_type::NAK);
    }

    #[test]
    fn test_release() {
        let server = DhcpServer::new(server_mac(), test_config());
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let server_ip = Ipv4Addr::new(10, 0, 0, 1);
        let assigned_ip = Ipv4Addr::new(10, 0, 0, 10);

        // Discover + Request to get a lease
        let frame = build_dhcp_request_frame(
            msg_type::DISCOVER, client_mac, 0x1234, 0x8000,
            Ipv4Addr::UNSPECIFIED, None, None,
        );
        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();
        server.make_reply(&pkt);

        let frame = build_dhcp_request_frame(
            msg_type::REQUEST, client_mac, 0x1234, 0x8000,
            Ipv4Addr::UNSPECIFIED, Some(assigned_ip), Some(server_ip),
        );
        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();
        server.make_reply(&pkt);
        assert_eq!(server.active_lease_count(), 1);

        // Release
        let frame = build_dhcp_request_frame(
            msg_type::RELEASE, client_mac, 0x1234, 0,
            assigned_ip, None, Some(server_ip),
        );
        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();
        let reply = server.make_reply(&pkt);
        assert!(reply.is_none()); // no reply for release
        assert_eq!(server.total_lease_count(), 0);
    }

    #[test]
    fn test_decline() {
        let server = DhcpServer::new(server_mac(), test_config());
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let declined_ip = Ipv4Addr::new(10, 0, 0, 10);

        // Decline an IP
        let frame = build_dhcp_request_frame(
            msg_type::DECLINE, client_mac, 0x1234, 0,
            Ipv4Addr::UNSPECIFIED, Some(declined_ip), None,
        );
        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();
        let reply = server.make_reply(&pkt);
        assert!(reply.is_none());

        // Next discover should skip the declined IP
        let client_mac2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let frame = build_dhcp_request_frame(
            msg_type::DISCOVER, client_mac2, 0x5678, 0x8000,
            Ipv4Addr::UNSPECIFIED, None, None,
        );
        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();
        let reply = server.make_reply(&pkt).unwrap();
        let (_, yiaddr) = parse_reply_dhcp(&reply);
        assert_eq!(yiaddr, Ipv4Addr::new(10, 0, 0, 11)); // skipped .10
    }

    #[test]
    fn test_inform() {
        let server = DhcpServer::new(server_mac(), test_config());
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client_ip = Ipv4Addr::new(10, 0, 0, 50);

        let frame = build_dhcp_request_frame(
            msg_type::INFORM, client_mac, 0x1234, 0,
            client_ip, None, None,
        );
        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();
        let reply = server.make_reply(&pkt).unwrap();

        let (mt, yiaddr) = parse_reply_dhcp(&reply);
        assert_eq!(mt, msg_type::ACK);
        // INFORM ACK should have no yiaddr
        assert_eq!(yiaddr, Ipv4Addr::UNSPECIFIED);
        // No lease created
        assert_eq!(server.active_lease_count(), 0);
    }

    #[test]
    fn test_ignore_wrong_server_id() {
        let server = DhcpServer::new(server_mac(), test_config());
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        // Request with wrong server ID
        let frame = build_dhcp_request_frame(
            msg_type::REQUEST, client_mac, 0x1234, 0x8000,
            Ipv4Addr::UNSPECIFIED,
            Some(Ipv4Addr::new(10, 0, 0, 10)),
            Some(Ipv4Addr::new(192, 168, 1, 1)), // wrong server
        );
        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();
        let reply = server.make_reply(&pkt);
        assert!(reply.is_none()); // should ignore
    }

    #[test]
    fn test_multiple_clients() {
        let server = DhcpServer::new(server_mac(), test_config());
        let server_ip = Ipv4Addr::new(10, 0, 0, 1);

        for i in 0..5u8 {
            let mac = [i, i, i, i, i, i];
            // Discover
            let frame = build_dhcp_request_frame(
                msg_type::DISCOVER, mac, u32::from(i), 0x8000,
                Ipv4Addr::UNSPECIFIED, None, None,
            );
            let mut pkt = Packet::from_bytes(frame);
            pkt.parse().unwrap();
            let reply = server.make_reply(&pkt).unwrap();
            let (mt, yiaddr) = parse_reply_dhcp(&reply);
            assert_eq!(mt, msg_type::OFFER);
            assert_eq!(yiaddr, Ipv4Addr::new(10, 0, 0, 10 + i));

            // Request
            let frame = build_dhcp_request_frame(
                msg_type::REQUEST, mac, u32::from(i), 0x8000,
                Ipv4Addr::UNSPECIFIED, Some(yiaddr), Some(server_ip),
            );
            let mut pkt = Packet::from_bytes(frame);
            pkt.parse().unwrap();
            server.make_reply(&pkt).unwrap();
        }

        assert_eq!(server.active_lease_count(), 5);
    }

    #[test]
    fn test_bpf_filter() {
        let server = DhcpServer::new(server_mac(), test_config());
        let filter = server.bpf_filter().unwrap();
        assert!(filter.contains("udp dst port 67"));
    }

    #[test]
    fn test_tick_sweep() {
        let mut server = DhcpServer::new(server_mac(), test_config());
        // on_tick should not panic even with no leases
        let result = server.on_tick();
        assert!(result.is_none());
    }

    #[test]
    fn test_reply_frame_is_valid_packet() {
        let server = DhcpServer::new(server_mac(), test_config());
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let frame = build_dhcp_request_frame(
            msg_type::DISCOVER, client_mac, 0xABCD, 0x8000,
            Ipv4Addr::UNSPECIFIED, None, None,
        );
        let mut pkt = Packet::from_bytes(frame);
        pkt.parse().unwrap();
        let reply = server.make_reply(&pkt).unwrap();

        // The reply should be a valid parseable packet
        let mut reply_pkt = Packet::from_bytes(reply);
        assert!(reply_pkt.parse().is_ok());
        assert!(reply_pkt.get_layer(LayerKind::Ethernet).is_some());
        assert!(reply_pkt.get_layer(LayerKind::Ipv4).is_some());
        assert!(reply_pkt.get_layer(LayerKind::Udp).is_some());
        assert!(reply_pkt.get_layer(LayerKind::Dhcp).is_some());
    }
}
