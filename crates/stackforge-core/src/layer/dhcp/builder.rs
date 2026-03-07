use std::net::Ipv4Addr;

use crate::layer::dhcp::options::{DhcpOption, code, msg_type, serialize_options};
use crate::layer::field::MacAddress;

/// DHCP magic cookie: 99.130.83.99
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// BOOTP op codes.
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;

/// Builder for constructing DHCP packets.
pub struct DhcpBuilder {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    options: Vec<DhcpOption>,
}

impl Default for DhcpBuilder {
    fn default() -> Self {
        Self {
            op: BOOTREQUEST,
            htype: 1, // Ethernet
            hlen: 6,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; 16],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: Vec::new(),
        }
    }
}

impl DhcpBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a DHCP Discover message.
    #[must_use]
    pub fn discover(client_mac: MacAddress, xid: u32) -> Self {
        let mut b = Self::new()
            .op(BOOTREQUEST)
            .xid(xid)
            .chaddr_mac(client_mac)
            .flags(0x8000); // Broadcast flag
        b.options.push(DhcpOption::message_type(msg_type::DISCOVER));
        b
    }

    /// Create a DHCP Offer message.
    #[must_use]
    pub fn offer(
        xid: u32,
        client_mac: MacAddress,
        offered_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
    ) -> Self {
        let mut b = Self::new()
            .op(BOOTREPLY)
            .xid(xid)
            .yiaddr(offered_ip)
            .siaddr(server_ip)
            .chaddr_mac(client_mac);
        b.options.push(DhcpOption::message_type(msg_type::OFFER));
        b.options.push(DhcpOption::server_id(server_ip));
        b
    }

    /// Create a DHCP Request message.
    #[must_use]
    pub fn request(
        client_mac: MacAddress,
        xid: u32,
        requested_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
    ) -> Self {
        let mut b = Self::new()
            .op(BOOTREQUEST)
            .xid(xid)
            .chaddr_mac(client_mac)
            .flags(0x8000);
        b.options.push(DhcpOption::message_type(msg_type::REQUEST));
        b.options.push(DhcpOption::new(
            code::REQUESTED_IP,
            requested_ip.octets().to_vec(),
        ));
        b.options.push(DhcpOption::server_id(server_ip));
        b
    }

    /// Create a DHCP ACK message.
    #[must_use]
    pub fn ack(
        xid: u32,
        client_mac: MacAddress,
        assigned_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
    ) -> Self {
        let mut b = Self::new()
            .op(BOOTREPLY)
            .xid(xid)
            .yiaddr(assigned_ip)
            .siaddr(server_ip)
            .chaddr_mac(client_mac);
        b.options.push(DhcpOption::message_type(msg_type::ACK));
        b.options.push(DhcpOption::server_id(server_ip));
        b
    }

    /// Create a DHCP NAK message.
    #[must_use]
    pub fn nak(xid: u32, client_mac: MacAddress, server_ip: Ipv4Addr) -> Self {
        let mut b = Self::new().op(BOOTREPLY).xid(xid).chaddr_mac(client_mac);
        b.options.push(DhcpOption::message_type(msg_type::NAK));
        b.options.push(DhcpOption::server_id(server_ip));
        b
    }

    #[must_use]
    pub fn op(mut self, op: u8) -> Self {
        self.op = op;
        self
    }

    #[must_use]
    pub fn xid(mut self, xid: u32) -> Self {
        self.xid = xid;
        self
    }

    #[must_use]
    pub fn flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    #[must_use]
    pub fn ciaddr(mut self, ip: Ipv4Addr) -> Self {
        self.ciaddr = ip;
        self
    }

    #[must_use]
    pub fn yiaddr(mut self, ip: Ipv4Addr) -> Self {
        self.yiaddr = ip;
        self
    }

    #[must_use]
    pub fn siaddr(mut self, ip: Ipv4Addr) -> Self {
        self.siaddr = ip;
        self
    }

    #[must_use]
    pub fn giaddr(mut self, ip: Ipv4Addr) -> Self {
        self.giaddr = ip;
        self
    }

    #[must_use]
    pub fn chaddr_mac(mut self, mac: MacAddress) -> Self {
        self.chaddr[0..6].copy_from_slice(&mac.0);
        self
    }

    /// Add a DHCP option.
    #[must_use]
    pub fn option(mut self, opt: DhcpOption) -> Self {
        self.options.push(opt);
        self
    }

    /// Add a lease time option.
    #[must_use]
    pub fn lease_time(self, seconds: u32) -> Self {
        self.option(DhcpOption::lease_time(seconds))
    }

    /// Add a subnet mask option.
    #[must_use]
    pub fn subnet_mask(self, mask: Ipv4Addr) -> Self {
        self.option(DhcpOption::subnet_mask(mask))
    }

    /// Add a router option.
    #[must_use]
    pub fn router(self, ip: Ipv4Addr) -> Self {
        self.option(DhcpOption::router(ip))
    }

    /// Add a DNS servers option.
    #[must_use]
    pub fn dns(self, servers: &[Ipv4Addr]) -> Self {
        self.option(DhcpOption::dns(servers))
    }

    /// Add a domain name option.
    #[must_use]
    pub fn domain_name(self, name: &str) -> Self {
        self.option(DhcpOption::domain_name(name))
    }

    /// Build the DHCP packet bytes (BOOTP header + options).
    ///
    /// This produces the UDP payload — the caller must wrap it in
    /// UDP(sport=67, dport=68) / IP / Ethernet.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let opts_bytes = serialize_options(&self.options);
        let mut out = Vec::with_capacity(240 + opts_bytes.len());

        // BOOTP fixed header (236 bytes)
        out.push(self.op);
        out.push(self.htype);
        out.push(self.hlen);
        out.push(self.hops);
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&self.secs.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.ciaddr.octets());
        out.extend_from_slice(&self.yiaddr.octets());
        out.extend_from_slice(&self.siaddr.octets());
        out.extend_from_slice(&self.giaddr.octets());
        out.extend_from_slice(&self.chaddr);
        out.extend_from_slice(&self.sname);
        out.extend_from_slice(&self.file);

        // Magic cookie
        out.extend_from_slice(&MAGIC_COOKIE);

        // Options
        out.extend_from_slice(&opts_bytes);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_build() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let pkt = DhcpBuilder::discover(mac, 0x12345678).build();

        assert_eq!(pkt[0], BOOTREQUEST); // op
        assert_eq!(pkt[1], 1); // htype (ethernet)
        assert_eq!(pkt[2], 6); // hlen
        // xid
        assert_eq!(&pkt[4..8], &[0x12, 0x34, 0x56, 0x78]);
        // flags (broadcast)
        assert_eq!(&pkt[10..12], &[0x80, 0x00]);
        // chaddr
        assert_eq!(&pkt[28..34], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // magic cookie at offset 236
        assert_eq!(&pkt[236..240], &[99, 130, 83, 99]);
        // First option should be message type = DISCOVER
        assert_eq!(pkt[240], code::MESSAGE_TYPE);
        assert_eq!(pkt[241], 1); // length
        assert_eq!(pkt[242], msg_type::DISCOVER);
    }

    #[test]
    fn test_offer_build() {
        let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let pkt = DhcpBuilder::offer(
            0xaabbccdd,
            mac,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
        )
        .lease_time(3600)
        .subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
        .build();

        assert_eq!(pkt[0], BOOTREPLY);
        // yiaddr = offered IP
        assert_eq!(&pkt[16..20], &[192, 168, 1, 100]);
        // siaddr = server IP
        assert_eq!(&pkt[20..24], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_ack_build() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let pkt = DhcpBuilder::ack(
            0x11223344,
            mac,
            Ipv4Addr::new(10, 0, 0, 50),
            Ipv4Addr::new(10, 0, 0, 1),
        )
        .build();

        assert_eq!(pkt[0], BOOTREPLY);
        assert_eq!(&pkt[16..20], &[10, 0, 0, 50]); // yiaddr
    }
}
