"""Ethernet layer Scapy compatibility tests."""

from stackforge import Ether


class TestEthernetCompat:
    """Test Ethernet layer byte-for-byte compatibility with Scapy."""

    def test_ethernet_default(self, compare_with_scapy):
        """Test default Ethernet frame."""
        stackforge_pkt = Ether().bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether()")
        assert matches, report

    def test_ethernet_broadcast(self, compare_with_scapy):
        """Test Ethernet broadcast frame."""
        stackforge_pkt = Ether(dst="ff:ff:ff:ff:ff:ff").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'Ether(dst="ff:ff:ff:ff:ff:ff")')
        assert matches, report

    def test_ethernet_custom_addresses(self, compare_with_scapy):
        """Test Ethernet with custom MAC addresses."""
        stackforge_pkt = Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66")'
        )
        assert matches, report

    def test_ethernet_zero_mac(self, compare_with_scapy):
        """Test Ethernet with zero MAC address."""
        stackforge_pkt = Ether(src="00:00:00:00:00:00").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'Ether(src="00:00:00:00:00:00")')
        assert matches, report

    def test_ethernet_multicast(self, compare_with_scapy):
        """Test Ethernet with multicast MAC address."""
        stackforge_pkt = Ether(dst="01:00:5e:00:00:01").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'Ether(dst="01:00:5e:00:00:01")')
        assert matches, report

    def test_ethernet_ethertype_ipv4(self, compare_with_scapy):
        """Test Ethernet with IPv4 EtherType."""
        stackforge_pkt = Ether(type=0x0800).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether(type=0x0800)")
        assert matches, report

    def test_ethernet_ethertype_arp(self, compare_with_scapy):
        """Test Ethernet with ARP EtherType."""
        stackforge_pkt = Ether(type=0x0806).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether(type=0x0806)")
        assert matches, report

    def test_ethernet_ethertype_ipv6(self, compare_with_scapy):
        """Test Ethernet with IPv6 EtherType."""
        stackforge_pkt = Ether(type=0x86DD).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether(type=0x86dd)")
        assert matches, report

    def test_ethernet_ethertype_8021q(self, compare_with_scapy):
        """Test Ethernet with 802.1Q VLAN EtherType."""
        stackforge_pkt = Ether(type=0x8100).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether(type=0x8100)")
        assert matches, report

    def test_ethernet_dash_separator(self, compare_with_scapy):
        """Test Ethernet with dash-separated MAC addresses."""
        stackforge_pkt = Ether(dst="aa-bb-cc-dd-ee-ff", src="11-22-33-44-55-66").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66")'
        )
        assert matches, report

    def test_ethernet_mixed_case_mac(self, compare_with_scapy):
        """Test Ethernet with mixed case MAC addresses."""
        stackforge_pkt = Ether(dst="AA:BB:CC:DD:EE:FF").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'Ether(dst="aa:bb:cc:dd:ee:ff")')
        assert matches, report

    def test_ethernet_all_ones_src(self, compare_with_scapy):
        """Test Ethernet with all-ones source MAC."""
        stackforge_pkt = Ether(src="ff:ff:ff:ff:ff:ff").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'Ether(src="ff:ff:ff:ff:ff:ff")')
        assert matches, report

    def test_ethernet_custom_ethertype(self, compare_with_scapy):
        """Test Ethernet with custom EtherType value."""
        stackforge_pkt = Ether(type=0x9000).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether(type=0x9000)")
        assert matches, report

    def test_ethernet_length_field(self):
        """Test Ethernet frame size."""
        stackforge_pkt = Ether().bytes()
        assert len(stackforge_pkt) == 14, "Ethernet frame should be 14 bytes"

    def test_ethernet_dst_offset(self):
        """Test destination MAC is at correct offset."""
        stackforge_pkt = Ether(dst="aa:bb:cc:dd:ee:ff").bytes()
        # Destination MAC at bytes 0-5
        assert stackforge_pkt[0:6] == b"\xaa\xbb\xcc\xdd\xee\xff"

    def test_ethernet_src_offset(self):
        """Test source MAC is at correct offset."""
        stackforge_pkt = Ether(src="11:22:33:44:55:66").bytes()
        # Source MAC at bytes 6-11
        assert stackforge_pkt[6:12] == b"\x11\x22\x33\x44\x55\x66"

    def test_ethernet_type_offset(self):
        """Test EtherType is at correct offset."""
        stackforge_pkt = Ether(type=0x0800).bytes()
        # EtherType at bytes 12-13 (big-endian)
        assert stackforge_pkt[12:14] == b"\x08\x00"

    def test_ethernet_local_admin_bit(self, compare_with_scapy):
        """Test Ethernet with locally administered MAC."""
        stackforge_pkt = Ether(src="02:00:00:00:00:01").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'Ether(src="02:00:00:00:00:01")')
        assert matches, report

    def test_ethernet_unicast_dst(self, compare_with_scapy):
        """Test Ethernet with unicast destination."""
        stackforge_pkt = Ether(dst="00:11:22:33:44:55").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'Ether(dst="00:11:22:33:44:55")')
        assert matches, report

    def test_ethernet_various_ethertypes(self, compare_with_scapy):
        """Test various common EtherType values."""
        ethertypes = [
            (0x0800, "IPv4"),
            (0x0806, "ARP"),
            (0x86DD, "IPv6"),
            (0x8100, "802.1Q"),
            (0x88CC, "LLDP"),
            (0x8847, "MPLS unicast"),
            (0x8848, "MPLS multicast"),
        ]

        for etype, name in ethertypes:
            stackforge_pkt = Ether(type=etype).bytes()
            matches, report = compare_with_scapy(stackforge_pkt, f"Ether(type={etype})")
            assert matches, f"{name} (0x{etype:04x}) mismatch: {report}"

    def test_ethernet_sequential_macs(self, compare_with_scapy):
        """Test Ethernet with sequential MAC addresses."""
        for i in range(5):
            mac = f"00:00:00:00:00:{i:02x}"
            stackforge_pkt = Ether(dst=mac).bytes()
            matches, report = compare_with_scapy(stackforge_pkt, f'Ether(dst="{mac}")')
            assert matches, f"MAC {mac} mismatch: {report}"

    def test_ethernet_boundary_ethertypes(self, compare_with_scapy):
        """Test Ethernet with boundary EtherType values."""
        # Test values around 1500 (802.3 vs Ethernet II boundary)
        for etype in [0x05DC, 0x0600, 0x0800, 0xFFFF]:
            stackforge_pkt = Ether(type=etype).bytes()
            matches, report = compare_with_scapy(stackforge_pkt, f"Ether(type={etype})")
            assert matches, f"EtherType 0x{etype:04x} mismatch: {report}"
