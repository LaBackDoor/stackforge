"""IPv4 layer Scapy compatibility tests."""

from stackforge import IP


class TestIPv4Compat:
    """Test IPv4 layer byte-for-byte compatibility with Scapy."""

    def test_ipv4_default(self, compare_with_scapy):
        """Test default IPv4 packet."""
        stackforge_pkt = IP().bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()")
        assert matches, report

    def test_ipv4_custom_src_dst(self, compare_with_scapy):
        """Test IPv4 with custom source and destination."""
        stackforge_pkt = IP(src="192.168.1.100", dst="192.168.1.1").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'IP(src="192.168.1.100", dst="192.168.1.1")'
        )
        assert matches, report

    def test_ipv4_ttl_default(self, compare_with_scapy):
        """Test IPv4 with default TTL."""
        stackforge_pkt = IP(ttl=64).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(ttl=64)")
        assert matches, report

    def test_ipv4_ttl_max(self, compare_with_scapy):
        """Test IPv4 with maximum TTL."""
        stackforge_pkt = IP(ttl=255).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(ttl=255)")
        assert matches, report

    def test_ipv4_ttl_min(self, compare_with_scapy):
        """Test IPv4 with minimum TTL."""
        stackforge_pkt = IP(ttl=1).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(ttl=1)")
        assert matches, report

    def test_ipv4_ttl_zero(self, compare_with_scapy):
        """Test IPv4 with zero TTL."""
        stackforge_pkt = IP(ttl=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(ttl=0)")
        assert matches, report

    def test_ipv4_tos_default(self, compare_with_scapy):
        """Test IPv4 with default TOS."""
        stackforge_pkt = IP(tos=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(tos=0)")
        assert matches, report

    def test_ipv4_tos_cs1(self, compare_with_scapy):
        """Test IPv4 with Class Selector 1 TOS."""
        stackforge_pkt = IP(tos=0x20).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(tos=0x20)")
        assert matches, report

    def test_ipv4_tos_ef(self, compare_with_scapy):
        """Test IPv4 with Expedited Forwarding TOS."""
        stackforge_pkt = IP(tos=0xB8).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(tos=0xb8)")
        assert matches, report

    def test_ipv4_flags_df(self, compare_with_scapy):
        """Test IPv4 with Don't Fragment flag."""
        stackforge_pkt = IP(flags="DF").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'IP(flags="DF")')
        assert matches, report

    def test_ipv4_flags_mf(self, compare_with_scapy):
        """Test IPv4 with More Fragments flag."""
        stackforge_pkt = IP(flags="MF").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'IP(flags="MF")')
        assert matches, report

    def test_ipv4_flags_none(self, compare_with_scapy):
        """Test IPv4 with no flags."""
        stackforge_pkt = IP(flags=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(flags=0)")
        assert matches, report

    def test_ipv4_frag_offset_zero(self, compare_with_scapy):
        """Test IPv4 with zero fragment offset."""
        stackforge_pkt = IP(frag=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(frag=0)")
        assert matches, report

    def test_ipv4_frag_offset_nonzero(self, compare_with_scapy):
        """Test IPv4 with non-zero fragment offset."""
        stackforge_pkt = IP(frag=100).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(frag=100)")
        assert matches, report

    def test_ipv4_frag_offset_max(self, compare_with_scapy):
        """Test IPv4 with maximum fragment offset."""
        stackforge_pkt = IP(frag=8191).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(frag=8191)")
        assert matches, report

    def test_ipv4_id_default(self, compare_with_scapy):
        """Test IPv4 with default ID."""
        stackforge_pkt = IP(id=1).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(id=1)")
        assert matches, report

    def test_ipv4_id_custom(self, compare_with_scapy):
        """Test IPv4 with custom ID."""
        stackforge_pkt = IP(id=12345).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(id=12345)")
        assert matches, report

    def test_ipv4_id_max(self, compare_with_scapy):
        """Test IPv4 with maximum ID."""
        stackforge_pkt = IP(id=65535).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(id=65535)")
        assert matches, report

    def test_ipv4_proto_tcp(self, compare_with_scapy):
        """Test IPv4 with TCP protocol."""
        stackforge_pkt = IP(proto=6).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(proto=6)")
        assert matches, report

    def test_ipv4_proto_udp(self, compare_with_scapy):
        """Test IPv4 with UDP protocol."""
        stackforge_pkt = IP(proto=17).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(proto=17)")
        assert matches, report

    def test_ipv4_proto_icmp(self, compare_with_scapy):
        """Test IPv4 with ICMP protocol."""
        stackforge_pkt = IP(proto=1).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(proto=1)")
        assert matches, report

    def test_ipv4_src_loopback(self, compare_with_scapy):
        """Test IPv4 with loopback source."""
        stackforge_pkt = IP(src="127.0.0.1").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'IP(src="127.0.0.1")')
        assert matches, report

    def test_ipv4_dst_broadcast(self, compare_with_scapy):
        """Test IPv4 with broadcast destination."""
        stackforge_pkt = IP(dst="255.255.255.255").bytes()
        # Ignore checksum (10-11) and source IP (12-15) which differ due to system IP
        matches, report = compare_with_scapy(
            stackforge_pkt, 'IP(dst="255.255.255.255")', ignore_fields=[(10, 16)]
        )
        assert matches, report

    def test_ipv4_src_zero(self, compare_with_scapy):
        """Test IPv4 with zero source address."""
        stackforge_pkt = IP(src="0.0.0.0").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'IP(src="0.0.0.0")')
        assert matches, report

    def test_ipv4_private_addresses(self, compare_with_scapy):
        """Test IPv4 with various private address ranges."""
        private_ips = [
            ("10.0.0.1", "10.255.255.254"),
            ("172.16.0.1", "172.31.255.254"),
            ("192.168.0.1", "192.168.255.254"),
        ]

        for src, dst in private_ips:
            stackforge_pkt = IP(src=src, dst=dst).bytes()
            matches, report = compare_with_scapy(stackforge_pkt, f'IP(src="{src}", dst="{dst}")')
            assert matches, f"Private IP {src} -> {dst} mismatch: {report}"

    def test_ipv4_public_dns(self, compare_with_scapy):
        """Test IPv4 with public DNS addresses."""
        dns_servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]

        for dns in dns_servers:
            stackforge_pkt = IP(dst=dns).bytes()
            # Ignore checksum and source IP (system dependent)
            matches, report = compare_with_scapy(
                stackforge_pkt, f'IP(dst="{dns}")', ignore_fields=[(10, 16)]
            )
            assert matches, f"DNS {dns} mismatch: {report}"

    def test_ipv4_multicast(self, compare_with_scapy):
        """Test IPv4 with multicast addresses."""
        multicast_ips = ["224.0.0.1", "224.0.0.251", "239.255.255.255"]

        for ip in multicast_ips:
            stackforge_pkt = IP(dst=ip).bytes()
            # Ignore checksum and source IP (system dependent)
            matches, report = compare_with_scapy(
                stackforge_pkt, f'IP(dst="{ip}")', ignore_fields=[(10, 16)]
            )
            assert matches, f"Multicast {ip} mismatch: {report}"

    def test_ipv4_version_field(self):
        """Test IPv4 version field is correct."""
        stackforge_pkt = IP().bytes()
        # Version is in upper 4 bits of first byte
        assert (stackforge_pkt[0] >> 4) == 4, "IP version should be 4"

    def test_ipv4_ihl_field(self):
        """Test IPv4 IHL field is correct."""
        stackforge_pkt = IP().bytes()
        # IHL is in lower 4 bits of first byte (should be 5 for no options)
        assert (stackforge_pkt[0] & 0x0F) == 5, "IHL should be 5 (20 bytes)"

    def test_ipv4_header_length(self):
        """Test IPv4 header length."""
        stackforge_pkt = IP().bytes()
        assert len(stackforge_pkt) == 20, "IPv4 header should be 20 bytes"

    def test_ipv4_ttl_offset(self):
        """Test TTL is at correct offset."""
        stackforge_pkt = IP(ttl=128).bytes()
        # TTL at byte 8
        assert stackforge_pkt[8] == 128

    def test_ipv4_protocol_offset(self):
        """Test protocol is at correct offset."""
        stackforge_pkt = IP(proto=6).bytes()
        # Protocol at byte 9
        assert stackforge_pkt[9] == 6

    def test_ipv4_src_offset(self):
        """Test source IP is at correct offset."""
        stackforge_pkt = IP(src="192.168.1.100").bytes()
        # Source IP at bytes 12-15
        assert stackforge_pkt[12:16] == b"\xc0\xa8\x01\x64"

    def test_ipv4_dst_offset(self):
        """Test destination IP is at correct offset."""
        stackforge_pkt = IP(dst="10.0.0.1").bytes()
        # Destination IP at bytes 16-19
        assert stackforge_pkt[16:20] == b"\x0a\x00\x00\x01"

    def test_ipv4_tos_offset(self):
        """Test TOS is at correct offset."""
        stackforge_pkt = IP(tos=0x10).bytes()
        # TOS at byte 1
        assert stackforge_pkt[1] == 0x10

    def test_ipv4_id_offset(self):
        """Test ID is at correct offset."""
        stackforge_pkt = IP(id=0x1234).bytes()
        # ID at bytes 4-5 (big-endian)
        assert stackforge_pkt[4:6] == b"\x12\x34"

    def test_ipv4_flags_df_offset(self):
        """Test DF flag is at correct offset."""
        stackforge_pkt = IP(flags="DF").bytes()
        # Flags at byte 6, DF is bit 1 (0x40)
        assert (stackforge_pkt[6] & 0x40) == 0x40

    def test_ipv4_flags_mf_offset(self):
        """Test MF flag is at correct offset."""
        stackforge_pkt = IP(flags="MF").bytes()
        # Flags at byte 6, MF is bit 0 (0x20)
        assert (stackforge_pkt[6] & 0x20) == 0x20

    def test_ipv4_combined_fields(self, compare_with_scapy):
        """Test IPv4 with multiple fields set."""
        stackforge_pkt = IP(
            src="192.168.1.100",
            dst="8.8.8.8",
            ttl=64,
            tos=0x10,
            id=54321,
            flags="DF",
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'IP(src="192.168.1.100", dst="8.8.8.8", ttl=64, tos=0x10, id=54321, flags="DF")',
        )
        assert matches, report

    def test_ipv4_link_local_address(self, compare_with_scapy):
        """Test IPv4 with link-local address."""
        stackforge_pkt = IP(src="169.254.0.1", dst="169.254.0.2").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'IP(src="169.254.0.1", dst="169.254.0.2")'
        )
        assert matches, report
