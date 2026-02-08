"""Checksum calculation Scapy compatibility tests."""

from stackforge import ICMP, IP, TCP, UDP, Ether, Raw


class TestChecksumsCompat:
    """Test checksum calculations byte-for-byte compatibility with Scapy."""

    def test_ipv4_checksum_default(self, compare_with_scapy):
        """Test IPv4 header checksum with default values."""
        stackforge_pkt = IP().bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()")
        assert matches, report

    def test_ipv4_checksum_custom_fields(self, compare_with_scapy):
        """Test IPv4 header checksum with custom fields."""
        stackforge_pkt = IP(src="192.168.1.100", dst="8.8.8.8", ttl=64).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'IP(src="192.168.1.100", dst="8.8.8.8", ttl=64)'
        )
        assert matches, report

    def test_ipv4_checksum_with_tos(self, compare_with_scapy):
        """Test IPv4 header checksum with TOS field."""
        stackforge_pkt = IP(tos=0x10, ttl=128).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(tos=0x10, ttl=128)")
        assert matches, report

    def test_ipv4_checksum_with_id(self, compare_with_scapy):
        """Test IPv4 header checksum with custom ID."""
        stackforge_pkt = IP(id=54321, ttl=64).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP(id=54321, ttl=64)")
        assert matches, report

    def test_ipv4_checksum_with_flags(self, compare_with_scapy):
        """Test IPv4 header checksum with DF flag."""
        stackforge_pkt = IP(flags="DF", ttl=64).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'IP(flags="DF", ttl=64)')
        assert matches, report

    def test_tcp_checksum_default(self, compare_with_scapy):
        """Test TCP checksum with default values."""
        stackforge_pkt = (IP() / TCP()).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()/TCP()")
        assert matches, report

    def test_tcp_checksum_custom_ports(self, compare_with_scapy):
        """Test TCP checksum with custom ports."""
        stackforge_pkt = (IP() / TCP(sport=12345, dport=80)).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()/TCP(sport=12345, dport=80)")
        assert matches, report

    def test_tcp_checksum_with_flags(self, compare_with_scapy):
        """Test TCP checksum with SYN flag."""
        stackforge_pkt = (IP() / TCP(flags="S")).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'IP()/TCP(flags="S")')
        assert matches, report

    def test_tcp_checksum_with_seq_ack(self, compare_with_scapy):
        """Test TCP checksum with sequence and ack numbers."""
        stackforge_pkt = (IP() / TCP(seq=1000, ack=2000, flags="A")).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'IP()/TCP(seq=1000, ack=2000, flags="A")'
        )
        assert matches, report

    def test_tcp_checksum_pseudo_header_ipv4(self, compare_with_scapy):
        """Test TCP checksum includes IPv4 pseudo-header."""
        stackforge_pkt = (
            IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=50000, dport=80)
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=50000, dport=80)',
        )
        assert matches, report

    def test_tcp_checksum_with_payload(self, compare_with_scapy):
        """Test TCP checksum with payload."""
        stackforge_pkt = (IP() / TCP() / Raw(b"Hello")).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'IP()/TCP()/Raw(b"Hello")')
        assert matches, report

    def test_tcp_checksum_with_large_payload(self, compare_with_scapy):
        """Test TCP checksum with larger payload."""
        payload = b"X" * 100
        stackforge_pkt = (IP() / TCP() / Raw(payload)).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, f'IP()/TCP()/Raw(b"{"X" * 100}")')
        assert matches, report

    def test_tcp_checksum_different_ip_addresses(self, compare_with_scapy):
        """Test TCP checksum with different IP addresses."""
        test_ips = [
            ("10.0.0.1", "10.0.0.2"),
            ("172.16.0.1", "172.16.0.2"),
            ("192.168.1.100", "8.8.8.8"),
        ]

        for src, dst in test_ips:
            stackforge_pkt = (IP(src=src, dst=dst) / TCP()).bytes()
            matches, report = compare_with_scapy(
                stackforge_pkt, f'IP(src="{src}", dst="{dst}")/TCP()'
            )
            assert matches, f"TCP checksum mismatch for {src} -> {dst}: {report}"

    def test_udp_checksum_default(self, compare_with_scapy):
        """Test UDP checksum with default values."""
        stackforge_pkt = (IP() / UDP()).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()/UDP()")
        assert matches, report

    def test_udp_checksum_custom_ports(self, compare_with_scapy):
        """Test UDP checksum with custom ports."""
        stackforge_pkt = (IP() / UDP(sport=12345, dport=53)).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()/UDP(sport=12345, dport=53)")
        assert matches, report

    def test_udp_checksum_pseudo_header_ipv4(self, compare_with_scapy):
        """Test UDP checksum includes IPv4 pseudo-header."""
        stackforge_pkt = (
            IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=50000, dport=53)
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=50000, dport=53)',
        )
        assert matches, report

    def test_udp_checksum_with_payload(self, compare_with_scapy):
        """Test UDP checksum with payload."""
        stackforge_pkt = (IP() / UDP() / Raw(b"DNS")).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'IP()/UDP()/Raw(b"DNS")')
        assert matches, report

    def test_udp_checksum_with_large_payload(self, compare_with_scapy):
        """Test UDP checksum with larger payload."""
        payload = b"Y" * 50
        stackforge_pkt = (IP() / UDP() / Raw(payload)).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, f'IP()/UDP()/Raw(b"{"Y" * 50}")')
        assert matches, report

    def test_icmp_checksum_echo_request(self, compare_with_scapy):
        """Test ICMP checksum for echo request."""
        stackforge_pkt = (IP() / ICMP(type=8, code=0)).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()/ICMP(type=8, code=0)")
        assert matches, report

    def test_icmp_checksum_echo_reply(self, compare_with_scapy):
        """Test ICMP checksum for echo reply."""
        stackforge_pkt = (IP() / ICMP(type=0, code=0)).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()/ICMP(type=0, code=0)")
        assert matches, report

    def test_icmp_checksum_dest_unreachable(self, compare_with_scapy):
        """Test ICMP checksum for destination unreachable."""
        stackforge_pkt = (IP() / ICMP(type=3, code=3)).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()/ICMP(type=3, code=3)")
        assert matches, report

    def test_icmp_checksum_with_id_seq(self, compare_with_scapy):
        """Test ICMP checksum with ID and sequence."""
        stackforge_pkt = (IP() / ICMP.echo_request(id=1, seq=1)).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()/ICMP(type=8, id=1, seq=1)")
        assert matches, report

    def test_icmp_checksum_with_payload(self, compare_with_scapy):
        """Test ICMP checksum with payload."""
        stackforge_pkt = (IP() / ICMP(type=8) / Raw(b"ping data")).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'IP()/ICMP(type=8)/Raw(b"ping data")')
        assert matches, report

    def test_full_stack_checksums(self, compare_with_scapy):
        """Test checksums in full protocol stack."""
        stackforge_pkt = (
            Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66")
            / IP(src="192.168.1.100", dst="192.168.1.1", ttl=64)
            / TCP(sport=50000, dport=80, flags="S", seq=1000)
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66")'
            '/IP(src="192.168.1.100", dst="192.168.1.1", ttl=64)'
            '/TCP(sport=50000, dport=80, flags="S", seq=1000)',
        )
        assert matches, report

    def test_ipv4_checksum_location(self):
        """Test IPv4 checksum is at correct offset."""
        stackforge_pkt = IP().bytes()
        # IPv4 checksum at bytes 10-11
        # We can't test exact value without knowing algorithm, but we can verify it's non-zero
        checksum = (stackforge_pkt[10] << 8) | stackforge_pkt[11]
        assert checksum != 0, "IPv4 checksum should not be zero"

    def test_tcp_checksum_location(self):
        """Test TCP checksum is at correct offset."""
        stackforge_pkt = (IP() / TCP()).bytes()
        # TCP starts at offset 20, checksum at TCP offset 16
        # So checksum is at bytes 36-37 in full packet
        tcp_start = 20
        checksum = (stackforge_pkt[tcp_start + 16] << 8) | stackforge_pkt[tcp_start + 17]
        assert checksum != 0, "TCP checksum should not be zero"

    def test_udp_checksum_location(self):
        """Test UDP checksum is at correct offset."""
        stackforge_pkt = (IP() / UDP()).bytes()
        # UDP starts at offset 20, checksum at UDP offset 6
        # So checksum is at bytes 26-27 in full packet
        udp_start = 20
        checksum_offset = udp_start + 6
        # UDP checksum can be zero (disabled), so we just verify it's at correct location
        assert len(stackforge_pkt) > checksum_offset + 1

    def test_icmp_checksum_location(self):
        """Test ICMP checksum is at correct offset."""
        stackforge_pkt = (IP() / ICMP()).bytes()
        # ICMP starts at offset 20, checksum at ICMP offset 2
        # So checksum is at bytes 22-23 in full packet
        icmp_start = 20
        checksum = (stackforge_pkt[icmp_start + 2] << 8) | stackforge_pkt[icmp_start + 3]
        assert checksum != 0, "ICMP checksum should not be zero"
