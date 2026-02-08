"""Edge case and round-trip compatibility tests."""

from stackforge import ARP, IP, TCP, UDP, Ether, Packet, Raw


class TestEdgeCasesCompat:
    """Test edge cases and boundary conditions."""

    def test_zero_length_tcp_payload(self, compare_with_scapy):
        """Test TCP packet with zero-length payload."""
        stackforge_pkt = (Ether() / IP() / TCP()).bytes()
        # May need to ignore checksums initially
        matches, report = compare_with_scapy(
            stackforge_pkt,
            "Ether()/IP()/TCP()",
            ignore_fields=[(50, 52)],  # TCP checksum
        )
        assert matches, report

    def test_zero_length_udp_payload(self, compare_with_scapy):
        """Test UDP packet with zero-length payload."""
        stackforge_pkt = (Ether() / IP() / UDP()).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            "Ether()/IP()/UDP()",
            ignore_fields=[(40, 42)],  # UDP checksum
        )
        assert matches, report

    def test_small_payload(self, compare_with_scapy):
        """Test packet with small payload."""
        stackforge_pkt = (Ether() / IP() / TCP() / Raw(load=b"X")).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'Ether()/IP()/TCP()/Raw(load=b"X")',
            ignore_fields=[(50, 52)],  # TCP checksum
        )
        assert matches, report

    def test_medium_payload(self, compare_with_scapy):
        """Test packet with medium-sized payload."""
        payload = b"Hello, World! This is a test payload."
        stackforge_pkt = (Ether() / IP() / TCP() / Raw(load=payload)).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            f"Ether()/IP()/TCP()/Raw(load={payload!r})",
            ignore_fields=[(50, 52)],  # TCP checksum
        )
        assert matches, report

    def test_round_trip_build_parse_bytes(self):
        """Test build → parse → bytes produces same output."""
        # Build original packet
        original_stack = Ether() / IP(dst="8.8.8.8") / TCP(dport=443)
        original_bytes = original_stack.bytes()

        # Parse it
        parsed_pkt = Packet(original_bytes)
        parsed_pkt.parse()

        # Get bytes back
        result_bytes = parsed_pkt.bytes()

        assert result_bytes == original_bytes, "Round-trip should preserve bytes"

    def test_ethernet_minimum_frame(self, compare_with_scapy):
        """Test minimum Ethernet frame."""
        stackforge_pkt = Ether().bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether()")
        assert matches, report

    def test_max_ttl(self, compare_with_scapy):
        """Test IPv4 with maximum TTL."""
        stackforge_pkt = (Ether() / IP(ttl=255)).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether()/IP(ttl=255)")
        assert matches, report

    def test_max_tcp_window(self, compare_with_scapy):
        """Test TCP with maximum window size."""
        stackforge_pkt = (Ether() / IP() / TCP(window=65535)).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            "Ether()/IP()/TCP(window=65535)",
            ignore_fields=[(50, 52)],  # TCP checksum
        )
        assert matches, report

    def test_max_tcp_seq(self, compare_with_scapy):
        """Test TCP with maximum sequence number."""
        stackforge_pkt = (Ether() / IP() / TCP(seq=0xFFFFFFFF)).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            "Ether()/IP()/TCP(seq=0xffffffff)",
            ignore_fields=[(50, 52)],  # TCP checksum
        )
        assert matches, report

    def test_max_tcp_ack(self, compare_with_scapy):
        """Test TCP with maximum acknowledgment number."""
        stackforge_pkt = (Ether() / IP() / TCP(ack=0xFFFFFFFF)).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            "Ether()/IP()/TCP(ack=0xffffffff)",
            ignore_fields=[(50, 52)],  # TCP checksum
        )
        assert matches, report

    def test_all_tcp_flags(self, compare_with_scapy):
        """Test TCP with all flags set."""
        stackforge_pkt = (Ether() / IP() / TCP(flags="FSRPAUEC")).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'Ether()/IP()/TCP(flags="FSRPAUEC")',
            ignore_fields=[(50, 52)],  # TCP checksum
        )
        assert matches, report

    def test_binary_payload_nulls(self, compare_with_scapy):
        """Test packet with null bytes in payload."""
        payload = b"\x00\x00\x00\x00"
        stackforge_pkt = (Ether() / IP() / UDP() / Raw(load=payload)).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            f"Ether()/IP()/UDP()/Raw(load={payload!r})",
            ignore_fields=[(40, 42)],  # UDP checksum
        )
        assert matches, report

    def test_binary_payload_all_ones(self, compare_with_scapy):
        """Test packet with all-ones bytes in payload."""
        payload = b"\xff\xff\xff\xff"
        stackforge_pkt = (Ether() / IP() / UDP() / Raw(load=payload)).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            f"Ether()/IP()/UDP()/Raw(load={payload!r})",
            ignore_fields=[(40, 42)],  # UDP checksum
        )
        assert matches, report

    def test_payload_with_printable_chars(self, compare_with_scapy):
        """Test packet with printable ASCII payload."""
        payload = b"ABCDEFGHIJKLMNOP"
        stackforge_pkt = (Ether() / IP() / TCP() / Raw(load=payload)).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            f"Ether()/IP()/TCP()/Raw(load={payload!r})",
            ignore_fields=[(50, 52)],  # TCP checksum
        )
        assert matches, report

    def test_sequential_port_numbers(self, compare_with_scapy):
        """Test TCP with sequential port numbers."""
        for port in range(1000, 1005):
            stackforge_pkt = (Ether() / IP() / TCP(dport=port)).bytes()
            matches, report = compare_with_scapy(
                stackforge_pkt,
                f"Ether()/IP()/TCP(dport={port})",
                ignore_fields=[(50, 52)],  # TCP checksum
            )
            assert matches, f"Port {port} mismatch: {report}"

    def test_well_known_tcp_ports(self, compare_with_scapy):
        """Test TCP with well-known port numbers."""
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]
        for port in ports:
            stackforge_pkt = (Ether() / IP() / TCP(dport=port)).bytes()
            matches, report = compare_with_scapy(
                stackforge_pkt,
                f"Ether()/IP()/TCP(dport={port})",
                ignore_fields=[(50, 52)],  # TCP checksum
            )
            assert matches, f"Port {port} mismatch: {report}"

    def test_ephemeral_ports(self, compare_with_scapy):
        """Test TCP with ephemeral port numbers."""
        ports = [49152, 55000, 60000, 65535]
        for port in ports:
            stackforge_pkt = (Ether() / IP() / TCP(sport=port)).bytes()
            matches, report = compare_with_scapy(
                stackforge_pkt,
                f"Ether()/IP()/TCP(sport={port})",
                ignore_fields=[(50, 52)],  # TCP checksum
            )
            assert matches, f"Port {port} mismatch: {report}"

    def test_ip_id_boundary_values(self, compare_with_scapy):
        """Test IPv4 with boundary ID values."""
        ids = [0, 1, 0x7FFF, 0xFFFF]
        for ip_id in ids:
            stackforge_pkt = (Ether() / IP(id=ip_id)).bytes()
            matches, report = compare_with_scapy(stackforge_pkt, f"Ether()/IP(id={ip_id})")
            assert matches, f"IP ID {ip_id} mismatch: {report}"

    def test_arp_with_ethernet(self, compare_with_scapy):
        """Test complete Ether/ARP packet."""
        stackforge_pkt = (Ether() / ARP(pdst="192.168.1.1")).bytes()
        # Ignore Ethernet src and ARP hwsrc/psrc
        matches, report = compare_with_scapy(
            stackforge_pkt, 'Ether()/ARP(pdst="192.168.1.1")', ignore_fields=[(6, 12), (22, 32)]
        )
        assert matches, report
