"""Protocol stacking Scapy compatibility tests."""

from stackforge import ARP, ICMP, IP, TCP, UDP, Ether, Raw


class TestStackingCompat:
    """Test protocol stacking byte-for-byte compatibility with Scapy."""

    def test_ether_arp(self, compare_with_scapy):
        """Test Ethernet/ARP stacking."""
        stackforge_pkt = (Ether() / ARP()).bytes()
        # Ignore Ethernet src MAC (6-11) and ARP hwsrc (22-27) and psrc (28-31)
        matches, report = compare_with_scapy(
            stackforge_pkt, "Ether()/ARP()", ignore_fields=[(6, 12), (22, 32)]
        )
        assert matches, report

    def test_ether_ip(self, compare_with_scapy):
        """Test Ethernet/IP stacking."""
        stackforge_pkt = (Ether() / IP()).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether()/IP()")
        assert matches, report

    def test_ether_ip_tcp(self, compare_with_scapy):
        """Test Ethernet/IP/TCP stacking."""
        stackforge_pkt = (Ether() / IP() / TCP()).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether()/IP()/TCP()")
        assert matches, report

    def test_ether_ip_udp(self, compare_with_scapy):
        """Test Ethernet/IP/UDP stacking."""
        stackforge_pkt = (Ether() / IP() / UDP()).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether()/IP()/UDP()")
        assert matches, report

    def test_ether_ip_icmp(self, compare_with_scapy):
        """Test Ethernet/IP/ICMP stacking."""
        stackforge_pkt = (Ether() / IP() / ICMP()).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "Ether()/IP()/ICMP()")
        assert matches, report

    def test_ip_tcp(self, compare_with_scapy):
        """Test IP/TCP stacking without Ethernet."""
        stackforge_pkt = (IP() / TCP()).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()/TCP()")
        assert matches, report

    def test_ip_udp(self, compare_with_scapy):
        """Test IP/UDP stacking without Ethernet."""
        stackforge_pkt = (IP() / UDP()).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()/UDP()")
        assert matches, report

    def test_ip_icmp(self, compare_with_scapy):
        """Test IP/ICMP stacking without Ethernet."""
        stackforge_pkt = (IP() / ICMP()).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "IP()/ICMP()")
        assert matches, report

    def test_ether_arp_with_payload(self, compare_with_scapy):
        """Test Ethernet/ARP with Raw payload."""
        stackforge_pkt = (Ether() / ARP() / Raw(b"test")).bytes()
        # Ignore Ethernet src MAC and ARP hwsrc/psrc
        matches, report = compare_with_scapy(
            stackforge_pkt, 'Ether()/ARP()/Raw(b"test")', ignore_fields=[(6, 12), (22, 32)]
        )
        assert matches, report

    def test_ether_ip_tcp_with_payload(self, compare_with_scapy):
        """Test Ethernet/IP/TCP with Raw payload."""
        stackforge_pkt = (Ether() / IP() / TCP() / Raw(b"Hello")).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'Ether()/IP()/TCP()/Raw(b"Hello")')
        assert matches, report

    def test_ether_ip_udp_with_payload(self, compare_with_scapy):
        """Test Ethernet/IP/UDP with Raw payload."""
        stackforge_pkt = (Ether() / IP() / UDP() / Raw(b"DNS Query")).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'Ether()/IP()/UDP()/Raw(b"DNS Query")')
        assert matches, report

    def test_ether_ip_icmp_with_payload(self, compare_with_scapy):
        """Test Ethernet/IP/ICMP with Raw payload."""
        stackforge_pkt = (Ether() / IP() / ICMP() / Raw(b"ping data")).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'Ether()/IP()/ICMP()/Raw(b"ping data")'
        )
        assert matches, report

    def test_ethertype_auto_binding_ipv4(self, compare_with_scapy):
        """Test automatic EtherType binding for IPv4."""
        stackforge_pkt = (Ether() / IP()).bytes()
        # EtherType should be 0x0800 for IPv4
        assert stackforge_pkt[12:14] == b"\x08\x00"

    def test_ethertype_auto_binding_arp(self, compare_with_scapy):
        """Test automatic EtherType binding for ARP."""
        stackforge_pkt = (Ether() / ARP()).bytes()
        # EtherType should be 0x0806 for ARP
        assert stackforge_pkt[12:14] == b"\x08\x06"

    def test_ip_protocol_auto_binding_tcp(self, compare_with_scapy):
        """Test automatic IP protocol binding for TCP."""
        stackforge_pkt = (IP() / TCP()).bytes()
        # Protocol should be 6 for TCP
        assert stackforge_pkt[9] == 6

    def test_ip_protocol_auto_binding_udp(self, compare_with_scapy):
        """Test automatic IP protocol binding for UDP."""
        stackforge_pkt = (IP() / UDP()).bytes()
        # Protocol should be 17 for UDP
        assert stackforge_pkt[9] == 17

    def test_ip_protocol_auto_binding_icmp(self, compare_with_scapy):
        """Test automatic IP protocol binding for ICMP."""
        stackforge_pkt = (IP() / ICMP()).bytes()
        # Protocol should be 1 for ICMP
        assert stackforge_pkt[9] == 1

    def test_ip_length_field_tcp(self, compare_with_scapy):
        """Test IP length field includes TCP header."""
        stackforge_pkt = (IP() / TCP()).bytes()
        # Total length at bytes 2-3 (big-endian)
        total_len = (stackforge_pkt[2] << 8) | stackforge_pkt[3]
        assert total_len == 40, "IP total length should be 40 (20 IP + 20 TCP)"

    def test_ip_length_field_udp(self, compare_with_scapy):
        """Test IP length field includes UDP header."""
        stackforge_pkt = (IP() / UDP()).bytes()
        # Total length at bytes 2-3 (big-endian)
        total_len = (stackforge_pkt[2] << 8) | stackforge_pkt[3]
        assert total_len == 28, "IP total length should be 28 (20 IP + 8 UDP)"

    def test_ip_length_field_with_payload(self, compare_with_scapy):
        """Test IP length field includes payload."""
        payload = b"test data"
        stackforge_pkt = (IP() / TCP() / Raw(payload)).bytes()
        # Total length at bytes 2-3 (big-endian)
        total_len = (stackforge_pkt[2] << 8) | stackforge_pkt[3]
        expected = 20 + 20 + len(payload)
        assert total_len == expected, f"IP total length should be {expected}"

    def test_udp_length_field_with_payload(self, compare_with_scapy):
        """Test UDP length field includes payload."""
        payload = b"DNS"
        stackforge_pkt = (UDP() / Raw(payload)).bytes()
        # UDP length at bytes 4-5 (big-endian)
        udp_len = (stackforge_pkt[4] << 8) | stackforge_pkt[5]
        expected = 8 + len(payload)
        assert udp_len == expected, f"UDP length should be {expected}"

    def test_http_request_simulation(self, compare_with_scapy):
        """Test simulated HTTP request."""
        stackforge_pkt = (
            Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66")
            / IP(src="192.168.1.100", dst="93.184.216.34")
            / TCP(sport=50000, dport=80, flags="PA")
            / Raw(b"GET / HTTP/1.1\r\n\r\n")
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66")'
            '/IP(src="192.168.1.100", dst="93.184.216.34")'
            '/TCP(sport=50000, dport=80, flags="PA")'
            '/Raw(b"GET / HTTP/1.1\\r\\n\\r\\n")',
        )
        assert matches, report

    def test_dns_query_simulation(self, compare_with_scapy):
        """Test simulated DNS query."""
        stackforge_pkt = (
            Ether()
            / IP(src="192.168.1.100", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / Raw(b"\x00\x01")
        ).bytes()
        # Ignore Ethernet dst and src MAC
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'Ether()/IP(src="192.168.1.100", dst="8.8.8.8")'
            '/UDP(sport=53000, dport=53)/Raw(b"\\x00\\x01")',
            ignore_fields=[(0, 12)],
        )
        assert matches, report

    def test_ping_request(self, compare_with_scapy):
        """Test ping (ICMP echo request) packet."""
        stackforge_pkt = (
            Ether()
            / IP(src="192.168.1.100", dst="8.8.8.8", ttl=64)
            / ICMP.echo_request(id=1, seq=1)
            / Raw(b"ping!")
        ).bytes()
        # Ignore Ethernet dst (0-5) and src MAC (6-11)
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'Ether()/IP(src="192.168.1.100", dst="8.8.8.8", ttl=64)'
            '/ICMP(type=8, id=1, seq=1)/Raw(b"ping!")',
            ignore_fields=[(0, 12)],
        )
        assert matches, report

    def test_arp_request_full_stack(self, compare_with_scapy):
        """Test complete ARP request packet."""
        stackforge_pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
            / ARP(op="who-has", hwsrc="00:11:22:33:44:55", psrc="192.168.1.100", pdst="192.168.1.1")
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")'
            '/ARP(op="who-has", hwsrc="00:11:22:33:44:55",'
            ' psrc="192.168.1.100", pdst="192.168.1.1")',
        )
        assert matches, report

    def test_tcp_syn_full_stack(self, compare_with_scapy):
        """Test complete TCP SYN packet."""
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

    def test_udp_dhcp_discover(self, compare_with_scapy):
        """Test DHCP discover simulation."""
        stackforge_pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / Raw(b"\x01\x01\x06\x00")
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")'
            '/IP(src="0.0.0.0", dst="255.255.255.255")'
            '/UDP(sport=68, dport=67)/Raw(b"\\x01\\x01\\x06\\x00")',
        )
        assert matches, report

    def test_multiple_layers_length_calculation(self):
        """Test length calculation across multiple layers."""
        payload = b"test payload data"
        stackforge_pkt = (Ether() / IP() / TCP() / Raw(payload)).bytes()

        # Ethernet header: 14 bytes
        # IP header: 20 bytes (starts at offset 14)
        # TCP header: 20 bytes (starts at offset 34)
        # Payload: len(payload) bytes (starts at offset 54)

        total_len = len(stackforge_pkt)
        expected = 14 + 20 + 20 + len(payload)
        assert total_len == expected, f"Total length should be {expected}"

    def test_nested_stacking_order(self):
        """Test that layers are stacked in correct order."""
        stackforge_pkt = (Ether() / IP() / TCP()).bytes()

        # Verify Ethernet header comes first (dst MAC at offset 0)
        # Verify IP header comes second (version/IHL at offset 14)
        assert (stackforge_pkt[14] >> 4) == 4, "IP version should be 4"

        # Verify TCP header comes third (sport at offset 34)
        # TCP should start after Ethernet (14) + IP (20) = 34

    def test_raw_payload_at_end(self):
        """Test Raw payload is placed at the end."""
        payload = b"end payload"
        stackforge_pkt = (Ether() / IP() / UDP() / Raw(payload)).bytes()

        # Payload should be at the end
        assert stackforge_pkt[-len(payload) :] == payload

    def test_fragmented_packet_simulation(self, compare_with_scapy):
        """Test fragmented packet with MF flag and offset."""
        stackforge_pkt = (
            IP(src="192.168.1.100", dst="192.168.1.1", flags="MF", frag=0, id=12345) / TCP()
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'IP(src="192.168.1.100", dst="192.168.1.1", flags="MF", frag=0, id=12345)/TCP()',
        )
        assert matches, report

    def test_large_payload_stacking(self, compare_with_scapy):
        """Test stacking with larger payload."""
        payload = b"X" * 100
        stackforge_pkt = (IP() / TCP() / Raw(payload)).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, f'IP()/TCP()/Raw(b"{"X" * 100}")')
        assert matches, report

    def test_multiple_small_packets(self, compare_with_scapy):
        """Test multiple different small stacked packets."""
        test_cases = [
            (Ether() / IP(), "Ether()/IP()"),
            (Ether() / ARP(), "Ether()/ARP()"),
            (IP() / TCP(), "IP()/TCP()"),
            (IP() / UDP(), "IP()/UDP()"),
            (IP() / ICMP(), "IP()/ICMP()"),
        ]

        for stackforge_builder, scapy_expr in test_cases:
            stackforge_pkt = stackforge_builder.bytes()
            # ARP tests need to ignore system-specific MAC/IP addresses
            ignore = [(6, 12), (22, 32)] if "ARP" in scapy_expr else None
            matches, report = compare_with_scapy(stackforge_pkt, scapy_expr, ignore_fields=ignore)
            assert matches, f"{scapy_expr} mismatch: {report}"

    def test_ether_ip_tcp_various_flags(self, compare_with_scapy):
        """Test Ethernet/IP/TCP with various flag combinations."""
        flag_combinations = ["S", "SA", "A", "PA", "FA", "R", "RA"]

        for flags in flag_combinations:
            stackforge_pkt = (Ether() / IP() / TCP(flags=flags)).bytes()
            matches, report = compare_with_scapy(
                stackforge_pkt, f'Ether()/IP()/TCP(flags="{flags}")'
            )
            assert matches, f"Flags {flags} mismatch: {report}"

    def test_ip_tcp_various_ports(self, compare_with_scapy):
        """Test IP/TCP with various well-known ports."""
        ports = [80, 443, 22, 21, 25, 53]

        for port in ports:
            stackforge_pkt = (IP() / TCP(dport=port)).bytes()
            matches, report = compare_with_scapy(stackforge_pkt, f"IP()/TCP(dport={port})")
            assert matches, f"Port {port} mismatch: {report}"

    def test_ip_udp_various_ports(self, compare_with_scapy):
        """Test IP/UDP with various well-known ports."""
        ports = [53, 67, 68, 123, 161, 514]

        for port in ports:
            stackforge_pkt = (IP() / UDP(dport=port)).bytes()
            matches, report = compare_with_scapy(stackforge_pkt, f"IP()/UDP(dport={port})")
            assert matches, f"Port {port} mismatch: {report}"

    def test_ip_icmp_various_types(self, compare_with_scapy):
        """Test IP/ICMP with various message types."""
        icmp_types = [(8, 0), (0, 0), (3, 3), (11, 0)]

        for type_val, code_val in icmp_types:
            stackforge_pkt = (IP() / ICMP(type=type_val, code=code_val)).bytes()
            matches, report = compare_with_scapy(
                stackforge_pkt, f"IP()/ICMP(type={type_val}, code={code_val})"
            )
            assert matches, f"Type {type_val} Code {code_val} mismatch: {report}"

    def test_ether_ip_with_ttl_variations(self, compare_with_scapy):
        """Test Ethernet/IP with various TTL values."""
        ttl_values = [1, 32, 64, 128, 255]

        for ttl in ttl_values:
            stackforge_pkt = (Ether() / IP(ttl=ttl)).bytes()
            matches, report = compare_with_scapy(stackforge_pkt, f"Ether()/IP(ttl={ttl})")
            assert matches, f"TTL {ttl} mismatch: {report}"

    def test_tcp_with_various_seq_numbers(self, compare_with_scapy):
        """Test TCP with various sequence numbers."""
        seq_values = [0, 1000, 1000000, 2147483647, 4294967295]

        for seq in seq_values:
            stackforge_pkt = (IP() / TCP(seq=seq)).bytes()
            matches, report = compare_with_scapy(stackforge_pkt, f"IP()/TCP(seq={seq})")
            assert matches, f"Seq {seq} mismatch: {report}"

    def test_udp_with_various_payloads(self, compare_with_scapy):
        """Test UDP with various payload sizes."""
        payloads = [b"", b"a", b"test", b"X" * 50, b"X" * 100]

        for payload in payloads:
            stackforge_pkt = (IP() / UDP() / Raw(payload)).bytes()
            matches, report = compare_with_scapy(
                stackforge_pkt,
                "IP()/UDP()/Raw(b\""
                f"{payload.decode() if len(payload) < 20 else 'X' * len(payload)}"
                "\")",
            )
            assert matches, f"Payload length {len(payload)} mismatch: {report}"
