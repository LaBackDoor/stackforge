"""ICMP layer Scapy compatibility tests."""

from stackforge import ICMP


class TestICMPCompat:
    """Test ICMP layer byte-for-byte compatibility with Scapy."""

    def test_icmp_default(self, compare_with_scapy):
        """Test default ICMP packet."""
        stackforge_pkt = ICMP().bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP()")
        assert matches, report

    def test_icmp_echo_request(self, compare_with_scapy):
        """Test ICMP echo request (ping)."""
        stackforge_pkt = ICMP(type=8, code=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=8, code=0)")
        assert matches, report

    def test_icmp_echo_reply(self, compare_with_scapy):
        """Test ICMP echo reply."""
        stackforge_pkt = ICMP(type=0, code=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=0, code=0)")
        assert matches, report

    def test_icmp_dest_unreachable_net(self, compare_with_scapy):
        """Test ICMP destination unreachable - network unreachable."""
        stackforge_pkt = ICMP(type=3, code=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=0)")
        assert matches, report

    def test_icmp_dest_unreachable_host(self, compare_with_scapy):
        """Test ICMP destination unreachable - host unreachable."""
        stackforge_pkt = ICMP(type=3, code=1).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=1)")
        assert matches, report

    def test_icmp_dest_unreachable_protocol(self, compare_with_scapy):
        """Test ICMP destination unreachable - protocol unreachable."""
        stackforge_pkt = ICMP(type=3, code=2).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=2)")
        assert matches, report

    def test_icmp_dest_unreachable_port(self, compare_with_scapy):
        """Test ICMP destination unreachable - port unreachable."""
        stackforge_pkt = ICMP(type=3, code=3).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=3)")
        assert matches, report

    def test_icmp_dest_unreachable_fragmentation(self, compare_with_scapy):
        """Test ICMP destination unreachable - fragmentation needed."""
        stackforge_pkt = ICMP(type=3, code=4).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=4)")
        assert matches, report

    def test_icmp_dest_unreachable_source_route(self, compare_with_scapy):
        """Test ICMP destination unreachable - source route failed."""
        stackforge_pkt = ICMP(type=3, code=5).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=5)")
        assert matches, report

    def test_icmp_dest_unreachable_net_unknown(self, compare_with_scapy):
        """Test ICMP destination unreachable - network unknown."""
        stackforge_pkt = ICMP(type=3, code=6).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=6)")
        assert matches, report

    def test_icmp_dest_unreachable_host_unknown(self, compare_with_scapy):
        """Test ICMP destination unreachable - host unknown."""
        stackforge_pkt = ICMP(type=3, code=7).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=7)")
        assert matches, report

    def test_icmp_dest_unreachable_isolated(self, compare_with_scapy):
        """Test ICMP destination unreachable - source host isolated."""
        stackforge_pkt = ICMP(type=3, code=8).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=8)")
        assert matches, report

    def test_icmp_dest_unreachable_net_prohibited(self, compare_with_scapy):
        """Test ICMP destination unreachable - network prohibited."""
        stackforge_pkt = ICMP(type=3, code=9).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=9)")
        assert matches, report

    def test_icmp_dest_unreachable_host_prohibited(self, compare_with_scapy):
        """Test ICMP destination unreachable - host prohibited."""
        stackforge_pkt = ICMP(type=3, code=10).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=10)")
        assert matches, report

    def test_icmp_dest_unreachable_tos_net(self, compare_with_scapy):
        """Test ICMP destination unreachable - TOS network unreachable."""
        stackforge_pkt = ICMP(type=3, code=11).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=11)")
        assert matches, report

    def test_icmp_dest_unreachable_tos_host(self, compare_with_scapy):
        """Test ICMP destination unreachable - TOS host unreachable."""
        stackforge_pkt = ICMP(type=3, code=12).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=12)")
        assert matches, report

    def test_icmp_dest_unreachable_prohibited(self, compare_with_scapy):
        """Test ICMP destination unreachable - communication prohibited."""
        stackforge_pkt = ICMP(type=3, code=13).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=3, code=13)")
        assert matches, report

    def test_icmp_time_exceeded_ttl(self, compare_with_scapy):
        """Test ICMP time exceeded - TTL exceeded."""
        stackforge_pkt = ICMP(type=11, code=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=11, code=0)")
        assert matches, report

    def test_icmp_time_exceeded_reassembly(self, compare_with_scapy):
        """Test ICMP time exceeded - fragment reassembly time exceeded."""
        stackforge_pkt = ICMP(type=11, code=1).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=11, code=1)")
        assert matches, report

    def test_icmp_redirect_network(self, compare_with_scapy):
        """Test ICMP redirect - for network."""
        stackforge_pkt = ICMP(type=5, code=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=5, code=0)")
        assert matches, report

    def test_icmp_redirect_host(self, compare_with_scapy):
        """Test ICMP redirect - for host."""
        stackforge_pkt = ICMP(type=5, code=1).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=5, code=1)")
        assert matches, report

    def test_icmp_redirect_tos_network(self, compare_with_scapy):
        """Test ICMP redirect - for TOS and network."""
        stackforge_pkt = ICMP(type=5, code=2).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=5, code=2)")
        assert matches, report

    def test_icmp_redirect_tos_host(self, compare_with_scapy):
        """Test ICMP redirect - for TOS and host."""
        stackforge_pkt = ICMP(type=5, code=3).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=5, code=3)")
        assert matches, report

    def test_icmp_echo_with_id(self, compare_with_scapy):
        """Test ICMP echo request with custom ID."""
        stackforge_pkt = ICMP.echo_request(id=12345, seq=1).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=8, id=12345, seq=1)")
        assert matches, report

    def test_icmp_echo_with_seq(self, compare_with_scapy):
        """Test ICMP echo request with custom sequence number."""
        stackforge_pkt = ICMP.echo_request(id=1, seq=100).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=8, id=1, seq=100)")
        assert matches, report

    def test_icmp_echo_with_id_and_seq(self, compare_with_scapy):
        """Test ICMP echo request with ID and sequence."""
        stackforge_pkt = ICMP.echo_request(id=1, seq=1).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "ICMP(type=8, id=1, seq=1)")
        assert matches, report

    def test_icmp_header_length(self):
        """Test ICMP header length."""
        stackforge_pkt = ICMP().bytes()
        assert len(stackforge_pkt) >= 8, "ICMP header should be at least 8 bytes"

    def test_icmp_type_offset(self):
        """Test ICMP type is at correct offset."""
        stackforge_pkt = ICMP(type=8).bytes()
        # Type at byte 0
        assert stackforge_pkt[0] == 8

    def test_icmp_code_offset(self):
        """Test ICMP code is at correct offset."""
        stackforge_pkt = ICMP(type=3, code=3).bytes()
        # Code at byte 1
        assert stackforge_pkt[1] == 3

    def test_icmp_id_offset(self):
        """Test ICMP ID is at correct offset."""
        stackforge_pkt = ICMP.echo_request(id=0x1234, seq=1).bytes()
        # ID at bytes 4-5 (big-endian)
        assert stackforge_pkt[4:6] == b"\x12\x34"

    def test_icmp_seq_offset(self):
        """Test ICMP sequence is at correct offset."""
        stackforge_pkt = ICMP.echo_request(id=1, seq=0x5678).bytes()
        # Sequence at bytes 6-7 (big-endian)
        assert stackforge_pkt[6:8] == b"\x56\x78"
