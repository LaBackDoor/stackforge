"""UDP layer Scapy compatibility tests."""

from stackforge import UDP


class TestUDPCompat:
    """Test UDP layer byte-for-byte compatibility with Scapy."""

    def test_udp_default(self, compare_with_scapy):
        """Test default UDP packet."""
        stackforge_pkt = UDP().bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP()")
        assert matches, report

    def test_udp_custom_ports(self, compare_with_scapy):
        """Test UDP with custom source and destination ports."""
        stackforge_pkt = UDP(sport=12345, dport=53).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(sport=12345, dport=53)")
        assert matches, report

    def test_udp_well_known_port_dns(self, compare_with_scapy):
        """Test UDP with DNS port."""
        stackforge_pkt = UDP(dport=53).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(dport=53)")
        assert matches, report

    def test_udp_well_known_port_dhcp_server(self, compare_with_scapy):
        """Test UDP with DHCP server port."""
        stackforge_pkt = UDP(sport=68, dport=67).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(sport=68, dport=67)")
        assert matches, report

    def test_udp_well_known_port_dhcp_client(self, compare_with_scapy):
        """Test UDP with DHCP client port."""
        stackforge_pkt = UDP(sport=67, dport=68).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(sport=67, dport=68)")
        assert matches, report

    def test_udp_well_known_port_ntp(self, compare_with_scapy):
        """Test UDP with NTP port."""
        stackforge_pkt = UDP(dport=123).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(dport=123)")
        assert matches, report

    def test_udp_well_known_port_snmp(self, compare_with_scapy):
        """Test UDP with SNMP port."""
        stackforge_pkt = UDP(dport=161).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(dport=161)")
        assert matches, report

    def test_udp_well_known_port_tftp(self, compare_with_scapy):
        """Test UDP with TFTP port."""
        stackforge_pkt = UDP(dport=69).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(dport=69)")
        assert matches, report

    def test_udp_well_known_port_syslog(self, compare_with_scapy):
        """Test UDP with Syslog port."""
        stackforge_pkt = UDP(dport=514).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(dport=514)")
        assert matches, report

    def test_udp_ephemeral_port(self, compare_with_scapy):
        """Test UDP with ephemeral source port."""
        stackforge_pkt = UDP(sport=50000, dport=53).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(sport=50000, dport=53)")
        assert matches, report

    def test_udp_high_port(self, compare_with_scapy):
        """Test UDP with high port numbers."""
        stackforge_pkt = UDP(sport=60000, dport=60001).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(sport=60000, dport=60001)")
        assert matches, report

    def test_udp_min_port(self, compare_with_scapy):
        """Test UDP with minimum valid port."""
        stackforge_pkt = UDP(sport=1, dport=1).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(sport=1, dport=1)")
        assert matches, report

    def test_udp_max_port(self, compare_with_scapy):
        """Test UDP with maximum port."""
        stackforge_pkt = UDP(sport=65535, dport=65535).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "UDP(sport=65535, dport=65535)")
        assert matches, report

    def test_udp_header_length(self):
        """Test UDP header length."""
        stackforge_pkt = UDP().bytes()
        assert len(stackforge_pkt) == 8, "UDP header should be 8 bytes"

    def test_udp_sport_offset(self):
        """Test source port is at correct offset."""
        stackforge_pkt = UDP(sport=12345).bytes()
        # Source port at bytes 0-1 (big-endian)
        assert stackforge_pkt[0:2] == b"\x30\x39"

    def test_udp_dport_offset(self):
        """Test destination port is at correct offset."""
        stackforge_pkt = UDP(dport=53).bytes()
        # Destination port at bytes 2-3 (big-endian)
        assert stackforge_pkt[2:4] == b"\x00\x35"

    def test_udp_len_offset(self):
        """Test length field is at correct offset."""
        stackforge_pkt = UDP().bytes()
        # Length at bytes 4-5 (big-endian), should be 8 for header only
        assert stackforge_pkt[4:6] == b"\x00\x08"

    def test_udp_length_field_value(self):
        """Test UDP length field includes header."""
        stackforge_pkt = UDP().bytes()
        length = (stackforge_pkt[4] << 8) | stackforge_pkt[5]
        assert length == 8, "UDP length should be 8 (header only)"
