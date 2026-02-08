"""TCP layer Scapy compatibility tests."""

from stackforge import TCP


class TestTCPCompat:
    """Test TCP layer byte-for-byte compatibility with Scapy."""

    def test_tcp_default(self, compare_with_scapy):
        """Test default TCP packet."""
        stackforge_pkt = TCP().bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP()")
        assert matches, report

    def test_tcp_custom_ports(self, compare_with_scapy):
        """Test TCP with custom source and destination ports."""
        stackforge_pkt = TCP(sport=12345, dport=80).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(sport=12345, dport=80)")
        assert matches, report

    def test_tcp_flag_syn(self, compare_with_scapy):
        """Test TCP SYN packet."""
        stackforge_pkt = TCP(flags="S").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="S")')
        assert matches, report

    def test_tcp_flag_synack(self, compare_with_scapy):
        """Test TCP SYN-ACK packet."""
        stackforge_pkt = TCP(flags="SA").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="SA")')
        assert matches, report

    def test_tcp_flag_ack(self, compare_with_scapy):
        """Test TCP ACK packet."""
        stackforge_pkt = TCP(flags="A").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="A")')
        assert matches, report

    def test_tcp_flag_fin(self, compare_with_scapy):
        """Test TCP FIN packet."""
        stackforge_pkt = TCP(flags="F").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="F")')
        assert matches, report

    def test_tcp_flag_finack(self, compare_with_scapy):
        """Test TCP FIN-ACK packet."""
        stackforge_pkt = TCP(flags="FA").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="FA")')
        assert matches, report

    def test_tcp_flag_rst(self, compare_with_scapy):
        """Test TCP RST packet."""
        stackforge_pkt = TCP(flags="R").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="R")')
        assert matches, report

    def test_tcp_flag_rstack(self, compare_with_scapy):
        """Test TCP RST-ACK packet."""
        stackforge_pkt = TCP(flags="RA").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="RA")')
        assert matches, report

    def test_tcp_flag_psh(self, compare_with_scapy):
        """Test TCP PSH packet."""
        stackforge_pkt = TCP(flags="P").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="P")')
        assert matches, report

    def test_tcp_flag_pshack(self, compare_with_scapy):
        """Test TCP PSH-ACK packet."""
        stackforge_pkt = TCP(flags="PA").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="PA")')
        assert matches, report

    def test_tcp_flag_urg(self, compare_with_scapy):
        """Test TCP URG packet."""
        stackforge_pkt = TCP(flags="U").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="U")')
        assert matches, report

    def test_tcp_flag_urgack(self, compare_with_scapy):
        """Test TCP URG-ACK packet."""
        stackforge_pkt = TCP(flags="UA").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="UA")')
        assert matches, report

    def test_tcp_flag_synfinack(self, compare_with_scapy):
        """Test TCP with SYN-FIN-ACK flags (unusual but valid)."""
        stackforge_pkt = TCP(flags="SFA").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="SFA")')
        assert matches, report

    def test_tcp_flag_all(self, compare_with_scapy):
        """Test TCP with all flags set."""
        stackforge_pkt = TCP(flags="FSRPAUEC").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="FSRPAUEC")')
        assert matches, report

    def test_tcp_flag_none(self, compare_with_scapy):
        """Test TCP with no flags."""
        stackforge_pkt = TCP(flags=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(flags=0)")
        assert matches, report

    def test_tcp_seq_default(self, compare_with_scapy):
        """Test TCP with default sequence number."""
        stackforge_pkt = TCP(seq=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(seq=0)")
        assert matches, report

    def test_tcp_seq_custom(self, compare_with_scapy):
        """Test TCP with custom sequence number."""
        stackforge_pkt = TCP(seq=1000000).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(seq=1000000)")
        assert matches, report

    def test_tcp_seq_max(self, compare_with_scapy):
        """Test TCP with maximum sequence number."""
        stackforge_pkt = TCP(seq=4294967295).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(seq=4294967295)")
        assert matches, report

    def test_tcp_ack_default(self, compare_with_scapy):
        """Test TCP with default ack number."""
        stackforge_pkt = TCP(ack=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(ack=0)")
        assert matches, report

    def test_tcp_ack_custom(self, compare_with_scapy):
        """Test TCP with custom ack number."""
        stackforge_pkt = TCP(ack=2000000).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(ack=2000000)")
        assert matches, report

    def test_tcp_ack_max(self, compare_with_scapy):
        """Test TCP with maximum ack number."""
        stackforge_pkt = TCP(ack=4294967295).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(ack=4294967295)")
        assert matches, report

    def test_tcp_window_default(self, compare_with_scapy):
        """Test TCP with default window size."""
        stackforge_pkt = TCP(window=8192).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(window=8192)")
        assert matches, report

    def test_tcp_window_zero(self, compare_with_scapy):
        """Test TCP with zero window size."""
        stackforge_pkt = TCP(window=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(window=0)")
        assert matches, report

    def test_tcp_window_max(self, compare_with_scapy):
        """Test TCP with maximum window size."""
        stackforge_pkt = TCP(window=65535).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(window=65535)")
        assert matches, report

    def test_tcp_urgent_pointer_zero(self, compare_with_scapy):
        """Test TCP with zero urgent pointer."""
        stackforge_pkt = TCP(urgptr=0).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(urgptr=0)")
        assert matches, report

    def test_tcp_urgent_pointer_custom(self, compare_with_scapy):
        """Test TCP with custom urgent pointer."""
        stackforge_pkt = TCP(urgptr=100).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(urgptr=100)")
        assert matches, report

    def test_tcp_urgent_pointer_max(self, compare_with_scapy):
        """Test TCP with maximum urgent pointer."""
        stackforge_pkt = TCP(urgptr=65535).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(urgptr=65535)")
        assert matches, report

    def test_tcp_well_known_port_http(self, compare_with_scapy):
        """Test TCP with HTTP port."""
        stackforge_pkt = TCP(dport=80).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(dport=80)")
        assert matches, report

    def test_tcp_well_known_port_https(self, compare_with_scapy):
        """Test TCP with HTTPS port."""
        stackforge_pkt = TCP(dport=443).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(dport=443)")
        assert matches, report

    def test_tcp_well_known_port_ssh(self, compare_with_scapy):
        """Test TCP with SSH port."""
        stackforge_pkt = TCP(dport=22).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(dport=22)")
        assert matches, report

    def test_tcp_well_known_port_ftp(self, compare_with_scapy):
        """Test TCP with FTP port."""
        stackforge_pkt = TCP(dport=21).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(dport=21)")
        assert matches, report

    def test_tcp_well_known_port_smtp(self, compare_with_scapy):
        """Test TCP with SMTP port."""
        stackforge_pkt = TCP(dport=25).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(dport=25)")
        assert matches, report

    def test_tcp_well_known_port_dns(self, compare_with_scapy):
        """Test TCP with DNS port."""
        stackforge_pkt = TCP(dport=53).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(dport=53)")
        assert matches, report

    def test_tcp_high_port(self, compare_with_scapy):
        """Test TCP with high ephemeral port."""
        stackforge_pkt = TCP(sport=60000, dport=80).bytes()
        matches, report = compare_with_scapy(stackforge_pkt, "TCP(sport=60000, dport=80)")
        assert matches, report

    def test_tcp_header_length(self):
        """Test TCP header length without options."""
        stackforge_pkt = TCP().bytes()
        assert len(stackforge_pkt) == 20, "TCP header should be 20 bytes"

    def test_tcp_sport_offset(self):
        """Test source port is at correct offset."""
        stackforge_pkt = TCP(sport=12345).bytes()
        # Source port at bytes 0-1 (big-endian)
        assert stackforge_pkt[0:2] == b"\x30\x39"

    def test_tcp_dport_offset(self):
        """Test destination port is at correct offset."""
        stackforge_pkt = TCP(dport=80).bytes()
        # Destination port at bytes 2-3 (big-endian)
        assert stackforge_pkt[2:4] == b"\x00\x50"

    def test_tcp_seq_offset(self):
        """Test sequence number is at correct offset."""
        stackforge_pkt = TCP(seq=0x12345678).bytes()
        # Sequence number at bytes 4-7 (big-endian)
        assert stackforge_pkt[4:8] == b"\x12\x34\x56\x78"

    def test_tcp_ack_offset(self):
        """Test acknowledgment number is at correct offset."""
        stackforge_pkt = TCP(ack=0x87654321).bytes()
        # Ack number at bytes 8-11 (big-endian)
        assert stackforge_pkt[8:12] == b"\x87\x65\x43\x21"

    def test_tcp_data_offset_field(self):
        """Test TCP data offset field is correct."""
        stackforge_pkt = TCP().bytes()
        # Data offset is in upper 4 bits of byte 12 (should be 5 for no options)
        assert (stackforge_pkt[12] >> 4) == 5, "Data offset should be 5 (20 bytes)"

    def test_tcp_flags_offset(self):
        """Test TCP flags are at correct offset."""
        stackforge_pkt = TCP(flags="S").bytes()
        # Flags at byte 13, SYN is bit 1 (0x02)
        assert (stackforge_pkt[13] & 0x02) == 0x02

    def test_tcp_window_offset(self):
        """Test window size is at correct offset."""
        stackforge_pkt = TCP(window=1234).bytes()
        # Window at bytes 14-15 (big-endian)
        assert stackforge_pkt[14:16] == b"\x04\xd2"

    def test_tcp_urgptr_offset(self):
        """Test urgent pointer is at correct offset."""
        stackforge_pkt = TCP(urgptr=100).bytes()
        # Urgent pointer at bytes 18-19 (big-endian)
        assert stackforge_pkt[18:20] == b"\x00\x64"

    def test_tcp_combined_fields(self, compare_with_scapy):
        """Test TCP with multiple fields set."""
        stackforge_pkt = TCP(
            sport=12345,
            dport=80,
            flags="SA",
            seq=1000000,
            ack=2000000,
            window=8192,
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'TCP(sport=12345, dport=80, flags="SA", seq=1000000, ack=2000000, window=8192)',
        )
        assert matches, report

    def test_tcp_handshake_syn(self, compare_with_scapy):
        """Test TCP handshake SYN packet."""
        stackforge_pkt = TCP(sport=50000, dport=80, flags="S", seq=1000).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'TCP(sport=50000, dport=80, flags="S", seq=1000)'
        )
        assert matches, report

    def test_tcp_handshake_synack(self, compare_with_scapy):
        """Test TCP handshake SYN-ACK packet."""
        stackforge_pkt = TCP(sport=80, dport=50000, flags="SA", seq=2000, ack=1001).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'TCP(sport=80, dport=50000, flags="SA", seq=2000, ack=1001)'
        )
        assert matches, report

    def test_tcp_handshake_ack(self, compare_with_scapy):
        """Test TCP handshake final ACK packet."""
        stackforge_pkt = TCP(sport=50000, dport=80, flags="A", seq=1001, ack=2001).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'TCP(sport=50000, dport=80, flags="A", seq=1001, ack=2001)'
        )
        assert matches, report

    def test_tcp_flag_ece(self, compare_with_scapy):
        """Test TCP ECE (ECN-Echo) flag."""
        stackforge_pkt = TCP(flags="E").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="E")')
        assert matches, report

    def test_tcp_flag_cwr(self, compare_with_scapy):
        """Test TCP CWR (Congestion Window Reduced) flag."""
        stackforge_pkt = TCP(flags="C").bytes()
        matches, report = compare_with_scapy(stackforge_pkt, 'TCP(flags="C")')
        assert matches, report
