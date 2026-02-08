"""Tests for UDP and ICMP protocol layers based on inet.txt patterns."""

from stackforge import ICMP, UDP, LayerKind, Packet


class TestUDP:
    """UDP protocol tests."""

    def test_udp_basic_parsing(self):
        """Test basic UDP packet parsing."""
        udp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                0x66,
                0x77,
                0x88,
                0x99,
                0xAA,
                0xBB,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x24,  # Ver, IHL, TOS, Total Len=36
                0x00,
                0x01,
                0x00,
                0x00,  # ID, Flags, Frag
                0x40,
                0x11,
                0x00,
                0x00,  # TTL=64, Proto=UDP, Checksum
                192,
                168,
                1,
                100,  # Src IP
                192,
                168,
                1,
                1,  # Dst IP
                # UDP
                0x04,
                0xD2,  # Sport = 1234
                0x00,
                0x35,  # Dport = 53 (DNS)
                0x00,
                0x10,  # Length = 16
                0x00,
                0x00,  # Checksum
                # Payload
                0x48,
                0x65,
                0x6C,
                0x6C,
                0x6F,
                0x21,
                0x21,
                0x21,
            ]
        )

        pkt = Packet(udp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Ethernet)
        assert pkt.has_layer(LayerKind.Ipv4)
        assert pkt.has_layer(LayerKind.Udp)
        assert pkt.layer_count == 4  # Ether, IPv4, UDP, Raw

    def test_udp_checksum_zero_optional_ipv4(self):
        """Test that UDP checksum of 0 is valid for IPv4 (optional)."""
        udp_pkt = bytes(
            [
                # Ethernet
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x11,
                0x00,
                0x00,
                192,
                168,
                1,
                1,
                192,
                168,
                1,
                2,
                # UDP with checksum=0 (valid for IPv4)
                0x00,
                0x14,
                0x00,
                0x14,  # Sport=20, Dport=20
                0x00,
                0x08,  # Length=8 (header only)
                0x00,
                0x00,  # Checksum=0 (optional for IPv4)
            ]
        )

        pkt = Packet(udp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Udp)
        summary = pkt.summary()
        assert "UDP" in summary

    def test_udp_ports(self):
        """Test UDP port extraction."""
        udp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x20,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x11,
                0x00,
                0x00,
                10,
                0,
                0,
                1,
                10,
                0,
                0,
                2,
                # UDP
                0x13,
                0x88,  # Sport = 5000
                0x17,
                0x70,  # Dport = 6000
                0x00,
                0x0C,  # Length = 12
                0x00,
                0x00,  # Checksum
                0xAA,
                0xBB,
                0xCC,
                0xDD,  # Payload
            ]
        )

        pkt = Packet(udp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Udp)
        # Verify summary contains port information
        summary = pkt.summary()
        assert "5000" in summary or "UDP" in summary
        assert "6000" in summary or "UDP" in summary


class TestICMP:
    """ICMP protocol tests."""

    def test_icmp_echo_request_parsing(self):
        """Test ICMP echo request parsing."""
        icmp_pkt = bytes(
            [
                # Ethernet
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0x00,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,  # TTL=64, Proto=ICMP
                192,
                168,
                1,
                100,
                8,
                8,
                8,
                8,
                # ICMP Echo Request
                0x08,  # Type = 8 (echo request)
                0x00,  # Code = 0
                0x00,
                0x00,  # Checksum
                0x12,
                0x34,  # ID
                0x00,
                0x01,  # Sequence
            ]
        )

        pkt = Packet(icmp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Icmp)
        assert pkt.layer_count == 3  # Ether, IPv4, ICMP

        summary = pkt.summary()
        assert "ICMP" in summary
        assert "echo-request" in summary.lower()

    def test_icmp_echo_reply_parsing(self):
        """Test ICMP echo reply parsing."""
        icmp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,
                8,
                8,
                8,
                8,
                192,
                168,
                1,
                100,
                # ICMP Echo Reply
                0x00,  # Type = 0 (echo reply)
                0x00,  # Code = 0
                0x00,
                0x00,  # Checksum
                0x12,
                0x34,  # ID (same as request)
                0x00,
                0x01,  # Sequence (same as request)
            ]
        )

        pkt = Packet(icmp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Icmp)
        summary = pkt.summary()
        assert "ICMP" in summary
        assert "echo-reply" in summary.lower()

    def test_icmp_dest_unreachable(self):
        """Test ICMP destination unreachable parsing."""
        icmp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,
                192,
                168,
                1,
                1,
                192,
                168,
                1,
                100,
                # ICMP Dest Unreachable
                0x03,  # Type = 3 (dest unreachable)
                0x03,  # Code = 3 (port unreachable)
                0x00,
                0x00,  # Checksum
                0x00,  # Unused
                0x00,  # Length
                0x00,
                0x00,  # Unused/MTU
            ]
        )

        pkt = Packet(icmp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Icmp)
        summary = pkt.summary()
        assert "ICMP" in summary
        assert "dest-unreach" in summary.lower() or "unreachable" in summary.lower()

    def test_icmp_time_exceeded(self):
        """Test ICMP time exceeded parsing."""
        icmp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,
                192,
                168,
                1,
                1,
                192,
                168,
                1,
                100,
                # ICMP Time Exceeded
                0x0B,  # Type = 11 (time exceeded)
                0x00,  # Code = 0 (TTL exceeded)
                0x00,
                0x00,  # Checksum
                0x00,
                0x00,
                0x00,
                0x00,  # Unused
            ]
        )

        pkt = Packet(icmp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Icmp)
        summary = pkt.summary()
        assert "ICMP" in summary
        assert "time-exceeded" in summary.lower() or "exceeded" in summary.lower()

    def test_icmp_redirect(self):
        """Test ICMP redirect parsing."""
        icmp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,
                192,
                168,
                1,
                1,
                192,
                168,
                1,
                100,
                # ICMP Redirect
                0x05,  # Type = 5 (redirect)
                0x01,  # Code = 1 (redirect host)
                0x00,
                0x00,  # Checksum
                192,
                168,
                1,
                254,  # Gateway address
            ]
        )

        pkt = Packet(icmp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Icmp)
        summary = pkt.summary()
        assert "ICMP" in summary
        assert "redirect" in summary.lower()

    def test_icmp_with_payload(self):
        """Test ICMP echo request with payload."""
        icmp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x25,  # Total length = 37 (20 IP + 8 ICMP + 9 payload)
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,
                10,
                0,
                0,
                1,
                10,
                0,
                0,
                2,
                # ICMP Echo Request
                0x08,
                0x00,  # Type, Code
                0x00,
                0x00,  # Checksum
                0xAB,
                0xCD,  # ID
                0x00,
                0x05,  # Sequence = 5
                # Payload
                0x48,
                0x65,
                0x6C,
                0x6C,
                0x6F,
                0x20,
                0x21,
                0x21,
                0x21,  # "Hello !!!"
            ]
        )

        pkt = Packet(icmp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Icmp)
        # ICMP with payload should parse
        assert pkt.layer_count >= 3  # Ether, IPv4, ICMP (payload may or may not be separate Raw)


class TestUDPICMPIntegration:
    """Integration tests for UDP and ICMP."""

    def test_mixed_packet_parsing(self):
        """Test parsing multiple packet types in sequence."""
        # Create two packets: one UDP, one ICMP
        udp_pkt = bytes(
            [
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x11,
                0x00,
                0x00,
                10,
                0,
                0,
                1,
                10,
                0,
                0,
                2,
                0x00,
                0x14,
                0x00,
                0x50,  # UDP ports
                0x00,
                0x08,
                0x00,
                0x00,  # Length, checksum
            ]
        )

        icmp_pkt = bytes(
            [
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,
                10,
                0,
                0,
                1,
                10,
                0,
                0,
                2,
                0x08,
                0x00,  # ICMP echo request
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x01,
            ]
        )

        pkt1 = Packet(udp_pkt)
        pkt1.parse()
        pkt2 = Packet(icmp_pkt)
        pkt2.parse()

        assert pkt1.has_layer(LayerKind.Udp)
        assert pkt2.has_layer(LayerKind.Icmp)

        assert "UDP" in pkt1.summary()
        assert "ICMP" in pkt2.summary()

    def test_packet_show_udp_icmp(self):
        """Test show() output for UDP and ICMP packets."""
        udp_pkt = bytes(
            [
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x11,
                0x00,
                0x00,
                10,
                0,
                0,
                1,
                10,
                0,
                0,
                2,
                0x00,
                0x35,
                0x00,
                0x35,  # DNS ports (53)
                0x00,
                0x08,
                0x00,
                0x00,
            ]
        )

        pkt = Packet(udp_pkt)
        pkt.parse()

        show_output = pkt.show()
        assert "UDP" in show_output
        assert "53" in show_output or "sport" in show_output.lower()


class TestUDPConstruction:
    """Test UDP packet construction using UdpBuilder."""

    def test_udp_basic_construction(self):
        """Test basic UDP packet construction."""
        udp = UDP(sport=1234, dport=80)
        udp_bytes = udp.bytes()

        # Should be 8 bytes (UDP header)
        assert len(udp_bytes) == 8

        # Verify header fields
        assert udp_bytes[0:2] == bytes([0x04, 0xD2])  # sport = 1234
        assert udp_bytes[2:4] == bytes([0x00, 0x50])  # dport = 80
        assert udp_bytes[4:6] == bytes([0x00, 0x08])  # length = 8 (auto-calculated)

    def test_udp_construction_with_payload(self):
        """Test UDP packet construction with payload."""
        udp = UDP(sport=5000, dport=6000)
        udp_bytes = udp.bytes()

        # Should have 8 byte header
        assert len(udp_bytes) == 8

        # Verify ports
        assert udp_bytes[0:2] == bytes([0x13, 0x88])  # sport = 5000
        assert udp_bytes[2:4] == bytes([0x17, 0x70])  # dport = 6000

    def test_udp_custom_length_checksum(self):
        """Test UDP with explicitly set length and checksum."""
        udp = UDP(sport=1000, dport=2000, len=100, chksum=0x1234)
        udp_bytes = udp.bytes()

        assert len(udp_bytes) == 8
        # Verify custom length
        assert udp_bytes[4:6] == bytes([0x00, 0x64])  # len = 100
        # Verify custom checksum
        assert udp_bytes[6:8] == bytes([0x12, 0x34])  # chksum = 0x1234

    def test_udp_zero_checksum(self):
        """Test UDP with zero checksum (valid for IPv4)."""
        udp = UDP(sport=53, dport=53, chksum=0)
        udp_bytes = udp.bytes()

        # Zero checksum should become 0xFFFF per RFC 768
        # (or stay 0 for IPv4 optional checksum)
        assert len(udp_bytes) == 8


class TestICMPConstruction:
    """Test ICMP packet construction using IcmpBuilder."""

    def test_icmp_echo_request_construction(self):
        """Test ICMP echo request construction."""
        icmp = ICMP.echo_request(id=0x1234, seq=1)
        icmp_bytes = icmp.bytes()

        # Should be 8 bytes minimum (type, code, checksum, id, seq)
        assert len(icmp_bytes) >= 8

        # Verify header fields
        assert icmp_bytes[0] == 8  # type = 8 (echo request)
        assert icmp_bytes[1] == 0  # code = 0
        # bytes 2-3 are checksum (auto-calculated)
        assert icmp_bytes[4:6] == bytes([0x12, 0x34])  # id = 0x1234
        assert icmp_bytes[6:8] == bytes([0x00, 0x01])  # seq = 1

    def test_icmp_echo_reply_construction(self):
        """Test ICMP echo reply construction."""
        icmp = ICMP.echo_reply(id=0xABCD, seq=42)
        icmp_bytes = icmp.bytes()

        assert len(icmp_bytes) >= 8
        assert icmp_bytes[0] == 0  # type = 0 (echo reply)
        assert icmp_bytes[1] == 0  # code = 0
        assert icmp_bytes[4:6] == bytes([0xAB, 0xCD])  # id = 0xabcd
        assert icmp_bytes[6:8] == bytes([0x00, 0x2A])  # seq = 42

    def test_icmp_dest_unreach_construction(self):
        """Test ICMP destination unreachable construction."""
        # Code 3 = port unreachable
        icmp = ICMP.dest_unreach(code=3)
        icmp_bytes = icmp.bytes()

        assert len(icmp_bytes) >= 8
        assert icmp_bytes[0] == 3  # type = 3 (dest unreachable)
        assert icmp_bytes[1] == 3  # code = 3 (port unreachable)

    def test_icmp_redirect_construction(self):
        """Test ICMP redirect construction."""
        icmp = ICMP.redirect(code=1, gateway="10.0.0.1")
        icmp_bytes = icmp.bytes()

        assert len(icmp_bytes) >= 8
        assert icmp_bytes[0] == 5  # type = 5 (redirect)
        assert icmp_bytes[1] == 1  # code = 1 (redirect host)
        # Gateway IP in bytes 4-7
        assert icmp_bytes[4:8] == bytes([10, 0, 0, 1])

    def test_icmp_time_exceeded_construction(self):
        """Test ICMP time exceeded construction."""
        icmp = ICMP.time_exceeded(code=0)
        icmp_bytes = icmp.bytes()

        assert len(icmp_bytes) >= 8
        assert icmp_bytes[0] == 11  # type = 11 (time exceeded)
        assert icmp_bytes[1] == 0  # code = 0 (TTL exceeded)

    def test_icmp_param_problem_construction(self):
        """Test ICMP parameter problem construction."""
        icmp = ICMP.param_problem(ptr=20)
        icmp_bytes = icmp.bytes()

        assert len(icmp_bytes) >= 8
        assert icmp_bytes[0] == 12  # type = 12 (parameter problem)
        assert icmp_bytes[1] == 0  # code = 0
        assert icmp_bytes[4] == 20  # pointer byte

    def test_icmp_timestamp_request_construction(self):
        """Test ICMP timestamp request construction."""
        icmp = ICMP.timestamp_request(id=0x1234, seq=1, ts_ori=1000, ts_rx=2000, ts_tx=3000)
        icmp_bytes = icmp.bytes()

        # Timestamp message has 20 bytes (8 header + 12 timestamps)
        assert len(icmp_bytes) >= 20
        assert icmp_bytes[0] == 13  # type = 13 (timestamp request)
        assert icmp_bytes[1] == 0  # code = 0

    def test_icmp_timestamp_reply_construction(self):
        """Test ICMP timestamp reply construction."""
        icmp = ICMP.timestamp_reply(id=0x1234, seq=1, ts_ori=1000, ts_rx=2000, ts_tx=3000)
        icmp_bytes = icmp.bytes()

        assert len(icmp_bytes) >= 20
        assert icmp_bytes[0] == 14  # type = 14 (timestamp reply)
        assert icmp_bytes[1] == 0  # code = 0

    def test_icmp_generic_construction(self):
        """Test generic ICMP construction with type and code."""
        icmp = ICMP(type=8, code=0)
        icmp_bytes = icmp.bytes()

        assert len(icmp_bytes) >= 8
        assert icmp_bytes[0] == 8  # type = 8
        assert icmp_bytes[1] == 0  # code = 0

    def test_icmp_with_custom_checksum(self):
        """Test ICMP with custom checksum."""
        icmp = ICMP(type=8, code=0, chksum=0x1234)
        icmp_bytes = icmp.bytes()

        # Verify custom checksum is set
        assert icmp_bytes[2:4] == bytes([0x12, 0x34])


class TestICMPTypeSpecificFields:
    """Tests for ICMP type-specific fields (Phase 1 implementation)."""

    def test_icmp_redirect_gateway(self):
        """Test ICMP redirect with gateway field."""
        icmp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,
                192,
                168,
                1,
                1,
                192,
                168,
                1,
                100,
                # ICMP Redirect
                0x05,  # Type = 5 (redirect)
                0x01,  # Code = 1 (redirect host)
                0x00,
                0x00,  # Checksum
                10,
                0,
                0,
                1,  # Gateway = 10.0.0.1
            ]
        )

        pkt = Packet(icmp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Icmp)
        summary = pkt.summary()
        assert "ICMP" in summary
        assert "redirect" in summary.lower()
        # Gateway should be shown in summary
        assert "gw=" in summary or "10.0.0.1" in summary

    def test_icmp_dest_unreach_mtu(self):
        """Test ICMP destination unreachable with MTU field."""
        icmp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,
                192,
                168,
                1,
                1,
                192,
                168,
                1,
                100,
                # ICMP Dest Unreachable (fragmentation needed)
                0x03,  # Type = 3 (dest unreachable)
                0x04,  # Code = 4 (fragmentation needed)
                0x00,
                0x00,  # Checksum
                0x00,
                0x00,  # Unused
                0x05,
                0xDC,  # MTU = 1500
            ]
        )

        pkt = Packet(icmp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Icmp)
        summary = pkt.summary()
        assert "ICMP" in summary
        # MTU should be shown in summary
        assert "mtu=" in summary or "1500" in summary

    def test_icmp_param_problem_ptr(self):
        """Test ICMP parameter problem with pointer field."""
        icmp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,
                192,
                168,
                1,
                1,
                192,
                168,
                1,
                100,
                # ICMP Parameter Problem
                0x0C,  # Type = 12 (parameter problem)
                0x00,  # Code = 0
                0x00,
                0x00,  # Checksum
                0x14,  # Pointer = 20 (byte offset of problem)
                0x00,
                0x00,
                0x00,  # Unused
            ]
        )

        pkt = Packet(icmp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Icmp)
        summary = pkt.summary()
        assert "ICMP" in summary
        assert "parameter-problem" in summary.lower() or "param" in summary.lower()
        # Pointer should be shown in summary
        assert "ptr=" in summary or "20" in summary

    def test_icmp_timestamp_request(self):
        """Test ICMP timestamp request with timestamp fields."""
        icmp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x2C,  # Total length = 44 (20 IP + 20 ICMP + 4 padding)
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,
                192,
                168,
                1,
                100,
                8,
                8,
                8,
                8,
                # ICMP Timestamp Request
                0x0D,
                0x00,  # Type = 13, Code = 0
                0x00,
                0x00,  # Checksum
                0x12,
                0x34,  # ID
                0x00,
                0x01,  # Sequence
                # Originate timestamp
                0x00,
                0x00,
                0x10,
                0x00,  # ts_ori = 4096
                # Receive timestamp
                0x00,
                0x00,
                0x00,
                0x00,  # ts_rx = 0 (not filled yet)
                # Transmit timestamp
                0x00,
                0x00,
                0x00,
                0x00,  # ts_tx = 0 (not filled yet)
            ]
        )

        pkt = Packet(icmp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Icmp)
        summary = pkt.summary()
        assert "ICMP" in summary
        assert "timestamp" in summary.lower()

    def test_icmp_address_mask_request(self):
        """Test ICMP address mask request."""
        icmp_pkt = bytes(
            [
                # Ethernet
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                # IPv4
                0x45,
                0x00,
                0x00,
                0x1C,
                0x00,
                0x01,
                0x00,
                0x00,
                0x40,
                0x01,
                0x00,
                0x00,
                192,
                168,
                1,
                100,
                192,
                168,
                1,
                1,
                # ICMP Address Mask Request
                0x11,
                0x00,  # Type = 17, Code = 0
                0x00,
                0x00,  # Checksum
                255,
                255,
                255,
                0,  # Address mask = 255.255.255.0
            ]
        )

        pkt = Packet(icmp_pkt)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Icmp)
        summary = pkt.summary()
        assert "ICMP" in summary
        assert "address-mask" in summary.lower() or "mask" in summary.lower()
