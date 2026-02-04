"""Tests for the Stackforge core packet functionality."""

import pytest
from stackforge import ARP, IP, TCP, Ether, LayerKind, LayerStack, Packet, Raw


class TestPacket:
    """Tests for the Packet class."""

    @pytest.fixture
    def sample_tcp_packet(self) -> bytes:
        """A minimal valid Ethernet/IPv4/TCP packet."""
        return bytes(
            [
                # Ethernet header (14 bytes)
                0x00,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,  # Destination MAC
                0x66,
                0x77,
                0x88,
                0x99,
                0xAA,
                0xBB,  # Source MAC
                0x08,
                0x00,  # EtherType: IPv4
                # IPv4 header (20 bytes, IHL=5)
                0x45,
                0x00,  # Version=4, IHL=5, DSCP=0, ECN=0
                0x00,
                0x28,  # Total Length = 40
                0x00,
                0x00,  # Identification
                0x40,
                0x00,  # Flags=DF, Fragment Offset=0
                0x40,  # TTL = 64
                0x06,  # Protocol = TCP
                0x00,
                0x00,  # Header Checksum
                0xC0,
                0xA8,
                0x01,
                0x01,  # Source IP: 192.168.1.1
                0xC0,
                0xA8,
                0x01,
                0x02,  # Dest IP: 192.168.1.2
                # TCP header (20 bytes, data offset=5)
                0x00,
                0x50,  # Source Port = 80
                0x1F,
                0x90,  # Dest Port = 8080
                0x00,
                0x00,
                0x00,
                0x01,  # Sequence Number
                0x00,
                0x00,
                0x00,
                0x00,  # Acknowledgment Number
                0x50,
                0x02,  # Data Offset=5, Flags=SYN
                0xFF,
                0xFF,  # Window Size
                0x00,
                0x00,  # Checksum
                0x00,
                0x00,  # Urgent Pointer
            ]
        )

    def test_packet_from_bytes(self, sample_tcp_packet):
        """Test creating a packet from raw bytes."""
        pkt = Packet(sample_tcp_packet)
        assert len(pkt) == len(sample_tcp_packet)

    def test_packet_parse(self, sample_tcp_packet):
        """Test parsing a packet identifies layer boundaries."""
        pkt = Packet(sample_tcp_packet)
        pkt.parse()
        assert pkt.layer_count == 3
        assert pkt.has_layer(LayerKind.Ethernet)
        assert pkt.has_layer(LayerKind.Ipv4)
        assert pkt.has_layer(LayerKind.Tcp)


class TestLayerStacking:
    """Tests for the Scapy-style / operator layer stacking."""

    def test_ether_ip_tcp_stack(self):
        """Test stacking Ether / IP / TCP creates a LayerStack."""
        pkt = Ether() / IP(dst="192.168.1.1") / TCP(dport=80)
        assert isinstance(pkt, LayerStack)
        assert len(pkt) == 3

    def test_ether_arp_stack(self):
        """Test stacking Ether / ARP creates a LayerStack."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst="192.168.1.100")
        assert isinstance(pkt, LayerStack)
        assert len(pkt) == 2

    def test_stack_with_raw_payload(self):
        """Test stacking with Raw payload."""
        pkt = Ether() / IP() / TCP(dport=80) / Raw(load=b"Hello")
        assert len(pkt) == 4

    def test_stack_build_to_packet(self):
        """Test building a LayerStack into a Packet."""
        stack = Ether() / IP(dst="10.0.0.1") / TCP(dport=443)
        pkt = stack.build()
        assert isinstance(pkt, Packet)
        # Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes
        assert len(pkt) == 54

    def test_stack_build_to_bytes(self):
        """Test building a LayerStack into raw bytes."""
        stack = Ether() / IP() / TCP()
        raw = stack.bytes()
        assert isinstance(raw, bytes)
        assert len(raw) == 54

    def test_auto_ethertype_ipv4(self):
        """Test that EtherType is auto-set to 0x0800 for IPv4."""
        stack = Ether() / IP()
        pkt = stack.build()
        pkt.parse()
        # EtherType at bytes 12-13
        raw = pkt.bytes()
        assert raw[12:14] == b"\x08\x00"  # IPv4

    def test_auto_ethertype_arp(self):
        """Test that EtherType is auto-set to 0x0806 for ARP."""
        stack = Ether() / ARP()
        pkt = stack.build()
        pkt.parse()
        raw = pkt.bytes()
        assert raw[12:14] == b"\x08\x06"  # ARP

    def test_auto_ip_protocol_tcp(self):
        """Test that IP protocol is auto-set to 6 for TCP."""
        stack = Ether() / IP() / TCP()
        pkt = stack.build()
        pkt.parse()
        raw = pkt.bytes()
        # IP protocol at byte 14 + 9 = 23
        assert raw[23] == 6  # TCP

    def test_ip_total_length(self):
        """Test that IP total length is calculated correctly."""
        stack = Ether() / IP() / TCP() / Raw(load=b"Hello, World!")
        pkt = stack.build()
        raw = pkt.bytes()
        # IP total length at bytes 14+2 = 16-17
        ip_len = (raw[16] << 8) | raw[17]
        # IPv4(20) + TCP(20) + payload(13) = 53
        assert ip_len == 53

    def test_mac_address_parsing(self):
        """Test various MAC address formats."""
        eth = Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66")
        raw = eth.bytes()
        assert raw[0:6] == bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        assert raw[6:12] == bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

    def test_ip_address_parsing(self):
        """Test IP address parsing in builders."""
        ip = IP(src="10.0.0.1", dst="192.168.1.100")
        raw = ip.bytes()
        # Source IP at offset 12-15, Dest IP at offset 16-19
        assert raw[12:16] == bytes([10, 0, 0, 1])
        assert raw[16:20] == bytes([192, 168, 1, 100])

    def test_tcp_flags(self):
        """Test TCP flags string parsing."""
        tcp_syn = TCP(flags="S")
        tcp_synack = TCP(flags="SA")
        tcp_fin = TCP(flags="F")

        raw_syn = tcp_syn.bytes()
        raw_synack = tcp_synack.bytes()
        raw_fin = tcp_fin.bytes()

        # TCP flags at offset 13 (data offset + flags byte)
        # SYN = 0x02, ACK = 0x10, FIN = 0x01
        assert raw_syn[13] & 0x02  # SYN set
        assert raw_synack[13] & 0x12  # SYN and ACK set
        assert raw_fin[13] & 0x01  # FIN set

    def test_arp_operations(self):
        """Test ARP operation codes."""
        arp_req = ARP(op="who-has")
        arp_reply = ARP(op="is-at")
        arp_num = ARP(op=1)

        raw_req = arp_req.bytes()
        raw_reply = arp_reply.bytes()
        raw_num = arp_num.bytes()

        # ARP op at offset 6-7
        assert raw_req[6:8] == b"\x00\x01"  # REQUEST
        assert raw_reply[6:8] == b"\x00\x02"  # REPLY
        assert raw_num[6:8] == b"\x00\x01"  # REQUEST

    def test_stack_show(self):
        """Test that show() produces readable output."""
        stack = Ether() / IP(dst="8.8.8.8") / TCP(dport=80)
        output = stack.show()
        assert "Ethernet" in output
        assert "IPv4" in output
        assert "TCP" in output
        assert "8.8.8.8" in output
        assert "80" in output

    def test_stack_repr(self):
        """Test that repr() produces a summary."""
        stack = Ether() / IP() / TCP()
        repr_str = repr(stack)
        assert "Ether" in repr_str or "ff:ff:ff:ff:ff:ff" in repr_str

    def test_chained_stacking(self):
        """Test chaining multiple / operations."""
        # All three ways should work
        pkt1 = Ether() / IP() / TCP()
        pkt2 = (Ether() / IP()) / TCP()

        assert len(pkt1) == 3
        assert len(pkt2) == 3

    def test_raw_string_payload(self):
        """Test Raw layer with string payload."""
        raw = Raw(load="Hello")
        assert len(raw) == 5

    def test_raw_bytes_payload(self):
        """Test Raw layer with bytes payload."""
        raw = Raw(load=b"\x00\x01\x02\x03")
        assert len(raw) == 4

    def test_stack_summary(self):
        """Test summary() produces layer names."""
        stack = Ether() / IP() / TCP()
        summary = stack.summary()
        assert "Ethernet" in summary
        assert "IPv4" in summary
        assert "TCP" in summary


class TestLayerBuilders:
    """Tests for individual layer builders."""

    def test_ether_defaults(self):
        """Test Ethernet builder default values."""
        eth = Ether()
        raw = eth.bytes()
        assert len(raw) == 14  # Ethernet header is 14 bytes
        # Default dst is broadcast
        assert raw[0:6] == b"\xff\xff\xff\xff\xff\xff"

    def test_ip_defaults(self):
        """Test IPv4 builder default values."""
        ip = IP()
        raw = ip.bytes()
        assert len(raw) == 20  # IPv4 header with IHL=5 is 20 bytes
        # Version and IHL
        assert raw[0] == 0x45  # Version 4, IHL 5
        # Default TTL is 64
        assert raw[8] == 64

    def test_tcp_defaults(self):
        """Test TCP builder default values."""
        tcp = TCP()
        raw = tcp.bytes()
        assert len(raw) == 20  # TCP header with data offset 5 is 20 bytes

    def test_ip_ttl(self):
        """Test setting IP TTL."""
        ip = IP(ttl=128)
        raw = ip.bytes()
        assert raw[8] == 128

    def test_tcp_ports(self):
        """Test setting TCP ports."""
        tcp = TCP(sport=12345, dport=443)
        raw = tcp.bytes()
        # Source port at offset 0-1
        assert (raw[0] << 8) | raw[1] == 12345
        # Dest port at offset 2-3
        assert (raw[2] << 8) | raw[3] == 443

    def test_tcp_seq_ack(self):
        """Test setting TCP sequence and ack numbers."""
        tcp = TCP(seq=1000, ack=2000)
        raw = tcp.bytes()
        # Seq at offset 4-7
        seq = (raw[4] << 24) | (raw[5] << 16) | (raw[6] << 8) | raw[7]
        assert seq == 1000
        # Ack at offset 8-11
        ack = (raw[8] << 24) | (raw[9] << 16) | (raw[10] << 8) | raw[11]
        assert ack == 2000


class TestRawLayer:
    """Tests for the Raw payload layer."""

    def test_raw_from_bytes(self):
        """Test Raw with bytes payload."""
        raw = Raw(load=b"Hello")
        assert len(raw) == 5
        assert raw.bytes() == b"Hello"

    def test_raw_from_string(self):
        """Test Raw with string payload."""
        raw = Raw(load="Hello")
        assert len(raw) == 5
        assert raw.bytes() == b"Hello"

    def test_raw_load_property(self):
        """Test Raw.load property."""
        raw = Raw(load=b"Test")
        assert raw.load == b"Test"

    def test_raw_hex_property(self):
        """Test Raw.hex property."""
        raw = Raw(load=b"\xde\xad\xbe\xef")
        assert raw.hex == "deadbeef"

    def test_raw_hexdump(self):
        """Test Raw.hexdump() method."""
        raw = Raw(load=b"\xde\xad\xbe\xef")
        assert raw.hexdump() == "de ad be ef"

    def test_raw_from_hex(self):
        """Test Raw.from_hex() static method."""
        raw = Raw.from_hex("deadbeef")
        assert raw.bytes() == b"\xde\xad\xbe\xef"

    def test_raw_from_hex_with_separators(self):
        """Test Raw.from_hex() with various separators."""
        raw1 = Raw.from_hex("de:ad:be:ef")
        raw2 = Raw.from_hex("de ad be ef")
        raw3 = Raw.from_hex("DE-AD-BE-EF")
        assert raw1.bytes() == b"\xde\xad\xbe\xef"
        assert raw2.bytes() == b"\xde\xad\xbe\xef"
        assert raw3.bytes() == b"\xde\xad\xbe\xef"

    def test_raw_from_hex_invalid(self):
        """Test Raw.from_hex() with invalid input."""
        import pytest

        with pytest.raises(ValueError):
            Raw.from_hex("xyz")  # No valid hex digits
        with pytest.raises(ValueError):
            Raw.from_hex("abc")  # Odd number of hex digits

    def test_raw_zeros(self):
        """Test Raw.zeros() static method."""
        raw = Raw.zeros(10)
        assert len(raw) == 10
        assert raw.bytes() == bytes(10)

    def test_raw_repeat(self):
        """Test Raw.repeat() static method."""
        raw = Raw.repeat(0x41, 5)
        assert raw.bytes() == b"AAAAA"

    def test_raw_pattern(self):
        """Test Raw.pattern() static method."""
        raw = Raw.pattern(b"AB", 7)
        assert raw.bytes() == b"ABABABA"

    def test_raw_pad(self):
        """Test Raw.pad() method."""
        raw = Raw(load=b"Hi")
        padded = raw.pad(5)
        assert len(padded) == 5
        assert padded.bytes() == b"Hi\x00\x00\x00"

    def test_raw_pad_already_long(self):
        """Test Raw.pad() with already long payload."""
        raw = Raw(load=b"Hello")
        padded = raw.pad(3)
        assert padded.bytes() == b"Hello"  # No change

    def test_raw_pad_with(self):
        """Test Raw.pad_with() method."""
        raw = Raw(load=b"Hi")
        padded = raw.pad_with(5, 0xFF)
        assert padded.bytes() == b"Hi\xff\xff\xff"

    def test_raw_repr_short(self):
        """Test Raw repr for short payloads."""
        raw = Raw(load=b"\xde\xad")
        repr_str = repr(raw)
        assert "dead" in repr_str

    def test_raw_repr_long(self):
        """Test Raw repr for long payloads."""
        raw = Raw(load=b"A" * 100)
        repr_str = repr(raw)
        assert "100 bytes" in repr_str

    def test_raw_str(self):
        """Test Raw str representation."""
        raw = Raw(load=b"\xde\xad")
        assert str(raw) == "de ad"

    def test_raw_stacking(self):
        """Test stacking Raw with other layers."""
        pkt = Ether() / IP() / TCP() / Raw(load=b"Data")
        assert len(pkt) == 4
        built = pkt.build()
        assert len(built) == 58  # 14 + 20 + 20 + 4
