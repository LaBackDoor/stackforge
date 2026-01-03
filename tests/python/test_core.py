"""Tests for the Stackforge core packet functionality."""

import pytest
from stackforge import LayerKind, Packet


class TestLayerKind:
    """Tests for the LayerKind enum."""

    def test_layer_kind_names(self):
        """LayerKind should have correct names."""
        assert LayerKind.Ethernet.name() == "Ethernet"
        assert LayerKind.Tcp.name() == "TCP"
        assert LayerKind.Udp.name() == "UDP"
        assert LayerKind.Raw.name() == "Raw"

    def test_layer_kind_min_header_sizes(self):
        """LayerKind should report correct minimum header sizes."""
        assert LayerKind.Ethernet.min_header_size() == 14
        assert LayerKind.Ipv4.min_header_size() == 20
        assert LayerKind.Tcp.min_header_size() == 20
        assert LayerKind.Udp.min_header_size() == 8

    def test_layer_kind_repr(self):
        """LayerKind should have a useful repr."""
        assert "Ethernet" in repr(LayerKind.Ethernet)

    def test_layer_kind_str(self):
        """LayerKind should have a useful str."""
        assert str(LayerKind.Tcp) == "TCP"


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

    def test_packet_creation(self):
        """Packets can be created from bytes."""
        data = b"\x00\x01\x02\x03\x04"
        pkt = Packet(data)
        assert len(pkt) == 5
        assert not pkt.is_empty()

    def test_packet_empty(self):
        """Empty packets can be created."""
        pkt = Packet.empty()
        assert len(pkt) == 0
        assert pkt.is_empty()

    def test_packet_not_dirty_initially(self):
        """New packets should not be dirty."""
        pkt = Packet(b"\x00\x01\x02")
        assert not pkt.is_dirty

    def test_packet_not_parsed_initially(self):
        """New packets should not be parsed."""
        pkt = Packet(b"\x00\x01\x02")
        assert not pkt.is_parsed
        assert pkt.layer_count == 0

    def test_packet_parse_tcp(self, sample_tcp_packet):
        """Packets can be parsed to identify layers."""
        pkt = Packet(sample_tcp_packet)
        pkt.parse()

        assert pkt.is_parsed
        assert pkt.layer_count == 3  # Ethernet, IPv4, TCP

    def test_packet_has_layer(self, sample_tcp_packet):
        """has_layer correctly identifies present layers."""
        pkt = Packet(sample_tcp_packet)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Ethernet)
        assert pkt.has_layer(LayerKind.Ipv4)
        assert pkt.has_layer(LayerKind.Tcp)
        assert not pkt.has_layer(LayerKind.Udp)

    def test_packet_layers_property(self, sample_tcp_packet):
        """layers property returns correct layer indices."""
        pkt = Packet(sample_tcp_packet)
        pkt.parse()

        layers = pkt.layers
        assert len(layers) == 3

        # Check Ethernet layer
        assert layers[0].kind == LayerKind.Ethernet
        assert layers[0].start == 0
        assert layers[0].end == 14
        assert len(layers[0]) == 14

        # Check IPv4 layer
        assert layers[1].kind == LayerKind.Ipv4
        assert layers[1].start == 14
        assert layers[1].end == 34

        # Check TCP layer
        assert layers[2].kind == LayerKind.Tcp
        assert layers[2].start == 34
        assert layers[2].end == 54

    def test_packet_get_layer_bytes(self, sample_tcp_packet):
        """get_layer_bytes returns correct bytes for each layer."""
        pkt = Packet(sample_tcp_packet)
        pkt.parse()

        eth_bytes = pkt.get_layer_bytes(LayerKind.Ethernet)
        assert len(eth_bytes) == 14
        assert eth_bytes == sample_tcp_packet[:14]

        tcp_bytes = pkt.get_layer_bytes(LayerKind.Tcp)
        assert len(tcp_bytes) == 20

    def test_packet_get_layer_bytes_not_found(self, sample_tcp_packet):
        """get_layer_bytes raises KeyError for missing layers."""
        pkt = Packet(sample_tcp_packet)
        pkt.parse()

        with pytest.raises(KeyError):
            pkt.get_layer_bytes(LayerKind.Udp)

    def test_packet_bytes_method(self, sample_tcp_packet):
        """bytes() returns the raw packet data."""
        pkt = Packet(sample_tcp_packet)
        assert pkt.bytes() == sample_tcp_packet

    def test_packet_payload(self, sample_tcp_packet):
        """payload returns data after all headers."""
        pkt = Packet(sample_tcp_packet)
        pkt.parse()

        # This packet has no payload (headers only)
        assert pkt.payload() == b""

    def test_packet_repr(self, sample_tcp_packet):
        """repr shows useful information."""
        pkt = Packet(sample_tcp_packet)
        pkt.parse()

        r = repr(pkt)
        assert "Packet" in r
        assert "54" in r  # length
        assert "Ethernet" in r
        assert "TCP" in r

    def test_packet_show(self, sample_tcp_packet):
        """show() returns formatted packet info."""
        pkt = Packet(sample_tcp_packet)
        pkt.parse()

        output = pkt.show()
        assert "Ethernet" in output
        assert "IPv4" in output
        assert "TCP" in output
        assert "bytes" in output

    def test_packet_hexdump(self, sample_tcp_packet):
        """hexdump() returns hex representation."""
        pkt = Packet(sample_tcp_packet)
        output = pkt.hexdump()

        # Should have offset, hex bytes, and ASCII
        assert "00000000" in output
        assert "|" in output


class TestLayerIndex:
    """Tests for the LayerIndex class."""

    def test_layer_index_repr(self):
        """LayerIndex should have a useful repr."""
        # We can't create LayerIndex directly, so we get one from a packet
        pkt = Packet(
            bytes(
                [
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
                    0x00,  # IPv4
                    0x45,
                    0x00,
                    0x00,
                    0x14,  # Minimal IP header start
                    0x00,
                    0x00,
                    0x40,
                    0x00,
                    0x40,
                    0x01,  # ICMP
                    0x00,
                    0x00,
                    0xC0,
                    0xA8,
                    0x01,
                    0x01,
                    0xC0,
                    0xA8,
                    0x01,
                    0x02,
                ]
            )
        )
        pkt.parse()

        idx = pkt.layers[0]
        r = repr(idx)
        assert "LayerIndex" in r
        assert "Ethernet" in r
        assert "0" in r
        assert "14" in r
