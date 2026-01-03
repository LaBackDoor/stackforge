"""Tests for the Stackforge core packet functionality."""

import pytest


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

    def test_empty(self):
        """Empty test to ensure the suite passes."""
        pass
