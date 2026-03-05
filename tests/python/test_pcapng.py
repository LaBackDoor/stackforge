"""Tests for PcapNG read/write support and auto-detection."""

import os
import tempfile

from stackforge import (
    IP,
    TCP,
    UDP,
    Ether,
    PcapPacket,
    PcapReader,
    extract_flows,
    rdpcap,
    wrpcap,
    wrpcapng,
)


def build_eth_ip_tcp(src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80):
    """Build a simple Ethernet/IP/TCP packet."""
    stack = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport)
    pkt = stack.build()
    pkt.parse()
    return pkt


def build_eth_ip_udp(src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=5000, dport=53):
    """Build a simple Ethernet/IP/UDP packet."""
    stack = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    pkt = stack.build()
    pkt.parse()
    return pkt


class TestPcapNgWrite:
    """Test PcapNG file writing."""

    def test_wrpcapng_single_packet(self):
        """Write a single packet to PcapNG and read back."""
        pkt = build_eth_ip_tcp()
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            path = f.name
        try:
            wrpcapng(path, [pkt])
            packets = rdpcap(path)
            assert len(packets) == 1
            assert packets[0].packet.src == pkt.src
            assert packets[0].packet.dst == pkt.dst
        finally:
            os.unlink(path)

    def test_wrpcapng_multiple_packets(self):
        """Write multiple packets to PcapNG and read back."""
        pkts = [build_eth_ip_tcp(sport=1000 + i, dport=80) for i in range(5)]
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            path = f.name
        try:
            wrpcapng(path, pkts)
            packets = rdpcap(path)
            assert len(packets) == 5
        finally:
            os.unlink(path)

    def test_wrpcapng_empty(self):
        """Write empty packet list to PcapNG."""
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            path = f.name
        try:
            wrpcapng(path, [])
            packets = rdpcap(path)
            assert len(packets) == 0
        finally:
            os.unlink(path)

    def test_wrpcap_auto_detect_pcapng_extension(self):
        """wrpcap should auto-detect .pcapng extension and write PcapNG format."""
        pkt = build_eth_ip_tcp()
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            path = f.name
        try:
            wrpcap(path, [pkt])
            packets = rdpcap(path)
            assert len(packets) == 1
        finally:
            os.unlink(path)


class TestPcapNgRead:
    """Test PcapNG file reading with auto-detection."""

    def test_rdpcap_reads_pcapng(self):
        """rdpcap should auto-detect PcapNG format."""
        pkt = build_eth_ip_tcp()
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            path = f.name
        try:
            wrpcapng(path, [pkt])
            packets = rdpcap(path)
            assert len(packets) == 1
        finally:
            os.unlink(path)

    def test_rdpcap_still_reads_pcap(self):
        """rdpcap should still handle classic PCAP files."""
        pkt = build_eth_ip_tcp()
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        try:
            wrpcap(path, [pkt])
            packets = rdpcap(path)
            assert len(packets) == 1
        finally:
            os.unlink(path)

    def test_pcap_reader_pcapng(self):
        """PcapReader should work with PcapNG files."""
        pkts = [build_eth_ip_tcp(sport=2000 + i) for i in range(3)]
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            path = f.name
        try:
            wrpcapng(path, pkts)
            reader = PcapReader(path)
            count = 0
            for pcap_pkt in reader:
                assert isinstance(pcap_pkt, PcapPacket)
                count += 1
            assert count == 3
        finally:
            os.unlink(path)


class TestPcapNgRoundtrip:
    """Test round-trip: write PcapNG -> read -> verify content."""

    def test_roundtrip_preserves_data(self):
        """Written and read-back packets should have matching raw bytes."""
        pkt = build_eth_ip_tcp()
        raw_bytes = pkt.bytes()
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            path = f.name
        try:
            wrpcapng(path, [pkt])
            packets = rdpcap(path)
            assert packets[0].packet.bytes() == raw_bytes
        finally:
            os.unlink(path)

    def test_roundtrip_mixed_protocols(self):
        """PcapNG should handle mixed TCP and UDP packets."""
        pkts = [
            build_eth_ip_tcp(sport=1234),
            build_eth_ip_udp(sport=5678),
            build_eth_ip_tcp(sport=9012),
        ]
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            path = f.name
        try:
            wrpcapng(path, pkts)
            read_pkts = rdpcap(path)
            assert len(read_pkts) == 3
        finally:
            os.unlink(path)

    def test_pcapng_to_pcap_conversion(self):
        """Write PcapNG, read, write as PCAP, read again."""
        pkt = build_eth_ip_tcp()
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            ng_path = f.name
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            pcap_path = f.name
        try:
            wrpcapng(ng_path, [pkt])
            packets = rdpcap(ng_path)
            wrpcap(pcap_path, [p.packet for p in packets])
            packets2 = rdpcap(pcap_path)
            assert len(packets2) == 1
            assert packets2[0].packet.bytes() == packets[0].packet.bytes()
        finally:
            os.unlink(ng_path)
            os.unlink(pcap_path)


class TestExtractFlowsPcapNg:
    """Test flow extraction from PcapNG files."""

    def test_extract_flows_from_pcapng(self):
        """extract_flows should work with PcapNG files."""
        pkts = [
            build_eth_ip_tcp(sport=1111, dport=80),
            build_eth_ip_tcp(sport=1111, dport=80),
            build_eth_ip_tcp(sport=2222, dport=443),
        ]
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            path = f.name
        try:
            wrpcapng(path, pkts)
            flows = extract_flows(path)
            assert len(flows) >= 1
        finally:
            os.unlink(path)
