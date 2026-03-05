"""Tests for streaming flow extraction with memory budget."""

import os
import tempfile

from stackforge import (
    IP,
    TCP,
    UDP,
    Ether,
    FlowConfig,
    extract_flows,
    wrpcap,
)


def build_tcp_pkt(src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80):
    """Build a simple TCP packet."""
    stack = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport)
    pkt = stack.build()
    pkt.parse()
    return pkt


def build_udp_pkt(src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=5000, dport=53):
    """Build a simple UDP packet."""
    stack = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    pkt = stack.build()
    pkt.parse()
    return pkt


class TestStreamingFlowExtraction:
    """Test that extract_flows works in streaming mode (from file)."""

    def test_basic_streaming(self):
        """extract_flows should stream packets from file, not load all at once."""
        pkts = [build_tcp_pkt(sport=1000 + i) for i in range(10)]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        try:
            wrpcap(path, pkts)
            flows = extract_flows(path)
            assert len(flows) >= 1
            total_pkts = sum(f.total_packets for f in flows)
            assert total_pkts == 10
        finally:
            os.unlink(path)

    def test_streaming_multiple_flows(self):
        """Streaming should correctly separate different flows."""
        pkts = [
            build_tcp_pkt(sport=1111, dport=80),
            build_tcp_pkt(sport=1111, dport=80),
            build_tcp_pkt(sport=2222, dport=443),
            build_tcp_pkt(sport=2222, dport=443),
            build_udp_pkt(sport=3333, dport=53),
        ]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        try:
            wrpcap(path, pkts)
            flows = extract_flows(path)
            assert len(flows) == 3
        finally:
            os.unlink(path)


class TestMemoryBudgetFlowConfig:
    """Test FlowConfig with memory budget parameters."""

    def test_flowconfig_with_memory_budget(self):
        """FlowConfig should accept memory_budget parameter."""
        config = FlowConfig(memory_budget=50 * 1024 * 1024)  # 50MB
        assert config is not None

    def test_flowconfig_with_spill_dir(self):
        """FlowConfig should accept spill_dir parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = FlowConfig(memory_budget=1024, spill_dir=tmpdir)
            assert config is not None

    def test_extract_flows_with_budget(self):
        """extract_flows should work with a memory budget."""
        pkts = [build_tcp_pkt(sport=1000 + i) for i in range(5)]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        try:
            wrpcap(path, pkts)
            config = FlowConfig(memory_budget=10 * 1024 * 1024)  # 10MB
            flows = extract_flows(path, config=config)
            assert len(flows) >= 1
        finally:
            os.unlink(path)

    def test_extract_flows_small_budget(self):
        """extract_flows should still work with a very small memory budget."""
        pkts = [build_tcp_pkt(sport=1000 + i) for i in range(20)]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        try:
            wrpcap(path, pkts)
            config = FlowConfig(memory_budget=1024)  # Very small: 1KB
            flows = extract_flows(path, config=config)
            assert len(flows) >= 1
            total_pkts = sum(f.total_packets for f in flows)
            assert total_pkts == 20
        finally:
            os.unlink(path)

    def test_extract_flows_no_budget(self):
        """extract_flows without budget should work (unlimited memory)."""
        pkts = [build_tcp_pkt(sport=1000 + i) for i in range(5)]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        try:
            wrpcap(path, pkts)
            config = FlowConfig()  # No budget
            flows = extract_flows(path, config=config)
            assert len(flows) >= 1
        finally:
            os.unlink(path)

    def test_budget_with_spill_dir(self):
        """Memory budget with custom spill directory should work."""
        pkts = [build_tcp_pkt(sport=1000 + i) for i in range(10)]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        with tempfile.TemporaryDirectory() as spill_dir:
            try:
                wrpcap(path, pkts)
                config = FlowConfig(memory_budget=512, spill_dir=spill_dir)
                flows = extract_flows(path, config=config)
                assert len(flows) >= 1
            finally:
                os.unlink(path)
