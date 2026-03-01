"""Tests for stateful conversation extraction (flow module)."""

import os
import tempfile

import pytest
from stackforge import (
    IP,
    TCP,
    UDP,
    Ether,
    FlowConfig,
    Raw,
    extract_flows,
    extract_flows_from_packets,
    rdpcap,
    wrpcap,
)

SAMPLE_PCAP_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_pcap")


# ============================================================================
# Helper: build packets and write to a temp PCAP
# ============================================================================


def _build_tcp_packet(src_ip, dst_ip, sport, dport, flags="S", payload=b""):
    """Build a simple TCP packet using the layer stack API."""
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload)
    built = pkt.build()
    built.parse()
    return built


def _build_udp_packet(src_ip, dst_ip, sport, dport, payload=b""):
    """Build a simple UDP packet using the layer stack API."""
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    if payload:
        pkt = pkt / Raw(load=payload)
    built = pkt.build()
    built.parse()
    return built


def _write_temp_pcap(packets):
    """Write packets to a temporary PCAP file, return the path."""
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    wrpcap(path, packets)
    return path


# ============================================================================
# Test: FlowConfig
# ============================================================================


class TestFlowConfig:
    def test_default_config(self):
        cfg = FlowConfig()
        assert repr(cfg).startswith("FlowConfig(")

    def test_custom_config(self):
        cfg = FlowConfig(
            tcp_established_timeout=3600.0,
            udp_timeout=60.0,
            max_reassembly_buffer=1024,
        )
        r = repr(cfg)
        assert "3600" in r
        assert "60" in r
        assert "1024" in r


# ============================================================================
# Test: extract_flows with PCAP files
# ============================================================================


class TestExtractFlowsPcap:
    def test_extract_from_http_pcap(self):
        """Extract flows from a real HTTP PCAP file."""
        pcap_path = os.path.join(SAMPLE_PCAP_DIR, "http_content_length.pcap")
        if not os.path.exists(pcap_path):
            pytest.skip("Sample PCAP not found")

        conversations = extract_flows(pcap_path)
        assert len(conversations) > 0

        # Verify conversation properties
        for conv in conversations:
            assert conv.total_packets > 0
            assert conv.total_bytes > 0
            assert conv.src_addr  # Non-empty IP string
            assert conv.dst_addr
            assert conv.protocol in ("TCP", "UDP", "ICMP", "ICMPv6", "Other")
            assert conv.status in ("Active", "HalfClosed", "Closed", "TimedOut")
            assert conv.start_time >= 0
            assert conv.duration >= 0
            assert len(conv.packet_indices) == conv.total_packets

    def test_extract_from_http2_pcap(self):
        """Extract flows from HTTP/2 PCAP."""
        pcap_path = os.path.join(SAMPLE_PCAP_DIR, "http2_h2c.pcap")
        if not os.path.exists(pcap_path):
            pytest.skip("Sample PCAP not found")

        conversations = extract_flows(pcap_path)
        assert len(conversations) > 0

        # HTTP/2 is TCP-based
        tcp_convs = [c for c in conversations if c.protocol == "TCP"]
        assert len(tcp_convs) > 0

        for conv in tcp_convs:
            assert conv.tcp_state is not None

    def test_extract_flows_nonexistent_file(self):
        """Should raise IOError for missing file."""
        with pytest.raises(OSError):
            extract_flows("/nonexistent/file.pcap")


# ============================================================================
# Test: Bidirectional conversation matching
# ============================================================================


class TestBidirectionalMatching:
    def test_forward_and_reverse_same_conversation(self):
        """Forward and reverse packets should be in the same conversation."""
        pkts = [
            _build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, "S"),
            _build_tcp_packet("10.0.0.2", "10.0.0.1", 80, 12345, "SA"),
            _build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, "A"),
        ]
        path = _write_temp_pcap(pkts)
        try:
            conversations = extract_flows(path)
            assert len(conversations) == 1
            conv = conversations[0]
            assert conv.total_packets == 3
            assert conv.forward_packets + conv.reverse_packets == 3
        finally:
            os.unlink(path)

    def test_different_flows_separate_conversations(self):
        """Different 5-tuples create different conversations."""
        pkts = [
            _build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, "S"),
            _build_tcp_packet("10.0.0.1", "10.0.0.3", 54321, 443, "S"),
        ]
        path = _write_temp_pcap(pkts)
        try:
            conversations = extract_flows(path)
            assert len(conversations) == 2
        finally:
            os.unlink(path)

    def test_tcp_and_udp_separate(self):
        """TCP and UDP to same host:port are separate conversations."""
        pkts = [
            _build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 53, "S"),
            _build_udp_packet("10.0.0.1", "10.0.0.2", 12345, 53),
        ]
        path = _write_temp_pcap(pkts)
        try:
            conversations = extract_flows(path)
            assert len(conversations) == 2
            protocols = {c.protocol for c in conversations}
            assert "TCP" in protocols
            assert "UDP" in protocols
        finally:
            os.unlink(path)


# ============================================================================
# Test: TCP state machine
# ============================================================================


class TestTcpStateMachine:
    def test_syn_detected(self):
        """A SYN packet should create a conversation with SYN_SENT state."""
        pkts = [_build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, "S")]
        path = _write_temp_pcap(pkts)
        try:
            conversations = extract_flows(path)
            assert len(conversations) == 1
            assert conversations[0].tcp_state == "SYN_SENT"
        finally:
            os.unlink(path)

    def test_three_way_handshake(self):
        """Full 3-way handshake should reach ESTABLISHED."""
        pkts = [
            _build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, "S"),
            _build_tcp_packet("10.0.0.2", "10.0.0.1", 80, 12345, "SA"),
            _build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, "A"),
        ]
        path = _write_temp_pcap(pkts)
        try:
            conversations = extract_flows(path)
            assert len(conversations) == 1
            assert conversations[0].tcp_state == "ESTABLISHED"
        finally:
            os.unlink(path)

    def test_rst_closes(self):
        """RST should move to CLOSED state."""
        pkts = [
            _build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, "S"),
            _build_tcp_packet("10.0.0.2", "10.0.0.1", 80, 12345, "R"),
        ]
        path = _write_temp_pcap(pkts)
        try:
            conversations = extract_flows(path)
            assert len(conversations) == 1
            assert conversations[0].tcp_state == "CLOSED"
            assert conversations[0].status == "Closed"
        finally:
            os.unlink(path)


# ============================================================================
# Test: UDP conversations
# ============================================================================


class TestUdpConversation:
    def test_udp_conversation_created(self):
        """UDP packets create a conversation without TCP state."""
        pkts = [
            _build_udp_packet("10.0.0.1", "10.0.0.2", 12345, 53),
            _build_udp_packet("10.0.0.2", "10.0.0.1", 53, 12345),
        ]
        path = _write_temp_pcap(pkts)
        try:
            conversations = extract_flows(path)
            assert len(conversations) == 1
            conv = conversations[0]
            assert conv.protocol == "UDP"
            assert conv.tcp_state is None
            assert conv.total_packets == 2
        finally:
            os.unlink(path)


# ============================================================================
# Test: Conversation properties
# ============================================================================


class TestConversationProperties:
    def test_packet_indices(self):
        """packet_indices should reference positions in original packet list."""
        pkts = [
            _build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, "S"),
            _build_udp_packet("10.0.0.1", "10.0.0.3", 54321, 53),
            _build_tcp_packet("10.0.0.2", "10.0.0.1", 80, 12345, "SA"),
        ]
        path = _write_temp_pcap(pkts)
        try:
            conversations = extract_flows(path)
            all_indices = set()
            for conv in conversations:
                for idx in conv.packet_indices:
                    all_indices.add(idx)
            # All packet indices should be valid
            assert all(0 <= idx < len(pkts) for idx in all_indices)
        finally:
            os.unlink(path)

    def test_show_and_summary(self):
        """show() and summary() should return non-empty strings."""
        pkts = [_build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, "S")]
        path = _write_temp_pcap(pkts)
        try:
            conversations = extract_flows(path)
            conv = conversations[0]
            assert len(conv.show()) > 0
            assert len(conv.summary()) > 0
            assert "10.0.0" in conv.show()
            assert repr(conv).startswith("<Conversation")
        finally:
            os.unlink(path)

    def test_reassembled_data_none_for_udp(self):
        """UDP conversations should have no reassembled data."""
        pkts = [_build_udp_packet("10.0.0.1", "10.0.0.2", 12345, 53)]
        path = _write_temp_pcap(pkts)
        try:
            conversations = extract_flows(path)
            conv = conversations[0]
            assert conv.reassembled_forward is None
            assert conv.reassembled_reverse is None
        finally:
            os.unlink(path)


# ============================================================================
# Test: extract_flows_from_packets
# ============================================================================


class TestExtractFlowsFromPackets:
    def test_from_packet_list(self):
        """extract_flows_from_packets works with already-loaded packets."""
        pkts = [
            _build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, "S"),
            _build_tcp_packet("10.0.0.2", "10.0.0.1", 80, 12345, "SA"),
        ]
        conversations = extract_flows_from_packets(pkts)
        assert len(conversations) == 1
        assert conversations[0].total_packets == 2

    def test_empty_list(self):
        """Empty packet list returns empty conversations."""
        conversations = extract_flows_from_packets([])
        assert len(conversations) == 0


# ============================================================================
# Test: Custom FlowConfig
# ============================================================================


class TestCustomConfig:
    def test_config_passed_to_extract(self):
        """Custom config should be accepted by extract_flows."""
        pkts = [_build_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, "S")]
        path = _write_temp_pcap(pkts)
        try:
            config = FlowConfig(tcp_established_timeout=1.0)
            conversations = extract_flows(path, config=config)
            assert len(conversations) >= 1
        finally:
            os.unlink(path)


# ============================================================================
# Test: Real PCAP integration
# ============================================================================


class TestRealPcapIntegration:
    def test_http_pcap_conversations(self):
        """Test flow extraction on a real HTTP capture."""
        pcap_path = os.path.join(SAMPLE_PCAP_DIR, "http_tcp_psh.pcap")
        if not os.path.exists(pcap_path):
            pytest.skip("Sample PCAP not found")

        packets = rdpcap(pcap_path)
        conversations = extract_flows(pcap_path)

        # Total packets across all conversations should equal input
        total = sum(c.total_packets for c in conversations)
        # May not equal exactly due to non-IP packets being skipped
        assert total <= len(packets)
        assert total > 0

        # Every conversation should have valid properties
        for conv in conversations:
            assert conv.src_port >= 0
            assert conv.dst_port >= 0
            assert conv.forward_bytes + conv.reverse_bytes == conv.total_bytes
            assert conv.forward_packets + conv.reverse_packets == conv.total_packets
