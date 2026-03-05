import pytest
from stackforge import IP, TCP, UDP, Ether, FlowConfig, Packet, Raw, extract_flows_from_packets


class TestMaxPacketFlowLengthTracking:
    """Test max packet and flow length tracking in flow extraction."""

    def test_default_no_tracking(self):
        """By default, no tracking is enabled."""
        packets = []
        for i in range(3):
            pkt = Packet(
                (
                    Ether()
                    / IP(src="10.0.0.1", dst="10.0.0.2")
                    / TCP(sport=5000 + i, dport=80)
                    / Raw(b"x" * (100 + i * 50))
                ).bytes()
            )
            pkt.parse()
            packets.append(pkt)

        config = FlowConfig()  # defaults: no tracking
        flows = extract_flows_from_packets(packets, config)
        conv = flows[0]

        assert conv.forward_max_packet_len is None
        assert conv.reverse_max_packet_len is None
        assert conv.max_flow_len is None

    def test_track_max_packet_len_forward_only(self):
        """Track max packet length in forward direction."""
        packets = []
        # Forward: 100, 150, 200 bytes
        for i in range(3):
            pkt = Packet(
                (
                    Ether()
                    / IP(src="10.0.0.1", dst="10.0.0.2")
                    / TCP(sport=5000, dport=80)
                    / Raw(b"x" * (100 + i * 50))
                ).bytes()
            )
            pkt.parse()
            packets.append(pkt)

        config = FlowConfig(track_max_packet_len=True)
        flows = extract_flows_from_packets(packets, config)
        conv = flows[0]

        # All packets are in forward direction
        assert conv.forward_max_packet_len is not None
        assert conv.forward_max_packet_len > 200  # 200 bytes + headers
        assert conv.reverse_max_packet_len is None
        assert conv.max_flow_len is None

    def test_track_max_packet_len_bidirectional(self):
        """Track max packet length in both directions separately."""
        packets = []
        # Forward: 100 bytes
        pkt = Packet(
            (
                Ether()
                / IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=5000, dport=80)
                / Raw(b"x" * 100)
            ).bytes()
        )
        pkt.parse()
        packets.append(pkt)

        # Reverse: 500 bytes
        pkt = Packet(
            (
                Ether()
                / IP(src="10.0.0.2", dst="10.0.0.1")
                / TCP(sport=80, dport=5000)
                / Raw(b"y" * 500)
            ).bytes()
        )
        pkt.parse()
        packets.append(pkt)

        config = FlowConfig(track_max_packet_len=True)
        flows = extract_flows_from_packets(packets, config)
        conv = flows[0]

        assert conv.forward_max_packet_len is not None
        assert conv.reverse_max_packet_len is not None
        assert conv.reverse_max_packet_len > conv.forward_max_packet_len
        assert conv.max_flow_len is None

    def test_track_max_flow_len(self):
        """Track max flow length (largest packet overall)."""
        packets = []
        # 100 bytes
        pkt = Packet(
            (
                Ether()
                / IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=5000, dport=80)
                / Raw(b"x" * 100)
            ).bytes()
        )
        pkt.parse()
        packets.append(pkt)

        # 500 bytes
        pkt = Packet(
            (
                Ether()
                / IP(src="10.0.0.2", dst="10.0.0.1")
                / TCP(sport=80, dport=5000)
                / Raw(b"y" * 500)
            ).bytes()
        )
        pkt.parse()
        packets.append(pkt)

        config = FlowConfig(track_max_flow_len=True)
        flows = extract_flows_from_packets(packets, config)
        conv = flows[0]

        assert conv.forward_max_packet_len is None
        assert conv.reverse_max_packet_len is None
        assert conv.max_flow_len is not None
        # Should be max of all packets
        assert conv.max_flow_len > 500

    def test_track_both_max_packet_and_flow_len(self):
        """Track both max packet length and max flow length."""
        packets = []
        sizes = [100, 200, 300, 400, 500]
        for i, size in enumerate(sizes):
            src = "10.0.0.1" if i % 2 == 0 else "10.0.0.2"
            dst = "10.0.0.2" if i % 2 == 0 else "10.0.0.1"
            sport = 5000 if i % 2 == 0 else 80
            dport = 80 if i % 2 == 0 else 5000
            pkt = Packet(
                (
                    Ether()
                    / IP(src=src, dst=dst)
                    / TCP(sport=sport, dport=dport)
                    / Raw(b"x" * size)
                ).bytes()
            )
            pkt.parse()
            packets.append(pkt)

        config = FlowConfig(track_max_packet_len=True, track_max_flow_len=True)
        flows = extract_flows_from_packets(packets, config)
        conv = flows[0]

        # Both should be tracked
        assert conv.forward_max_packet_len is not None
        assert conv.reverse_max_packet_len is not None
        assert conv.max_flow_len is not None

        # max_flow_len should be >= both directional maxes
        assert conv.max_flow_len >= conv.forward_max_packet_len
        assert conv.max_flow_len >= conv.reverse_max_packet_len

    def test_max_packet_len_multiple_packets_same_direction(self):
        """Test that max_packet_len tracks the largest packet in multiple packets."""
        packets = []
        sizes = [50, 150, 100, 200, 75]  # Max is 200
        for size in sizes:
            pkt = Packet(
                (
                    Ether()
                    / IP(src="10.0.0.1", dst="10.0.0.2")
                    / TCP(sport=5000, dport=80)
                    / Raw(b"x" * size)
                ).bytes()
            )
            pkt.parse()
            packets.append(pkt)

        config = FlowConfig(track_max_packet_len=True)
        flows = extract_flows_from_packets(packets, config)
        conv = flows[0]

        # Largest packet is 200 bytes + headers
        assert conv.forward_max_packet_len is not None
        assert conv.forward_max_packet_len > 200

    def test_different_protocols_different_flows(self):
        """Test that TCP and UDP flows don't interfere with each other."""
        packets = []

        # TCP flow
        pkt = Packet(
            (
                Ether()
                / IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=5000, dport=80)
                / Raw(b"x" * 100)
            ).bytes()
        )
        pkt.parse()
        packets.append(pkt)

        # UDP flow
        pkt = Packet(
            (
                Ether()
                / IP(src="10.0.0.1", dst="10.0.0.2")
                / UDP(sport=5000, dport=53)
                / Raw(b"y" * 500)
            ).bytes()
        )
        pkt.parse()
        packets.append(pkt)

        config = FlowConfig(track_max_packet_len=True, track_max_flow_len=True)
        flows = extract_flows_from_packets(packets, config)

        # Should have 2 flows
        assert len(flows) == 2

        tcp_flow = next(f for f in flows if f.protocol == "TCP")
        udp_flow = next(f for f in flows if f.protocol == "UDP")

        # UDP should have larger packet
        assert udp_flow.max_flow_len > tcp_flow.max_flow_len

    def test_can_disable_tracking(self):
        """Test that setting flags to False disables tracking."""
        packets = []
        for i in range(3):
            pkt = Packet(
                (
                    Ether()
                    / IP(src="10.0.0.1", dst="10.0.0.2")
                    / TCP(sport=5000 + i, dport=80)
                    / Raw(b"x" * (100 + i * 50))
                ).bytes()
            )
            pkt.parse()
            packets.append(pkt)

        config = FlowConfig(track_max_packet_len=False, track_max_flow_len=False)
        flows = extract_flows_from_packets(packets, config)
        conv = flows[0]

        assert conv.forward_max_packet_len is None
        assert conv.reverse_max_packet_len is None
        assert conv.max_flow_len is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
