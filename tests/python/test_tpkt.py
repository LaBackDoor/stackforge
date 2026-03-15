"""TPKT protocol tests."""

from stackforge import TPKT, LayerKind, Packet


class TestTpktBuilder:
    def test_default_build(self):
        data = TPKT().bytes()
        assert len(data) == 4
        assert data[0] == 0x03  # version
        assert data[1] == 0x00  # reserved

    def test_repr(self):
        assert repr(TPKT()) == "<TPKT>"

    def test_with_payload(self):
        data = TPKT(payload=b"\x02\xf0\x80").bytes()
        assert len(data) == 7
        length = int.from_bytes(data[2:4], "big")
        assert length == 7


class TestTpktParsing:
    def test_tpkt_over_tcp_102(self):
        """TPKT detected on TCP port 102."""
        from stackforge import IP, TCP, Ether

        tpkt_data = TPKT(payload=b"\x02\xf0\x80").bytes()
        stack = Ether() / IP(dst="192.168.1.1") / TCP(dport=102) / tpkt_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.has_layer(LayerKind.Tpkt)

    def test_tpkt_fields(self):
        from stackforge import IP, TCP, Ether

        tpkt_data = TPKT(payload=b"\x02\xf0\x80").bytes()
        stack = Ether() / IP(dst="192.168.1.1") / TCP(dport=102) / tpkt_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.getfieldval(LayerKind.Tpkt, "version") == 3
