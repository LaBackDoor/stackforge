"""COTP protocol tests."""

from stackforge import COTP, LayerKind, Packet


class TestCotpBuilder:
    def test_default_dt(self):
        data = COTP().bytes()
        assert len(data) == 3
        assert data[0] == 0x02  # LI = 2
        assert data[1] == 0xF0  # DT

    def test_repr(self):
        assert repr(COTP()) == "<COTP>"


class TestCotpParsing:
    def test_cotp_inside_tpkt(self):
        from stackforge import IP, TCP, TPKT, Ether

        cotp_data = COTP().bytes()
        tpkt_data = TPKT(payload=cotp_data).bytes()
        stack = Ether() / IP(dst="192.168.1.1") / TCP(dport=102) / tpkt_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.has_layer(LayerKind.Tpkt)
        assert pkt.has_layer(LayerKind.Cotp)
