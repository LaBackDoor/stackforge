"""S7 Comm protocol tests."""

from stackforge import LayerKind, Packet, S7Comm


class TestS7CommBuilder:
    def test_default_build(self):
        data = S7Comm().bytes()
        assert len(data) >= 10
        assert data[0] == 0x32  # protocol ID

    def test_with_rosctr(self):
        data = S7Comm(rosctr=0x01).bytes()
        assert data[1] == 0x01  # Job

    def test_repr(self):
        assert repr(S7Comm()) == "<S7Comm>"


class TestS7CommParsing:
    def test_s7comm_inside_tpkt_cotp(self):
        from stackforge import COTP, IP, TCP, TPKT, Ether

        s7_data = S7Comm(rosctr=0x01, function=0xF0).bytes()
        cotp_data = COTP().bytes()
        payload = cotp_data + s7_data
        tpkt_data = TPKT(payload=payload).bytes()
        stack = Ether() / IP(dst="192.168.1.1") / TCP(dport=102) / tpkt_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.has_layer(LayerKind.Tpkt)
        assert pkt.has_layer(LayerKind.Cotp)
        assert pkt.has_layer(LayerKind.S7Comm)
        assert pkt.getfieldval(LayerKind.S7Comm, "protocol_id") == 0x32

    def test_s7comm_fields(self):
        from stackforge import COTP, IP, TCP, TPKT, Ether

        s7_data = S7Comm(rosctr=0x01, function=0x04).bytes()
        cotp_data = COTP().bytes()
        payload = cotp_data + s7_data
        tpkt_data = TPKT(payload=payload).bytes()
        stack = Ether() / IP(dst="192.168.1.1") / TCP(dport=102) / tpkt_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.getfieldval(LayerKind.S7Comm, "rosctr") == 0x01
