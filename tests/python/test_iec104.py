"""IEC 60870-5-104 protocol tests."""

from stackforge import IEC104, LayerKind, Packet


class TestIec104Builder:
    def test_default_u_format(self):
        data = IEC104().bytes()
        assert len(data) == 6
        assert data[0] == 0x68  # start byte
        assert data[1] == 0x04  # APDU length

    def test_repr(self):
        assert repr(IEC104()) == "<IEC104>"

    def test_startdt_act(self):
        data = IEC104(apdu_type="U", u_type=0x07).bytes()
        assert data[0] == 0x68
        assert data[2] == 0x07  # STARTDT_ACT

    def test_s_format(self):
        data = IEC104(apdu_type="S", rx=10).bytes()
        assert data[0] == 0x68

    def test_i_format(self):
        data = IEC104(apdu_type="I", tx=5, rx=3, type_id=1, cot=3, common_addr=1, ioa=100).bytes()
        assert data[0] == 0x68


class TestIec104Parsing:
    def test_iec104_over_tcp_2404(self):
        from stackforge import IP, TCP, Ether

        iec_data = IEC104(apdu_type="U", u_type=0x07).bytes()
        stack = Ether() / IP(dst="192.168.1.1") / TCP(dport=2404) / iec_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.has_layer(LayerKind.Iec104)

    def test_iec104_fields(self):
        from stackforge import IP, TCP, Ether

        iec_data = IEC104(apdu_type="U", u_type=0x07).bytes()
        stack = Ether() / IP(dst="192.168.1.1") / TCP(dport=2404) / iec_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.getfieldval(LayerKind.Iec104, "start") == 0x68
        assert pkt.getfieldval(LayerKind.Iec104, "apdu_length") == 4

    def test_iec104_not_detected_wrong_port(self):
        from stackforge import IP, TCP, Ether

        iec_data = IEC104().bytes()
        stack = Ether() / IP(dst="192.168.1.1") / TCP(dport=9999) / iec_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert not pkt.has_layer(LayerKind.Iec104)
