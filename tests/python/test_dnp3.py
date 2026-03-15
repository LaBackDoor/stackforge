"""DNP3 protocol tests."""

from stackforge import DNP3, LayerKind, Packet


class TestDnp3Builder:
    def test_default_build(self):
        data = DNP3().bytes()
        assert len(data) >= 10
        assert data[0] == 0x05
        assert data[1] == 0x64

    def test_repr(self):
        assert repr(DNP3()) == "<DNP3>"

    def test_with_addresses(self):
        data = DNP3(dst=1, src=0).bytes()
        assert data[0] == 0x05
        assert data[1] == 0x64


class TestDnp3Parsing:
    def test_dnp3_over_tcp_20000(self):
        from stackforge import IP, TCP, Ether

        dnp3_data = DNP3(dst=1, src=0).bytes()
        stack = Ether() / IP(dst="192.168.1.1") / TCP(dport=20000) / dnp3_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.has_layer(LayerKind.Dnp3)

    def test_dnp3_over_udp_20000(self):
        from stackforge import IP, UDP, Ether

        dnp3_data = DNP3(dst=1, src=0).bytes()
        stack = Ether() / IP(dst="192.168.1.1") / UDP(sport=20000, dport=20000) / dnp3_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.has_layer(LayerKind.Dnp3)

    def test_dnp3_fields(self):
        from stackforge import IP, TCP, Ether

        dnp3_data = DNP3(dst=1, src=0).bytes()
        stack = Ether() / IP(dst="192.168.1.1") / TCP(dport=20000) / dnp3_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.getfieldval(LayerKind.Dnp3, "dst") == 1
        assert pkt.getfieldval(LayerKind.Dnp3, "src") == 0

    def test_dnp3_not_detected_wrong_port(self):
        from stackforge import IP, TCP, Ether

        dnp3_data = DNP3().bytes()
        stack = Ether() / IP(dst="192.168.1.1") / TCP(dport=9999) / dnp3_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert not pkt.has_layer(LayerKind.Dnp3)
