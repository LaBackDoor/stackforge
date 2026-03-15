"""CoAP protocol tests."""

from stackforge import IP, UDP, CoAP, Ether, LayerKind, Packet


class TestCoapBuilder:
    def test_default_build(self):
        """Default CoAP should be a CON GET."""
        pkt = CoAP()
        data = pkt.bytes()
        assert isinstance(data, bytes)
        assert len(data) >= 4
        # Version must be 1
        assert (data[0] >> 6) & 0x03 == 1

    def test_build_with_params(self):
        pkt = CoAP(msg_type=0, code_class=0, code_detail=1, msg_id=0x1234)
        data = pkt.bytes()
        assert len(data) >= 4

    def test_repr(self):
        assert repr(CoAP()) == "<CoAP>"


class TestCoapParsing:
    def test_coap_over_udp(self):
        """Build and parse a CoAP packet over Ethernet/IP/UDP."""
        coap_data = CoAP(msg_type=0, code_class=0, code_detail=1, msg_id=1).bytes()
        stack = Ether() / IP(dst="192.168.1.1") / UDP(dport=5683) / coap_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.has_layer(LayerKind.Coap)

    def test_coap_fields(self):
        coap_data = CoAP(msg_type=0, code_class=0, code_detail=1, msg_id=0x1234).bytes()
        stack = Ether() / IP(dst="192.168.1.1") / UDP(dport=5683) / coap_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert pkt.has_layer(LayerKind.Coap)
        assert pkt.getfieldval(LayerKind.Coap, "ver") == 1
        assert pkt.getfieldval(LayerKind.Coap, "msg_id") == 0x1234

    def test_coap_not_detected_wrong_port(self):
        """CoAP should not be detected on non-CoAP ports."""
        coap_data = CoAP().bytes()
        stack = Ether() / IP(dst="192.168.1.1") / UDP(dport=9999) / coap_data
        pkt = Packet(stack.bytes())
        pkt.parse()
        assert not pkt.has_layer(LayerKind.Coap)
