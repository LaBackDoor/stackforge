"""Tests for TLS protocol layer."""

from stackforge import IP, TCP, TLS, Ether, LayerKind, Packet


class TestTLSBuilder:
    def test_tls_class_exists(self):
        """TLS class should be importable."""
        tls = TLS()
        assert tls is not None

    def test_default_tls_record(self):
        """Default TLS() creates a Handshake record with TLS 1.2."""
        tls = TLS()
        raw = tls.bytes()
        assert len(raw) == 5  # header only, no fragment
        assert raw[0] == 0x16  # Handshake
        assert raw[1:3] == b"\x03\x03"  # TLS 1.2

    def test_custom_content_type(self):
        """TLS(type=23) sets Application Data content type."""
        tls = TLS(type=23)
        raw = tls.bytes()
        assert raw[0] == 23  # ApplicationData

    def test_custom_version(self):
        """TLS(version=0x0301) sets TLS 1.0."""
        tls = TLS(version=0x0301)
        raw = tls.bytes()
        assert raw[1:3] == b"\x03\x01"

    def test_custom_fragment(self):
        """TLS(fragment=b'hello') includes fragment data."""
        tls = TLS(fragment=b"hello")
        raw = tls.bytes()
        assert len(raw) == 10  # 5 header + 5 fragment
        assert raw[5:] == b"hello"
        # Auto-calculated length
        length = int.from_bytes(raw[3:5], "big")
        assert length == 5

    def test_explicit_length(self):
        """TLS(len=100) overrides auto-calculated length."""
        tls = TLS(len=100, fragment=b"hi")
        raw = tls.bytes()
        length = int.from_bytes(raw[3:5], "big")
        assert length == 100
        assert len(raw) == 7  # 5 header + 2 fragment

    def test_alert_record(self):
        """Build an Alert record."""
        tls = TLS(type=21, version=0x0303, fragment=bytes([2, 40]))
        raw = tls.bytes()
        assert raw[0] == 0x15  # Alert
        assert raw[5] == 2  # fatal
        assert raw[6] == 40  # handshake_failure

    def test_ccs_record(self):
        """Build a ChangeCipherSpec record."""
        tls = TLS(type=20, version=0x0303, fragment=bytes([1]))
        raw = tls.bytes()
        assert raw[0] == 0x14  # CCS
        assert raw[5] == 0x01


class TestTLSStacking:
    def test_tls_with_tcp(self):
        """TCP() / TLS() stacking works."""
        stack = TCP(dport=443) / TLS()
        raw = stack.bytes()
        # TCP header (20 bytes min) + TLS header (5 bytes)
        assert len(raw) >= 25

    def test_full_stack(self):
        """Ether() / IP() / TCP() / TLS() full stack."""
        stack = Ether() / IP() / TCP(dport=443) / TLS(fragment=b"\x01\x00\x00\x01\x00")
        raw = stack.bytes()
        # Ethernet(14) + IP(20) + TCP(20) + TLS(5+5) = 64
        assert len(raw) == 64


class TestTLSLayerKind:
    def test_tls_layer_kind_exists(self):
        """LayerKind.Tls should exist."""
        assert hasattr(LayerKind, "Tls")

    def test_tls_layer_kind_name(self):
        """LayerKind.Tls should have name 'TLS'."""
        assert LayerKind.Tls.name() == "TLS"


# ============================================================================
# Tests derived from .uts test data
# ============================================================================


def hex_to_bytes(hex_str):
    """Convert space-separated hex string to bytes."""
    return bytes(int(x, 16) for x in hex_str.split())


class TestTLSRecordFromUts:
    """TLS record tests using data from tls13.uts."""

    def test_tls13_client_hello_record(self):
        """Build a TLS record matching the tls13.uts ClientHello record header."""
        # From tls13.uts: record type=0x16, version=0x0301, len=196
        ch_body = hex_to_bytes(
            "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da "
            "cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 "
            "13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 "
            "65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 "
            "01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 "
            "38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d "
            "54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 "
            "05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 "
            "02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01"
        )

        tls = TLS(type=0x16, version=0x0301, fragment=ch_body)
        raw = tls.bytes()

        # Verify record header
        assert raw[0] == 0x16  # Handshake
        assert raw[1:3] == b"\x03\x01"  # TLS 1.0 (legacy)
        length = int.from_bytes(raw[3:5], "big")
        assert length == 196  # matches t1.len == 196 from .uts
        assert raw[5] == 0x01  # ClientHello msg_type

    def test_tls13_server_hello_record(self):
        """Build a TLS record matching the tls13.uts ServerHello."""
        sh_body = hex_to_bytes(
            "02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 "
            "9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 "
            "00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db "
            "f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 "
            "02 03 04"
        )

        tls = TLS(type=0x16, version=0x0303, fragment=sh_body)
        raw = tls.bytes()

        assert raw[0] == 0x16  # Handshake
        assert raw[1:3] == b"\x03\x03"  # TLS 1.2
        assert raw[5] == 0x02  # ServerHello msg_type

    def test_tls13_encrypted_record(self):
        """Encrypted application data record header from tls13.uts."""
        # From tls13.uts: type=0x17 (ApplicationData), version=0x0303, len=674
        tls = TLS(type=0x17, version=0x0303, len=674)
        raw = tls.bytes()
        assert raw[0] == 0x17  # ApplicationData
        assert raw[1:3] == b"\x03\x03"
        length = int.from_bytes(raw[3:5], "big")
        assert length == 674

    def test_tls_alert_handshake_failure(self):
        """Build alert from tls.uts test data."""
        # TLS Alert: fatal (2) handshake_failure (40) = 0x0228
        tls = TLS(type=21, version=0x0303, fragment=bytes([2, 40]))
        raw = tls.bytes()
        assert raw[0] == 0x15  # Alert
        assert raw[1:3] == b"\x03\x03"
        assert raw[5] == 2  # fatal
        assert raw[6] == 40  # handshake_failure

    def test_tls_ccs_from_uts(self):
        """Build ChangeCipherSpec from tls.uts."""
        tls = TLS(type=20, version=0x0303, fragment=bytes([1]))
        raw = tls.bytes()
        assert raw[0] == 0x14  # CCS
        length = int.from_bytes(raw[3:5], "big")
        assert length == 1
        assert raw[5] == 0x01


class TestTLSApplicationData:
    """Application data tests inspired by .uts test patterns."""

    def test_application_data_payload(self):
        """TLS Application Data with payload."""
        payload = b"Hello, TLS!"
        tls = TLS(type=23, version=0x0303, fragment=payload)
        raw = tls.bytes()

        assert raw[0] == 0x17  # ApplicationData
        length = int.from_bytes(raw[3:5], "big")
        assert length == len(payload)
        assert raw[5:] == payload

    def test_application_data_binary(self):
        """TLS Application Data with binary payload."""
        payload = bytes(range(256))
        tls = TLS(type=23, version=0x0303, fragment=payload)
        raw = tls.bytes()

        assert raw[0] == 0x17
        length = int.from_bytes(raw[3:5], "big")
        assert length == 256
        assert raw[5:] == payload


class TestTLSVersions:
    """Test all TLS protocol versions from .uts files."""

    def test_sslv3(self):
        """SSLv3 (0x0300)."""
        tls = TLS(version=0x0300)
        raw = tls.bytes()
        assert raw[1:3] == b"\x03\x00"

    def test_tls10(self):
        """TLS 1.0 (0x0301) - used in tls13.uts ClientHello record."""
        tls = TLS(version=0x0301)
        raw = tls.bytes()
        assert raw[1:3] == b"\x03\x01"

    def test_tls11(self):
        """TLS 1.1 (0x0302)."""
        tls = TLS(version=0x0302)
        raw = tls.bytes()
        assert raw[1:3] == b"\x03\x02"

    def test_tls12(self):
        """TLS 1.2 (0x0303) - default and used throughout .uts."""
        tls = TLS(version=0x0303)
        raw = tls.bytes()
        assert raw[1:3] == b"\x03\x03"


class TestTLSPacketParsing:
    """Test TLS detection in parsed packets."""

    def test_parse_ethernet_ip_tcp_tls(self):
        """Parse Ether/IP/TCP/TLS packet and find TLS layer."""
        stack = Ether() / IP() / TCP(dport=443) / TLS(fragment=b"\x01\x00\x00\x01\x00")
        raw = stack.bytes()

        pkt = Packet(raw)
        pkt.parse()

        assert pkt.has_layer(LayerKind.Tls)
        assert pkt.has_layer(LayerKind.Tcp)

        summary = pkt.summary()
        assert "TLS" in summary

    def test_tls_show_output(self):
        """TLS show() output includes TLS info."""
        stack = Ether() / IP() / TCP(dport=443) / TLS()
        raw = stack.bytes()

        pkt = Packet(raw)
        pkt.parse()

        if pkt.has_layer(LayerKind.Tls):
            show = pkt.show()
            assert "TLS" in show

    def test_tls_repr(self):
        """TLS repr shows type info."""
        tls = TLS()
        assert "TLS" in repr(tls)

        tls2 = TLS(type=23, version=0x0303, fragment=b"test")
        assert "TLS" in repr(tls2)


class TestTLSEdgeCases:
    """Edge cases and permissive builder tests from .uts patterns."""

    def test_zero_length_fragment(self):
        """TLS record with empty fragment (header only)."""
        tls = TLS()
        raw = tls.bytes()
        assert len(raw) == 5
        length = int.from_bytes(raw[3:5], "big")
        assert length == 0

    def test_explicit_length_mismatch(self):
        """Permissive builder allows length != actual fragment size."""
        tls = TLS(len=999, fragment=b"short")
        raw = tls.bytes()
        length = int.from_bytes(raw[3:5], "big")
        assert length == 999  # explicit override
        assert len(raw) == 10  # 5 header + 5 actual fragment

    def test_invalid_content_type(self):
        """Permissive builder allows non-standard content types."""
        tls = TLS(type=0xFF)
        raw = tls.bytes()
        assert raw[0] == 0xFF

    def test_all_content_types(self):
        """Test all standard TLS content types."""
        content_types = {
            20: "ChangeCipherSpec",
            21: "Alert",
            22: "Handshake",
            23: "ApplicationData",
        }
        for ct, name in content_types.items():
            tls = TLS(type=ct)
            raw = tls.bytes()
            assert raw[0] == ct, f"Content type {name} ({ct}) mismatch"


class TestTLSPKICerts:
    """Tests using PKI certificate files from tests/uts/tls/pki/."""

    def test_load_server_cert_as_fragment(self):
        """Load server cert PEM and use as TLS fragment."""
        import os

        cert_path = "tests/uts/tls/pki/srv_cert.pem"
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                cert_data = f.read()

            # Build a TLS record carrying cert data as fragment
            tls = TLS(type=22, version=0x0303, fragment=cert_data)
            raw = tls.bytes()
            assert raw[0] == 0x16
            length = int.from_bytes(raw[3:5], "big")
            assert length == len(cert_data)
            assert raw[5:] == cert_data

    def test_load_all_pki_certs(self):
        """All PKI cert files should be loadable."""
        import os

        cert_files = [
            "tests/uts/tls/pki/ca_cert.pem",
            "tests/uts/tls/pki/srv_cert.pem",
            "tests/uts/tls/pki/cli_cert.pem",
            "tests/uts/tls/pki/srv_cert_ed25519.pem",
        ]
        for cert_path in cert_files:
            if os.path.exists(cert_path):
                with open(cert_path, "rb") as f:
                    data = f.read()
                assert len(data) > 0, f"{cert_path} should not be empty"
                assert b"BEGIN CERTIFICATE" in data, f"{cert_path} should be PEM"
