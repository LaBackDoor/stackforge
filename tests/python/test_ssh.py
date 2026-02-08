"""Tests for SSH protocol layer."""

from stackforge import SSH, LayerKind, rdpcap


class TestSSHBuilder:
    def test_ssh_class_exists(self):
        """SSH class should be importable."""
        ssh = SSH()
        assert ssh is not None

    def test_version_exchange_default(self):
        """SSH() creates a default version exchange."""
        ssh = SSH()
        raw = ssh.bytes()
        assert raw.startswith(b"SSH-2.0-")
        assert raw.endswith(b"\r\n")

    def test_version_exchange_custom(self):
        """SSH(version=...) creates a custom version exchange."""
        ssh = SSH(version="OpenSSH_9.2p1")
        raw = ssh.bytes()
        assert raw == b"SSH-2.0-OpenSSH_9.2p1\r\n"

    def test_version_exchange_classmethod(self):
        """SSH.version_exchange() factory method."""
        ssh = SSH.version_exchange("OpenSSH_9.2p1")
        raw = ssh.bytes()
        assert raw == b"SSH-2.0-OpenSSH_9.2p1\r\n"

    def test_repr(self):
        """SSH has a repr."""
        ssh = SSH()
        assert "SSH" in repr(ssh)


class TestSSHLayerKind:
    def test_ssh_layer_kind_exists(self):
        """LayerKind.Ssh should exist."""
        assert hasattr(LayerKind, "Ssh")

    def test_ssh_layer_kind_name(self):
        """LayerKind.Ssh should have name 'SSH'."""
        assert LayerKind.Ssh.name() == "SSH"


class TestSSHPcapParsing:
    def test_parse_ssh_pcap(self):
        """Parse SSH packets from the sample pcap."""
        packets = rdpcap("tests/sample_pcap/ssh_ed25519.pcap")
        assert len(packets) > 0

    def test_ssh_layer_detected(self):
        """SSH layers should be detected in SSH pcap."""
        packets = rdpcap("tests/sample_pcap/ssh_ed25519.pcap")

        found_ssh = False
        for pcap_pkt in packets:
            pkt = pcap_pkt.packet
            pkt.parse()
            if pkt.has_layer(LayerKind.Ssh):
                found_ssh = True
                break

        assert found_ssh, "Should find at least one SSH packet"

    def test_ssh_summary(self):
        """SSH packets should have SSH in summary."""
        packets = rdpcap("tests/sample_pcap/ssh_ed25519.pcap")

        for pcap_pkt in packets:
            pkt = pcap_pkt.packet
            pkt.parse()
            if pkt.has_layer(LayerKind.Ssh):
                summary = pkt.summary()
                assert "SSH" in summary
                break

    def test_ssh_show(self):
        """SSH packets should have SSH in show output."""
        packets = rdpcap("tests/sample_pcap/ssh_ed25519.pcap")

        for pcap_pkt in packets:
            pkt = pcap_pkt.packet
            pkt.parse()
            if pkt.has_layer(LayerKind.Ssh):
                show = pkt.show()
                assert "SSH" in show
                break
