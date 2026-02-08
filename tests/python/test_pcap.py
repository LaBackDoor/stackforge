"""Tests for PCAP read/write functionality."""

from stackforge import (
    IP,
    TCP,
    UDP,
    Ether,
    PcapPacket,
    PcapReader,
    rdpcap,
    wrpcap,
)


def _build_sample_packets():
    """Build a list of sample packets for testing."""
    pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
    pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="10.0.0.1") / UDP(dport=53)
    return [pkt1, pkt2]


class TestRdpcapWrpcap:
    def test_roundtrip(self, tmp_path):
        """Write packets and read them back."""
        packets = _build_sample_packets()
        pcap_file = str(tmp_path / "test.pcap")

        wrpcap(pcap_file, packets)
        result = rdpcap(pcap_file)

        assert len(result) == 2
        assert isinstance(result[0], PcapPacket)
        assert isinstance(result[1], PcapPacket)

    def test_roundtrip_preserves_data(self, tmp_path):
        """Packet bytes survive write/read roundtrip."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
        pcap_file = str(tmp_path / "test.pcap")

        wrpcap(pcap_file, [pkt])
        result = rdpcap(pcap_file)

        assert len(result) == 1
        # The packet data should match
        original_bytes = pkt.build().bytes()
        read_bytes = result[0].packet.bytes()
        assert original_bytes == read_bytes

    def test_rdpcap_count(self, tmp_path):
        """rdpcap with count limits number of packets."""
        packets = _build_sample_packets()
        pcap_file = str(tmp_path / "test.pcap")

        wrpcap(pcap_file, packets)
        result = rdpcap(pcap_file, count=1)

        assert len(result) == 1

    def test_empty_pcap(self, tmp_path):
        """Writing and reading an empty PCAP file."""
        pcap_file = str(tmp_path / "empty.pcap")

        wrpcap(pcap_file, [])
        result = rdpcap(pcap_file)

        assert len(result) == 0


class TestPcapPacket:
    def test_metadata(self, tmp_path):
        """PcapPacket has time and wirelen attributes."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
        pcap_file = str(tmp_path / "test.pcap")

        wrpcap(pcap_file, [pkt])
        result = rdpcap(pcap_file)

        assert result[0].time >= 0.0
        assert result[0].wirelen > 0

    def test_show(self, tmp_path):
        """PcapPacket.show() returns a string."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
        pcap_file = str(tmp_path / "test.pcap")

        wrpcap(pcap_file, [pkt])
        result = rdpcap(pcap_file)

        show_output = result[0].show()
        assert isinstance(show_output, str)
        assert "Ethernet" in show_output

    def test_summary(self, tmp_path):
        """PcapPacket.summary() returns a string."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
        pcap_file = str(tmp_path / "test.pcap")

        wrpcap(pcap_file, [pkt])
        result = rdpcap(pcap_file)

        summary = result[0].summary()
        assert isinstance(summary, str)

    def test_repr(self, tmp_path):
        """PcapPacket has a repr."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
        pcap_file = str(tmp_path / "test.pcap")

        wrpcap(pcap_file, [pkt])
        result = rdpcap(pcap_file)

        r = repr(result[0])
        assert "PcapPacket" in r
        assert "time=" in r

    def test_len(self, tmp_path):
        """PcapPacket supports len()."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
        pcap_file = str(tmp_path / "test.pcap")

        wrpcap(pcap_file, [pkt])
        result = rdpcap(pcap_file)

        assert len(result[0]) > 0


class TestPcapReader:
    def test_streaming(self, tmp_path):
        """PcapReader iterates over packets one at a time."""
        packets = _build_sample_packets()
        pcap_file = str(tmp_path / "test.pcap")

        wrpcap(pcap_file, packets)

        count = 0
        for pkt in PcapReader(pcap_file):
            assert isinstance(pkt, PcapPacket)
            count += 1

        assert count == 2

    def test_streaming_empty(self, tmp_path):
        """PcapReader handles empty PCAP files."""
        pcap_file = str(tmp_path / "empty.pcap")

        wrpcap(pcap_file, [])

        count = 0
        for _pkt in PcapReader(pcap_file):
            count += 1

        assert count == 0

    def test_invalid_file(self):
        """PcapReader raises IOError for invalid files."""
        import pytest

        with pytest.raises(IOError):
            PcapReader("/nonexistent/file.pcap")


class TestWrpcapInputTypes:
    def test_write_layer_stacks(self, tmp_path):
        """wrpcap accepts LayerStack objects (from / operator)."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
        pcap_file = str(tmp_path / "test.pcap")

        wrpcap(pcap_file, [pkt])
        result = rdpcap(pcap_file)
        assert len(result) == 1

    def test_write_pcap_packets(self, tmp_path):
        """wrpcap accepts PcapPacket objects (preserving metadata)."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
        pcap_file = str(tmp_path / "original.pcap")

        wrpcap(pcap_file, [pkt])
        original = rdpcap(pcap_file)

        # Re-write the PcapPacket objects
        pcap_file2 = str(tmp_path / "copy.pcap")
        wrpcap(pcap_file2, original)
        copied = rdpcap(pcap_file2)

        assert len(copied) == 1
        assert copied[0].packet.bytes() == original[0].packet.bytes()
