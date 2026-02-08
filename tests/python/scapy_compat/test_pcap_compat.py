"""PCAP parsing compatibility tests: Stackforge rdpcap vs Scapy rdpcap.

Reads real PCAP captures from tests/sample_pcap/ with both libraries and
compares packet count, raw bytes, and parsed layer structure.
"""

import json
import subprocess
from pathlib import Path

import pytest
from stackforge import PcapReader, rdpcap

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent / "sample_pcap" / "tcprelay"
TEST_PCAP = SAMPLE_DIR / "test.pcap"
SMALL_FLOWS_PCAP = SAMPLE_DIR / "smallFlows.pcap"


def scapy_available() -> bool:
    """Check if Scapy is importable."""
    try:
        result = subprocess.run(
            ["python3", "-c", "from scapy.all import rdpcap"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


requires_scapy = pytest.mark.skipif(not scapy_available(), reason="Scapy not installed")
requires_test_pcap = pytest.mark.skipif(not TEST_PCAP.exists(), reason="test.pcap not found")
requires_small_flows = pytest.mark.skipif(
    not SMALL_FLOWS_PCAP.exists(), reason="smallFlows.pcap not found"
)


# ---------------------------------------------------------------------------
# Scapy helpers (run in subprocess to avoid import conflicts)
# ---------------------------------------------------------------------------


def scapy_rdpcap_info(pcap_path: str, limit: int = 0) -> list[dict]:
    """Read a PCAP with Scapy and return per-packet metadata as JSON.

    Returns list of dicts with keys:
      - len: int (raw packet length)
      - hex: str (full packet hex)
      - layers: list[str] (layer names)
      - time: float (timestamp)
    """
    limit_clause = f", count={limit}" if limit else ""
    script = f"""
import json, sys
from scapy.all import rdpcap, raw

pkts = rdpcap("{pcap_path}"{limit_clause})
info = []
for p in pkts:
    raw_bytes = raw(p)
    info.append({{
        "len": len(raw_bytes),
        "hex": raw_bytes.hex(),
        "layers": [layer.__class__.__name__ for layer in p.layers()],
        "time": float(p.time),
    }})
json.dump(info, sys.stdout)
"""
    result = subprocess.run(
        ["python3", "-c", script],
        capture_output=True,
        check=True,
        timeout=120,
    )
    return json.loads(result.stdout)


def scapy_packet_count(pcap_path: str) -> int:
    """Get packet count from Scapy without loading full metadata."""
    script = f"""
import sys
from scapy.all import rdpcap
pkts = rdpcap("{pcap_path}")
sys.stdout.write(str(len(pkts)))
"""
    result = subprocess.run(
        ["python3", "-c", script],
        capture_output=True,
        check=True,
        timeout=120,
    )
    return int(result.stdout.strip())


# ---------------------------------------------------------------------------
# Layer name mapping: Scapy class names -> Stackforge LayerKind names
# ---------------------------------------------------------------------------
SCAPY_TO_STACKFORGE_LAYER = {
    "Ether": "Ethernet",
    "802.3": "Dot3",
    "ARP": "ARP",
    "IP": "IPv4",
    "IPv6": "IPv6",
    "TCP": "TCP",
    "UDP": "UDP",
    "ICMP": "ICMP",
    "ICMPv6": "ICMPv6",
    "DNS": "DNS",
    "Raw": "Raw",
    "Padding": "Raw",
}


def stackforge_layer_names(pkt) -> list[str]:
    """Extract layer kind names from a Stackforge Packet."""
    return [layer.kind.name for layer in pkt.layers]


# ---------------------------------------------------------------------------
# Tests: test.pcap (141 packets, small)
# ---------------------------------------------------------------------------


@requires_scapy
@requires_test_pcap
class TestPcapCompatTestPcap:
    """Compare Stackforge vs Scapy on test.pcap."""

    def test_packet_count(self):
        """Both libraries read the same number of packets."""
        sf_packets = rdpcap(str(TEST_PCAP))
        scapy_count = scapy_packet_count(str(TEST_PCAP))
        assert (
            len(sf_packets) == scapy_count
        ), f"Stackforge read {len(sf_packets)}, Scapy read {scapy_count}"

    def test_raw_bytes_match(self):
        """Every packet's raw bytes match exactly."""
        sf_packets = rdpcap(str(TEST_PCAP))
        scapy_info = scapy_rdpcap_info(str(TEST_PCAP))

        assert len(sf_packets) == len(scapy_info), "Packet count mismatch"

        mismatches = []
        for i, (sf, sc) in enumerate(zip(sf_packets, scapy_info)):
            sf_hex = sf.packet.bytes().hex()
            sc_hex = sc["hex"]
            if sf_hex != sc_hex:
                mismatches.append(f"Pkt #{i}: SF len={len(sf_hex) // 2} SC len={len(sc_hex) // 2}")
        assert not mismatches, f"{len(mismatches)} packets differ:\n" + "\n".join(mismatches[:20])

    def test_packet_lengths(self):
        """Every packet has the same length in both libraries."""
        sf_packets = rdpcap(str(TEST_PCAP))
        scapy_info = scapy_rdpcap_info(str(TEST_PCAP))

        for i, (sf, sc) in enumerate(zip(sf_packets, scapy_info)):
            assert (
                len(sf.packet.bytes()) == sc["len"]
            ), f"Pkt #{i}: Stackforge {len(sf.packet.bytes())} vs Scapy {sc['len']}"

    def test_layer_detection(self):
        """Stackforge identifies the same top-level layers as Scapy."""
        sf_packets = rdpcap(str(TEST_PCAP))
        scapy_info = scapy_rdpcap_info(str(TEST_PCAP))

        mismatches = []
        for i, (sf, sc) in enumerate(zip(sf_packets, scapy_info)):
            sf_layers = stackforge_layer_names(sf.packet)
            # Map Scapy layer names, skip unknown ones
            sc_layers = [
                SCAPY_TO_STACKFORGE_LAYER[name]
                for name in sc["layers"]
                if name in SCAPY_TO_STACKFORGE_LAYER
            ]
            # Compare first layer (link layer) at minimum
            if sf_layers and sc_layers and sf_layers[0] != sc_layers[0]:
                mismatches.append(f"Pkt #{i}: SF={sf_layers} vs SC={sc_layers}")
        assert not mismatches, (
            f"{len(mismatches)} packets have different link layer:\n" + "\n".join(mismatches[:20])
        )

    def test_all_packets_parsed(self):
        """Every packet in test.pcap is successfully parsed (has layers)."""
        sf_packets = rdpcap(str(TEST_PCAP))
        unparsed = [i for i, p in enumerate(sf_packets) if not p.packet.layers]
        assert not unparsed, f"{len(unparsed)} packets unparsed: {unparsed[:20]}"

    def test_show_does_not_crash(self):
        """Calling show() on every parsed packet should not raise."""
        sf_packets = rdpcap(str(TEST_PCAP))
        for i, p in enumerate(sf_packets):
            try:
                output = p.packet.show()
                assert isinstance(output, str)
            except Exception as exc:
                pytest.fail(f"show() crashed on pkt #{i}: {exc}")

    def test_summary_does_not_crash(self):
        """Calling summary() on every parsed packet should not raise."""
        sf_packets = rdpcap(str(TEST_PCAP))
        for i, p in enumerate(sf_packets):
            try:
                output = p.packet.summary()
                assert isinstance(output, str)
            except Exception as exc:
                pytest.fail(f"summary() crashed on pkt #{i}: {exc}")

    def test_protocol_distribution(self):
        """Stackforge and Scapy agree on protocol distribution (TCP/UDP/etc.)."""
        sf_packets = rdpcap(str(TEST_PCAP))
        scapy_info = scapy_rdpcap_info(str(TEST_PCAP))

        def count_protocol(packets_info, scapy_name):
            return sum(1 for p in packets_info if scapy_name in p["layers"])

        def sf_count_protocol(packets, kind_name):
            return sum(
                1 for p in packets if any(layer.kind.name == kind_name for layer in p.packet.layers)
            )

        for scapy_name, sf_name in [("TCP", "TCP"), ("UDP", "UDP"), ("ICMP", "ICMP")]:
            sc_count = count_protocol(scapy_info, scapy_name)
            sf_count = sf_count_protocol(sf_packets, sf_name)
            assert sf_count == sc_count, f"{sf_name}: Stackforge={sf_count} vs Scapy={sc_count}"


# ---------------------------------------------------------------------------
# Tests: smallFlows.pcap (14,261 packets, 9.4 MB)
# ---------------------------------------------------------------------------


@requires_scapy
@requires_small_flows
class TestPcapCompatSmallFlows:
    """Compare Stackforge vs Scapy on smallFlows.pcap."""

    def test_packet_count(self):
        """Both libraries read the same number of packets."""
        sf_packets = rdpcap(str(SMALL_FLOWS_PCAP))
        scapy_count = scapy_packet_count(str(SMALL_FLOWS_PCAP))
        assert len(sf_packets) == scapy_count

    def test_raw_bytes_first_100(self):
        """First 100 packets match byte-for-byte."""
        sf_packets = rdpcap(str(SMALL_FLOWS_PCAP), count=100)
        scapy_info = scapy_rdpcap_info(str(SMALL_FLOWS_PCAP), limit=100)

        assert len(sf_packets) == len(scapy_info)

        mismatches = []
        for i, (sf, sc) in enumerate(zip(sf_packets, scapy_info)):
            sf_hex = sf.packet.bytes().hex()
            if sf_hex != sc["hex"]:
                mismatches.append(f"Pkt #{i}")
        assert not mismatches, f"{len(mismatches)}/100 packets differ: {mismatches}"

    def test_all_packets_parsed(self):
        """Every packet is successfully parsed (has at least one layer)."""
        sf_packets = rdpcap(str(SMALL_FLOWS_PCAP))
        unparsed = [i for i, p in enumerate(sf_packets) if not p.packet.layers]
        assert not unparsed, f"{len(unparsed)} packets unparsed (first 20): {unparsed[:20]}"

    def test_streaming_vs_bulk(self):
        """PcapReader and rdpcap produce identical results."""
        bulk = rdpcap(str(SMALL_FLOWS_PCAP))
        streaming = list(PcapReader(str(SMALL_FLOWS_PCAP)))

        assert len(bulk) == len(streaming)

        mismatches = []
        for i, (b, s) in enumerate(zip(bulk, streaming)):
            if b.packet.bytes() != s.packet.bytes():
                mismatches.append(i)
        assert not mismatches, f"{len(mismatches)} packets differ between bulk/streaming"

    def test_protocol_distribution(self):
        """Protocol counts match between Stackforge and Scapy."""
        sf_packets = rdpcap(str(SMALL_FLOWS_PCAP))

        # Get Scapy counts via subprocess
        script = f"""
import json, sys
from scapy.all import rdpcap

pkts = rdpcap("{SMALL_FLOWS_PCAP}")
counts = {{}}
for p in pkts:
    for layer in p.layers():
        name = layer.__class__.__name__
        counts[name] = counts.get(name, 0) + 1
json.dump(counts, sys.stdout)
"""
        result = subprocess.run(
            ["python3", "-c", script],
            capture_output=True,
            check=True,
            timeout=120,
        )
        scapy_counts = json.loads(result.stdout)

        # Compare key protocols
        for scapy_name, sf_name in [("TCP", "TCP"), ("UDP", "UDP"), ("ICMP", "ICMP")]:
            sc_count = scapy_counts.get(scapy_name, 0)
            sf_count = sum(
                1
                for p in sf_packets
                if any(layer.kind.name == sf_name for layer in p.packet.layers)
            )
            assert sf_count == sc_count, f"{sf_name}: Stackforge={sf_count} vs Scapy={sc_count}"

    def test_show_sample(self):
        """show() works on a sample of packets without crashing."""
        sf_packets = rdpcap(str(SMALL_FLOWS_PCAP), count=50)
        for i, p in enumerate(sf_packets):
            try:
                output = p.packet.show()
                assert isinstance(output, str)
                assert len(output) > 0
            except Exception as exc:
                pytest.fail(f"show() crashed on pkt #{i}: {exc}")
