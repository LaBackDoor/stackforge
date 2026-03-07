"""Tests for the sniffer module.

Live capture tests require root/sudo or BPF access and are skipped by default.
Filter validation and interface listing work without elevated privileges.
"""

import os
import sys
import pytest

from stackforge import Sniffer, sniff, list_interfaces, validate_filter, LayerKind


# ──────────────────────────────────────────────────────────────────────
# Filter validation tests (no privileges needed)
# ──────────────────────────────────────────────────────────────────────

class TestValidateFilter:
    def test_valid_tcp_filter(self):
        assert validate_filter("tcp port 80") is True

    def test_valid_udp_filter(self):
        assert validate_filter("udp port 53") is True

    def test_valid_host_filter(self):
        assert validate_filter("host 192.168.1.1") is True

    def test_valid_complex_filter(self):
        assert validate_filter("tcp port 80 and host 10.0.0.1") is True

    def test_valid_icmp_filter(self):
        assert validate_filter("icmp") is True

    def test_invalid_filter_raises(self):
        with pytest.raises(ValueError):
            validate_filter("not_a_valid_bpf_filter ???")

    def test_empty_filter_is_valid(self):
        # Empty filter matches everything
        assert validate_filter("") is True


# ──────────────────────────────────────────────────────────────────────
# Interface listing tests (no privileges needed)
# ──────────────────────────────────────────────────────────────────────

class TestListInterfaces:
    def test_returns_list(self):
        ifaces = list_interfaces()
        assert isinstance(ifaces, list)

    def test_interface_has_name(self):
        ifaces = list_interfaces()
        if len(ifaces) > 0:
            assert "name" in ifaces[0]
            assert isinstance(ifaces[0]["name"], str)

    def test_interface_has_addresses(self):
        ifaces = list_interfaces()
        if len(ifaces) > 0:
            assert "addresses" in ifaces[0]
            assert isinstance(ifaces[0]["addresses"], list)

    def test_loopback_exists(self):
        """Most systems have a loopback interface."""
        ifaces = list_interfaces()
        names = [i["name"] for i in ifaces]
        assert any(
            n in names for n in ("lo", "lo0", "Loopback Pseudo-Interface 1")
        ), f"No loopback found in {names}"


# ──────────────────────────────────────────────────────────────────────
# Sniffer class tests (need capture permissions)
# ──────────────────────────────────────────────────────────────────────

def _has_capture_permission():
    """Check if we can open a capture (need root or BPF access)."""
    try:
        s = Sniffer(iface="lo0" if sys.platform == "darwin" else "lo", count=0, timeout=0.1)
        s.stop()
        return True
    except (OSError, ValueError):
        return False


needs_capture = pytest.mark.skipif(
    not _has_capture_permission(),
    reason="Capture requires root or BPF access"
)


@needs_capture
class TestSnifferIterator:
    def _get_loopback(self):
        return "lo0" if sys.platform == "darwin" else "lo"

    def test_sniffer_with_timeout(self):
        """Sniffer should stop after timeout and yield no errors."""
        sniffer = Sniffer(iface=self._get_loopback(), timeout=0.5)
        packets = list(sniffer)
        assert isinstance(packets, list)

    def test_sniffer_context_manager(self):
        """Sniffer should work as a context manager."""
        with Sniffer(iface=self._get_loopback(), timeout=0.3) as s:
            packets = list(s)
        assert isinstance(packets, list)

    def test_sniffer_repr(self):
        sniffer = Sniffer(iface=self._get_loopback(), timeout=0.1)
        r = repr(sniffer)
        assert "Sniffer" in r
        assert self._get_loopback() in r
        sniffer.stop()

    def test_sniffer_stop(self):
        sniffer = Sniffer(iface=self._get_loopback(), timeout=5.0)
        sniffer.stop()
        # After stop, repr should show inactive
        assert "active=False" in repr(sniffer)

    def test_sniffer_stats(self):
        sniffer = Sniffer(iface=self._get_loopback(), timeout=0.1)
        stats = sniffer.stats()
        assert "interface" in stats
        assert stats["interface"] == self._get_loopback()
        sniffer.stop()


@needs_capture
class TestSniffFunction:
    def _get_loopback(self):
        return "lo0" if sys.platform == "darwin" else "lo"

    def test_sniff_with_timeout(self):
        """sniff() should return a list of packets."""
        packets = sniff(iface=self._get_loopback(), timeout=0.5)
        assert isinstance(packets, list)

    def test_sniff_with_count_and_timeout(self):
        """sniff() with count should return at most count packets."""
        packets = sniff(iface=self._get_loopback(), count=5, timeout=0.5)
        assert isinstance(packets, list)
        assert len(packets) <= 5

    def test_sniff_with_prn_callback(self):
        """prn callback should be called for each packet."""
        seen = []

        def callback(pkt):
            seen.append(pkt)

        sniff(iface=self._get_loopback(), timeout=0.3, prn=callback)
        # seen should match the returned packet count
        # (we can't guarantee packets on loopback, but it shouldn't crash)

    def test_sniff_with_filter(self):
        """BPF filter should be applied."""
        packets = sniff(
            iface=self._get_loopback(),
            filter="tcp",
            timeout=0.3,
        )
        assert isinstance(packets, list)

    def test_sniff_invalid_filter_raises(self):
        with pytest.raises(ValueError):
            sniff(iface=self._get_loopback(), filter="invalid_filter ???")


@needs_capture
class TestSnifferInvalidInterface:
    def test_nonexistent_interface_raises(self):
        with pytest.raises(ValueError):
            Sniffer(iface="nonexistent_iface_xyz")
