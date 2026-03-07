"""Tests for the AnsweringMachine / Automata framework.

These tests verify the Python API surface and configuration without
actually starting network capture (which requires root privileges).
"""

import pytest

from stackforge import (
    AnsweringMachine,
    AutomatonConfig,
    DhcpPoolConfig,
    DhcpServerAM,
    Packet,
    LayerKind,
)


# ---------------------------------------------------------------------------
# AutomatonConfig
# ---------------------------------------------------------------------------


class TestAutomatonConfig:
    def test_default(self):
        config = AutomatonConfig()
        assert config is not None

    def test_with_iface(self):
        config = AutomatonConfig(iface="lo0")
        assert config is not None

    def test_with_bpf_filter(self):
        config = AutomatonConfig(bpf_filter="udp port 67")
        assert config is not None

    def test_with_all_params(self):
        config = AutomatonConfig(
            iface="en0",
            bpf_filter="tcp port 80",
            snaplen=1500,
            promisc=False,
        )
        assert config is not None


# ---------------------------------------------------------------------------
# DhcpPoolConfig
# ---------------------------------------------------------------------------


class TestDhcpPoolConfig:
    def test_default(self):
        pool = DhcpPoolConfig()
        r = repr(pool)
        assert "192.168.1.100" in r
        assert "192.168.1.200" in r
        assert "192.168.1.1" in r

    def test_custom_pool(self):
        pool = DhcpPoolConfig(
            pool_start="10.0.0.10",
            pool_end="10.0.0.200",
            server_ip="10.0.0.1",
            subnet_mask="255.255.255.0",
            gateway="10.0.0.1",
        )
        r = repr(pool)
        assert "10.0.0.10" in r
        assert "10.0.0.200" in r

    def test_with_dns(self):
        pool = DhcpPoolConfig(
            dns_servers=["8.8.8.8", "1.1.1.1"],
        )
        assert pool is not None

    def test_with_domain(self):
        pool = DhcpPoolConfig(domain="example.com")
        assert pool is not None

    def test_with_lease_time(self):
        pool = DhcpPoolConfig(lease_time=7200)
        r = repr(pool)
        assert "7200" in r

    def test_with_renewal_rebinding(self):
        pool = DhcpPoolConfig(
            lease_time=3600,
            renewal_time=1800,
            rebinding_time=3150,
        )
        assert pool is not None

    def test_invalid_ip_raises(self):
        with pytest.raises(ValueError, match="invalid IP"):
            DhcpPoolConfig(pool_start="not.an.ip")

    def test_invalid_dns_raises(self):
        with pytest.raises(ValueError, match="invalid IP"):
            DhcpPoolConfig(dns_servers=["bad"])


# ---------------------------------------------------------------------------
# DhcpServerAM
# ---------------------------------------------------------------------------


class TestDhcpServerAM:
    def test_create_default(self):
        pool = DhcpPoolConfig()
        server = DhcpServerAM(pool)
        assert server is not None
        assert not server.is_running

    def test_create_with_mac(self):
        pool = DhcpPoolConfig()
        server = DhcpServerAM(pool, server_mac="aa:bb:cc:dd:ee:ff")
        assert server is not None

    def test_create_with_sweep_interval(self):
        pool = DhcpPoolConfig()
        server = DhcpServerAM(pool, sweep_interval=30.0)
        assert server is not None

    def test_invalid_mac_raises(self):
        pool = DhcpPoolConfig()
        with pytest.raises(ValueError, match="invalid MAC"):
            DhcpServerAM(pool, server_mac="not-a-mac")

    def test_invalid_mac_octet_raises(self):
        pool = DhcpPoolConfig()
        with pytest.raises(ValueError, match="invalid MAC octet"):
            DhcpServerAM(pool, server_mac="zz:bb:cc:dd:ee:ff")

    def test_repr(self):
        pool = DhcpPoolConfig(
            pool_start="10.0.0.10",
            pool_end="10.0.0.50",
            server_ip="10.0.0.1",
        )
        server = DhcpServerAM(pool)
        r = repr(server)
        assert "10.0.0.10" in r
        assert "10.0.0.50" in r

    def test_stop_when_not_running(self):
        pool = DhcpPoolConfig()
        server = DhcpServerAM(pool)
        # Should not raise
        server.stop()

    def test_is_running_initially_false(self):
        pool = DhcpPoolConfig()
        server = DhcpServerAM(pool)
        assert not server.is_running


# ---------------------------------------------------------------------------
# AnsweringMachine (callback-based)
# ---------------------------------------------------------------------------


class TestAnsweringMachine:
    def test_create(self):
        def is_req(pkt):
            return True

        def make_rep(pkt):
            return None

        am = AnsweringMachine(is_req, make_rep)
        assert am is not None
        assert not am.is_running

    def test_create_with_bpf(self):
        am = AnsweringMachine(
            lambda pkt: True,
            lambda pkt: None,
            bpf_filter="udp port 67",
        )
        assert am is not None

    def test_stop_when_not_running(self):
        am = AnsweringMachine(lambda p: True, lambda p: None)
        # Should not raise
        am.stop()

    def test_is_running_initially_false(self):
        am = AnsweringMachine(lambda p: True, lambda p: None)
        assert not am.is_running


# ---------------------------------------------------------------------------
# Integration: verify all types importable
# ---------------------------------------------------------------------------


class TestImports:
    def test_all_automata_classes(self):
        from stackforge import (
            AnsweringMachine,
            AutomatonConfig,
            DhcpPoolConfig,
            DhcpServerAM,
        )
        assert AnsweringMachine is not None
        assert AutomatonConfig is not None
        assert DhcpPoolConfig is not None
        assert DhcpServerAM is not None
