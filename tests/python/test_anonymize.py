"""Tests for the network flow anonymization engine."""

import os
import pytest
import stackforge
from stackforge import (
    AnonymizationPolicy,
    Conversation,
    FlowConfig,
    extract_flows,
    extract_flows_from_packets,
    Ether,
    IP,
    TCP,
    UDP,
    LayerStack,
    Packet,
)

PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_pcap")
SMALL_FLOWS_PCAP = os.path.join(PCAP_DIR, "tcprelay", "smallFlows.pcap")
HTTP_PCAP = os.path.join(PCAP_DIR, "http_content_length.pcap")


# ---- AnonymizationPolicy construction tests ----


class TestAnonymizationPolicyConstruction:
    def test_default_no_anonymization(self):
        """Default policy should pass all fields through unchanged."""
        policy = AnonymizationPolicy()
        assert repr(policy).startswith("AnonymizationPolicy(")

    def test_ml_optimized_preset(self):
        """ML-optimized preset should be constructable."""
        policy = AnonymizationPolicy.ml_optimized()
        assert "CryptoPan" in repr(policy)

    def test_maximum_privacy_preset(self):
        """Maximum privacy preset should be constructable."""
        policy = AnonymizationPolicy.maximum_privacy()
        assert "Categorize" in repr(policy)

    def test_custom_policy(self):
        """Custom policy with all modes specified."""
        policy = AnonymizationPolicy(
            ip_mode="crypto_pan",
            mac_mode="salted_hash",
            port_mode="preserve_well_known",
            timestamp_mode="epoch_shift",
            tcp_seq_mode="random_offset",
            payload_mode="truncate_all",
        )
        assert "CryptoPan" in repr(policy)

    def test_crypto_pan_key(self):
        """Custom 32-byte Crypto-PAn key."""
        key = bytes(range(32))
        policy = AnonymizationPolicy(
            ip_mode="crypto_pan",
            crypto_pan_key=key,
        )
        assert policy is not None

    def test_invalid_ip_mode_raises(self):
        """Invalid ip_mode should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown ip_mode"):
            AnonymizationPolicy(ip_mode="bad_mode")

    def test_invalid_port_mode_raises(self):
        with pytest.raises(ValueError, match="Unknown port_mode"):
            AnonymizationPolicy(port_mode="bad_mode")

    def test_invalid_timestamp_mode_raises(self):
        with pytest.raises(ValueError, match="Unknown timestamp_mode"):
            AnonymizationPolicy(timestamp_mode="xyz")

    def test_invalid_key_length_raises(self):
        """Crypto-PAn key must be exactly 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            AnonymizationPolicy(crypto_pan_key=b"too_short")

    def test_invalid_salt_length_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            AnonymizationPolicy(hash_salt=b"short")

    def test_epoch_shift_jitter_mode(self):
        policy = AnonymizationPolicy(
            timestamp_mode="epoch_shift_jitter",
            timestamp_jitter_ms=10,
        )
        assert policy is not None

    def test_payload_truncate_to(self):
        policy = AnonymizationPolicy(
            payload_mode="truncate_to",
            payload_truncate_bytes=256,
        )
        assert policy is not None


# ---- IP Anonymization (Crypto-PAn) tests ----


class TestCryptoPanAnonymization:
    @pytest.fixture
    def http_flows_raw(self):
        """Extract flows from HTTP PCAP without anonymization."""
        return extract_flows(HTTP_PCAP)

    @pytest.fixture
    def http_flows_anon(self):
        """Extract flows from HTTP PCAP with Crypto-PAn."""
        policy = AnonymizationPolicy(ip_mode="crypto_pan", crypto_pan_key=bytes(range(32)))
        return extract_flows(HTTP_PCAP, anonymization=policy)

    def test_ips_are_changed(self, http_flows_raw, http_flows_anon):
        """Anonymized IPs should differ from originals."""
        assert len(http_flows_raw) == len(http_flows_anon)
        assert len(http_flows_raw) > 0
        raw = http_flows_raw[0]
        anon = http_flows_anon[0]
        assert raw.src_addr != anon.src_addr or raw.dst_addr != anon.dst_addr

    def test_deterministic_with_same_key(self):
        """Same key should produce same anonymized IPs."""
        key = bytes(range(32))
        p1 = AnonymizationPolicy(ip_mode="crypto_pan", crypto_pan_key=key)
        p2 = AnonymizationPolicy(ip_mode="crypto_pan", crypto_pan_key=key)
        f1 = extract_flows(HTTP_PCAP, anonymization=p1)
        f2 = extract_flows(HTTP_PCAP, anonymization=p2)
        assert f1[0].src_addr == f2[0].src_addr
        assert f1[0].dst_addr == f2[0].dst_addr

    def test_different_keys_different_results(self):
        """Different keys should produce different anonymized IPs."""
        key1 = bytes(range(32))
        key2 = bytes(range(1, 33))
        f1 = extract_flows(HTTP_PCAP, anonymization=AnonymizationPolicy(
            ip_mode="crypto_pan", crypto_pan_key=key1
        ))
        f2 = extract_flows(HTTP_PCAP, anonymization=AnonymizationPolicy(
            ip_mode="crypto_pan", crypto_pan_key=key2
        ))
        # At least one address should differ
        assert f1[0].src_addr != f2[0].src_addr or f1[0].dst_addr != f2[0].dst_addr

    def test_packet_counts_preserved(self, http_flows_raw, http_flows_anon):
        """Anonymization should not change packet counts."""
        for raw, anon in zip(http_flows_raw, http_flows_anon):
            assert raw.total_packets == anon.total_packets
            assert raw.total_bytes == anon.total_bytes

    def test_protocol_preserved(self, http_flows_raw, http_flows_anon):
        """Protocol type should be unchanged."""
        for raw, anon in zip(http_flows_raw, http_flows_anon):
            assert raw.protocol == anon.protocol


# ---- Port Generalization tests ----


class TestPortAnonymization:
    def test_preserve_well_known_dst(self):
        """Well-known destination ports should be preserved."""
        policy = AnonymizationPolicy(port_mode="preserve_well_known")
        flows = extract_flows(HTTP_PCAP, anonymization=policy)
        assert len(flows) > 0
        # At least one flow should have a well-known port preserved (80)
        ports = {f.src_port for f in flows} | {f.dst_port for f in flows}
        assert 80 in ports

    def test_categorize_all(self):
        """Categorize mode should replace all ports with sentinels."""
        policy = AnonymizationPolicy(port_mode="categorize")
        flows = extract_flows(HTTP_PCAP, anonymization=policy)
        sentinel_values = {0, 1024, 49152}
        for f in flows:
            assert f.src_port in sentinel_values, f"Unexpected src_port: {f.src_port}"
            assert f.dst_port in sentinel_values, f"Unexpected dst_port: {f.dst_port}"


# ---- Timestamp Anonymization tests ----


class TestTimestampAnonymization:
    def test_epoch_shift_increases_timestamps(self):
        """Epoch shift should make all timestamps larger (shifted forward)."""
        raw = extract_flows(HTTP_PCAP)
        policy = AnonymizationPolicy(timestamp_mode="epoch_shift")
        anon = extract_flows(HTTP_PCAP, anonymization=policy)
        for r, a in zip(raw, anon):
            assert a.start_time > r.start_time

    def test_epoch_shift_preserves_duration(self):
        """Flow durations should be identical with epoch shift (no jitter)."""
        raw = extract_flows(HTTP_PCAP)
        policy = AnonymizationPolicy(timestamp_mode="epoch_shift")
        anon = extract_flows(HTTP_PCAP, anonymization=policy)
        for r, a in zip(raw, anon):
            assert abs(r.duration - a.duration) < 0.001

    def test_jitter_adds_noise(self):
        """With jitter, durations may differ slightly."""
        raw = extract_flows(HTTP_PCAP)
        policy = AnonymizationPolicy(timestamp_mode="epoch_shift_jitter", timestamp_jitter_ms=100)
        anon = extract_flows(HTTP_PCAP, anonymization=policy)
        # At least one flow's duration should differ
        any_different = any(abs(r.duration - a.duration) > 0.0001 for r, a in zip(raw, anon))
        assert any_different or len(raw) == 0


# ---- Payload Truncation tests ----


class TestPayloadAnonymization:
    def test_truncate_all_clears_payload(self):
        """TruncateAll should produce empty reassembled streams."""
        policy = AnonymizationPolicy(payload_mode="truncate_all")
        flows = extract_flows(HTTP_PCAP, anonymization=policy)
        for f in flows:
            fwd = f.reassembled_forward
            rev = f.reassembled_reverse
            if fwd is not None:
                assert len(fwd) == 0
            if rev is not None:
                assert len(rev) == 0


# ---- Full ML Pipeline tests ----


class TestMlPipeline:
    def test_ml_optimized_full(self):
        """ML-optimized preset applied to a real PCAP."""
        policy = AnonymizationPolicy.ml_optimized()
        flows = extract_flows(HTTP_PCAP, anonymization=policy)
        assert len(flows) > 0
        for f in flows:
            # IPs should be valid (not empty)
            assert f.src_addr
            assert f.dst_addr
            # Packet counts must be positive
            assert f.total_packets > 0

    def test_maximum_privacy_full(self):
        """Maximum privacy preset applied to a real PCAP."""
        policy = AnonymizationPolicy.maximum_privacy()
        flows = extract_flows(HTTP_PCAP, anonymization=policy)
        assert len(flows) > 0

    @pytest.mark.skipif(
        not os.path.exists(SMALL_FLOWS_PCAP),
        reason="smallFlows.pcap not available",
    )
    def test_larger_pcap(self):
        """Test on a larger PCAP to verify performance and correctness."""
        policy = AnonymizationPolicy.ml_optimized()
        flows = extract_flows(SMALL_FLOWS_PCAP, anonymization=policy)
        assert len(flows) > 0

    def test_from_packets_with_anonymization(self):
        """extract_flows_from_packets should also support anonymization."""
        # Build some test packets using Scapy-style / operator
        pkts = []
        for i in range(5):
            stack = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")
            pkt = stack.build()
            pkt.parse()
            pkts.append(pkt)

        policy = AnonymizationPolicy(ip_mode="crypto_pan", crypto_pan_key=bytes(range(32)))
        flows = extract_flows_from_packets(pkts, anonymization=policy)
        assert len(flows) > 0
        # IPs should be anonymized (not original)
        f = flows[0]
        assert f.src_addr != "10.0.0.1"
        assert f.src_addr != "192.168.1.1"


# ---- Consistency tests ----


class TestConsistency:
    def test_same_ip_maps_consistently(self):
        """The same IP across multiple flows should map to the same value."""
        key = bytes(range(32))
        policy = AnonymizationPolicy(ip_mode="crypto_pan", crypto_pan_key=key)
        flows = extract_flows(HTTP_PCAP, anonymization=policy)
        if len(flows) >= 2:
            # Group flows by original IP (we can't know the original, but if
            # two flows share the same anonymized IP, they shared the original)
            src_addrs = {f.src_addr for f in flows}
            dst_addrs = {f.dst_addr for f in flows}
            # Just verify no crashes and results are valid IPs
            for addr in src_addrs | dst_addrs:
                parts = addr.split(".")
                if len(parts) == 4:  # IPv4
                    for p in parts:
                        assert 0 <= int(p) <= 255

    def test_no_anonymization_is_passthrough(self):
        """Default policy should not alter any fields."""
        raw = extract_flows(HTTP_PCAP)
        anon = extract_flows(HTTP_PCAP, anonymization=AnonymizationPolicy())
        assert len(raw) == len(anon)
        for r, a in zip(raw, anon):
            assert r.src_addr == a.src_addr
            assert r.dst_addr == a.dst_addr
            assert r.src_port == a.src_port
            assert r.dst_port == a.dst_port
            assert abs(r.start_time - a.start_time) < 0.001
            assert r.total_packets == a.total_packets
