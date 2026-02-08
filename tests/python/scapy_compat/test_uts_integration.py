"""Integration with Scapy .uts test specifications."""

import re
from pathlib import Path

import pytest


class TestUTSIntegration:
    """Run selected tests from Scapy .uts files."""

    @pytest.fixture
    def uts_dir(self):
        """Path to uts directory."""
        return Path(__file__).parent.parent.parent / "uts"

    def extract_uts_tests(self, uts_file: Path) -> list[tuple[str, str]]:
        """
        Extract test cases from .uts file.

        Returns:
            List of (test_name, test_code) tuples
        """
        if not uts_file.exists():
            return []

        content = uts_file.read_text()

        # Simple regex to find test blocks (= Test Name)
        pattern = r"^=\s+(.+?)$(.+?)(?=^=|\Z)"
        matches = re.findall(pattern, content, re.MULTILINE | re.DOTALL)

        return [(name.strip(), code.strip()) for name, code in matches]

    def test_uts_files_exist(self, uts_dir):
        """Verify .uts files exist in tests/uts/ directory."""
        expected_files = ["l2.uts", "inet.uts", "inet6.uts", "l2tp.uts"]
        for filename in expected_files:
            uts_file = uts_dir / filename
            assert uts_file.exists(), f"{filename} should exist in tests/uts/"

    def test_uts_l2_basic_structure(self, uts_dir):
        """Test basic structure of l2.uts file."""
        uts_file = uts_dir / "l2.uts"
        tests = self.extract_uts_tests(uts_file)
        assert len(tests) > 0, "Should extract at least one test from l2.uts"

    def test_uts_inet_basic_structure(self, uts_dir):
        """Test basic structure of inet.uts file."""
        uts_file = uts_dir / "inet.uts"
        tests = self.extract_uts_tests(uts_file)
        assert len(tests) > 0, "Should extract at least one test from inet.uts"

    def test_uts_inet6_basic_structure(self, uts_dir):
        """Test basic structure of inet6.uts file."""
        uts_file = uts_dir / "inet6.uts"
        tests = self.extract_uts_tests(uts_file)
        assert len(tests) > 0, "Should extract at least one test from inet6.uts"

    def test_uts_l2tp_basic_structure(self, uts_dir):
        """Test basic structure of l2tp.uts file."""
        uts_file = uts_dir / "l2tp.uts"
        tests = self.extract_uts_tests(uts_file)
        assert len(tests) > 0, "Should extract at least one test from l2tp.uts"

    # TODO: Add specific .uts test conversions
    # Example structure for porting .uts tests:
    #
    # def test_l2_uts_arp_basic(self, compare_with_scapy):
    #     """Test basic ARP packet from l2.uts."""
    #     from stackforge import ARP
    #
    #     stackforge_pkt = ARP().bytes()
    #     matches, report = compare_with_scapy(stackforge_pkt, "ARP()")
    #     assert matches, report
    #
    # def test_inet_uts_ip_default(self, compare_with_scapy):
    #     """Test default IP packet from inet.uts."""
    #     from stackforge import IP
    #
    #     stackforge_pkt = IP().bytes()
    #     matches, report = compare_with_scapy(stackforge_pkt, "IP()")
    #     assert matches, report
