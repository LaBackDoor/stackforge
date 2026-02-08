"""Shared fixtures and utilities for Scapy compatibility tests."""

import subprocess
from typing import Optional

import pytest


class ScapyCompat:
    """Helper class for Scapy compatibility testing."""

    @staticmethod
    def build_scapy_packet(scapy_expr: str) -> bytes:
        """
        Build a packet using Scapy and return raw bytes.

        Args:
            scapy_expr: Scapy expression like "Ether()/IP()/TCP()"

        Returns:
            Raw packet bytes from Scapy

        Raises:
            subprocess.CalledProcessError: If Scapy command fails
        """
        script = f"""
from scapy.all import *
import sys

pkt = {scapy_expr}
sys.stdout.buffer.write(raw(pkt))
"""
        result = subprocess.run(
            ["python3", "-c", script], capture_output=True, check=True, timeout=10
        )
        return result.stdout

    @staticmethod
    def compare_bytes(
        stackforge_bytes: bytes,
        scapy_bytes: bytes,
        ignore_fields: Optional[list[tuple[int, int]]] = None,
    ) -> tuple[bool, str]:
        """
        Compare two byte arrays, optionally ignoring specific byte ranges.

        Args:
            stackforge_bytes: Bytes from Stackforge
            scapy_bytes: Bytes from Scapy
            ignore_fields: List of (start, end) tuples to ignore (e.g., checksums)

        Returns:
            (matches, diff_report) tuple where matches is True if bytes match,
            and diff_report describes any differences
        """
        if ignore_fields is None:
            ignore_fields = []

        if len(stackforge_bytes) != len(scapy_bytes):
            return (
                False,
                f"Length mismatch: {len(stackforge_bytes)} vs {len(scapy_bytes)}",
            )

        # Create mask for ignored fields
        mask = [True] * len(stackforge_bytes)
        for start, end in ignore_fields:
            for i in range(start, min(end, len(mask))):
                mask[i] = False

        # Compare byte by byte
        diffs = []
        for i, (sf_byte, sc_byte) in enumerate(zip(stackforge_bytes, scapy_bytes)):
            if mask[i] and sf_byte != sc_byte:
                diffs.append(f"Offset {i}: {sf_byte:#04x} vs {sc_byte:#04x}")

        if diffs:
            # Show first 10 diffs to avoid overwhelming output
            diff_report = "\n".join(diffs[:10])
            if len(diffs) > 10:
                diff_report += f"\n... and {len(diffs) - 10} more differences"
            return False, diff_report

        return True, "Packets match"

    @staticmethod
    def hexdump_compare(stackforge_bytes: bytes, scapy_bytes: bytes) -> str:
        """
        Generate side-by-side hexdump for comparison.

        Args:
            stackforge_bytes: Bytes from Stackforge
            scapy_bytes: Bytes from Scapy

        Returns:
            Formatted string with side-by-side hexdumps
        """

        def hexdump(data: bytes, label: str) -> str:
            """Generate hexdump of data with label."""
            lines = [f"\n{label}:"]
            for i in range(0, len(data), 16):
                chunk = data[i : i + 16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"{i:04x}: {hex_str:<48} {ascii_str}")
            return "\n".join(lines)

        return hexdump(stackforge_bytes, "Stackforge") + "\n" + hexdump(scapy_bytes, "Scapy")


@pytest.fixture
def scapy_compat():
    """Provide ScapyCompat helper instance."""
    return ScapyCompat()


@pytest.fixture
def compare_with_scapy(scapy_compat):
    """
    Fixture that returns a comparison function for easy testing.

    Usage:
        def test_example(compare_with_scapy):
            from stackforge import Ether, IP, TCP
            stackforge_pkt = Ether() / IP() / TCP()
            matches, report = compare_with_scapy(
                stackforge_pkt.bytes(),
                "Ether()/IP()/TCP()"
            )
            assert matches, report
    """

    def _compare(
        stackforge_bytes: bytes,
        scapy_expr: str,
        ignore_fields: Optional[list[tuple[int, int]]] = None,
    ) -> tuple[bool, str]:
        """
        Compare Stackforge bytes with Scapy expression.

        Args:
            stackforge_bytes: Raw bytes from Stackforge packet
            scapy_expr: Scapy expression string
            ignore_fields: Optional list of (start, end) byte ranges to ignore

        Returns:
            (matches, report) tuple
        """
        try:
            scapy_bytes = scapy_compat.build_scapy_packet(scapy_expr)
        except subprocess.CalledProcessError as e:
            return False, f"Scapy build failed: {e.stderr.decode()}"
        except subprocess.TimeoutExpired:
            return False, "Scapy build timed out"

        matches, report = scapy_compat.compare_bytes(stackforge_bytes, scapy_bytes, ignore_fields)

        if not matches:
            # Add hexdump for debugging
            hexdump = scapy_compat.hexdump_compare(stackforge_bytes, scapy_bytes)
            report = f"{report}\n{hexdump}"

        return matches, report

    return _compare
