#!/usr/bin/env python3
"""
Utility for comparing Stackforge and Scapy packets.

Usage:
    python compare_packets.py "Ether()/IP()/TCP()"
"""

import subprocess
import sys


def build_scapy_packet(expr: str) -> bytes:
    """Build packet with Scapy."""
    script = f"""
from scapy.all import *
import sys
pkt = {expr}
sys.stdout.buffer.write(raw(pkt))
"""
    result = subprocess.run(["python3", "-c", script], capture_output=True, check=True)
    return result.stdout


def build_stackforge_packet(expr: str) -> bytes:
    """
    Build packet with Stackforge.

    Note: This uses eval which is simplified - production code should use
    proper parsing or builder API.
    """
    # Import stackforge in subprocess to ensure clean environment
    script = f"""
from stackforge import *
import sys
pkt = {expr}
sys.stdout.buffer.write(pkt.bytes())
"""
    result = subprocess.run(["python3", "-c", script], capture_output=True, check=True)
    return result.stdout


def hexdump(data: bytes, label: str = ""):
    """Pretty print hexdump."""
    if label:
        print(f"\n{label}:")
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{i:04x}: {hex_str:<48} {ascii_str}")


def compare_packets(expr: str):
    """Compare Stackforge and Scapy packet output."""
    print(f"Building: {expr}")
    print("=" * 80)

    try:
        stackforge = build_stackforge_packet(expr)
        print(f"\nStackforge: {len(stackforge)} bytes")
    except subprocess.CalledProcessError as e:
        print(f"\nStackforge build failed: {e.stderr.decode()}")
        return
    except Exception as e:
        print(f"\nStackforge build error: {e}")
        return

    try:
        scapy = build_scapy_packet(expr)
        print(f"Scapy:      {len(scapy)} bytes")
    except subprocess.CalledProcessError as e:
        print(f"\nScapy build failed: {e.stderr.decode()}")
        return

    hexdump(stackforge, "Stackforge Hexdump")
    hexdump(scapy, "Scapy Hexdump")

    if stackforge == scapy:
        print("\n" + "=" * 80)
        print("✓ Packets match exactly!")
        print("=" * 80)
    else:
        print("\n" + "=" * 80)
        print("✗ Packets differ:")
        print("=" * 80)
        for i, (sf, sc) in enumerate(zip(stackforge, scapy)):
            if sf != sc:
                print(f"  Offset {i}: Stackforge {sf:#04x} vs Scapy {sc:#04x}")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print('Usage: python compare_packets.py "Ether()/IP()/TCP()"')
        print("\nExamples:")
        print('  python compare_packets.py "Ether()"')
        print('  python compare_packets.py "Ether()/ARP()"')
        print("  python compare_packets.py \"Ether()/IP(dst='192.168.1.1')/TCP(dport=80)\"")
        sys.exit(1)

    compare_packets(sys.argv[1])


if __name__ == "__main__":
    main()
