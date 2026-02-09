//! Compatibility test utilities for comparing with Scapy output.
//!
//! This module provides utilities for byte-level comparison between
//! Stackforge packet builders and Scapy's output.

use std::process::Command;

/// Generate a packet using Scapy and return raw bytes.
///
/// # Arguments
///
/// * `expr` - Scapy expression like "Ether()/IP()/TCP()"
///
/// # Returns
///
/// Raw packet bytes built by Scapy
///
/// # Panics
///
/// Panics if Scapy command fails or times out
///
/// # Example
///
/// ```ignore
/// let scapy = scapy_build("Ether()");
/// assert_eq!(scapy.len(), 14); // Ethernet header size
/// ```
pub fn scapy_build(expr: &str) -> Vec<u8> {
    let script = format!(
        r#"
from scapy.all import *
import sys
pkt = {}
sys.stdout.buffer.write(raw(pkt))
"#,
        expr
    );

    let output = Command::new("python3")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("Failed to run Scapy command");

    assert!(
        output.status.success(),
        "Scapy command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    output.stdout
}

/// Compare two byte arrays, returning detailed diff on mismatch.
///
/// # Arguments
///
/// * `stackforge` - Bytes from Stackforge builder
/// * `scapy` - Bytes from Scapy
///
/// # Returns
///
/// `Ok(())` if bytes match, `Err(String)` with detailed diff if they don't
///
/// # Example
///
/// ```ignore
/// let stackforge = EthernetBuilder::new().build();
/// let scapy = scapy_build("Ether()");
/// compare_bytes(&stackforge, &scapy).unwrap();
/// ```
pub fn compare_bytes(stackforge: &[u8], scapy: &[u8]) -> Result<(), String> {
    if stackforge.len() != scapy.len() {
        return Err(format!(
            "Length mismatch: Stackforge {} bytes vs Scapy {} bytes",
            stackforge.len(),
            scapy.len()
        ));
    }

    let mut diffs = Vec::new();
    for (i, (sf_byte, sc_byte)) in stackforge.iter().zip(scapy.iter()).enumerate() {
        if sf_byte != sc_byte {
            diffs.push(format!(
                "Offset {}: {:#04x} vs {:#04x}",
                i, sf_byte, sc_byte
            ));
            // Limit to first 20 differences to avoid overwhelming output
            if diffs.len() >= 20 {
                diffs.push(format!("... (more differences not shown)"));
                break;
            }
        }
    }

    if !diffs.is_empty() {
        let diff_msg = format!(
            "Byte differences found:\n{}\n\nStackforge hexdump:\n{}\n\nScapy hexdump:\n{}",
            diffs.join("\n"),
            hexdump(stackforge),
            hexdump(scapy)
        );
        Err(diff_msg)
    } else {
        Ok(())
    }
}

/// Compare with optional field masking (e.g., to ignore checksums during initial tests).
///
/// # Arguments
///
/// * `stackforge` - Bytes from Stackforge builder
/// * `scapy` - Bytes from Scapy
/// * `ignore_ranges` - Slice of (start, end) tuples indicating byte ranges to ignore
///
/// # Returns
///
/// `Ok(())` if bytes match (excluding ignored ranges), `Err(String)` with diff if they don't
///
/// # Example
///
/// ```ignore
/// let stackforge = TcpBuilder::new().build();
/// let scapy = scapy_build("TCP()");
/// // Ignore TCP checksum at bytes 16-17
/// compare_bytes_masked(&stackforge, &scapy, &[(16, 18)]).unwrap();
/// ```
pub fn compare_bytes_masked(
    stackforge: &[u8],
    scapy: &[u8],
    ignore_ranges: &[(usize, usize)],
) -> Result<(), String> {
    if stackforge.len() != scapy.len() {
        return Err(format!(
            "Length mismatch: Stackforge {} bytes vs Scapy {} bytes",
            stackforge.len(),
            scapy.len()
        ));
    }

    // Create mask
    let mut mask = vec![true; stackforge.len()];
    for (start, end) in ignore_ranges {
        for i in *start..*end {
            if i < mask.len() {
                mask[i] = false;
            }
        }
    }

    let mut diffs = Vec::new();
    for (i, (sf_byte, sc_byte)) in stackforge.iter().zip(scapy.iter()).enumerate() {
        if mask[i] && sf_byte != sc_byte {
            diffs.push(format!(
                "Offset {}: {:#04x} vs {:#04x}",
                i, sf_byte, sc_byte
            ));
            if diffs.len() >= 20 {
                diffs.push(format!("... (more differences not shown)"));
                break;
            }
        }
    }

    if !diffs.is_empty() {
        let diff_msg = format!(
            "Byte differences found (with masking):\n{}\n\nStackforge hexdump:\n{}\n\nScapy hexdump:\n{}",
            diffs.join("\n"),
            hexdump(stackforge),
            hexdump(scapy)
        );
        Err(diff_msg)
    } else {
        Ok(())
    }
}

/// Generate hexdump of byte slice for debugging.
fn hexdump(data: &[u8]) -> String {
    let mut lines = Vec::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        let hex_part: String = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii_part: String = chunk
            .iter()
            .map(|&b| {
                if (32..127).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        lines.push(format!("{:04x}: {:<48} {}", offset, hex_part, ascii_part));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scapy_build_basic() {
        let scapy = scapy_build("Ether()");
        assert_eq!(scapy.len(), 14, "Ethernet header should be 14 bytes");
    }

    #[test]
    fn test_compare_bytes_identical() {
        let bytes1 = vec![1, 2, 3, 4, 5];
        let bytes2 = vec![1, 2, 3, 4, 5];
        assert!(compare_bytes(&bytes1, &bytes2).is_ok());
    }

    #[test]
    fn test_compare_bytes_different() {
        let bytes1 = vec![1, 2, 3, 4, 5];
        let bytes2 = vec![1, 2, 9, 4, 5];
        assert!(compare_bytes(&bytes1, &bytes2).is_err());
    }

    #[test]
    fn test_compare_bytes_masked() {
        let bytes1 = vec![1, 2, 3, 4, 5];
        let bytes2 = vec![1, 2, 9, 4, 5];
        // Ignore byte at offset 2
        assert!(compare_bytes_masked(&bytes1, &bytes2, &[(2, 3)]).is_ok());
    }

    #[test]
    fn test_hexdump_format() {
        let data = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
        let dump = hexdump(&data);
        assert!(dump.contains("0000:"));
        assert!(dump.contains("48 65 6c 6c 6f"));
    }
}

// Module declarations for protocol-specific tests
pub mod arp_compat;
pub mod ethernet_compat;
pub mod icmp_compat;
pub mod ipv4_compat;
pub mod ssh_compat;
pub mod tcp_compat;
pub mod tls_compat;
pub mod udp_compat;
