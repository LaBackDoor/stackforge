use bytes::Bytes;
use pcap::{Capture, Device};

use super::config::SnifferConfig;
use super::error::SnifferError;

/// Information about a network interface.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub is_loopback: bool,
    pub is_up: bool,
}

/// A raw captured packet with timestamp.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Packet data as a zero-copy `Bytes` buffer.
    pub data: Bytes,
    /// Capture timestamp in microseconds since epoch.
    pub timestamp_us: i64,
}

/// Opens a live capture on the given interface with the specified config.
pub(crate) fn open_capture(
    config: &SnifferConfig,
) -> Result<Capture<pcap::Active>, SnifferError> {
    // Find the device
    let device = Device::list()
        .map_err(SnifferError::Pcap)?
        .into_iter()
        .find(|d| d.name == config.iface)
        .ok_or_else(|| SnifferError::InterfaceNotFound(config.iface.clone()))?;

    // Open capture
    let mut cap = Capture::from_device(device)
        .map_err(SnifferError::Pcap)?
        .snaplen(config.snaplen)
        .promisc(config.promisc)
        // Use a short read timeout so the capture thread can check the stop flag
        .timeout(100)
        .open()
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("ermission") || msg.contains("Operation not permitted") {
                SnifferError::PermissionDenied(msg)
            } else {
                SnifferError::Pcap(e)
            }
        })?;

    // Apply BPF filter if specified
    if let Some(ref filter) = config.filter {
        cap.filter(filter, true).map_err(|e| {
            SnifferError::InvalidFilter(format!("{filter}: {e}"))
        })?;
    }

    Ok(cap)
}

/// List all available network interfaces.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, SnifferError> {
    let devices = Device::list().map_err(SnifferError::Pcap)?;
    Ok(devices
        .into_iter()
        .map(|d| {
            let addresses: Vec<String> = d
                .addresses
                .iter()
                .map(|a| a.addr.to_string())
                .collect();

            InterfaceInfo {
                name: d.name,
                description: d.desc,
                addresses,
                is_loopback: false, // pcap crate doesn't expose flags directly
                is_up: true,
            }
        })
        .collect())
}

/// Validate a BPF filter string without starting a capture.
pub fn validate_filter(filter: &str) -> Result<(), SnifferError> {
    // Open a dead capture and compile (not set) the filter to check validity
    let cap = Capture::dead(pcap::Linktype::ETHERNET)
        .map_err(SnifferError::Pcap)?;
    cap.compile(filter, true)
        .map_err(|e| SnifferError::InvalidFilter(format!("{filter}: {e}")))?;
    Ok(())
}
