//! PCAP and PcapNG file I/O for reading and writing packet captures.
//!
//! Provides `rdpcap` for reading all packets from a file (auto-detects format),
//! `PcapIterator` / `PcapNgIterator` / `CaptureIterator` for streaming,
//! and `wrpcap` / `wrpcapng` for writing.

pub mod reader;
pub mod writer;

use std::time::Duration;

use crate::Packet;

/// Capture file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFormat {
    /// Classic PCAP format (`.pcap`).
    Pcap,
    /// PcapNG format (`.pcapng`).
    PcapNg,
}

/// Metadata from a PCAP/PcapNG packet record.
#[derive(Debug, Clone)]
pub struct PcapMetadata {
    /// Timestamp of when the packet was captured.
    pub timestamp: Duration,
    /// Original length of the packet on the wire (may be larger than captured data).
    pub orig_len: u32,
    /// PcapNG interface ID (None for classic PCAP).
    pub interface_id: Option<u32>,
    /// PcapNG per-packet comment (None for classic PCAP).
    pub comment: Option<String>,
}

impl Default for PcapMetadata {
    fn default() -> Self {
        Self {
            timestamp: Duration::ZERO,
            orig_len: 0,
            interface_id: None,
            comment: None,
        }
    }
}

/// A captured packet with associated PCAP metadata.
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    /// The parsed/parseable packet.
    pub packet: Packet,
    /// PCAP capture metadata (timestamp, original length).
    pub metadata: PcapMetadata,
}

/// PCAP link-layer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkType(pub u32);

impl LinkType {
    pub const ETHERNET: Self = Self(1);
    pub const RAW: Self = Self(101);
    pub const LINUX_SLL: Self = Self(113);
}

pub use reader::{CaptureIterator, PcapIterator, PcapNgIterator, rdpcap};
pub use writer::{PcapNgStreamWriter, wrpcap, wrpcap_packets, wrpcapng, wrpcapng_packets};
