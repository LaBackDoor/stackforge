//! PCAP file I/O for reading and writing packet captures.
//!
//! Provides `rdpcap` for reading all packets from a file,
//! `PcapIterator` for streaming large captures, and `wrpcap` for writing.

pub mod reader;
pub mod writer;

use std::time::Duration;

use crate::Packet;

/// Metadata from a PCAP packet record.
#[derive(Debug, Clone, Default)]
pub struct PcapMetadata {
    /// Timestamp of when the packet was captured.
    pub timestamp: Duration,
    /// Original length of the packet on the wire (may be larger than captured data).
    pub orig_len: u32,
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

pub use reader::{PcapIterator, rdpcap};
pub use writer::{wrpcap, wrpcap_packets};
