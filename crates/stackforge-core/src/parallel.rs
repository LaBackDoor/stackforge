//! Multithreaded packet processing using Rayon.
//!
//! This module provides parallel variants of common packet operations
//! for high-throughput scenarios like PCAP batch processing and flow extraction.

use bytes::Bytes;
use rayon::prelude::*;

use crate::error::Result;
use crate::packet::Packet;

/// Parse a batch of raw byte buffers into packets in parallel.
///
/// Each buffer is wrapped in a `Packet`, parsed, and returned.
/// Parse errors are collected; packets that fail to parse are returned unparsed.
///
/// # Example
///
/// ```rust
/// use stackforge_core::parallel::parse_batch;
///
/// let raw_packets: Vec<Vec<u8>> = vec![
///     // Ethernet + ARP
///     vec![
///         0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
///         0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
///         0x08, 0x06,
///         0x00, 0x01, 0x08, 0x00, 0x06, 0x04,
///         0x00, 0x01,
///         0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
///         0xc0, 0xa8, 0x01, 0x01,
///         0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///         0xc0, 0xa8, 0x01, 0x02,
///     ],
/// ];
///
/// let parsed = parse_batch(&raw_packets);
/// assert_eq!(parsed.len(), 1);
/// assert!(parsed[0].is_parsed());
/// ```
pub fn parse_batch(raw_packets: &[Vec<u8>]) -> Vec<Packet> {
    raw_packets
        .par_iter()
        .map(|raw| {
            let mut pkt = Packet::from_bytes(raw.clone());
            let _ = pkt.parse();
            pkt
        })
        .collect()
}

/// Parse a batch of `Bytes` buffers into packets in parallel (zero-copy).
pub fn parse_batch_bytes(raw_packets: &[Bytes]) -> Vec<Packet> {
    raw_packets
        .par_iter()
        .map(|raw| {
            let mut pkt = Packet::from_bytes(raw.clone());
            let _ = pkt.parse();
            pkt
        })
        .collect()
}

/// Parse a batch and return only successfully parsed packets.
pub fn parse_batch_ok(raw_packets: &[Vec<u8>]) -> Vec<Packet> {
    raw_packets
        .par_iter()
        .filter_map(|raw| {
            let mut pkt = Packet::from_bytes(raw.clone());
            pkt.parse().ok().map(|()| pkt)
        })
        .collect()
}

/// Apply a function to each packet in parallel, collecting results.
///
/// Useful for extracting fields, computing summaries, or filtering.
pub fn par_map<F, R>(packets: &[Packet], f: F) -> Vec<R>
where
    F: Fn(&Packet) -> R + Sync + Send,
    R: Send,
{
    packets.par_iter().map(f).collect()
}

/// Filter packets in parallel using a predicate.
pub fn par_filter<F>(packets: &[Packet], predicate: F) -> Vec<&Packet>
where
    F: Fn(&Packet) -> bool + Sync + Send,
{
    packets.par_iter().filter(|p| predicate(p)).collect()
}

/// Parse and immediately apply a transform in parallel.
///
/// This is more efficient than `parse_batch` + `par_map` because it avoids
/// materializing the intermediate `Vec<Packet>`.
pub fn parse_and_map<F, R>(raw_packets: &[Vec<u8>], f: F) -> Vec<R>
where
    F: Fn(&Packet) -> R + Sync + Send,
    R: Send,
{
    raw_packets
        .par_iter()
        .map(|raw| {
            let mut pkt = Packet::from_bytes(raw.clone());
            let _ = pkt.parse();
            f(&pkt)
        })
        .collect()
}

/// Count packets matching a predicate in parallel.
pub fn par_count<F>(packets: &[Packet], predicate: F) -> usize
where
    F: Fn(&Packet) -> bool + Sync + Send,
{
    packets.par_iter().filter(|p| predicate(p)).count()
}

/// Parallel summary extraction: parse and summarize each packet.
pub fn summarize_batch(raw_packets: &[Vec<u8>]) -> Vec<String> {
    parse_and_map(raw_packets, |pkt| {
        let buf = pkt.as_bytes();
        pkt.layer_enums()
            .iter()
            .map(|le| le.summary(buf))
            .collect::<Vec<_>>()
            .join(" / ")
    })
}

/// Configure the global Rayon thread pool.
///
/// Call this once at startup to control the number of worker threads.
/// If not called, Rayon defaults to the number of logical CPUs.
///
/// # Errors
///
/// Returns an error if the thread pool has already been initialized.
pub fn configure_thread_pool(num_threads: usize) -> Result<()> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .map_err(|e| crate::error::PacketError::ParseError {
            offset: 0,
            message: format!("Failed to configure thread pool: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::LayerKind;

    fn arp_packet() -> Vec<u8> {
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06,
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0xc0, 0xa8, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x02,
        ]
    }

    #[test]
    fn test_parse_batch() {
        let packets: Vec<Vec<u8>> = (0..100).map(|_| arp_packet()).collect();
        let parsed = parse_batch(&packets);
        assert_eq!(parsed.len(), 100);
        for pkt in &parsed {
            assert!(pkt.is_parsed());
            assert_eq!(pkt.layer_count(), 2);
        }
    }

    #[test]
    fn test_parse_batch_bytes() {
        let packets: Vec<Bytes> = (0..50).map(|_| Bytes::from(arp_packet())).collect();
        let parsed = parse_batch_bytes(&packets);
        assert_eq!(parsed.len(), 50);
        for pkt in &parsed {
            assert!(pkt.is_parsed());
        }
    }

    #[test]
    fn test_par_map() {
        let packets: Vec<Vec<u8>> = (0..10).map(|_| arp_packet()).collect();
        let parsed = parse_batch(&packets);
        let has_arp: Vec<bool> = par_map(&parsed, |pkt| pkt.get_layer(LayerKind::Arp).is_some());
        assert!(has_arp.iter().all(|&v| v));
    }

    #[test]
    fn test_par_filter() {
        let packets: Vec<Vec<u8>> = (0..10).map(|_| arp_packet()).collect();
        let parsed = parse_batch(&packets);
        let arp_packets = par_filter(&parsed, |pkt| pkt.get_layer(LayerKind::Arp).is_some());
        assert_eq!(arp_packets.len(), 10);
    }

    #[test]
    fn test_parse_and_map() {
        let packets: Vec<Vec<u8>> = (0..10).map(|_| arp_packet()).collect();
        let layer_counts: Vec<usize> = parse_and_map(&packets, |pkt| pkt.layer_count());
        assert!(layer_counts.iter().all(|&c| c == 2));
    }

    #[test]
    fn test_par_count() {
        let packets: Vec<Vec<u8>> = (0..20).map(|_| arp_packet()).collect();
        let parsed = parse_batch(&packets);
        let count = par_count(&parsed, |pkt| pkt.get_layer(LayerKind::Arp).is_some());
        assert_eq!(count, 20);
    }

    #[test]
    fn test_empty_batch() {
        let empty: Vec<Vec<u8>> = vec![];
        let parsed = parse_batch(&empty);
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_parse_batch_with_errors() {
        let packets = vec![
            arp_packet(),     // valid
            vec![0x01, 0x02], // too short, but won't error (just empty layers)
            arp_packet(),     // valid
        ];
        let parsed = parse_batch(&packets);
        assert_eq!(parsed.len(), 3);
        assert!(parsed[0].is_parsed());
        assert!(parsed[2].is_parsed());
    }
}
