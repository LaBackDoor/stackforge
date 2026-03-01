//! PCAP file reader with streaming support.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use bytes::Bytes;
use pcap_file::pcap::PcapReader as PcapFileReader;

use crate::error::{PacketError, Result};
use crate::packet::Packet;

use super::{CapturedPacket, LinkType, PcapMetadata};

/// Read all packets from a PCAP file into memory.
///
/// This is the simple Scapy-like API. For large files, use [`PcapIterator`] instead.
pub fn rdpcap(path: impl AsRef<Path>) -> Result<Vec<CapturedPacket>> {
    let iter = PcapIterator::open(path)?;
    iter.collect()
}

/// Streaming iterator over packets in a PCAP file.
///
/// Reads packets one at a time, suitable for gigabyte-sized captures.
/// Implements `Iterator<Item = Result<CapturedPacket>>`.
pub struct PcapIterator<R: Read> {
    inner: PcapFileReader<R>,
    link_type: LinkType,
}

impl PcapIterator<BufReader<File>> {
    /// Open a PCAP file for streaming iteration.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path.as_ref()).map_err(|e| {
            PacketError::Io(format!("failed to open {}: {}", path.as_ref().display(), e))
        })?;
        let reader = BufReader::new(file);
        Self::from_reader(reader)
    }
}

impl<R: Read> PcapIterator<R> {
    /// Create a `PcapIterator` from any reader.
    pub fn from_reader(reader: R) -> Result<Self> {
        let pcap_reader = PcapFileReader::new(reader)
            .map_err(|e| PacketError::Io(format!("invalid PCAP: {}", e)))?;
        let link_type = LinkType(u32::from(pcap_reader.header().datalink));
        Ok(Self {
            inner: pcap_reader,
            link_type,
        })
    }

    /// Returns the link-layer type from the PCAP global header.
    pub fn link_type(&self) -> LinkType {
        self.link_type
    }
}

impl<R: Read> Iterator for PcapIterator<R> {
    type Item = Result<CapturedPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next_packet() {
            Some(Ok(pcap_pkt)) => {
                let ts = pcap_pkt.timestamp;
                let data = Bytes::copy_from_slice(&pcap_pkt.data);
                let mut pkt = Packet::from_bytes(data);
                // Auto-parse; ignore parse errors (store as unparsed)
                let _ = pkt.parse();
                Some(Ok(CapturedPacket {
                    packet: pkt,
                    metadata: PcapMetadata {
                        timestamp: ts,
                        orig_len: pcap_pkt.orig_len,
                    },
                }))
            },
            Some(Err(e)) => Some(Err(PacketError::Io(format!("PCAP read error: {}", e)))),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;

    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter as PcapFileWriter};

    fn sample_ethernet_packet() -> Vec<u8> {
        // Minimal Ethernet frame: dst(6) + src(6) + type(2) + payload(4)
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: broadcast
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x00, // EtherType: IPv4
            0x00, 0x00, 0x00, 0x00, // dummy payload
        ]
    }

    fn create_test_pcap(packets: &[(Duration, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        let header = PcapHeader::default();
        let mut writer = PcapFileWriter::with_header(Cursor::new(&mut buf), header).unwrap();
        for (ts, data) in packets {
            let pkt = PcapPacket::new(*ts, data.len() as u32, data);
            writer.write_packet(&pkt).unwrap();
        }
        drop(writer);
        buf
    }

    #[test]
    fn test_pcap_iterator_from_reader() {
        let eth = sample_ethernet_packet();
        let pcap_data = create_test_pcap(&[
            (Duration::from_secs(1), &eth),
            (Duration::from_secs(2), &eth),
        ]);
        let iter = PcapIterator::from_reader(Cursor::new(pcap_data)).unwrap();
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].metadata.timestamp, Duration::from_secs(1));
        assert_eq!(packets[1].metadata.timestamp, Duration::from_secs(2));
    }

    #[test]
    fn test_pcap_iterator_link_type() {
        let pcap_data = create_test_pcap(&[]);
        let iter = PcapIterator::from_reader(Cursor::new(pcap_data)).unwrap();
        assert_eq!(iter.link_type(), LinkType::ETHERNET);
    }

    #[test]
    fn test_pcap_iterator_empty() {
        let pcap_data = create_test_pcap(&[]);
        let iter = PcapIterator::from_reader(Cursor::new(pcap_data)).unwrap();
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert!(packets.is_empty());
    }

    #[test]
    fn test_pcap_iterator_metadata() {
        let eth = sample_ethernet_packet();
        let pcap_data = create_test_pcap(&[(Duration::from_millis(1500), &eth)]);
        let iter = PcapIterator::from_reader(Cursor::new(pcap_data)).unwrap();
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].metadata.orig_len, eth.len() as u32);
        assert_eq!(packets[0].packet.len(), eth.len());
    }

    #[test]
    fn test_pcap_iterator_is_lazy() {
        let eth = sample_ethernet_packet();
        let pcap_data = create_test_pcap(&[
            (Duration::from_secs(1), &eth),
            (Duration::from_secs(2), &eth),
            (Duration::from_secs(3), &eth),
        ]);
        let mut iter = PcapIterator::from_reader(Cursor::new(pcap_data)).unwrap();
        // Only read one packet
        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.metadata.timestamp, Duration::from_secs(1));
        // Iterator still has more
        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.metadata.timestamp, Duration::from_secs(2));
    }
}
