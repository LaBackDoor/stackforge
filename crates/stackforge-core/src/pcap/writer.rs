//! PCAP file writer.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Duration;

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter as PcapFileWriter};

use crate::error::{PacketError, Result};
use crate::packet::Packet;

use super::{CapturedPacket, PcapMetadata};

/// Write captured packets to a PCAP file.
///
/// Preserves timestamps and original length from [`CapturedPacket`] metadata.
pub fn wrpcap(path: impl AsRef<Path>, packets: &[CapturedPacket]) -> Result<()> {
    let file = File::create(path.as_ref()).map_err(|e| {
        PacketError::Io(format!(
            "failed to create {}: {}",
            path.as_ref().display(),
            e
        ))
    })?;
    let writer = BufWriter::new(file);

    let header = PcapHeader::default();
    let mut pcap_writer = PcapFileWriter::with_header(writer, header)
        .map_err(|e| PacketError::Io(format!("PCAP write error: {e}")))?;

    for cap in packets {
        let pcap_pkt = PcapPacket::new(
            cap.metadata.timestamp,
            cap.metadata.orig_len,
            cap.packet.as_bytes(),
        );
        pcap_writer
            .write_packet(&pcap_pkt)
            .map_err(|e| PacketError::Io(format!("PCAP write error: {e}")))?;
    }

    Ok(())
}

/// Write plain packets to a PCAP file (convenience function).
///
/// Timestamps are set to zero, `orig_len` matches each packet's data length.
pub fn wrpcap_packets(path: impl AsRef<Path>, packets: &[Packet]) -> Result<()> {
    let captured: Vec<CapturedPacket> = packets
        .iter()
        .map(|pkt| CapturedPacket {
            packet: pkt.clone(),
            metadata: PcapMetadata {
                timestamp: Duration::ZERO,
                orig_len: pkt.len() as u32,
            },
        })
        .collect();
    wrpcap(path, &captured)
}

/// PCAP writer for streaming writes.
///
/// Writes packets one at a time without buffering them all in memory.
pub struct PcapStreamWriter<W: Write> {
    inner: PcapFileWriter<W>,
}

impl PcapStreamWriter<BufWriter<File>> {
    /// Create a new PCAP file for writing.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::create(path.as_ref()).map_err(|e| {
            PacketError::Io(format!(
                "failed to create {}: {}",
                path.as_ref().display(),
                e
            ))
        })?;
        let writer = BufWriter::new(file);
        Self::from_writer(writer)
    }
}

impl<W: Write> PcapStreamWriter<W> {
    /// Create a `PcapStreamWriter` from any writer.
    pub fn from_writer(writer: W) -> Result<Self> {
        let header = PcapHeader::default();
        let pcap_writer = PcapFileWriter::with_header(writer, header)
            .map_err(|e| PacketError::Io(format!("PCAP write error: {e}")))?;
        Ok(Self { inner: pcap_writer })
    }

    /// Write a captured packet with metadata.
    pub fn write(&mut self, cap: &CapturedPacket) -> Result<()> {
        let pcap_pkt = PcapPacket::new(
            cap.metadata.timestamp,
            cap.metadata.orig_len,
            cap.packet.as_bytes(),
        );
        self.inner
            .write_packet(&pcap_pkt)
            .map_err(|e| PacketError::Io(format!("PCAP write error: {e}")))?;
        Ok(())
    }

    /// Write a plain packet (timestamp=0, `orig_len=data` length).
    pub fn write_packet(&mut self, pkt: &Packet) -> Result<()> {
        let pcap_pkt = PcapPacket::new(Duration::ZERO, pkt.len() as u32, pkt.as_bytes());
        self.inner
            .write_packet(&pcap_pkt)
            .map_err(|e| PacketError::Io(format!("PCAP write error: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::reader::PcapIterator;
    use std::io::Cursor;
    use std::time::Duration;

    fn sample_ethernet_packet() -> Vec<u8> {
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: broadcast
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x00, // EtherType: IPv4
            0x00, 0x00, 0x00, 0x00, // dummy payload
        ]
    }

    #[test]
    fn test_wrpcap_roundtrip() {
        let eth = sample_ethernet_packet();
        let pkt = Packet::from_bytes(bytes::Bytes::copy_from_slice(&eth));
        let cap = CapturedPacket {
            packet: pkt,
            metadata: PcapMetadata {
                timestamp: Duration::from_secs(42),
                orig_len: eth.len() as u32,
            },
        };

        // Write to in-memory buffer via PcapStreamWriter
        let mut buf = Vec::new();
        {
            let mut writer = PcapStreamWriter::from_writer(Cursor::new(&mut buf)).unwrap();
            writer.write(&cap).unwrap();
        }

        // Read back
        let iter = PcapIterator::from_reader(Cursor::new(buf)).unwrap();
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].metadata.timestamp, Duration::from_secs(42));
        assert_eq!(packets[0].packet.as_bytes(), eth.as_slice());
    }

    #[test]
    fn test_wrpcap_multiple_packets() {
        let eth = sample_ethernet_packet();

        let caps: Vec<CapturedPacket> = (0..5)
            .map(|i| CapturedPacket {
                packet: Packet::from_bytes(bytes::Bytes::copy_from_slice(&eth)),
                metadata: PcapMetadata {
                    timestamp: Duration::from_secs(i),
                    orig_len: eth.len() as u32,
                },
            })
            .collect();

        let mut buf = Vec::new();
        {
            let mut writer = PcapStreamWriter::from_writer(Cursor::new(&mut buf)).unwrap();
            for cap in &caps {
                writer.write(cap).unwrap();
            }
        }

        let iter = PcapIterator::from_reader(Cursor::new(buf)).unwrap();
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 5);
        for (i, pkt) in packets.iter().enumerate() {
            assert_eq!(pkt.metadata.timestamp, Duration::from_secs(i as u64));
        }
    }

    #[test]
    fn test_write_packet_convenience() {
        let eth = sample_ethernet_packet();
        let pkt = Packet::from_bytes(bytes::Bytes::copy_from_slice(&eth));

        let mut buf = Vec::new();
        {
            let mut writer = PcapStreamWriter::from_writer(Cursor::new(&mut buf)).unwrap();
            writer.write_packet(&pkt).unwrap();
        }

        let iter = PcapIterator::from_reader(Cursor::new(buf)).unwrap();
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].metadata.timestamp, Duration::ZERO);
        assert_eq!(packets[0].metadata.orig_len, eth.len() as u32);
    }
}
