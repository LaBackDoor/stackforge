//! PCAP and PcapNG file writer.

use std::borrow::Cow;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Duration;

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter as PcapFileWriter};
use pcap_file::pcapng::PcapNgWriter as PcapNgFileWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;

use crate::error::{PacketError, Result};
use crate::packet::Packet;

use super::{CapturedPacket, PcapMetadata};

// ---------------------------------------------------------------------------
// Classic PCAP writer
// ---------------------------------------------------------------------------

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
                ..Default::default()
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

// ---------------------------------------------------------------------------
// PcapNG writer
// ---------------------------------------------------------------------------

/// Write captured packets to a PcapNG file.
///
/// Writes SHB + IDB (Ethernet) header, then each packet as an Enhanced Packet Block.
pub fn wrpcapng(path: impl AsRef<Path>, packets: &[CapturedPacket]) -> Result<()> {
    let file = File::create(path.as_ref()).map_err(|e| {
        PacketError::Io(format!(
            "failed to create {}: {}",
            path.as_ref().display(),
            e
        ))
    })?;
    let writer = BufWriter::new(file);
    let mut ng_writer = PcapNgStreamWriter::from_writer(writer)?;

    for cap in packets {
        ng_writer.write(cap)?;
    }

    Ok(())
}

/// Write plain packets to a PcapNG file (convenience function).
///
/// Timestamps are set to zero, `orig_len` matches each packet's data length.
pub fn wrpcapng_packets(path: impl AsRef<Path>, packets: &[Packet]) -> Result<()> {
    let captured: Vec<CapturedPacket> = packets
        .iter()
        .map(|pkt| CapturedPacket {
            packet: pkt.clone(),
            metadata: PcapMetadata {
                timestamp: Duration::ZERO,
                orig_len: pkt.len() as u32,
                ..Default::default()
            },
        })
        .collect();
    wrpcapng(path, &captured)
}

/// PcapNG writer for streaming writes.
///
/// Writes packets one at a time. Auto-writes SHB + IDB on first packet.
pub struct PcapNgStreamWriter<W: Write> {
    inner: PcapNgFileWriter<W>,
    interface_written: bool,
}

impl PcapNgStreamWriter<BufWriter<File>> {
    /// Create a new PcapNG file for writing.
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

impl<W: Write> PcapNgStreamWriter<W> {
    /// Create a `PcapNgStreamWriter` from any writer.
    ///
    /// The SHB is written immediately. The IDB is written on the first packet.
    pub fn from_writer(writer: W) -> Result<Self> {
        let ng_writer = PcapNgFileWriter::new(writer)
            .map_err(|e| PacketError::Io(format!("PcapNG write error: {e}")))?;
        Ok(Self {
            inner: ng_writer,
            interface_written: false,
        })
    }

    /// Ensure at least one Interface Description Block has been written.
    fn ensure_interface(&mut self) -> Result<()> {
        if !self.interface_written {
            let idb = InterfaceDescriptionBlock {
                linktype: pcap_file::DataLink::ETHERNET,
                snaplen: 0xFFFF,
                options: vec![],
            };
            self.inner
                .write_pcapng_block(idb)
                .map_err(|e| PacketError::Io(format!("PcapNG write error: {e}")))?;
            self.interface_written = true;
        }
        Ok(())
    }

    /// Write a captured packet with metadata as an Enhanced Packet Block.
    pub fn write(&mut self, cap: &CapturedPacket) -> Result<()> {
        self.ensure_interface()?;
        let epb = EnhancedPacketBlock {
            interface_id: cap.metadata.interface_id.unwrap_or(0),
            timestamp: cap.metadata.timestamp,
            original_len: cap.metadata.orig_len,
            data: Cow::Borrowed(cap.packet.as_bytes()),
            options: vec![],
        };
        self.inner
            .write_pcapng_block(epb)
            .map_err(|e| PacketError::Io(format!("PcapNG write error: {e}")))?;
        Ok(())
    }

    /// Write a plain packet (timestamp=0, `orig_len=data` length).
    pub fn write_packet(&mut self, pkt: &Packet) -> Result<()> {
        self.ensure_interface()?;
        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::ZERO,
            original_len: pkt.len() as u32,
            data: Cow::Borrowed(pkt.as_bytes()),
            options: vec![],
        };
        self.inner
            .write_pcapng_block(epb)
            .map_err(|e| PacketError::Io(format!("PcapNG write error: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::reader::{PcapIterator, PcapNgIterator};
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
                ..Default::default()
            },
        };

        let mut buf = Vec::new();
        {
            let mut writer = PcapStreamWriter::from_writer(Cursor::new(&mut buf)).unwrap();
            writer.write(&cap).unwrap();
        }

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
                    ..Default::default()
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

    #[test]
    fn test_pcapng_writer_roundtrip() {
        let eth = sample_ethernet_packet();
        let cap = CapturedPacket {
            packet: Packet::from_bytes(bytes::Bytes::copy_from_slice(&eth)),
            metadata: PcapMetadata {
                timestamp: Duration::from_secs(100),
                orig_len: eth.len() as u32,
                interface_id: Some(0),
                comment: None,
            },
        };

        let mut buf = Vec::new();
        {
            let mut writer = PcapNgStreamWriter::from_writer(Cursor::new(&mut buf)).unwrap();
            writer.write(&cap).unwrap();
        }

        let iter = PcapNgIterator::from_reader(Cursor::new(buf)).unwrap();
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].metadata.timestamp, Duration::from_secs(100));
        assert_eq!(packets[0].packet.as_bytes(), eth.as_slice());
        assert_eq!(packets[0].metadata.interface_id, Some(0));
    }

    #[test]
    fn test_pcapng_writer_multiple_packets() {
        let eth = sample_ethernet_packet();

        let caps: Vec<CapturedPacket> = (0..3)
            .map(|i| CapturedPacket {
                packet: Packet::from_bytes(bytes::Bytes::copy_from_slice(&eth)),
                metadata: PcapMetadata {
                    timestamp: Duration::from_secs(i * 10),
                    orig_len: eth.len() as u32,
                    ..Default::default()
                },
            })
            .collect();

        let mut buf = Vec::new();
        {
            let mut writer = PcapNgStreamWriter::from_writer(Cursor::new(&mut buf)).unwrap();
            for cap in &caps {
                writer.write(cap).unwrap();
            }
        }

        let iter = PcapNgIterator::from_reader(Cursor::new(buf)).unwrap();
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].metadata.timestamp, Duration::from_secs(0));
        assert_eq!(packets[1].metadata.timestamp, Duration::from_secs(10));
        assert_eq!(packets[2].metadata.timestamp, Duration::from_secs(20));
    }

    #[test]
    fn test_pcapng_write_packet_convenience() {
        let eth = sample_ethernet_packet();
        let pkt = Packet::from_bytes(bytes::Bytes::copy_from_slice(&eth));

        let mut buf = Vec::new();
        {
            let mut writer = PcapNgStreamWriter::from_writer(Cursor::new(&mut buf)).unwrap();
            writer.write_packet(&pkt).unwrap();
        }

        let iter = PcapNgIterator::from_reader(Cursor::new(buf)).unwrap();
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].metadata.timestamp, Duration::ZERO);
    }
}
