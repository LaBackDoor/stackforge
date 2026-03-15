//! PCAP and PcapNG file reader with streaming support and auto-detection.

use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};

use bytes::Bytes;
use pcap_file::pcap::PcapReader as PcapFileReader;
use pcap_file::pcapng::Block;
use pcap_file::pcapng::PcapNgReader as PcapNgFileReader;

use crate::error::{PacketError, Result};
use crate::packet::Packet;

use super::{CaptureFormat, CapturedPacket, LinkType, PcapMetadata};

/// Detect capture format from the first 4 bytes (magic number).
fn detect_format(magic: &[u8; 4]) -> Result<CaptureFormat> {
    let le = u32::from_le_bytes(*magic);
    let be = u32::from_be_bytes(*magic);

    // PcapNG Section Header Block type is 0x0A0D0D0A in both endiannesses
    if le == 0x0A0D_0D0A || be == 0x0A0D_0D0A {
        return Ok(CaptureFormat::PcapNg);
    }

    // PCAP magic: microsecond or nanosecond, either endian
    if le == 0xA1B2_C3D4 || be == 0xA1B2_C3D4 || le == 0xA1B2_3C4D || be == 0xA1B2_3C4D {
        return Ok(CaptureFormat::Pcap);
    }

    Err(PacketError::Io(
        "unknown capture file format (not PCAP or PcapNG)".into(),
    ))
}

/// Read all packets from a PCAP or PcapNG file into memory.
///
/// Auto-detects the file format from magic bytes. For classic PCAP files this
/// uses memory-mapped I/O for zero-copy packet access, eliminating per-packet
/// heap allocations. PcapNG files fall back to the streaming reader.
///
/// This is the simple Scapy-like API. For large files, use [`CaptureIterator`]
/// or [`super::MmapPcapReader`] instead.
pub fn rdpcap(path: impl AsRef<Path>) -> Result<Vec<CapturedPacket>> {
    // Try the zero-copy mmap path first (classic PCAP only).
    match super::MmapPcapReader::open(path.as_ref()) {
        Ok(reader) => reader.collect(),
        // Fall back to the streaming reader for PcapNG or other errors.
        Err(_) => {
            let iter = CaptureIterator::open(path.as_ref())?;
            iter.collect()
        },
    }
}

use std::path::Path;

// ---------------------------------------------------------------------------
// Classic PCAP iterator
// ---------------------------------------------------------------------------

/// Streaming iterator over packets in a classic PCAP file.
///
/// Reads packets one at a time, suitable for gigabyte-sized captures.
pub struct PcapIterator<R: Read> {
    inner: PcapFileReader<R>,
    link_type: LinkType,
}

impl PcapIterator<BufReader<File>> {
    /// Open a classic PCAP file for streaming iteration.
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
            .map_err(|e| PacketError::Io(format!("invalid PCAP: {e}")))?;
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
                let _ = pkt.parse();
                Some(Ok(CapturedPacket {
                    packet: pkt,
                    metadata: PcapMetadata {
                        timestamp: ts,
                        orig_len: pcap_pkt.orig_len,
                        interface_id: None,
                        comment: None,
                    },
                }))
            },
            Some(Err(e)) => Some(Err(PacketError::Io(format!("PCAP read error: {e}")))),
            None => None,
        }
    }
}

// ---------------------------------------------------------------------------
// PcapNG iterator
// ---------------------------------------------------------------------------

/// Streaming iterator over packets in a PcapNG file.
///
/// Reads packets one at a time, skipping non-packet blocks (SHB, IDB, etc.).
pub struct PcapNgIterator<R: Read> {
    inner: PcapNgFileReader<R>,
}

impl PcapNgIterator<BufReader<File>> {
    /// Open a PcapNG file for streaming iteration.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path.as_ref()).map_err(|e| {
            PacketError::Io(format!("failed to open {}: {}", path.as_ref().display(), e))
        })?;
        let reader = BufReader::new(file);
        Self::from_reader(reader)
    }
}

impl<R: Read> PcapNgIterator<R> {
    /// Create a `PcapNgIterator` from any reader.
    pub fn from_reader(reader: R) -> Result<Self> {
        let ng_reader = PcapNgFileReader::new(reader)
            .map_err(|e| PacketError::Io(format!("invalid PcapNG: {e}")))?;
        Ok(Self { inner: ng_reader })
    }

    /// Returns the link type of the first interface (most common case).
    pub fn link_type(&self) -> LinkType {
        self.inner
            .interfaces()
            .first()
            .map(|idb| LinkType(u32::from(idb.linktype)))
            .unwrap_or(LinkType::ETHERNET)
    }
}

impl<R: Read> Iterator for PcapNgIterator<R> {
    type Item = Result<CapturedPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.inner.next_block() {
                Some(Ok(block)) => {
                    match block {
                        Block::EnhancedPacket(epb) => {
                            let data = Bytes::copy_from_slice(&epb.data);
                            let mut pkt = Packet::from_bytes(data);
                            let _ = pkt.parse();
                            return Some(Ok(CapturedPacket {
                                packet: pkt,
                                metadata: PcapMetadata {
                                    timestamp: epb.timestamp,
                                    orig_len: epb.original_len,
                                    interface_id: Some(epb.interface_id),
                                    comment: None,
                                },
                            }));
                        },
                        Block::SimplePacket(spb) => {
                            let data = Bytes::copy_from_slice(&spb.data);
                            let mut pkt = Packet::from_bytes(data);
                            let _ = pkt.parse();
                            return Some(Ok(CapturedPacket {
                                packet: pkt,
                                metadata: PcapMetadata {
                                    timestamp: std::time::Duration::ZERO,
                                    orig_len: spb.original_len,
                                    interface_id: Some(0),
                                    comment: None,
                                },
                            }));
                        },
                        // Skip non-packet blocks (SHB, IDB, NRB, ISB, etc.)
                        _ => continue,
                    }
                },
                Some(Err(e)) => {
                    return Some(Err(PacketError::Io(format!("PcapNG read error: {e}"))));
                },
                None => return None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unified auto-detecting iterator
// ---------------------------------------------------------------------------

/// Auto-detecting iterator over packets from either PCAP or PcapNG files.
///
/// Detects the format from magic bytes and delegates to the appropriate reader.
pub enum CaptureIterator<R: Read> {
    /// Classic PCAP format.
    Pcap(PcapIterator<R>),
    /// PcapNG format.
    PcapNg(PcapNgIterator<R>),
}

impl CaptureIterator<BufReader<File>> {
    /// Open any capture file, auto-detecting format from magic bytes.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut file = File::open(path.as_ref()).map_err(|e| {
            PacketError::Io(format!("failed to open {}: {}", path.as_ref().display(), e))
        })?;

        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).map_err(|e| {
            PacketError::Io(format!(
                "failed to read magic bytes from {}: {e}",
                path.as_ref().display()
            ))
        })?;

        let format = detect_format(&magic)?;

        // Seek back to start so the reader sees the full header
        file.seek(SeekFrom::Start(0))
            .map_err(|e| PacketError::Io(format!("failed to seek: {e}")))?;

        let reader = BufReader::new(file);
        match format {
            CaptureFormat::Pcap => Ok(Self::Pcap(PcapIterator::from_reader(reader)?)),
            CaptureFormat::PcapNg => Ok(Self::PcapNg(PcapNgIterator::from_reader(reader)?)),
        }
    }
}

impl<R: Read> CaptureIterator<R> {
    /// Create from a reader by reading 4 magic bytes, then chaining them back.
    ///
    /// For readers that don't support `Seek`, this reads the magic bytes and
    /// chains them back using `Cursor::chain`.
    pub fn from_reader(
        mut reader: R,
    ) -> Result<CaptureIterator<std::io::Chain<Cursor<[u8; 4]>, R>>> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|e| PacketError::Io(format!("failed to read magic bytes: {e}")))?;

        let format = detect_format(&magic)?;
        let chain = Cursor::new(magic).chain(reader);

        match format {
            CaptureFormat::Pcap => Ok(CaptureIterator::Pcap(PcapIterator::from_reader(chain)?)),
            CaptureFormat::PcapNg => {
                Ok(CaptureIterator::PcapNg(PcapNgIterator::from_reader(chain)?))
            },
        }
    }

    /// Returns the link-layer type of the capture.
    pub fn link_type(&self) -> LinkType {
        match self {
            Self::Pcap(p) => p.link_type(),
            Self::PcapNg(p) => p.link_type(),
        }
    }

    /// Returns the detected capture format.
    pub fn format(&self) -> CaptureFormat {
        match self {
            Self::Pcap(_) => CaptureFormat::Pcap,
            Self::PcapNg(_) => CaptureFormat::PcapNg,
        }
    }
}

impl<R: Read> Iterator for CaptureIterator<R> {
    type Item = Result<CapturedPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Pcap(iter) => iter.next(),
            Self::PcapNg(iter) => iter.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn create_test_pcapng(packets: &[(Duration, &[u8])]) -> Vec<u8> {
        use pcap_file::pcapng::PcapNgWriter;
        use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
        use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
        use std::borrow::Cow;

        let mut buf = Vec::new();
        let mut writer = PcapNgWriter::new(Cursor::new(&mut buf)).unwrap();

        // Write interface description block
        let idb = InterfaceDescriptionBlock {
            linktype: pcap_file::DataLink::ETHERNET,
            snaplen: 0xFFFF,
            options: vec![],
        };
        writer.write_pcapng_block(idb).unwrap();

        for (ts, data) in packets {
            let epb = EnhancedPacketBlock {
                interface_id: 0,
                timestamp: *ts,
                original_len: data.len() as u32,
                data: Cow::Borrowed(data),
                options: vec![],
            };
            writer.write_pcapng_block(epb).unwrap();
        }
        drop(writer);
        buf
    }

    #[test]
    fn test_detect_format_pcap() {
        // Little-endian PCAP magic
        let magic = [0xD4, 0xC3, 0xB2, 0xA1];
        assert_eq!(detect_format(&magic).unwrap(), CaptureFormat::Pcap);
    }

    #[test]
    fn test_detect_format_pcapng() {
        // PcapNG SHB magic
        let magic = [0x0A, 0x0D, 0x0D, 0x0A];
        assert_eq!(detect_format(&magic).unwrap(), CaptureFormat::PcapNg);
    }

    #[test]
    fn test_detect_format_unknown() {
        let magic = [0x00, 0x00, 0x00, 0x00];
        assert!(detect_format(&magic).is_err());
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
        // Classic PCAP should have no interface_id
        assert!(packets[0].metadata.interface_id.is_none());
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
        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.metadata.timestamp, Duration::from_secs(1));
        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.metadata.timestamp, Duration::from_secs(2));
    }

    #[test]
    fn test_pcapng_iterator_from_reader() {
        let eth = sample_ethernet_packet();
        let pcapng_data = create_test_pcapng(&[
            (Duration::from_secs(10), &eth),
            (Duration::from_secs(20), &eth),
        ]);
        let iter = PcapNgIterator::from_reader(Cursor::new(pcapng_data)).unwrap();
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].metadata.timestamp, Duration::from_secs(10));
        assert_eq!(packets[1].metadata.timestamp, Duration::from_secs(20));
        assert_eq!(packets[0].metadata.interface_id, Some(0));
    }

    #[test]
    fn test_pcapng_iterator_empty() {
        let pcapng_data = create_test_pcapng(&[]);
        let iter = PcapNgIterator::from_reader(Cursor::new(pcapng_data)).unwrap();
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert!(packets.is_empty());
    }

    #[test]
    fn test_capture_iterator_auto_detect_pcap() {
        let eth = sample_ethernet_packet();
        let pcap_data = create_test_pcap(&[(Duration::from_secs(1), &eth)]);
        let iter = CaptureIterator::from_reader(Cursor::new(pcap_data)).unwrap();
        assert_eq!(iter.format(), CaptureFormat::Pcap);
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 1);
    }

    #[test]
    fn test_capture_iterator_auto_detect_pcapng() {
        let eth = sample_ethernet_packet();
        let pcapng_data = create_test_pcapng(&[(Duration::from_secs(5), &eth)]);
        let iter = CaptureIterator::from_reader(Cursor::new(pcapng_data)).unwrap();
        assert_eq!(iter.format(), CaptureFormat::PcapNg);
        let packets: Vec<_> = iter.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].metadata.timestamp, Duration::from_secs(5));
    }

    #[test]
    fn test_rdpcap_pcapng_roundtrip() {
        let eth = sample_ethernet_packet();
        let pcapng_data = create_test_pcapng(&[
            (Duration::from_secs(1), &eth),
            (Duration::from_secs(2), &eth),
            (Duration::from_secs(3), &eth),
        ]);
        // Write to temp file and read back with rdpcap
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("test.pcapng");
        std::fs::write(&path, &pcapng_data).unwrap();
        let packets = rdpcap(&path).unwrap();
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].metadata.timestamp, Duration::from_secs(1));
        assert_eq!(packets[2].metadata.timestamp, Duration::from_secs(3));
    }
}
