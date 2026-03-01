//! IPv4 fragmentation and reassembly.
//!
//! Provides utilities for fragmenting large IP packets and reassembling
//! fragments back into complete packets.

use std::net::Ipv4Addr;

use crate::layer::field::FieldError;

use super::checksum::ipv4_checksum;
use super::header::{IPV4_MIN_HEADER_LEN, Ipv4Flags, Ipv4Layer, offsets};
use super::options::Ipv4Options;

/// Default MTU for fragmentation.
pub const DEFAULT_MTU: usize = 1500;

/// Minimum fragment payload size (must be multiple of 8).
pub const MIN_FRAGMENT_PAYLOAD: usize = 8;

/// Maximum fragment offset (in 8-byte units).
pub const MAX_FRAGMENT_OFFSET: u16 = 0x1FFF;

/// Information about a fragment.
#[derive(Debug, Clone)]
pub struct FragmentInfo {
    /// Fragment offset in bytes.
    pub offset: u32,
    /// Fragment payload length.
    pub length: usize,
    /// Whether this is the last fragment.
    pub last: bool,
    /// The fragment data (header + payload).
    pub data: Vec<u8>,
}

impl FragmentInfo {
    /// Get the end offset (offset + length).
    pub fn end_offset(&self) -> u32 {
        self.offset + self.length as u32
    }
}

/// A single fragment ready for transmission.
#[derive(Debug, Clone)]
pub struct Fragment {
    /// The complete fragment packet (header + payload).
    pub packet: Vec<u8>,
    /// Fragment offset in bytes.
    pub offset: u32,
    /// Whether this is the last fragment.
    pub last: bool,
}

/// Fragmenter for IPv4 packets.
#[derive(Debug, Clone)]
pub struct Ipv4Fragmenter {
    /// Maximum fragment size (including IP header).
    pub mtu: usize,
    /// Whether to copy options to all fragments.
    pub copy_options: bool,
}

impl Default for Ipv4Fragmenter {
    fn default() -> Self {
        Self {
            mtu: DEFAULT_MTU,
            copy_options: true,
        }
    }
}

impl Ipv4Fragmenter {
    /// Create a new fragmenter with default MTU.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a fragmenter with a specific MTU.
    pub fn with_mtu(mtu: usize) -> Self {
        Self {
            mtu,
            ..Self::default()
        }
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set whether to copy options to non-first fragments.
    pub fn copy_options(mut self, copy: bool) -> Self {
        self.copy_options = copy;
        self
    }

    /// Check if a packet needs fragmentation.
    pub fn needs_fragmentation(&self, packet: &[u8]) -> bool {
        packet.len() > self.mtu
    }

    /// Fragment an IPv4 packet.
    ///
    /// Returns a vector of fragment packets, or None if the packet
    /// has the Don't Fragment flag set and exceeds MTU.
    pub fn fragment(&self, packet: &[u8]) -> Result<Vec<Fragment>, FragmentError> {
        let layer = Ipv4Layer::at_offset_dynamic(packet, 0)
            .map_err(|e| FragmentError::ParseError(e.to_string()))?;

        // Check DF flag
        let flags = layer.flags(packet).unwrap_or(Ipv4Flags::NONE);
        if flags.df && packet.len() > self.mtu {
            return Err(FragmentError::DontFragmentSet {
                packet_size: packet.len(),
                mtu: self.mtu,
            });
        }

        // No fragmentation needed
        if packet.len() <= self.mtu {
            return Ok(vec![Fragment {
                packet: packet.to_vec(),
                offset: 0,
                last: true,
            }]);
        }

        // Get original header info
        let header_len = layer.calculate_header_len(packet);
        let total_len = layer.total_len(packet).unwrap_or(packet.len() as u16) as usize;
        let _payload_start = header_len;
        let payload_len = total_len.saturating_sub(header_len);

        // Parse options for copying
        let options = if header_len > IPV4_MIN_HEADER_LEN {
            layer.options(packet).ok()
        } else {
            None
        };

        // Calculate fragment sizes
        // Fragment payload must be multiple of 8
        let first_header_len = header_len; // First fragment keeps all options
        let other_header_len = if self.copy_options {
            if let Some(ref opts) = options {
                IPV4_MIN_HEADER_LEN + opts.copied_options().padded_len()
            } else {
                IPV4_MIN_HEADER_LEN
            }
        } else {
            IPV4_MIN_HEADER_LEN
        };

        let first_payload_max = ((self.mtu - first_header_len) / 8) * 8;
        let other_payload_max = ((self.mtu - other_header_len) / 8) * 8;

        if first_payload_max < MIN_FRAGMENT_PAYLOAD || other_payload_max < MIN_FRAGMENT_PAYLOAD {
            return Err(FragmentError::MtuTooSmall {
                mtu: self.mtu,
                min_required: other_header_len + MIN_FRAGMENT_PAYLOAD,
            });
        }

        let mut fragments = Vec::new();
        let mut offset: u32 = 0;
        let mut remaining = payload_len;
        let mut is_first = true;

        // Original fragment offset (in case we're fragmenting a fragment)
        let original_offset = layer.frag_offset(packet).unwrap_or(0) as u32 * 8;
        let original_mf = flags.mf;

        while remaining > 0 {
            let _header_size = if is_first {
                first_header_len
            } else {
                other_header_len
            };
            let max_payload = if is_first {
                first_payload_max
            } else {
                other_payload_max
            };

            let frag_payload_len = remaining.min(max_payload);
            let is_last = frag_payload_len == remaining && !original_mf;

            // Ensure non-last fragments have payload that's multiple of 8
            let actual_payload_len = if !is_last {
                (frag_payload_len / 8) * 8
            } else {
                frag_payload_len
            };

            if actual_payload_len == 0 {
                break;
            }

            // Build fragment
            let frag_packet = self.build_fragment(
                packet,
                &layer,
                &options,
                offset,
                actual_payload_len,
                !is_last,
                is_first,
                original_offset,
            )?;

            fragments.push(Fragment {
                packet: frag_packet,
                offset: original_offset + offset,
                last: is_last,
            });

            offset += actual_payload_len as u32;
            remaining -= actual_payload_len;
            is_first = false;
        }

        Ok(fragments)
    }

    /// Build a single fragment packet.
    fn build_fragment(
        &self,
        original: &[u8],
        layer: &Ipv4Layer,
        options: &Option<Ipv4Options>,
        offset: u32,
        payload_len: usize,
        more_fragments: bool,
        is_first: bool,
        original_offset: u32,
    ) -> Result<Vec<u8>, FragmentError> {
        let original_header_len = layer.calculate_header_len(original);

        // Determine header for this fragment
        let frag_options = if is_first {
            options.clone()
        } else if self.copy_options {
            options.as_ref().map(|o| o.copied_options())
        } else {
            None
        };

        let frag_header_len = if let Some(ref opts) = frag_options {
            IPV4_MIN_HEADER_LEN + opts.padded_len()
        } else {
            IPV4_MIN_HEADER_LEN
        };

        let total_len = frag_header_len + payload_len;
        let mut buf = vec![0u8; total_len];

        // Copy and modify header
        buf[..IPV4_MIN_HEADER_LEN].copy_from_slice(&original[..IPV4_MIN_HEADER_LEN]);

        // Update IHL
        let ihl = (frag_header_len / 4) as u8;
        buf[offsets::VERSION_IHL] = (buf[offsets::VERSION_IHL] & 0xF0) | (ihl & 0x0F);

        // Update total length
        buf[offsets::TOTAL_LEN] = (total_len >> 8) as u8;
        buf[offsets::TOTAL_LEN + 1] = (total_len & 0xFF) as u8;

        // Update flags and fragment offset
        let frag_offset_units = ((original_offset + offset) / 8) as u16;
        let mut flags_byte = if more_fragments { 0x20 } else { 0x00 }; // MF flag

        // Preserve DF flag? No - if we're fragmenting, DF must be clear
        // Preserve evil bit from original
        let orig_flags = layer.flags(original).unwrap_or(Ipv4Flags::NONE);
        if orig_flags.reserved {
            flags_byte |= 0x80;
        }

        let flags_frag = ((flags_byte as u16) << 8) | frag_offset_units;
        buf[offsets::FLAGS_FRAG] = (flags_frag >> 8) as u8;
        buf[offsets::FLAGS_FRAG + 1] = (flags_frag & 0xFF) as u8;

        // Copy options (if any)
        if let Some(ref opts) = frag_options {
            let opts_bytes = opts.to_bytes();
            buf[offsets::OPTIONS..offsets::OPTIONS + opts_bytes.len()].copy_from_slice(&opts_bytes);
        }

        // Copy payload portion
        let payload_start = original_header_len + offset as usize;
        let payload_end = payload_start + payload_len;
        if payload_end <= original.len() {
            buf[frag_header_len..].copy_from_slice(&original[payload_start..payload_end]);
        }

        // Recompute checksum
        buf[offsets::CHECKSUM] = 0;
        buf[offsets::CHECKSUM + 1] = 0;
        let checksum = ipv4_checksum(&buf[..frag_header_len]);
        buf[offsets::CHECKSUM] = (checksum >> 8) as u8;
        buf[offsets::CHECKSUM + 1] = (checksum & 0xFF) as u8;

        Ok(buf)
    }
}

/// Errors that can occur during fragmentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentError {
    /// Don't Fragment flag is set but packet exceeds MTU.
    DontFragmentSet { packet_size: usize, mtu: usize },
    /// MTU is too small to fragment.
    MtuTooSmall { mtu: usize, min_required: usize },
    /// Error parsing the packet.
    ParseError(String),
}

impl std::fmt::Display for FragmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DontFragmentSet { packet_size, mtu } => {
                write!(
                    f,
                    "packet size {} exceeds MTU {} but DF flag is set",
                    packet_size, mtu
                )
            },
            Self::MtuTooSmall { mtu, min_required } => {
                write!(
                    f,
                    "MTU {} is too small, minimum required is {}",
                    mtu, min_required
                )
            },
            Self::ParseError(msg) => write!(f, "parse error: {}", msg),
        }
    }
}

impl std::error::Error for FragmentError {}

/// Key for identifying a fragment group.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub id: u16,
    pub protocol: u8,
}

impl FragmentKey {
    /// Create a key from a packet.
    pub fn from_packet(packet: &[u8]) -> Result<Self, FieldError> {
        let layer = Ipv4Layer::at_offset_dynamic(packet, 0)?;
        Ok(Self {
            src: layer.src(packet)?,
            dst: layer.dst(packet)?,
            id: layer.id(packet)?,
            protocol: layer.protocol(packet)?,
        })
    }
}

/// A collection of fragments being reassembled.
#[derive(Debug, Clone)]
pub struct FragmentGroup {
    /// The fragment key.
    pub key: FragmentKey,
    /// Collected fragments.
    pub fragments: Vec<FragmentInfo>,
    /// Total expected length (known when last fragment received).
    pub total_length: Option<u32>,
    /// First fragment header (for reconstruction).
    pub first_header: Option<Vec<u8>>,
    /// Timestamp when first fragment was received.
    pub first_received: std::time::Instant,
}

impl FragmentGroup {
    /// Create a new fragment group.
    pub fn new(key: FragmentKey) -> Self {
        Self {
            key,
            fragments: Vec::new(),
            total_length: None,
            first_header: None,
            first_received: std::time::Instant::now(),
        }
    }

    /// Add a fragment to the group.
    pub fn add_fragment(&mut self, packet: &[u8]) -> Result<(), FieldError> {
        let layer = Ipv4Layer::at_offset_dynamic(packet, 0)?;
        let header_len = layer.calculate_header_len(packet);
        let total_len = layer.total_len(packet)? as usize;
        let flags = layer.flags(packet)?;
        let offset = layer.frag_offset(packet)? as u32 * 8;
        let payload_len = total_len.saturating_sub(header_len);

        // Store first fragment header
        if offset == 0 {
            self.first_header = Some(packet[..header_len].to_vec());
        }

        // If this is the last fragment, we know the total length
        if !flags.mf {
            self.total_length = Some(offset + payload_len as u32);
        }

        // Add fragment info
        self.fragments.push(FragmentInfo {
            offset,
            length: payload_len,
            last: !flags.mf,
            data: packet.to_vec(),
        });

        Ok(())
    }

    /// Check if all fragments have been received.
    pub fn is_complete(&self) -> bool {
        let total = match self.total_length {
            Some(t) => t,
            None => return false,
        };

        // Sort fragments by offset
        let mut sorted: Vec<_> = self.fragments.iter().collect();
        sorted.sort_by_key(|f| f.offset);

        // Check for gaps
        let mut expected_offset = 0u32;
        for frag in sorted {
            if frag.offset != expected_offset {
                return false;
            }
            expected_offset = frag.end_offset();
        }

        expected_offset >= total
    }

    /// Reassemble the fragments into a complete packet.
    pub fn reassemble(&self) -> Result<Vec<u8>, ReassemblyError> {
        if !self.is_complete() {
            return Err(ReassemblyError::Incomplete);
        }

        let total_length = self.total_length.ok_or(ReassemblyError::Incomplete)?;
        let first_header = self
            .first_header
            .as_ref()
            .ok_or(ReassemblyError::MissingFirstFragment)?;

        let header_len = first_header.len();
        let mut result = vec![0u8; header_len + total_length as usize];

        // Copy header
        result[..header_len].copy_from_slice(first_header);

        // Sort and copy payloads
        let mut sorted: Vec<_> = self.fragments.iter().collect();
        sorted.sort_by_key(|f| f.offset);

        for frag in sorted {
            let layer = Ipv4Layer::at_offset_dynamic(&frag.data, 0)
                .map_err(|e| ReassemblyError::ParseError(e.to_string()))?;
            let frag_header_len = layer.calculate_header_len(&frag.data);

            let src_start = frag_header_len;
            let src_end = src_start + frag.length;
            let dst_start = header_len + frag.offset as usize;
            let dst_end = dst_start + frag.length;

            if src_end <= frag.data.len() && dst_end <= result.len() {
                result[dst_start..dst_end].copy_from_slice(&frag.data[src_start..src_end]);
            }
        }

        // Update header fields
        let new_total_len = (header_len + total_length as usize) as u16;
        result[offsets::TOTAL_LEN] = (new_total_len >> 8) as u8;
        result[offsets::TOTAL_LEN + 1] = (new_total_len & 0xFF) as u8;

        // Clear MF flag and fragment offset
        result[offsets::FLAGS_FRAG] &= 0xC0; // Preserve DF and reserved
        result[offsets::FLAGS_FRAG + 1] = 0;

        // Recompute checksum
        result[offsets::CHECKSUM] = 0;
        result[offsets::CHECKSUM + 1] = 0;
        let checksum = ipv4_checksum(&result[..header_len]);
        result[offsets::CHECKSUM] = (checksum >> 8) as u8;
        result[offsets::CHECKSUM + 1] = (checksum & 0xFF) as u8;

        Ok(result)
    }
}

/// Errors during reassembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyError {
    /// Not all fragments received.
    Incomplete,
    /// First fragment (offset 0) not received.
    MissingFirstFragment,
    /// Fragment overlaps with another.
    Overlap,
    /// Error parsing fragment.
    ParseError(String),
    /// Timeout waiting for fragments.
    Timeout,
}

impl std::fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete => write!(f, "not all fragments received"),
            Self::MissingFirstFragment => write!(f, "first fragment not received"),
            Self::Overlap => write!(f, "fragment overlap detected"),
            Self::ParseError(msg) => write!(f, "parse error: {}", msg),
            Self::Timeout => write!(f, "timeout waiting for fragments"),
        }
    }
}

impl std::error::Error for ReassemblyError {}

/// Reassemble fragments from a list of packets.
///
/// This is a convenience function for simple reassembly.
/// For stateful reassembly across multiple calls, use `FragmentGroup`.
pub fn reassemble_fragments(fragments: &[Vec<u8>]) -> Result<Vec<u8>, ReassemblyError> {
    if fragments.is_empty() {
        return Err(ReassemblyError::Incomplete);
    }

    // Get key from first fragment
    let key = FragmentKey::from_packet(&fragments[0])
        .map_err(|e| ReassemblyError::ParseError(e.to_string()))?;

    let mut group = FragmentGroup::new(key);

    for frag in fragments {
        group
            .add_fragment(frag)
            .map_err(|e| ReassemblyError::ParseError(e.to_string()))?;
    }

    group.reassemble()
}

/// Fragment a packet into multiple fragments.
///
/// Convenience function using default fragmenter.
pub fn fragment_packet(packet: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>, FragmentError> {
    let fragmenter = Ipv4Fragmenter::with_mtu(mtu);
    let fragments = fragmenter.fragment(packet)?;
    Ok(fragments.into_iter().map(|f| f.packet).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ipv4Builder;

    fn build_large_packet(payload_size: usize) -> Vec<u8> {
        Ipv4Builder::new()
            .src(Ipv4Addr::new(192, 168, 1, 1))
            .dst(Ipv4Addr::new(192, 168, 1, 2))
            .id(0x1234)
            .protocol(17) // UDP
            .payload(vec![0xAA; payload_size])
            .build()
    }

    #[test]
    fn test_no_fragmentation_needed() {
        let packet = build_large_packet(100);
        let fragmenter = Ipv4Fragmenter::with_mtu(1500);

        assert!(!fragmenter.needs_fragmentation(&packet));

        let frags = fragmenter.fragment(&packet).unwrap();
        assert_eq!(frags.len(), 1);
        assert!(frags[0].last);
        assert_eq!(frags[0].offset, 0);
    }

    #[test]
    fn test_basic_fragmentation() {
        let packet = build_large_packet(3000);
        let fragmenter = Ipv4Fragmenter::with_mtu(1500);

        assert!(fragmenter.needs_fragmentation(&packet));

        let frags = fragmenter.fragment(&packet).unwrap();
        assert!(frags.len() >= 2);

        // First fragment
        assert_eq!(frags[0].offset, 0);
        assert!(!frags[0].last);

        // Last fragment
        assert!(frags.last().unwrap().last);

        // Verify each fragment is within MTU
        for frag in &frags {
            assert!(frag.packet.len() <= 1500);
        }
    }

    #[test]
    fn test_dont_fragment_flag() {
        let packet = Ipv4Builder::new()
            .src(Ipv4Addr::new(192, 168, 1, 1))
            .dst(Ipv4Addr::new(192, 168, 1, 2))
            .dont_fragment()
            .payload(vec![0; 2000])
            .build();

        let fragmenter = Ipv4Fragmenter::with_mtu(1500);
        let result = fragmenter.fragment(&packet);

        assert!(matches!(result, Err(FragmentError::DontFragmentSet { .. })));
    }

    #[test]
    fn test_reassembly() {
        let original = build_large_packet(3000);
        let fragmenter = Ipv4Fragmenter::with_mtu(1000);

        let frags = fragmenter.fragment(&original).unwrap();
        let frag_packets: Vec<Vec<u8>> = frags.into_iter().map(|f| f.packet).collect();

        let reassembled = reassemble_fragments(&frag_packets).unwrap();

        // Check payload matches
        let orig_layer = Ipv4Layer::at_offset(0);
        let reasm_layer = Ipv4Layer::at_offset(0);

        let orig_payload = orig_layer.payload(&original).unwrap();
        let reasm_payload = reasm_layer.payload(&reassembled).unwrap();

        assert_eq!(orig_payload, reasm_payload);
    }

    #[test]
    fn test_fragment_key() {
        let packet = build_large_packet(100);
        let key = FragmentKey::from_packet(&packet).unwrap();

        assert_eq!(key.src, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(key.dst, Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(key.id, 0x1234);
        assert_eq!(key.protocol, 17);
    }

    #[test]
    fn test_fragment_group_complete() {
        let packet = build_large_packet(2000);
        let fragmenter = Ipv4Fragmenter::with_mtu(1000);

        let frags = fragmenter.fragment(&packet).unwrap();
        let key = FragmentKey::from_packet(&frags[0].packet).unwrap();

        let mut group = FragmentGroup::new(key);

        // Add fragments in random order
        for frag in frags.iter().rev() {
            group.add_fragment(&frag.packet).unwrap();
        }

        assert!(group.is_complete());
    }

    #[test]
    fn test_fragment_group_incomplete() {
        let packet = build_large_packet(2000);
        let fragmenter = Ipv4Fragmenter::with_mtu(1000);

        let frags = fragmenter.fragment(&packet).unwrap();
        let key = FragmentKey::from_packet(&frags[0].packet).unwrap();

        let mut group = FragmentGroup::new(key);

        // Add only first fragment
        group.add_fragment(&frags[0].packet).unwrap();

        assert!(!group.is_complete());
    }

    #[test]
    fn test_small_mtu() {
        let packet = build_large_packet(1000);
        let fragmenter = Ipv4Fragmenter::with_mtu(100);

        let frags = fragmenter.fragment(&packet).unwrap();

        // Should create many small fragments
        assert!(frags.len() > 10);

        // All should be within MTU
        for frag in &frags {
            assert!(frag.packet.len() <= 100);
        }
    }

    #[test]
    fn test_fragment_offset_alignment() {
        let packet = build_large_packet(1000);
        let fragmenter = Ipv4Fragmenter::with_mtu(500);

        let frags = fragmenter.fragment(&packet).unwrap();

        // All non-last fragments should have payloads that are multiples of 8
        for frag in &frags[..frags.len() - 1] {
            let layer = Ipv4Layer::at_offset(0);
            let header_len = layer.calculate_header_len(&frag.packet);
            let payload_len = frag.packet.len() - header_len;
            assert_eq!(
                payload_len % 8,
                0,
                "payload len {} not multiple of 8",
                payload_len
            );
        }
    }

    #[test]
    fn test_mtu_too_small() {
        let packet = build_large_packet(100);
        let fragmenter = Ipv4Fragmenter::with_mtu(20); // Too small even for header

        let result = fragmenter.fragment(&packet);
        assert!(matches!(result, Err(FragmentError::MtuTooSmall { .. })));
    }
}
