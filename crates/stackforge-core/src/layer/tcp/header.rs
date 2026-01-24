//! TCP header layer implementation.
//!
//! Provides zero-copy access to TCP header fields per RFC 793.
//!
//! # TCP Header Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Source Port          |       Destination Port        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Sequence Number                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Acknowledgment Number                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Data |     |N|C|E|U|A|P|R|S|F|                               |
//! | Offset| Res |S|W|C|R|C|S|S|Y|I|            Window             |
//! |       |     | |R|E|G|K|H|T|N|N|                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Checksum            |         Urgent Pointer        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Options                    |    Padding    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                             data                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::layer::field::{Field, FieldDesc, FieldError, FieldType, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

use super::flags::TcpFlags;
use super::options::{TcpOptions, parse_options};
use super::services;

/// Minimum TCP header length (no options).
pub const TCP_MIN_HEADER_LEN: usize = 20;

/// Maximum TCP header length (with maximum options).
pub const TCP_MAX_HEADER_LEN: usize = 60;

/// Field offsets within the TCP header.
pub mod offsets {
    /// Source port (16 bits)
    pub const SRC_PORT: usize = 0;
    /// Destination port (16 bits)
    pub const DST_PORT: usize = 2;
    /// Sequence number (32 bits)
    pub const SEQ: usize = 4;
    /// Acknowledgment number (32 bits)
    pub const ACK: usize = 8;
    /// Data offset (4 bits) + Reserved (3 bits) + NS flag (1 bit)
    pub const DATA_OFFSET: usize = 12;
    /// Flags byte (8 bits: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
    pub const FLAGS: usize = 13;
    /// Window size (16 bits)
    pub const WINDOW: usize = 14;
    /// Checksum (16 bits)
    pub const CHECKSUM: usize = 16;
    /// Urgent pointer (16 bits)
    pub const URG_PTR: usize = 18;
    /// Options start (if data offset > 5)
    pub const OPTIONS: usize = 20;
}

/// Field descriptors for dynamic access.
pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::new("sport", offsets::SRC_PORT, 2, FieldType::U16),
    FieldDesc::new("dport", offsets::DST_PORT, 2, FieldType::U16),
    FieldDesc::new("seq", offsets::SEQ, 4, FieldType::U32),
    FieldDesc::new("ack", offsets::ACK, 4, FieldType::U32),
    FieldDesc::new("dataofs", offsets::DATA_OFFSET, 1, FieldType::U8),
    FieldDesc::new("reserved", offsets::DATA_OFFSET, 1, FieldType::U8),
    FieldDesc::new("flags", offsets::FLAGS, 1, FieldType::U8),
    FieldDesc::new("window", offsets::WINDOW, 2, FieldType::U16),
    FieldDesc::new("chksum", offsets::CHECKSUM, 2, FieldType::U16),
    FieldDesc::new("urgptr", offsets::URG_PTR, 2, FieldType::U16),
];

/// A view into a TCP packet header.
#[derive(Debug, Clone)]
pub struct TcpLayer {
    pub index: LayerIndex,
}

impl TcpLayer {
    /// Create a new TCP layer view with specified bounds.
    #[inline]
    pub const fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Tcp, start, end),
        }
    }

    /// Create a layer at offset 0 with minimum header length.
    #[inline]
    pub const fn at_start() -> Self {
        Self::new(0, TCP_MIN_HEADER_LEN)
    }

    /// Create a layer at the specified offset with minimum header length.
    #[inline]
    pub const fn at_offset(offset: usize) -> Self {
        Self::new(offset, offset + TCP_MIN_HEADER_LEN)
    }

    /// Create a layer at offset, calculating actual header length from data offset.
    pub fn at_offset_dynamic(buf: &[u8], offset: usize) -> Result<Self, FieldError> {
        if buf.len() < offset + TCP_MIN_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: TCP_MIN_HEADER_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }

        let data_offset = ((buf[offset + offsets::DATA_OFFSET] >> 4) & 0x0F) as usize;
        let header_len = data_offset * 4;

        if header_len < TCP_MIN_HEADER_LEN {
            return Err(FieldError::InvalidValue(format!(
                "Data offset {} is less than minimum (5)",
                data_offset
            )));
        }

        if buf.len() < offset + header_len {
            return Err(FieldError::BufferTooShort {
                offset,
                need: header_len,
                have: buf.len().saturating_sub(offset),
            });
        }

        Ok(Self::new(offset, offset + header_len))
    }

    /// Validate that the buffer contains a valid TCP header at the offset.
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + TCP_MIN_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: TCP_MIN_HEADER_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }

        let data_offset = ((buf[offset + offsets::DATA_OFFSET] >> 4) & 0x0F) as usize;
        if data_offset < 5 {
            return Err(FieldError::InvalidValue(format!(
                "Data offset {} is less than minimum (5)",
                data_offset
            )));
        }

        let header_len = data_offset * 4;
        if buf.len() < offset + header_len {
            return Err(FieldError::BufferTooShort {
                offset,
                need: header_len,
                have: buf.len().saturating_sub(offset),
            });
        }

        Ok(())
    }

    /// Calculate the actual header length from the buffer.
    pub fn calculate_header_len(&self, buf: &[u8]) -> usize {
        self.data_offset(buf)
            .map(|doff| (doff as usize) * 4)
            .unwrap_or(TCP_MIN_HEADER_LEN)
    }

    /// Get the options length (header length - 20).
    pub fn options_len(&self, buf: &[u8]) -> usize {
        self.calculate_header_len(buf)
            .saturating_sub(TCP_MIN_HEADER_LEN)
    }

    // ========== Field Readers ==========

    /// Read the source port.
    #[inline]
    pub fn src_port(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::SRC_PORT)
    }

    /// Alias for src_port (Scapy compatibility).
    #[inline]
    pub fn sport(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.src_port(buf)
    }

    /// Read the destination port.
    #[inline]
    pub fn dst_port(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::DST_PORT)
    }

    /// Alias for dst_port (Scapy compatibility).
    #[inline]
    pub fn dport(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.dst_port(buf)
    }

    /// Read the sequence number.
    #[inline]
    pub fn seq(&self, buf: &[u8]) -> Result<u32, FieldError> {
        u32::read(buf, self.index.start + offsets::SEQ)
    }

    /// Read the acknowledgment number.
    #[inline]
    pub fn ack(&self, buf: &[u8]) -> Result<u32, FieldError> {
        u32::read(buf, self.index.start + offsets::ACK)
    }

    /// Read the data offset (in 32-bit words).
    #[inline]
    pub fn data_offset(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let b = u8::read(buf, self.index.start + offsets::DATA_OFFSET)?;
        Ok((b >> 4) & 0x0F)
    }

    /// Alias for data_offset (Scapy compatibility).
    #[inline]
    pub fn dataofs(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.data_offset(buf)
    }

    /// Read the reserved bits (should be 0).
    #[inline]
    pub fn reserved(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let b = u8::read(buf, self.index.start + offsets::DATA_OFFSET)?;
        Ok((b >> 1) & 0x07)
    }

    /// Read the flags as raw byte.
    #[inline]
    pub fn flags_raw(&self, buf: &[u8]) -> Result<u8, FieldError> {
        u8::read(buf, self.index.start + offsets::FLAGS)
    }

    /// Read the flags as a structured type.
    #[inline]
    pub fn flags(&self, buf: &[u8]) -> Result<TcpFlags, FieldError> {
        let hi = u8::read(buf, self.index.start + offsets::DATA_OFFSET)?;
        let lo = u8::read(buf, self.index.start + offsets::FLAGS)?;
        Ok(TcpFlags::from_bytes(hi, lo))
    }

    /// Read the window size.
    #[inline]
    pub fn window(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::WINDOW)
    }

    /// Read the checksum.
    #[inline]
    pub fn checksum(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::CHECKSUM)
    }

    /// Alias for checksum (Scapy compatibility).
    #[inline]
    pub fn chksum(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.checksum(buf)
    }

    /// Read the urgent pointer.
    #[inline]
    pub fn urgent_ptr(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::URG_PTR)
    }

    /// Alias for urgent_ptr (Scapy compatibility).
    #[inline]
    pub fn urgptr(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.urgent_ptr(buf)
    }

    /// Read the options bytes (if any).
    pub fn options_bytes<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8], FieldError> {
        let header_len = self.calculate_header_len(buf);
        let opts_start = self.index.start + TCP_MIN_HEADER_LEN;
        let opts_end = self.index.start + header_len;

        if buf.len() < opts_end {
            return Err(FieldError::BufferTooShort {
                offset: opts_start,
                need: header_len - TCP_MIN_HEADER_LEN,
                have: buf.len().saturating_sub(opts_start),
            });
        }

        Ok(&buf[opts_start..opts_end])
    }

    /// Parse and return the options.
    pub fn options(&self, buf: &[u8]) -> Result<TcpOptions, FieldError> {
        let opts_bytes = self.options_bytes(buf)?;
        parse_options(opts_bytes)
    }

    // ========== Field Writers ==========

    /// Set the source port.
    #[inline]
    pub fn set_src_port(&self, buf: &mut [u8], port: u16) -> Result<(), FieldError> {
        port.write(buf, self.index.start + offsets::SRC_PORT)
    }

    /// Alias for set_src_port (Scapy compatibility).
    #[inline]
    pub fn set_sport(&self, buf: &mut [u8], port: u16) -> Result<(), FieldError> {
        self.set_src_port(buf, port)
    }

    /// Set the destination port.
    #[inline]
    pub fn set_dst_port(&self, buf: &mut [u8], port: u16) -> Result<(), FieldError> {
        port.write(buf, self.index.start + offsets::DST_PORT)
    }

    /// Alias for set_dst_port (Scapy compatibility).
    #[inline]
    pub fn set_dport(&self, buf: &mut [u8], port: u16) -> Result<(), FieldError> {
        self.set_dst_port(buf, port)
    }

    /// Set the sequence number.
    #[inline]
    pub fn set_seq(&self, buf: &mut [u8], seq: u32) -> Result<(), FieldError> {
        seq.write(buf, self.index.start + offsets::SEQ)
    }

    /// Set the acknowledgment number.
    #[inline]
    pub fn set_ack(&self, buf: &mut [u8], ack: u32) -> Result<(), FieldError> {
        ack.write(buf, self.index.start + offsets::ACK)
    }

    /// Set the data offset (in 32-bit words).
    #[inline]
    pub fn set_data_offset(&self, buf: &mut [u8], offset: u8) -> Result<(), FieldError> {
        let idx = self.index.start + offsets::DATA_OFFSET;
        let current = u8::read(buf, idx)?;
        let new_val = (current & 0x0F) | ((offset & 0x0F) << 4);
        new_val.write(buf, idx)
    }

    /// Alias for set_data_offset (Scapy compatibility).
    #[inline]
    pub fn set_dataofs(&self, buf: &mut [u8], offset: u8) -> Result<(), FieldError> {
        self.set_data_offset(buf, offset)
    }

    /// Set the reserved bits.
    #[inline]
    pub fn set_reserved(&self, buf: &mut [u8], reserved: u8) -> Result<(), FieldError> {
        let idx = self.index.start + offsets::DATA_OFFSET;
        let current = u8::read(buf, idx)?;
        let new_val = (current & 0xF1) | ((reserved & 0x07) << 1);
        new_val.write(buf, idx)
    }

    /// Set the flags from raw byte.
    #[inline]
    pub fn set_flags_raw(&self, buf: &mut [u8], flags: u8) -> Result<(), FieldError> {
        flags.write(buf, self.index.start + offsets::FLAGS)
    }

    /// Set the flags from structured type.
    #[inline]
    pub fn set_flags(&self, buf: &mut [u8], flags: TcpFlags) -> Result<(), FieldError> {
        // Set flags byte
        flags
            .to_byte()
            .write(buf, self.index.start + offsets::FLAGS)?;

        // Set NS bit in data offset byte
        let idx = self.index.start + offsets::DATA_OFFSET;
        let current = u8::read(buf, idx)?;
        let new_val = (current & 0xFE) | flags.ns_bit();
        new_val.write(buf, idx)
    }

    /// Set the window size.
    #[inline]
    pub fn set_window(&self, buf: &mut [u8], window: u16) -> Result<(), FieldError> {
        window.write(buf, self.index.start + offsets::WINDOW)
    }

    /// Set the checksum.
    #[inline]
    pub fn set_checksum(&self, buf: &mut [u8], checksum: u16) -> Result<(), FieldError> {
        checksum.write(buf, self.index.start + offsets::CHECKSUM)
    }

    /// Alias for set_checksum (Scapy compatibility).
    #[inline]
    pub fn set_chksum(&self, buf: &mut [u8], checksum: u16) -> Result<(), FieldError> {
        self.set_checksum(buf, checksum)
    }

    /// Set the urgent pointer.
    #[inline]
    pub fn set_urgent_ptr(&self, buf: &mut [u8], urgptr: u16) -> Result<(), FieldError> {
        urgptr.write(buf, self.index.start + offsets::URG_PTR)
    }

    /// Alias for set_urgent_ptr (Scapy compatibility).
    #[inline]
    pub fn set_urgptr(&self, buf: &mut [u8], urgptr: u16) -> Result<(), FieldError> {
        self.set_urgent_ptr(buf, urgptr)
    }

    // ========== Dynamic Field Access ==========

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "sport" | "src_port" => Some(self.src_port(buf).map(FieldValue::U16)),
            "dport" | "dst_port" => Some(self.dst_port(buf).map(FieldValue::U16)),
            "seq" => Some(self.seq(buf).map(FieldValue::U32)),
            "ack" => Some(self.ack(buf).map(FieldValue::U32)),
            "dataofs" | "data_offset" => Some(self.data_offset(buf).map(FieldValue::U8)),
            "reserved" => Some(self.reserved(buf).map(FieldValue::U8)),
            "flags" => Some(self.flags_raw(buf).map(FieldValue::U8)),
            "window" => Some(self.window(buf).map(FieldValue::U16)),
            "chksum" | "checksum" => Some(self.checksum(buf).map(FieldValue::U16)),
            "urgptr" | "urgent_ptr" => Some(self.urgent_ptr(buf).map(FieldValue::U16)),
            _ => None,
        }
    }

    /// Set a field value by name.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match (name, value) {
            ("sport" | "src_port", FieldValue::U16(v)) => Some(self.set_src_port(buf, v)),
            ("dport" | "dst_port", FieldValue::U16(v)) => Some(self.set_dst_port(buf, v)),
            ("seq", FieldValue::U32(v)) => Some(self.set_seq(buf, v)),
            ("ack", FieldValue::U32(v)) => Some(self.set_ack(buf, v)),
            ("dataofs" | "data_offset", FieldValue::U8(v)) => Some(self.set_data_offset(buf, v)),
            ("reserved", FieldValue::U8(v)) => Some(self.set_reserved(buf, v)),
            ("flags", FieldValue::U8(v)) => Some(self.set_flags_raw(buf, v)),
            ("window", FieldValue::U16(v)) => Some(self.set_window(buf, v)),
            ("chksum" | "checksum", FieldValue::U16(v)) => Some(self.set_checksum(buf, v)),
            ("urgptr" | "urgent_ptr", FieldValue::U16(v)) => Some(self.set_urgent_ptr(buf, v)),
            _ => None,
        }
    }

    /// Get list of field names.
    pub fn field_names() -> &'static [&'static str] {
        &[
            "sport", "dport", "seq", "ack", "dataofs", "reserved", "flags", "window", "chksum",
            "urgptr",
        ]
    }

    // ========== Utility Methods ==========

    /// Get the payload length from IP total length.
    /// Note: TCP doesn't have its own length field; it relies on IP layer.
    pub fn payload_len(&self, buf: &[u8], ip_payload_len: usize) -> usize {
        let header_len = self.calculate_header_len(buf);
        ip_payload_len.saturating_sub(header_len)
    }

    /// Get a slice of the payload data.
    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let header_len = self.calculate_header_len(buf);
        let payload_start = self.index.start + header_len;

        if payload_start > buf.len() {
            return &[];
        }

        &buf[payload_start..]
    }

    /// Get the header bytes.
    #[inline]
    pub fn header_bytes<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let header_len = self.calculate_header_len(buf);
        let end = (self.index.start + header_len).min(buf.len());
        &buf[self.index.start..end]
    }

    /// Get the source port service name.
    pub fn src_service(&self, buf: &[u8]) -> &'static str {
        self.src_port(buf)
            .map(services::service_name)
            .unwrap_or("unknown")
    }

    /// Get the destination port service name.
    pub fn dst_service(&self, buf: &[u8]) -> &'static str {
        self.dst_port(buf)
            .map(services::service_name)
            .unwrap_or("unknown")
    }

    /// Compute hash for packet matching (like Scapy's hashret).
    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        let sport = self.src_port(buf).unwrap_or(0);
        let dport = self.dst_port(buf).unwrap_or(0);

        // XOR the ports
        let xored = sport ^ dport;

        // Return as bytes
        xored.to_be_bytes().to_vec()
    }

    /// Check if this packet answers another (for sr() matching).
    pub fn answers(&self, buf: &[u8], other: &TcpLayer, other_buf: &[u8]) -> bool {
        let self_flags = self.flags(buf).unwrap_or(TcpFlags::NONE);
        let other_flags = other.flags(other_buf).unwrap_or(TcpFlags::NONE);

        // RST packets don't get answers
        if other_flags.rst {
            return false;
        }

        // SYN packets without ACK don't answer anything
        if self_flags.syn && !self_flags.ack {
            return false;
        }

        // SYN+ACK answers SYN
        if self_flags.syn && self_flags.ack {
            if !other_flags.syn {
                return false;
            }
        }

        // Check ports
        let self_sport = self.src_port(buf).unwrap_or(0);
        let self_dport = self.dst_port(buf).unwrap_or(0);
        let other_sport = other.src_port(other_buf).unwrap_or(0);
        let other_dport = other.dst_port(other_buf).unwrap_or(0);

        if self_sport != other_dport || self_dport != other_sport {
            return false;
        }

        // Check sequence/ack numbers (with tolerance)
        let self_seq = self.seq(buf).unwrap_or(0);
        let self_ack = self.ack(buf).unwrap_or(0);
        let other_seq = other.seq(other_buf).unwrap_or(0);
        let other_ack = other.ack(other_buf).unwrap_or(0);

        // For SYN packets without ACK, don't check ack value
        if !(other_flags.syn && !other_flags.ack) {
            let diff = if other_ack > self_seq {
                other_ack - self_seq
            } else {
                self_seq - other_ack
            };
            if diff > 2 {
                return false;
            }
        }

        // For RST packets without ACK, skip remaining checks
        if self_flags.rst && !self_flags.ack {
            return true;
        }

        // Check ack vs seq with payload length tolerance
        let other_payload_len = other.payload(other_buf).len() as u32;
        let diff = if other_seq > self_ack {
            other_seq - self_ack
        } else {
            self_ack - other_seq
        };
        if diff > 2 + other_payload_len {
            return false;
        }

        true
    }
}

impl Layer for TcpLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Tcp
    }

    fn summary(&self, buf: &[u8]) -> String {
        let sport = self.src_port(buf).unwrap_or(0);
        let dport = self.dst_port(buf).unwrap_or(0);
        let flags = self.flags(buf).unwrap_or(TcpFlags::NONE);

        format!("TCP {} > {} {}", sport, dport, flags)
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        self.calculate_header_len(buf)
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        self.hashret(buf)
    }

    fn answers(&self, buf: &[u8], other: &Self, other_buf: &[u8]) -> bool {
        self.answers(buf, other, other_buf)
    }

    fn field_names(&self) -> &'static [&'static str] {
        Self::field_names()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tcp_header() -> Vec<u8> {
        vec![
            0x00, 0x50, // Source port: 80
            0x1F, 0x90, // Dest port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq: 1
            0x00, 0x00, 0x00, 0x00, // Ack: 0
            0x50, // Data offset: 5 (20 bytes), Reserved: 0, NS: 0
            0x02, // Flags: SYN
            0xFF, 0xFF, // Window: 65535
            0x00, 0x00, // Checksum (to be computed)
            0x00, 0x00, // Urgent pointer: 0
        ]
    }

    #[test]
    fn test_field_readers() {
        let buf = sample_tcp_header();
        let layer = TcpLayer::at_offset(0);

        assert_eq!(layer.src_port(&buf).unwrap(), 80);
        assert_eq!(layer.dst_port(&buf).unwrap(), 8080);
        assert_eq!(layer.seq(&buf).unwrap(), 1);
        assert_eq!(layer.ack(&buf).unwrap(), 0);
        assert_eq!(layer.data_offset(&buf).unwrap(), 5);
        assert_eq!(layer.window(&buf).unwrap(), 65535);
        assert_eq!(layer.urgent_ptr(&buf).unwrap(), 0);

        let flags = layer.flags(&buf).unwrap();
        assert!(flags.syn);
        assert!(!flags.ack);
    }

    #[test]
    fn test_field_writers() {
        let mut buf = sample_tcp_header();
        let layer = TcpLayer::at_offset(0);

        layer.set_src_port(&mut buf, 12345).unwrap();
        assert_eq!(layer.src_port(&buf).unwrap(), 12345);

        layer.set_dst_port(&mut buf, 443).unwrap();
        assert_eq!(layer.dst_port(&buf).unwrap(), 443);

        layer.set_seq(&mut buf, 0x12345678).unwrap();
        assert_eq!(layer.seq(&buf).unwrap(), 0x12345678);

        layer.set_ack(&mut buf, 0xABCDEF00).unwrap();
        assert_eq!(layer.ack(&buf).unwrap(), 0xABCDEF00);

        layer.set_flags(&mut buf, TcpFlags::SA).unwrap();
        let flags = layer.flags(&buf).unwrap();
        assert!(flags.syn);
        assert!(flags.ack);
    }

    #[test]
    fn test_flags() {
        let mut buf = sample_tcp_header();
        let layer = TcpLayer::at_offset(0);

        // Test NS flag
        let mut flags = TcpFlags::SA;
        flags.ns = true;
        layer.set_flags(&mut buf, flags).unwrap();

        let read_flags = layer.flags(&buf).unwrap();
        assert!(read_flags.syn);
        assert!(read_flags.ack);
        assert!(read_flags.ns);
    }

    #[test]
    fn test_header_len() {
        let buf = sample_tcp_header();
        let layer = TcpLayer::at_offset(0);

        assert_eq!(layer.calculate_header_len(&buf), 20);

        // Test with options (data offset = 6 = 24 bytes)
        let mut buf_with_opts = sample_tcp_header();
        buf_with_opts[12] = 0x60; // Data offset = 6
        buf_with_opts.extend_from_slice(&[0, 0, 0, 0]); // 4 bytes of options/padding

        assert_eq!(layer.calculate_header_len(&buf_with_opts), 24);
    }

    #[test]
    fn test_validate() {
        let buf = sample_tcp_header();
        assert!(TcpLayer::validate(&buf, 0).is_ok());

        // Too short
        let short = vec![0x00, 0x50];
        assert!(TcpLayer::validate(&short, 0).is_err());

        // Invalid data offset
        let mut bad_doff = sample_tcp_header();
        bad_doff[12] = 0x30; // Data offset = 3 (< minimum 5)
        assert!(TcpLayer::validate(&bad_doff, 0).is_err());
    }

    #[test]
    fn test_summary() {
        let buf = sample_tcp_header();
        let layer = TcpLayer::at_offset(0);

        let summary = layer.summary(&buf);
        assert!(summary.contains("80"));
        assert!(summary.contains("8080"));
        assert!(summary.contains("S")); // SYN flag
    }

    #[test]
    fn test_at_offset_dynamic() {
        let buf = sample_tcp_header();
        let layer = TcpLayer::at_offset_dynamic(&buf, 0).unwrap();

        assert_eq!(layer.index.start, 0);
        assert_eq!(layer.index.end, 20);
    }

    #[test]
    fn test_payload() {
        let mut buf = sample_tcp_header();
        buf.extend_from_slice(b"Hello, TCP!");

        let layer = TcpLayer::at_offset(0);
        let payload = layer.payload(&buf);

        assert_eq!(payload, b"Hello, TCP!");
    }
}
