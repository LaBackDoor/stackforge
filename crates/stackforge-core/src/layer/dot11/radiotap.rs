//! `RadioTap` header implementation for IEEE 802.11 frames.
//!
//! `RadioTap` is a de facto standard for 802.11 frame injection and reception.
//! It provides a flexible, extensible header format that precedes the actual
//! 802.11 frame and carries metadata like signal strength, channel, and rate.
//!
//! Reference: <https://www.radiotap.org/>

use crate::layer::field::FieldError;
use crate::layer::{Layer, LayerIndex, LayerKind};

use super::types::radiotap_present;

/// Minimum `RadioTap` header length: version(1) + pad(1) + len(2) + present(4) = 8 bytes.
pub const RADIOTAP_MIN_HEADER_LEN: usize = 8;

/// `RadioTap` header field offsets.
pub mod offsets {
    pub const VERSION: usize = 0;
    pub const PAD: usize = 1;
    pub const LENGTH: usize = 2;
    pub const PRESENT: usize = 4;
}

/// Alignment requirements for `RadioTap` fields (size, alignment).
/// Returns (`field_size`, `required_alignment`) for a given present bit.
fn field_alignment(bit: u32) -> (usize, usize) {
    match bit {
        radiotap_present::TSFT => (8, 8),
        radiotap_present::FLAGS => (1, 1),
        radiotap_present::RATE => (1, 1),
        radiotap_present::CHANNEL => (4, 2), // freq(2) + flags(2)
        radiotap_present::FHSS => (2, 1),
        radiotap_present::DBM_ANT_SIGNAL => (1, 1),
        radiotap_present::DBM_ANT_NOISE => (1, 1),
        radiotap_present::LOCK_QUALITY => (2, 2),
        radiotap_present::TX_ATTENUATION => (2, 2),
        radiotap_present::DB_TX_ATTENUATION => (2, 2),
        radiotap_present::DBM_TX_POWER => (1, 1),
        radiotap_present::ANTENNA => (1, 1),
        radiotap_present::DB_ANT_SIGNAL => (1, 1),
        radiotap_present::DB_ANT_NOISE => (1, 1),
        radiotap_present::RX_FLAGS => (2, 2),
        radiotap_present::TX_FLAGS => (2, 2),
        radiotap_present::MCS => (3, 1), // known(1) + flags(1) + mcs(1)
        radiotap_present::A_MPDU => (8, 4), // ref(4) + flags(4)
        radiotap_present::VHT => (12, 2), // known(2)+flags(1)+bw(1)+mcs_nss(4x1)+coding(1)+group(1)+partial_aid(2)
        radiotap_present::HE => (12, 2),  // 6x u16
        _ => (0, 1),
    }
}

/// Parsed `RadioTap` field values.
#[derive(Debug, Clone, Default)]
pub struct RadioTapFields {
    /// TSFT (MAC timestamp in microseconds).
    pub tsft: Option<u64>,
    /// Flags byte.
    pub flags: Option<u8>,
    /// Rate in units of 500 Kbps.
    pub rate: Option<u8>,
    /// Channel frequency in MHz.
    pub channel_freq: Option<u16>,
    /// Channel flags.
    pub channel_flags: Option<u16>,
    /// Antenna signal in dBm.
    pub dbm_ant_signal: Option<i8>,
    /// Antenna noise in dBm.
    pub dbm_ant_noise: Option<i8>,
    /// Lock quality (signal quality).
    pub lock_quality: Option<u16>,
    /// Antenna index.
    pub antenna: Option<u8>,
    /// Antenna signal in dB.
    pub db_ant_signal: Option<u8>,
    /// Antenna noise in dB.
    pub db_ant_noise: Option<u8>,
    /// RX flags.
    pub rx_flags: Option<u16>,
    /// TX flags.
    pub tx_flags: Option<u16>,
    /// MCS known bitmask.
    pub mcs_known: Option<u8>,
    /// MCS flags.
    pub mcs_flags: Option<u8>,
    /// MCS index.
    pub mcs_index: Option<u8>,
    /// A-MPDU reference number.
    pub a_mpdu_ref: Option<u32>,
    /// A-MPDU flags.
    pub a_mpdu_flags: Option<u32>,
}

/// `RadioTap` layer - a zero-copy view into the `RadioTap` header.
///
/// The `RadioTap` header has a variable length indicated by the `it_len` field.
/// Present fields are indicated by a bitmask in `it_present`.
#[derive(Debug, Clone)]
pub struct RadioTapLayer {
    pub index: LayerIndex,
}

impl RadioTapLayer {
    /// Create a new `RadioTapLayer` from start/end offsets.
    #[must_use]
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Dot11, start, end),
        }
    }

    /// Validate the buffer has enough data for a `RadioTap` header.
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + RADIOTAP_MIN_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: RADIOTAP_MIN_HEADER_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    // ========================================================================
    // Fixed header fields
    // ========================================================================

    /// `RadioTap` version (always 0).
    #[inline]
    pub fn version(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.index.start + offsets::VERSION;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len(),
            });
        }
        Ok(buf[off])
    }

    /// Padding byte.
    #[inline]
    pub fn pad(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.index.start + offsets::PAD;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len(),
            });
        }
        Ok(buf[off])
    }

    /// Total header length (little-endian u16).
    #[inline]
    pub fn header_length(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.index.start + offsets::LENGTH;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Present flags bitmask (little-endian u32).
    #[inline]
    pub fn present(&self, buf: &[u8]) -> Result<u32, FieldError> {
        let off = self.index.start + offsets::PRESENT;
        if buf.len() < off + 4 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 4,
                have: buf.len(),
            });
        }
        Ok(u32::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
        ]))
    }

    /// Check if a specific present field bit is set.
    #[inline]
    #[must_use]
    pub fn has_field(&self, buf: &[u8], bit: u32) -> bool {
        self.present(buf)
            .map(|p| p & (1 << bit) != 0)
            .unwrap_or(false)
    }

    /// Check if the FCS flag is set (indicating the payload includes FCS).
    #[must_use]
    pub fn has_fcs(&self, buf: &[u8]) -> bool {
        if self.has_field(buf, radiotap_present::FLAGS)
            && let Ok(fields) = self.parse_fields(buf)
            && let Some(flags) = fields.flags
        {
            return flags & super::types::radiotap_flags::FCS != 0;
        }
        false
    }

    // ========================================================================
    // Field parsing
    // ========================================================================

    /// Count the number of present bitmask words (including extended).
    fn count_present_words(&self, buf: &[u8]) -> usize {
        let mut count = 1;
        let mut off = self.index.start + offsets::PRESENT;

        loop {
            if buf.len() < off + 4 {
                break;
            }
            let word = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            if word & (1 << radiotap_present::EXT) == 0 {
                break;
            }
            count += 1;
            off += 4;
        }
        count
    }

    /// Parse all present fields from the `RadioTap` header.
    pub fn parse_fields(&self, buf: &[u8]) -> Result<RadioTapFields, FieldError> {
        let present = self.present(buf)?;
        let header_len = self.header_length(buf)? as usize;
        let start = self.index.start;

        if buf.len() < start + header_len {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: header_len,
                have: buf.len().saturating_sub(start),
            });
        }

        let num_present_words = self.count_present_words(buf);
        // Data starts after all present words
        let mut pos = start + 4 + (num_present_words * 4);
        let end = start + header_len;
        let mut fields = RadioTapFields::default();

        // Iterate through present bits and parse each field
        for bit in 0..28u32 {
            if present & (1 << bit) == 0 {
                continue;
            }

            let (size, align) = field_alignment(bit);
            if size == 0 {
                continue;
            }

            // Apply alignment
            if align > 1 {
                let base = start + 4 + (num_present_words * 4);
                let relative = pos - base;
                let _padding = (align - (relative % align)) % align;
                // Also need to align relative to the start of header
                let abs_padding = (align - ((pos - start) % align)) % align;
                pos += abs_padding;
            }

            if pos + size > end {
                break;
            }

            match bit {
                radiotap_present::TSFT => {
                    fields.tsft = Some(u64::from_le_bytes([
                        buf[pos],
                        buf[pos + 1],
                        buf[pos + 2],
                        buf[pos + 3],
                        buf[pos + 4],
                        buf[pos + 5],
                        buf[pos + 6],
                        buf[pos + 7],
                    ]));
                },
                radiotap_present::FLAGS => {
                    fields.flags = Some(buf[pos]);
                },
                radiotap_present::RATE => {
                    fields.rate = Some(buf[pos]);
                },
                radiotap_present::CHANNEL => {
                    fields.channel_freq = Some(u16::from_le_bytes([buf[pos], buf[pos + 1]]));
                    fields.channel_flags = Some(u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]));
                },
                radiotap_present::DBM_ANT_SIGNAL => {
                    fields.dbm_ant_signal = Some(buf[pos] as i8);
                },
                radiotap_present::DBM_ANT_NOISE => {
                    fields.dbm_ant_noise = Some(buf[pos] as i8);
                },
                radiotap_present::LOCK_QUALITY => {
                    fields.lock_quality = Some(u16::from_le_bytes([buf[pos], buf[pos + 1]]));
                },
                radiotap_present::ANTENNA => {
                    fields.antenna = Some(buf[pos]);
                },
                radiotap_present::DB_ANT_SIGNAL => {
                    fields.db_ant_signal = Some(buf[pos]);
                },
                radiotap_present::DB_ANT_NOISE => {
                    fields.db_ant_noise = Some(buf[pos]);
                },
                radiotap_present::RX_FLAGS => {
                    fields.rx_flags = Some(u16::from_le_bytes([buf[pos], buf[pos + 1]]));
                },
                radiotap_present::TX_FLAGS => {
                    fields.tx_flags = Some(u16::from_le_bytes([buf[pos], buf[pos + 1]]));
                },
                radiotap_present::MCS => {
                    fields.mcs_known = Some(buf[pos]);
                    fields.mcs_flags = Some(buf[pos + 1]);
                    fields.mcs_index = Some(buf[pos + 2]);
                },
                radiotap_present::A_MPDU => {
                    fields.a_mpdu_ref = Some(u32::from_le_bytes([
                        buf[pos],
                        buf[pos + 1],
                        buf[pos + 2],
                        buf[pos + 3],
                    ]));
                    fields.a_mpdu_flags = Some(u32::from_le_bytes([
                        buf[pos + 4],
                        buf[pos + 5],
                        buf[pos + 6],
                        buf[pos + 7],
                    ]));
                },
                _ => {},
            }

            pos += size;
        }

        Ok(fields)
    }
}

impl Layer for RadioTapLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Dot11
    }

    fn summary(&self, buf: &[u8]) -> String {
        let len = self
            .header_length(buf)
            .map_or_else(|_| "?".to_string(), |l| l.to_string());
        let present = self
            .present(buf)
            .map_or_else(|_| "?".to_string(), |p| format!("{p:#010x}"));
        format!("RadioTap len={len} present={present}")
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        self.header_length(buf)
            .map(|v| v as usize)
            .unwrap_or(RADIOTAP_MIN_HEADER_LEN)
    }

    fn field_names(&self) -> &'static [&'static str] {
        &[
            "version",
            "pad",
            "len",
            "present",
            "mac_timestamp",
            "Flags",
            "Rate",
            "ChannelFrequency",
            "ChannelFlags",
            "dBm_AntSignal",
            "dBm_AntNoise",
            "Antenna",
        ]
    }
}

/// Builder for constructing `RadioTap` headers.
#[derive(Debug, Clone, Default)]
pub struct RadioTapBuilder {
    /// TSFT timestamp.
    pub tsft: Option<u64>,
    /// Flags.
    pub flags: Option<u8>,
    /// Rate (in units of 500 Kbps).
    pub rate: Option<u8>,
    /// Channel frequency (MHz).
    pub channel_freq: Option<u16>,
    /// Channel flags.
    pub channel_flags: Option<u16>,
    /// dBm antenna signal.
    pub dbm_ant_signal: Option<i8>,
    /// dBm antenna noise.
    pub dbm_ant_noise: Option<i8>,
    /// Antenna index.
    pub antenna: Option<u8>,
}

impl RadioTapBuilder {
    /// Create a new `RadioTapBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn tsft(mut self, tsft: u64) -> Self {
        self.tsft = Some(tsft);
        self
    }

    #[must_use]
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = Some(flags);
        self
    }

    #[must_use]
    pub fn rate(mut self, rate: u8) -> Self {
        self.rate = Some(rate);
        self
    }

    #[must_use]
    pub fn channel(mut self, freq: u16, flags: u16) -> Self {
        self.channel_freq = Some(freq);
        self.channel_flags = Some(flags);
        self
    }

    #[must_use]
    pub fn dbm_ant_signal(mut self, signal: i8) -> Self {
        self.dbm_ant_signal = Some(signal);
        self
    }

    #[must_use]
    pub fn dbm_ant_noise(mut self, noise: i8) -> Self {
        self.dbm_ant_noise = Some(noise);
        self
    }

    #[must_use]
    pub fn antenna(mut self, antenna: u8) -> Self {
        self.antenna = Some(antenna);
        self
    }

    /// Build the `RadioTap` header bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut present: u32 = 0;
        let mut fields_data = Vec::new();

        // Build fields in order of present bit position
        if let Some(tsft) = self.tsft {
            present |= 1 << radiotap_present::TSFT;
            // TSFT requires 8-byte alignment
            while (8 + fields_data.len()) % 8 != 0 {
                fields_data.push(0);
            }
            fields_data.extend_from_slice(&tsft.to_le_bytes());
        }

        if let Some(flags) = self.flags {
            present |= 1 << radiotap_present::FLAGS;
            fields_data.push(flags);
        }

        if let Some(rate) = self.rate {
            present |= 1 << radiotap_present::RATE;
            fields_data.push(rate);
        }

        if self.channel_freq.is_some() {
            present |= 1 << radiotap_present::CHANNEL;
            // Channel requires 2-byte alignment
            let header_fixed = 8; // version(1) + pad(1) + len(2) + present(4)
            let current = header_fixed + fields_data.len();
            if current % 2 != 0 {
                fields_data.push(0);
            }
            fields_data.extend_from_slice(&self.channel_freq.unwrap_or(0).to_le_bytes());
            fields_data.extend_from_slice(&self.channel_flags.unwrap_or(0).to_le_bytes());
        }

        if let Some(signal) = self.dbm_ant_signal {
            present |= 1 << radiotap_present::DBM_ANT_SIGNAL;
            fields_data.push(signal as u8);
        }

        if let Some(noise) = self.dbm_ant_noise {
            present |= 1 << radiotap_present::DBM_ANT_NOISE;
            fields_data.push(noise as u8);
        }

        if let Some(antenna) = self.antenna {
            present |= 1 << radiotap_present::ANTENNA;
            fields_data.push(antenna);
        }

        let total_len = (8 + fields_data.len()) as u16;

        let mut out = Vec::with_capacity(total_len as usize);
        out.push(0); // version
        out.push(0); // pad
        out.extend_from_slice(&total_len.to_le_bytes());
        out.extend_from_slice(&present.to_le_bytes());
        out.extend_from_slice(&fields_data);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal RadioTap header: version=0, pad=0, len=8, present=0.
    fn make_minimal_radiotap() -> Vec<u8> {
        vec![
            0x00, // version
            0x00, // pad
            0x08, 0x00, // len = 8 (LE)
            0x00, 0x00, 0x00, 0x00, // present = 0
        ]
    }

    /// Build a RadioTap header with Flags + Rate + Channel + dBm_AntSignal.
    fn make_radiotap_with_fields() -> Vec<u8> {
        // present: Flags(1) | Rate(2) | Channel(3) | dBm_AntSignal(5) => bits 1,2,3,5
        // = 0x0000002E
        let present: u32 = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5);
        let mut buf = Vec::new();
        buf.push(0x00); // version
        buf.push(0x00); // pad

        // Fields in order:
        // Flags(1B) | Rate(1B) | Channel(2B freq + 2B flags) | dBm_AntSignal(1B)
        // Total = 8 + 1 + 1 + 4 + 1 = 15, but channel needs 2-byte alignment.
        // After flags(1) + rate(1) = 2 bytes relative, already aligned for channel.
        let fields_len = 1 + 1 + 4 + 1; // 7 bytes of fields
        let total_len: u16 = 8 + fields_len;
        buf.extend_from_slice(&total_len.to_le_bytes());
        buf.extend_from_slice(&present.to_le_bytes());

        // Flags
        buf.push(0x10); // FCS flag
        // Rate
        buf.push(0x0C); // 6 Mbps
        // Channel (2-byte aligned already since offset is 8+2=10, which is even)
        buf.extend_from_slice(&2437u16.to_le_bytes()); // freq=2437 (channel 6)
        buf.extend_from_slice(&0x00A0u16.to_le_bytes()); // flags: OFDM+2GHz
        // dBm_AntSignal
        buf.push(0xCE_u8); // -50 dBm as i8

        buf
    }

    #[test]
    fn test_minimal_radiotap() {
        let buf = make_minimal_radiotap();
        let layer = RadioTapLayer::new(0, buf.len());

        assert_eq!(layer.version(&buf).unwrap(), 0);
        assert_eq!(layer.pad(&buf).unwrap(), 0);
        assert_eq!(layer.header_length(&buf).unwrap(), 8);
        assert_eq!(layer.present(&buf).unwrap(), 0);
    }

    #[test]
    fn test_radiotap_with_fields() {
        let buf = make_radiotap_with_fields();
        let layer = RadioTapLayer::new(0, buf.len());

        assert_eq!(layer.version(&buf).unwrap(), 0);
        let present = layer.present(&buf).unwrap();
        assert!(present & (1 << radiotap_present::FLAGS) != 0);
        assert!(present & (1 << radiotap_present::RATE) != 0);
        assert!(present & (1 << radiotap_present::CHANNEL) != 0);

        let fields = layer.parse_fields(&buf).unwrap();
        assert_eq!(fields.flags, Some(0x10));
        assert_eq!(fields.rate, Some(0x0C));
        assert_eq!(fields.channel_freq, Some(2437));
        assert_eq!(fields.dbm_ant_signal, Some(-50));
    }

    #[test]
    fn test_has_fcs() {
        let buf = make_radiotap_with_fields();
        let layer = RadioTapLayer::new(0, buf.len());
        assert!(layer.has_fcs(&buf)); // Flags has FCS bit set
    }

    #[test]
    fn test_header_len_trait() {
        let buf = make_radiotap_with_fields();
        let layer = RadioTapLayer::new(0, buf.len());
        assert_eq!(layer.header_len(&buf), 15);
    }

    #[test]
    fn test_summary() {
        let buf = make_radiotap_with_fields();
        let layer = RadioTapLayer::new(0, buf.len());
        let s = layer.summary(&buf);
        assert!(s.contains("RadioTap"));
        assert!(s.contains("len="));
    }

    #[test]
    fn test_builder_minimal() {
        let header = RadioTapBuilder::new().build();
        assert_eq!(header.len(), 8);
        assert_eq!(header[0], 0); // version
        assert_eq!(u16::from_le_bytes([header[2], header[3]]), 8); // len
        assert_eq!(
            u32::from_le_bytes([header[4], header[5], header[6], header[7]]),
            0
        ); // present
    }

    #[test]
    fn test_builder_with_fields() {
        let header = RadioTapBuilder::new()
            .flags(0x10)
            .rate(12)
            .channel(2437, 0x00A0)
            .dbm_ant_signal(-50)
            .build();

        let layer = RadioTapLayer::new(0, header.len());
        assert_eq!(layer.version(&header).unwrap(), 0);
        let present = layer.present(&header).unwrap();
        assert!(present & (1 << radiotap_present::FLAGS) != 0);
        assert!(present & (1 << radiotap_present::RATE) != 0);
        assert!(present & (1 << radiotap_present::CHANNEL) != 0);
        assert!(present & (1 << radiotap_present::DBM_ANT_SIGNAL) != 0);

        let fields = layer.parse_fields(&header).unwrap();
        assert_eq!(fields.flags, Some(0x10));
        assert_eq!(fields.rate, Some(12));
        assert_eq!(fields.channel_freq, Some(2437));
        assert_eq!(fields.dbm_ant_signal, Some(-50));
    }

    #[test]
    fn test_roundtrip_builder_parse() {
        let header = RadioTapBuilder::new()
            .flags(0x02) // short preamble
            .rate(22) // 11 Mbps
            .antenna(1)
            .build();

        let layer = RadioTapLayer::new(0, header.len());
        let fields = layer.parse_fields(&header).unwrap();
        assert_eq!(fields.flags, Some(0x02));
        assert_eq!(fields.rate, Some(22));
        assert_eq!(fields.antenna, Some(1));
    }

    #[test]
    fn test_extended_present_words() {
        // Build a header with EXT bit set in present
        let mut buf = vec![0u8; 16];
        buf[0] = 0x00; // version
        buf[1] = 0x00; // pad
        buf[2] = 0x10; // len = 16
        buf[3] = 0x00;
        // present word 1: EXT bit set (bit 31)
        let present1: u32 = 1 << 31;
        buf[4..8].copy_from_slice(&present1.to_le_bytes());
        // present word 2: no EXT
        buf[8..12].copy_from_slice(&0u32.to_le_bytes());
        // 4 bytes of padding/data
        buf[12..16].copy_from_slice(&[0; 4]);

        let layer = RadioTapLayer::new(0, buf.len());
        assert_eq!(layer.count_present_words(&buf), 2);
    }
}
