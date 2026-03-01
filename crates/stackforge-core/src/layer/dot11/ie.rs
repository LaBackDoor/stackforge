//! IEEE 802.11 Information Elements (IEs).
//!
//! Information elements are TLV (Tag-Length-Value) structures appended to
//! management frame bodies (beacons, probe requests/responses, etc.).
//!
//! Each IE has a 1-byte ID, 1-byte length, and variable-length data.
//! This module provides a generic `Dot11Elt` for arbitrary IEs, plus
//! specialized parsers for common IEs (SSID, Rates, RSN, HT, VHT, etc.).

use crate::layer::dot11::types;
use crate::layer::field::FieldError;

// ============================================================================
// Dot11Elt — Generic Information Element
// ============================================================================

/// Generic 802.11 Information Element (TLV).
///
/// Layout:
/// - ID (1 byte)
/// - Length (1 byte)
/// - Info (variable, `length` bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11Elt {
    /// Element ID.
    pub id: u8,
    /// Length of the info field.
    pub len: u8,
    /// Info/data bytes.
    pub info: Vec<u8>,
}

impl Dot11Elt {
    /// Create a new IE with the given ID and data.
    pub fn new(id: u8, info: Vec<u8>) -> Self {
        Self {
            id,
            len: info.len() as u8,
            info,
        }
    }

    /// Parse a single IE from a buffer at the given offset.
    /// Returns the parsed IE and the number of bytes consumed.
    pub fn parse(buf: &[u8], offset: usize) -> Result<(Self, usize), FieldError> {
        if buf.len() < offset + 2 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 2,
                have: buf.len().saturating_sub(offset),
            });
        }
        let id = buf[offset];
        let len = buf[offset + 1] as usize;
        if buf.len() < offset + 2 + len {
            return Err(FieldError::BufferTooShort {
                offset: offset + 2,
                need: len,
                have: buf.len().saturating_sub(offset + 2),
            });
        }
        let info = buf[offset + 2..offset + 2 + len].to_vec();
        Ok((
            Self {
                id,
                len: len as u8,
                info,
            },
            2 + len,
        ))
    }

    /// Parse all IEs from a buffer starting at the given offset.
    /// Stops on error (truncated IE) and returns what was parsed so far.
    pub fn parse_all(buf: &[u8], mut offset: usize) -> Vec<Self> {
        let mut elements = Vec::new();
        while offset < buf.len() {
            match Self::parse(buf, offset) {
                Ok((elt, consumed)) => {
                    offset += consumed;
                    elements.push(elt);
                },
                Err(_) => break,
            }
        }
        elements
    }

    /// Build this IE to wire format (ID + Length + Info).
    pub fn build(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.info.len());
        buf.push(self.id);
        buf.push(self.len);
        buf.extend_from_slice(&self.info);
        buf
    }

    /// Build a chain of IEs to wire format.
    pub fn build_chain(elements: &[Dot11Elt]) -> Vec<u8> {
        let total: usize = elements.iter().map(|e| 2 + e.info.len()).sum();
        let mut buf = Vec::with_capacity(total);
        for elt in elements {
            buf.extend(elt.build());
        }
        buf
    }

    /// Create an SSID element (ID=0).
    pub fn ssid(name: &str) -> Self {
        Self::new(types::ie_id::SSID, name.as_bytes().to_vec())
    }

    /// Create a hidden/broadcast SSID element (empty SSID).
    pub fn ssid_hidden() -> Self {
        Self::new(types::ie_id::SSID, Vec::new())
    }

    /// Check if this is an SSID element.
    pub fn is_ssid(&self) -> bool {
        self.id == types::ie_id::SSID
    }

    /// Get SSID as string (if this is an SSID element).
    pub fn ssid_str(&self) -> Option<String> {
        if self.id == types::ie_id::SSID {
            Some(String::from_utf8_lossy(&self.info).into_owned())
        } else {
            None
        }
    }

    /// Get the IE name from the types module.
    pub fn name(&self) -> &'static str {
        types::ie_id::name(self.id)
    }

    /// Total wire length of this IE (2 + data length).
    pub fn wire_len(&self) -> usize {
        2 + self.info.len()
    }
}

// ============================================================================
// Dot11EltSSID — SSID (ID=0)
// ============================================================================

/// SSID Information Element (ID=0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltSSID {
    /// SSID string (may be empty for broadcast/hidden).
    pub ssid: String,
}

impl Dot11EltSSID {
    /// Create a new SSID IE.
    pub fn new(ssid: &str) -> Self {
        Self {
            ssid: ssid.to_string(),
        }
    }

    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::SSID {
            return None;
        }
        Some(Self {
            ssid: String::from_utf8_lossy(&elt.info).into_owned(),
        })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        Dot11Elt::new(types::ie_id::SSID, self.ssid.as_bytes().to_vec())
    }

    /// Check if this is a hidden/broadcast SSID.
    pub fn is_hidden(&self) -> bool {
        self.ssid.is_empty()
    }
}

// ============================================================================
// Dot11EltRates — Supported Rates (ID=1)
// ============================================================================

/// Supported Rates Information Element (ID=1).
///
/// Each rate byte: bit 7 = basic rate flag, bits 0-6 = rate in 0.5 Mbps units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltRates {
    /// Raw rate bytes.
    pub rates: Vec<u8>,
}

impl Dot11EltRates {
    /// Create a new Rates IE.
    pub fn new(rates: Vec<u8>) -> Self {
        Self { rates }
    }

    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::RATES {
            return None;
        }
        Some(Self {
            rates: elt.info.clone(),
        })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        Dot11Elt::new(types::ie_id::RATES, self.rates.clone())
    }

    /// Get the rate in Mbps for a given rate byte.
    pub fn rate_mbps(rate_byte: u8) -> f32 {
        (rate_byte & 0x7F) as f32 * 0.5
    }

    /// Check if a rate byte indicates a basic rate.
    pub fn is_basic(rate_byte: u8) -> bool {
        rate_byte & 0x80 != 0
    }

    /// Get all rates in Mbps.
    pub fn rates_mbps(&self) -> Vec<f32> {
        self.rates.iter().map(|&r| Self::rate_mbps(r)).collect()
    }
}

// ============================================================================
// Dot11EltDSSSet — DS Parameter Set (ID=3)
// ============================================================================

/// DS Parameter Set Information Element (ID=3).
///
/// Contains the current channel number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltDSSSet {
    /// Current channel number.
    pub channel: u8,
}

impl Dot11EltDSSSet {
    /// Create a new DS Parameter Set IE.
    pub fn new(channel: u8) -> Self {
        Self { channel }
    }

    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::DS_PARAMETER_SET || elt.info.is_empty() {
            return None;
        }
        Some(Self {
            channel: elt.info[0],
        })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        Dot11Elt::new(types::ie_id::DS_PARAMETER_SET, vec![self.channel])
    }
}

// ============================================================================
// Dot11EltTIM — Traffic Indication Map (ID=5)
// ============================================================================

/// Traffic Indication Map (TIM) Information Element (ID=5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltTIM {
    /// DTIM Count.
    pub dtim_count: u8,
    /// DTIM Period.
    pub dtim_period: u8,
    /// Bitmap Control.
    pub bitmap_control: u8,
    /// Partial Virtual Bitmap.
    pub bitmap: Vec<u8>,
}

impl Dot11EltTIM {
    /// Create a new TIM IE.
    pub fn new(dtim_count: u8, dtim_period: u8, bitmap_control: u8, bitmap: Vec<u8>) -> Self {
        Self {
            dtim_count,
            dtim_period,
            bitmap_control,
            bitmap,
        }
    }

    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::TIM || elt.info.len() < 3 {
            return None;
        }
        Some(Self {
            dtim_count: elt.info[0],
            dtim_period: elt.info[1],
            bitmap_control: elt.info[2],
            bitmap: elt.info[3..].to_vec(),
        })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        let mut info = Vec::with_capacity(3 + self.bitmap.len());
        info.push(self.dtim_count);
        info.push(self.dtim_period);
        info.push(self.bitmap_control);
        info.extend_from_slice(&self.bitmap);
        Dot11Elt::new(types::ie_id::TIM, info)
    }
}

// ============================================================================
// Dot11EltCountry — Country (ID=7)
// ============================================================================

/// A regulatory triplet within a Country IE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountryTriplet {
    /// First channel number.
    pub first_channel: u8,
    /// Number of channels.
    pub num_channels: u8,
    /// Maximum transmit power (dBm).
    pub max_power: u8,
}

/// Country Information Element (ID=7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltCountry {
    /// Country string (3 bytes, e.g., "US\x20").
    pub country: [u8; 3],
    /// Regulatory triplets.
    pub triplets: Vec<CountryTriplet>,
}

impl Dot11EltCountry {
    /// Create a new Country IE.
    pub fn new(country: [u8; 3], triplets: Vec<CountryTriplet>) -> Self {
        Self { country, triplets }
    }

    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::COUNTRY || elt.info.len() < 3 {
            return None;
        }
        let mut country = [0u8; 3];
        country.copy_from_slice(&elt.info[0..3]);

        let mut triplets = Vec::new();
        let mut pos = 3;
        while pos + 3 <= elt.info.len() {
            triplets.push(CountryTriplet {
                first_channel: elt.info[pos],
                num_channels: elt.info[pos + 1],
                max_power: elt.info[pos + 2],
            });
            pos += 3;
        }

        Some(Self { country, triplets })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        let mut info = Vec::with_capacity(3 + self.triplets.len() * 3);
        info.extend_from_slice(&self.country);
        for t in &self.triplets {
            info.push(t.first_channel);
            info.push(t.num_channels);
            info.push(t.max_power);
        }
        Dot11Elt::new(types::ie_id::COUNTRY, info)
    }

    /// Get the country code as a string.
    pub fn country_str(&self) -> String {
        String::from_utf8_lossy(&self.country).into_owned()
    }
}

// ============================================================================
// Dot11EltCSA — Channel Switch Announcement (ID=37)
// ============================================================================

/// Channel Switch Announcement Information Element (ID=37).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltCSA {
    /// Channel switch mode (0 = no restriction, 1 = stop transmitting).
    pub mode: u8,
    /// New channel number.
    pub new_channel: u8,
    /// Channel switch count (number of TBTTs until switch).
    pub count: u8,
}

impl Dot11EltCSA {
    /// Create a new CSA IE.
    pub fn new(mode: u8, new_channel: u8, count: u8) -> Self {
        Self {
            mode,
            new_channel,
            count,
        }
    }

    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::CHANNEL_SWITCH_ANNOUNCEMENT || elt.info.len() < 3 {
            return None;
        }
        Some(Self {
            mode: elt.info[0],
            new_channel: elt.info[1],
            count: elt.info[2],
        })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        Dot11Elt::new(
            types::ie_id::CHANNEL_SWITCH_ANNOUNCEMENT,
            vec![self.mode, self.new_channel, self.count],
        )
    }
}

// ============================================================================
// Dot11EltHTCapabilities — HT Capabilities (ID=45)
// ============================================================================

/// HT Capabilities Information Element (ID=45).
///
/// Contains 802.11n (HT) capability information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltHTCapabilities {
    /// HT Capabilities Info (2 bytes, little-endian).
    pub ht_cap_info: u16,
    /// A-MPDU Parameters (1 byte).
    pub ampdu_params: u8,
    /// Supported MCS Set (16 bytes).
    pub mcs_set: [u8; 16],
    /// HT Extended Capabilities (2 bytes, little-endian).
    pub ht_ext_cap: u16,
    /// Transmit Beamforming Capabilities (4 bytes, little-endian).
    pub txbf_cap: u32,
    /// ASEL Capabilities (1 byte).
    pub asel_cap: u8,
}

/// HT Capabilities IE data length.
pub const HT_CAP_LEN: usize = 26;

impl Dot11EltHTCapabilities {
    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::HT_CAPABILITIES || elt.info.len() < HT_CAP_LEN {
            return None;
        }
        let d = &elt.info;
        let ht_cap_info = u16::from_le_bytes([d[0], d[1]]);
        let ampdu_params = d[2];
        let mut mcs_set = [0u8; 16];
        mcs_set.copy_from_slice(&d[3..19]);
        let ht_ext_cap = u16::from_le_bytes([d[19], d[20]]);
        let txbf_cap = u32::from_le_bytes([d[21], d[22], d[23], d[24]]);
        let asel_cap = d[25];

        Some(Self {
            ht_cap_info,
            ampdu_params,
            mcs_set,
            ht_ext_cap,
            txbf_cap,
            asel_cap,
        })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        let mut info = Vec::with_capacity(HT_CAP_LEN);
        info.extend_from_slice(&self.ht_cap_info.to_le_bytes());
        info.push(self.ampdu_params);
        info.extend_from_slice(&self.mcs_set);
        info.extend_from_slice(&self.ht_ext_cap.to_le_bytes());
        info.extend_from_slice(&self.txbf_cap.to_le_bytes());
        info.push(self.asel_cap);
        Dot11Elt::new(types::ie_id::HT_CAPABILITIES, info)
    }

    /// Check LDPC Coding Capability (bit 0 of HT Cap Info).
    pub fn ldpc(&self) -> bool {
        self.ht_cap_info & 0x0001 != 0
    }

    /// Channel Width Set (bit 1): 0 = 20 MHz only, 1 = 20/40 MHz.
    pub fn channel_width_set(&self) -> bool {
        self.ht_cap_info & 0x0002 != 0
    }

    /// Short GI for 20 MHz (bit 5).
    pub fn short_gi_20(&self) -> bool {
        self.ht_cap_info & 0x0020 != 0
    }

    /// Short GI for 40 MHz (bit 6).
    pub fn short_gi_40(&self) -> bool {
        self.ht_cap_info & 0x0040 != 0
    }
}

// ============================================================================
// Dot11EltHTInfo — HT Information (ID=61)
// ============================================================================

/// HT Information (Operation) Element (ID=61).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltHTInfo {
    /// Primary channel.
    pub primary_channel: u8,
    /// HT Operation Information (5 bytes).
    pub ht_info: [u8; 5],
    /// Basic MCS Set (16 bytes).
    pub basic_mcs_set: [u8; 16],
}

/// HT Info IE data length.
pub const HT_INFO_LEN: usize = 22;

impl Dot11EltHTInfo {
    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::HT_INFORMATION || elt.info.len() < HT_INFO_LEN {
            return None;
        }
        let d = &elt.info;
        let primary_channel = d[0];
        let mut ht_info = [0u8; 5];
        ht_info.copy_from_slice(&d[1..6]);
        let mut basic_mcs_set = [0u8; 16];
        basic_mcs_set.copy_from_slice(&d[6..22]);

        Some(Self {
            primary_channel,
            ht_info,
            basic_mcs_set,
        })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        let mut info = Vec::with_capacity(HT_INFO_LEN);
        info.push(self.primary_channel);
        info.extend_from_slice(&self.ht_info);
        info.extend_from_slice(&self.basic_mcs_set);
        Dot11Elt::new(types::ie_id::HT_INFORMATION, info)
    }

    /// Secondary channel offset (bits 0-1 of ht_info byte 0).
    /// 0 = no secondary, 1 = above, 3 = below.
    pub fn secondary_channel_offset(&self) -> u8 {
        self.ht_info[0] & 0x03
    }

    /// STA Channel Width (bit 2 of ht_info byte 0).
    pub fn sta_channel_width(&self) -> bool {
        self.ht_info[0] & 0x04 != 0
    }
}

// ============================================================================
// Dot11EltVHTCapabilities — VHT Capabilities (ID=191)
// ============================================================================

/// VHT Capabilities Information Element (ID=191).
///
/// Contains 802.11ac (VHT) capability information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltVHTCapabilities {
    /// VHT Capabilities Info (4 bytes, little-endian).
    pub vht_cap_info: u32,
    /// Supported VHT-MCS and NSS Set (8 bytes).
    pub mcs_nss_set: [u8; 8],
}

/// VHT Capabilities IE data length.
pub const VHT_CAP_LEN: usize = 12;

impl Dot11EltVHTCapabilities {
    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::VHT_CAPABILITIES || elt.info.len() < VHT_CAP_LEN {
            return None;
        }
        let d = &elt.info;
        let vht_cap_info = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        let mut mcs_nss_set = [0u8; 8];
        mcs_nss_set.copy_from_slice(&d[4..12]);

        Some(Self {
            vht_cap_info,
            mcs_nss_set,
        })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        let mut info = Vec::with_capacity(VHT_CAP_LEN);
        info.extend_from_slice(&self.vht_cap_info.to_le_bytes());
        info.extend_from_slice(&self.mcs_nss_set);
        Dot11Elt::new(types::ie_id::VHT_CAPABILITIES, info)
    }

    /// Max MPDU Length (bits 0-1 of VHT Cap Info).
    /// 0 = 3895, 1 = 7991, 2 = 11454.
    pub fn max_mpdu_length(&self) -> u8 {
        (self.vht_cap_info & 0x03) as u8
    }

    /// Supported Channel Width Set (bits 2-3).
    pub fn supported_channel_width(&self) -> u8 {
        ((self.vht_cap_info >> 2) & 0x03) as u8
    }

    /// Short GI for 80 MHz (bit 5).
    pub fn short_gi_80(&self) -> bool {
        self.vht_cap_info & 0x0020 != 0
    }

    /// Short GI for 160/80+80 MHz (bit 6).
    pub fn short_gi_160(&self) -> bool {
        self.vht_cap_info & 0x0040 != 0
    }
}

// ============================================================================
// Dot11EltVHTOperation — VHT Operation (ID=192)
// ============================================================================

/// VHT Operation Information Element (ID=192).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltVHTOperation {
    /// Channel Width (1 byte): 0=20/40, 1=80, 2=160, 3=80+80.
    pub channel_width: u8,
    /// Channel Center Frequency Segment 0.
    pub center_freq_seg0: u8,
    /// Channel Center Frequency Segment 1.
    pub center_freq_seg1: u8,
    /// Basic VHT-MCS and NSS Set (2 bytes, little-endian).
    pub basic_mcs_nss: u16,
}

/// VHT Operation IE data length.
pub const VHT_OP_LEN: usize = 5;

impl Dot11EltVHTOperation {
    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::VHT_OPERATION || elt.info.len() < VHT_OP_LEN {
            return None;
        }
        let d = &elt.info;
        Some(Self {
            channel_width: d[0],
            center_freq_seg0: d[1],
            center_freq_seg1: d[2],
            basic_mcs_nss: u16::from_le_bytes([d[3], d[4]]),
        })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        let mut info = Vec::with_capacity(VHT_OP_LEN);
        info.push(self.channel_width);
        info.push(self.center_freq_seg0);
        info.push(self.center_freq_seg1);
        info.extend_from_slice(&self.basic_mcs_nss.to_le_bytes());
        Dot11Elt::new(types::ie_id::VHT_OPERATION, info)
    }
}

// ============================================================================
// Dot11EltRSN — RSN (Robust Security Network) (ID=48)
// ============================================================================

/// A cipher suite descriptor (OUI + type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherSuite {
    /// OUI (3 bytes).
    pub oui: [u8; 3],
    /// Suite type.
    pub suite_type: u8,
}

impl CipherSuite {
    /// Create from raw 4-byte data.
    pub fn from_bytes(data: &[u8; 4]) -> Self {
        Self {
            oui: [data[0], data[1], data[2]],
            suite_type: data[3],
        }
    }

    /// Convert to raw 4-byte data.
    pub fn to_bytes(&self) -> [u8; 4] {
        [self.oui[0], self.oui[1], self.oui[2], self.suite_type]
    }

    /// Get the cipher suite name.
    pub fn name(&self) -> &'static str {
        if self.oui == [0x00, 0x0F, 0xAC] {
            types::cipher_suite::name(self.suite_type)
        } else {
            "Vendor-Specific"
        }
    }
}

/// An AKM (Authentication and Key Management) suite descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkmSuite {
    /// OUI (3 bytes).
    pub oui: [u8; 3],
    /// Suite type.
    pub suite_type: u8,
}

impl AkmSuite {
    /// Create from raw 4-byte data.
    pub fn from_bytes(data: &[u8; 4]) -> Self {
        Self {
            oui: [data[0], data[1], data[2]],
            suite_type: data[3],
        }
    }

    /// Convert to raw 4-byte data.
    pub fn to_bytes(&self) -> [u8; 4] {
        [self.oui[0], self.oui[1], self.oui[2], self.suite_type]
    }

    /// Get the AKM suite name.
    pub fn name(&self) -> &'static str {
        if self.oui == [0x00, 0x0F, 0xAC] {
            types::akm_suite::name(self.suite_type)
        } else {
            "Vendor-Specific"
        }
    }
}

/// Parsed RSN (WPA2/WPA3) information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsnInfo {
    /// RSN version (should be 1).
    pub version: u16,
    /// Group data cipher suite.
    pub group_cipher: CipherSuite,
    /// Pairwise cipher suites.
    pub pairwise_ciphers: Vec<CipherSuite>,
    /// AKM suites.
    pub akm_suites: Vec<AkmSuite>,
    /// RSN capabilities (2 bytes, little-endian).
    pub rsn_capabilities: u16,
    /// PMKID count.
    pub pmkid_count: u16,
    /// PMKIDs (16 bytes each).
    pub pmkids: Vec<[u8; 16]>,
    /// Group management cipher suite (optional).
    pub group_mgmt_cipher: Option<CipherSuite>,
}

/// RSN (Robust Security Network) Information Element (ID=48).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltRSN {
    /// Parsed RSN information.
    pub info: RsnInfo,
}

impl Dot11EltRSN {
    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::RSN || elt.info.len() < 2 {
            return None;
        }
        let data = &elt.info;
        let mut offset = 0;

        // Version
        if offset + 2 > data.len() {
            return None;
        }
        let version = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Group Data Cipher Suite
        if offset + 4 > data.len() {
            return None;
        }
        let mut gc = [0u8; 4];
        gc.copy_from_slice(&data[offset..offset + 4]);
        let group_cipher = CipherSuite::from_bytes(&gc);
        offset += 4;

        // Pairwise Cipher Suite Count
        let pairwise_count = if offset + 2 <= data.len() {
            let c = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            c
        } else {
            0
        };

        // Pairwise Cipher Suites
        let mut pairwise_ciphers = Vec::with_capacity(pairwise_count);
        for _ in 0..pairwise_count {
            if offset + 4 > data.len() {
                break;
            }
            let mut suite = [0u8; 4];
            suite.copy_from_slice(&data[offset..offset + 4]);
            pairwise_ciphers.push(CipherSuite::from_bytes(&suite));
            offset += 4;
        }

        // AKM Suite Count
        let akm_count = if offset + 2 <= data.len() {
            let c = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            c
        } else {
            0
        };

        // AKM Suites
        let mut akm_suites = Vec::with_capacity(akm_count);
        for _ in 0..akm_count {
            if offset + 4 > data.len() {
                break;
            }
            let mut suite = [0u8; 4];
            suite.copy_from_slice(&data[offset..offset + 4]);
            akm_suites.push(AkmSuite::from_bytes(&suite));
            offset += 4;
        }

        // RSN Capabilities
        let rsn_capabilities = if offset + 2 <= data.len() {
            let c = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            c
        } else {
            0
        };

        // PMKID Count
        let pmkid_count = if offset + 2 <= data.len() {
            let c = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            c
        } else {
            0
        };

        // PMKIDs
        let mut pmkids = Vec::new();
        for _ in 0..pmkid_count {
            if offset + 16 > data.len() {
                break;
            }
            let mut pmkid = [0u8; 16];
            pmkid.copy_from_slice(&data[offset..offset + 16]);
            pmkids.push(pmkid);
            offset += 16;
        }

        // Group Management Cipher Suite (optional)
        let group_mgmt_cipher = if offset + 4 <= data.len() {
            let mut suite = [0u8; 4];
            suite.copy_from_slice(&data[offset..offset + 4]);
            Some(CipherSuite::from_bytes(&suite))
        } else {
            None
        };

        Some(Self {
            info: RsnInfo {
                version,
                group_cipher,
                pairwise_ciphers,
                akm_suites,
                rsn_capabilities,
                pmkid_count,
                pmkids,
                group_mgmt_cipher,
            },
        })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        let rsn = &self.info;
        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&rsn.version.to_le_bytes());

        // Group Data Cipher Suite
        data.extend_from_slice(&rsn.group_cipher.to_bytes());

        // Pairwise Cipher Suite Count + Suites
        data.extend_from_slice(&(rsn.pairwise_ciphers.len() as u16).to_le_bytes());
        for cs in &rsn.pairwise_ciphers {
            data.extend_from_slice(&cs.to_bytes());
        }

        // AKM Suite Count + Suites
        data.extend_from_slice(&(rsn.akm_suites.len() as u16).to_le_bytes());
        for akm in &rsn.akm_suites {
            data.extend_from_slice(&akm.to_bytes());
        }

        // RSN Capabilities
        data.extend_from_slice(&rsn.rsn_capabilities.to_le_bytes());

        // PMKIDs (if any)
        if !rsn.pmkids.is_empty() {
            data.extend_from_slice(&(rsn.pmkids.len() as u16).to_le_bytes());
            for pmkid in &rsn.pmkids {
                data.extend_from_slice(pmkid);
            }
        }

        // Group Management Cipher Suite (if present)
        if let Some(ref gmc) = rsn.group_mgmt_cipher {
            // If no PMKIDs were written, we need to write PMKID count = 0
            if rsn.pmkids.is_empty() {
                data.extend_from_slice(&0u16.to_le_bytes());
            }
            data.extend_from_slice(&gmc.to_bytes());
        }

        Dot11Elt::new(types::ie_id::RSN, data)
    }

    /// Check if pre-authentication is supported (bit 0 of RSN capabilities).
    pub fn pre_auth(&self) -> bool {
        self.info.rsn_capabilities & 0x0001 != 0
    }

    /// Check if no pairwise is set (bit 1 of RSN capabilities).
    pub fn no_pairwise(&self) -> bool {
        self.info.rsn_capabilities & 0x0002 != 0
    }

    /// PTKSA Replay Counter (bits 2-3 of RSN capabilities).
    pub fn ptksa_replay_counter(&self) -> u8 {
        ((self.info.rsn_capabilities >> 2) & 0x03) as u8
    }

    /// GTKSA Replay Counter (bits 4-5 of RSN capabilities).
    pub fn gtksa_replay_counter(&self) -> u8 {
        ((self.info.rsn_capabilities >> 4) & 0x03) as u8
    }

    /// Management Frame Protection Required (bit 6).
    pub fn mfp_required(&self) -> bool {
        self.info.rsn_capabilities & 0x0040 != 0
    }

    /// Management Frame Protection Capable (bit 7).
    pub fn mfp_capable(&self) -> bool {
        self.info.rsn_capabilities & 0x0080 != 0
    }
}

// ============================================================================
// Dot11EltVendorSpecific — Vendor Specific (ID=221)
// ============================================================================

/// Vendor Specific Information Element (ID=221).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltVendorSpecific {
    /// OUI (3 bytes).
    pub oui: [u8; 3],
    /// Vendor-specific data (after OUI).
    pub data: Vec<u8>,
}

impl Dot11EltVendorSpecific {
    /// Create a new Vendor Specific IE.
    pub fn new(oui: [u8; 3], data: Vec<u8>) -> Self {
        Self { oui, data }
    }

    /// Parse from a generic Dot11Elt.
    pub fn parse(elt: &Dot11Elt) -> Option<Self> {
        if elt.id != types::ie_id::VENDOR_SPECIFIC || elt.info.len() < 3 {
            return None;
        }
        let mut oui = [0u8; 3];
        oui.copy_from_slice(&elt.info[0..3]);
        Some(Self {
            oui,
            data: elt.info[3..].to_vec(),
        })
    }

    /// Build as a Dot11Elt.
    pub fn build(&self) -> Dot11Elt {
        let mut info = Vec::with_capacity(3 + self.data.len());
        info.extend_from_slice(&self.oui);
        info.extend_from_slice(&self.data);
        Dot11Elt::new(types::ie_id::VENDOR_SPECIFIC, info)
    }

    /// Check if this is a Microsoft WPA IE.
    pub fn is_wpa(&self) -> bool {
        self.oui == types::MICROSOFT_WPA_OUI
            && !self.data.is_empty()
            && self.data[0] == types::MICROSOFT_WPA_TYPE
    }

    /// Check if this is a WMM/WME IE (Microsoft OUI, type 2).
    pub fn is_wmm(&self) -> bool {
        self.oui == types::MICROSOFT_WPA_OUI && !self.data.is_empty() && self.data[0] == 0x02
    }
}

// ============================================================================
// Dot11EltMicrosoftWPA — Microsoft WPA (Vendor Specific, OUI=00:50:F2, Type=1)
// ============================================================================

/// Microsoft WPA Information Element (WPA1).
///
/// This is a Vendor Specific IE (ID=221) with Microsoft OUI and type=1.
/// The structure is similar to RSN but with WPA OUI (00:50:F2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EltMicrosoftWPA {
    /// WPA version (should be 1).
    pub version: u16,
    /// Group cipher suite.
    pub group_cipher: CipherSuite,
    /// Pairwise cipher suites.
    pub pairwise_ciphers: Vec<CipherSuite>,
    /// AKM suites.
    pub akm_suites: Vec<AkmSuite>,
}

impl Dot11EltMicrosoftWPA {
    /// Parse from a Vendor Specific IE.
    pub fn parse(vs: &Dot11EltVendorSpecific) -> Option<Self> {
        if !vs.is_wpa() {
            return None;
        }
        // data[0] = type (1), data[1..] = WPA IE body
        let data = &vs.data;
        if data.len() < 7 {
            // type(1) + version(2) + group cipher(4) = 7 minimum
            return None;
        }
        let mut offset = 1; // skip type byte

        let version = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        if offset + 4 > data.len() {
            return None;
        }
        let mut gc = [0u8; 4];
        gc.copy_from_slice(&data[offset..offset + 4]);
        let group_cipher = CipherSuite::from_bytes(&gc);
        offset += 4;

        // Pairwise ciphers
        let pw_count = if offset + 2 <= data.len() {
            let c = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            c
        } else {
            0
        };

        let mut pairwise_ciphers = Vec::with_capacity(pw_count);
        for _ in 0..pw_count {
            if offset + 4 > data.len() {
                break;
            }
            let mut suite = [0u8; 4];
            suite.copy_from_slice(&data[offset..offset + 4]);
            pairwise_ciphers.push(CipherSuite::from_bytes(&suite));
            offset += 4;
        }

        // AKM suites
        let akm_count = if offset + 2 <= data.len() {
            let c = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            c
        } else {
            0
        };

        let mut akm_suites = Vec::with_capacity(akm_count);
        for _ in 0..akm_count {
            if offset + 4 > data.len() {
                break;
            }
            let mut suite = [0u8; 4];
            suite.copy_from_slice(&data[offset..offset + 4]);
            akm_suites.push(AkmSuite::from_bytes(&suite));
            offset += 4;
        }

        Some(Self {
            version,
            group_cipher,
            pairwise_ciphers,
            akm_suites,
        })
    }

    /// Build as a Dot11Elt (Vendor Specific).
    pub fn build(&self) -> Dot11Elt {
        let mut data = Vec::new();

        // OUI + Type
        data.extend_from_slice(&types::MICROSOFT_WPA_OUI);
        data.push(types::MICROSOFT_WPA_TYPE);

        // Version
        data.extend_from_slice(&self.version.to_le_bytes());

        // Group cipher
        data.extend_from_slice(&self.group_cipher.to_bytes());

        // Pairwise ciphers
        data.extend_from_slice(&(self.pairwise_ciphers.len() as u16).to_le_bytes());
        for cs in &self.pairwise_ciphers {
            data.extend_from_slice(&cs.to_bytes());
        }

        // AKM suites
        data.extend_from_slice(&(self.akm_suites.len() as u16).to_le_bytes());
        for akm in &self.akm_suites {
            data.extend_from_slice(&akm.to_bytes());
        }

        Dot11Elt::new(types::ie_id::VENDOR_SPECIFIC, data)
    }
}

// ============================================================================
// Helper: find IEs by ID
// ============================================================================

/// Find the first IE with the given ID in a list of IEs.
pub fn find_ie(elements: &[Dot11Elt], id: u8) -> Option<&Dot11Elt> {
    elements.iter().find(|e| e.id == id)
}

/// Find all IEs with the given ID in a list of IEs.
pub fn find_all_ies(elements: &[Dot11Elt], id: u8) -> Vec<&Dot11Elt> {
    elements.iter().filter(|e| e.id == id).collect()
}

/// Extract the SSID from a list of IEs.
pub fn extract_ssid(elements: &[Dot11Elt]) -> Option<String> {
    find_ie(elements, types::ie_id::SSID).and_then(|e| e.ssid_str())
}

/// Extract the channel from DS Parameter Set IE.
pub fn extract_channel(elements: &[Dot11Elt]) -> Option<u8> {
    find_ie(elements, types::ie_id::DS_PARAMETER_SET)
        .and_then(|e| Dot11EltDSSSet::parse(e))
        .map(|ds| ds.channel)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dot11elt_parse_build_roundtrip() {
        let elt = Dot11Elt::new(0, b"TestSSID".to_vec());
        let wire = elt.build();
        assert_eq!(wire[0], 0); // ID
        assert_eq!(wire[1], 8); // Length
        assert_eq!(&wire[2..], b"TestSSID");

        let (parsed, consumed) = Dot11Elt::parse(&wire, 0).unwrap();
        assert_eq!(consumed, 10);
        assert_eq!(parsed.id, 0);
        assert_eq!(parsed.len, 8);
        assert_eq!(&parsed.info, b"TestSSID");
    }

    #[test]
    fn test_dot11elt_parse_all() {
        let ssid = Dot11Elt::ssid("MyNetwork");
        let rates = Dot11Elt::new(1, vec![0x82, 0x84, 0x8B, 0x96]);
        let chain = Dot11Elt::build_chain(&[ssid.clone(), rates.clone()]);

        let parsed = Dot11Elt::parse_all(&chain, 0);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, 0);
        assert_eq!(parsed[0].ssid_str().unwrap(), "MyNetwork");
        assert_eq!(parsed[1].id, 1);
        assert_eq!(parsed[1].info, vec![0x82, 0x84, 0x8B, 0x96]);
    }

    #[test]
    fn test_ssid_ie() {
        let ssid_ie = Dot11EltSSID::new("HelloWiFi");
        assert_eq!(ssid_ie.ssid, "HelloWiFi");
        assert!(!ssid_ie.is_hidden());

        let elt = ssid_ie.build();
        assert_eq!(elt.id, 0);
        let parsed = Dot11EltSSID::parse(&elt).unwrap();
        assert_eq!(parsed.ssid, "HelloWiFi");

        // Hidden SSID
        let hidden = Dot11EltSSID::new("");
        assert!(hidden.is_hidden());
    }

    #[test]
    fn test_rates_ie() {
        let rates = Dot11EltRates::new(vec![0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]);
        let elt = rates.build();
        assert_eq!(elt.id, 1);

        let parsed = Dot11EltRates::parse(&elt).unwrap();
        assert_eq!(parsed.rates.len(), 8);
        assert!(Dot11EltRates::is_basic(0x82)); // 1 Mbps basic
        assert!(!Dot11EltRates::is_basic(0x0C)); // 6 Mbps not basic
        assert_eq!(Dot11EltRates::rate_mbps(0x82), 1.0);
        assert_eq!(Dot11EltRates::rate_mbps(0x0C), 6.0);
    }

    #[test]
    fn test_dsset_ie() {
        let ds = Dot11EltDSSSet::new(6);
        let elt = ds.build();
        assert_eq!(elt.id, 3);
        assert_eq!(elt.info, vec![6]);

        let parsed = Dot11EltDSSSet::parse(&elt).unwrap();
        assert_eq!(parsed.channel, 6);
    }

    #[test]
    fn test_tim_ie() {
        let tim = Dot11EltTIM::new(0, 3, 0, vec![0x00]);
        let elt = tim.build();
        assert_eq!(elt.id, 5);
        assert_eq!(elt.info.len(), 4);

        let parsed = Dot11EltTIM::parse(&elt).unwrap();
        assert_eq!(parsed.dtim_count, 0);
        assert_eq!(parsed.dtim_period, 3);
        assert_eq!(parsed.bitmap_control, 0);
        assert_eq!(parsed.bitmap, vec![0x00]);
    }

    #[test]
    fn test_country_ie() {
        let country = Dot11EltCountry::new(
            *b"US ",
            vec![
                CountryTriplet {
                    first_channel: 1,
                    num_channels: 11,
                    max_power: 30,
                },
                CountryTriplet {
                    first_channel: 36,
                    num_channels: 4,
                    max_power: 17,
                },
            ],
        );
        let elt = country.build();
        assert_eq!(elt.id, 7);

        let parsed = Dot11EltCountry::parse(&elt).unwrap();
        assert_eq!(parsed.country_str(), "US ");
        assert_eq!(parsed.triplets.len(), 2);
        assert_eq!(parsed.triplets[0].first_channel, 1);
        assert_eq!(parsed.triplets[0].num_channels, 11);
        assert_eq!(parsed.triplets[0].max_power, 30);
        assert_eq!(parsed.triplets[1].first_channel, 36);
    }

    #[test]
    fn test_csa_ie() {
        let csa = Dot11EltCSA::new(1, 11, 5);
        let elt = csa.build();
        assert_eq!(elt.id, 37);

        let parsed = Dot11EltCSA::parse(&elt).unwrap();
        assert_eq!(parsed.mode, 1);
        assert_eq!(parsed.new_channel, 11);
        assert_eq!(parsed.count, 5);
    }

    #[test]
    fn test_ht_capabilities_ie() {
        let ht = Dot11EltHTCapabilities {
            ht_cap_info: 0x016F, // LDPC, 20/40MHz, SGI20, SGI40
            ampdu_params: 0x17,
            mcs_set: [0xFF, 0xFF, 0xFF, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ht_ext_cap: 0x0000,
            txbf_cap: 0x00000000,
            asel_cap: 0x00,
        };
        let elt = ht.build();
        assert_eq!(elt.id, 45);
        assert_eq!(elt.info.len(), HT_CAP_LEN);

        let parsed = Dot11EltHTCapabilities::parse(&elt).unwrap();
        assert!(parsed.ldpc());
        assert!(parsed.channel_width_set());
        assert!(parsed.short_gi_20());
        assert!(parsed.short_gi_40());
        assert_eq!(parsed.ampdu_params, 0x17);
    }

    #[test]
    fn test_ht_info_ie() {
        let ht_info = Dot11EltHTInfo {
            primary_channel: 6,
            ht_info: [0x05, 0x00, 0x00, 0x00, 0x00], // sec offset=1, STA width=1
            basic_mcs_set: [0; 16],
        };
        let elt = ht_info.build();
        assert_eq!(elt.id, 61);
        assert_eq!(elt.info.len(), HT_INFO_LEN);

        let parsed = Dot11EltHTInfo::parse(&elt).unwrap();
        assert_eq!(parsed.primary_channel, 6);
        assert_eq!(parsed.secondary_channel_offset(), 1);
        assert!(parsed.sta_channel_width());
    }

    #[test]
    fn test_vht_capabilities_ie() {
        let vht = Dot11EltVHTCapabilities {
            vht_cap_info: 0x00000062, // SGI 80, SGI 160
            mcs_nss_set: [0xFF, 0xFE, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00],
        };
        let elt = vht.build();
        assert_eq!(elt.id, 191);
        assert_eq!(elt.info.len(), VHT_CAP_LEN);

        let parsed = Dot11EltVHTCapabilities::parse(&elt).unwrap();
        assert_eq!(parsed.max_mpdu_length(), 2);
        assert!(parsed.short_gi_80());
        assert!(parsed.short_gi_160());
    }

    #[test]
    fn test_vht_operation_ie() {
        let vht_op = Dot11EltVHTOperation {
            channel_width: 1,
            center_freq_seg0: 42,
            center_freq_seg1: 0,
            basic_mcs_nss: 0xFFFC,
        };
        let elt = vht_op.build();
        assert_eq!(elt.id, 192);
        assert_eq!(elt.info.len(), VHT_OP_LEN);

        let parsed = Dot11EltVHTOperation::parse(&elt).unwrap();
        assert_eq!(parsed.channel_width, 1);
        assert_eq!(parsed.center_freq_seg0, 42);
        assert_eq!(parsed.center_freq_seg1, 0);
        assert_eq!(parsed.basic_mcs_nss, 0xFFFC);
    }

    #[test]
    fn test_rsn_ie_wpa2_psk() {
        let rsn = Dot11EltRSN {
            info: RsnInfo {
                version: 1,
                group_cipher: CipherSuite::from_bytes(&[0x00, 0x0F, 0xAC, 0x04]), // CCMP
                pairwise_ciphers: vec![CipherSuite::from_bytes(&[0x00, 0x0F, 0xAC, 0x04])],
                akm_suites: vec![AkmSuite::from_bytes(&[0x00, 0x0F, 0xAC, 0x02])], // PSK
                rsn_capabilities: 0x000C,
                pmkid_count: 0,
                pmkids: Vec::new(),
                group_mgmt_cipher: None,
            },
        };

        let elt = rsn.build();
        assert_eq!(elt.id, 48);

        let parsed = Dot11EltRSN::parse(&elt).unwrap();
        assert_eq!(parsed.info.version, 1);
        assert_eq!(parsed.info.group_cipher.name(), "CCMP-128");
        assert_eq!(parsed.info.pairwise_ciphers.len(), 1);
        assert_eq!(parsed.info.pairwise_ciphers[0].name(), "CCMP-128");
        assert_eq!(parsed.info.akm_suites.len(), 1);
        assert_eq!(parsed.info.akm_suites[0].name(), "PSK");
        assert_eq!(parsed.info.rsn_capabilities, 0x000C);
    }

    #[test]
    fn test_rsn_ie_with_mfp() {
        let rsn = Dot11EltRSN {
            info: RsnInfo {
                version: 1,
                group_cipher: CipherSuite::from_bytes(&[0x00, 0x0F, 0xAC, 0x04]),
                pairwise_ciphers: vec![CipherSuite::from_bytes(&[0x00, 0x0F, 0xAC, 0x04])],
                akm_suites: vec![AkmSuite::from_bytes(&[0x00, 0x0F, 0xAC, 0x08])], // SAE
                rsn_capabilities: 0x00CC, // MFP Required + Capable
                pmkid_count: 0,
                pmkids: Vec::new(),
                group_mgmt_cipher: Some(CipherSuite::from_bytes(&[0x00, 0x0F, 0xAC, 0x06])), // BIP-CMAC-128
            },
        };

        let elt = rsn.build();
        let parsed = Dot11EltRSN::parse(&elt).unwrap();
        assert!(parsed.mfp_required());
        assert!(parsed.mfp_capable());
        assert!(parsed.info.group_mgmt_cipher.is_some());
        assert_eq!(
            parsed.info.group_mgmt_cipher.unwrap().name(),
            "BIP-CMAC-128"
        );
    }

    #[test]
    fn test_vendor_specific_ie() {
        let vs = Dot11EltVendorSpecific::new([0x00, 0x50, 0xF2], vec![0x01, 0x01, 0x00]);
        assert!(vs.is_wpa());
        assert!(!vs.is_wmm());

        let elt = vs.build();
        assert_eq!(elt.id, 221);

        let parsed = Dot11EltVendorSpecific::parse(&elt).unwrap();
        assert_eq!(parsed.oui, [0x00, 0x50, 0xF2]);
        assert!(parsed.is_wpa());
    }

    #[test]
    fn test_microsoft_wpa_ie() {
        let wpa = Dot11EltMicrosoftWPA {
            version: 1,
            group_cipher: CipherSuite::from_bytes(&[0x00, 0x50, 0xF2, 0x02]), // TKIP
            pairwise_ciphers: vec![CipherSuite::from_bytes(&[0x00, 0x50, 0xF2, 0x02])], // TKIP
            akm_suites: vec![AkmSuite::from_bytes(&[0x00, 0x50, 0xF2, 0x02])], // PSK
        };

        let elt = wpa.build();
        assert_eq!(elt.id, 221);

        // Parse back through vendor specific
        let vs = Dot11EltVendorSpecific::parse(&elt).unwrap();
        assert!(vs.is_wpa());

        let parsed = Dot11EltMicrosoftWPA::parse(&vs).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.group_cipher.to_bytes(), [0x00, 0x50, 0xF2, 0x02]);
        assert_eq!(parsed.pairwise_ciphers.len(), 1);
        assert_eq!(parsed.akm_suites.len(), 1);
    }

    #[test]
    fn test_find_ie_helpers() {
        let elements = vec![
            Dot11Elt::ssid("TestNet"),
            Dot11Elt::new(1, vec![0x82, 0x84]),
            Dot11Elt::new(3, vec![6]),
        ];

        assert_eq!(extract_ssid(&elements), Some("TestNet".to_string()));
        assert_eq!(extract_channel(&elements), Some(6));
        assert!(find_ie(&elements, 48).is_none()); // No RSN
    }

    #[test]
    fn test_dot11elt_name() {
        let ssid = Dot11Elt::ssid("Test");
        assert_eq!(ssid.name(), "SSID");

        let rsn = Dot11Elt::new(48, vec![]);
        assert_eq!(rsn.name(), "RSN");

        let ht = Dot11Elt::new(45, vec![]);
        assert_eq!(ht.name(), "HT Capabilities");
    }

    #[test]
    fn test_dot11elt_wire_len() {
        let elt = Dot11Elt::new(0, b"Test".to_vec());
        assert_eq!(elt.wire_len(), 6); // 2 header + 4 data
    }

    #[test]
    fn test_parse_truncated_ie() {
        // Only 1 byte - too short for IE header
        let buf = vec![0x00];
        assert!(Dot11Elt::parse(&buf, 0).is_err());

        // Header says 10 bytes but only 5 available
        let buf = vec![0x00, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(Dot11Elt::parse(&buf, 0).is_err());
    }

    #[test]
    fn test_parse_all_partial() {
        // Two complete IEs followed by a truncated one
        let mut buf = Dot11Elt::ssid("AB").build();
        buf.extend(Dot11Elt::new(1, vec![0x82]).build());
        buf.extend(&[0x03, 0x05]); // truncated: says 5 bytes but none follow

        let parsed = Dot11Elt::parse_all(&buf, 0);
        assert_eq!(parsed.len(), 2); // only the 2 complete ones
    }

    #[test]
    fn test_rates_mbps() {
        let rates = Dot11EltRates::new(vec![0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]);
        let mbps = rates.rates_mbps();
        assert_eq!(mbps, vec![1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0]);
    }
}
