use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::layer::field::{Field, FieldDesc, FieldError, FieldType, FieldValue, MacAddress};
use crate::layer::{Layer, LayerIndex, LayerKind};

pub const ARP_HEADER_LEN: usize = 28;
pub const ARP_FIXED_HEADER_LEN: usize = 8;

/// Hardware types (RFC 826, IANA assignments).
pub mod hardware_type {
    pub const ETHERNET: u16 = 1;
    pub const EXPERIMENTAL_ETHERNET: u16 = 2;
    pub const AX25: u16 = 3;
    pub const PRONET_TOKEN_RING: u16 = 4;
    pub const CHAOS: u16 = 5;
    pub const IEEE802: u16 = 6;
    pub const ARCNET: u16 = 7;
    pub const HYPERCHANNEL: u16 = 8;
    pub const LANSTAR: u16 = 9;
    pub const AUTONET: u16 = 10;
    pub const LOCALTALK: u16 = 11;
    pub const LOCALNET: u16 = 12;
    pub const ULTRA_LINK: u16 = 13;
    pub const SMDS: u16 = 14;
    pub const FRAME_RELAY: u16 = 15;
    pub const ATM: u16 = 16;
    pub const HDLC: u16 = 17;
    pub const FIBRE_CHANNEL: u16 = 18;
    pub const ATM_2: u16 = 19;
    pub const SERIAL_LINE: u16 = 20;
    pub const ATM_3: u16 = 21;

    pub fn name(t: u16) -> &'static str {
        match t {
            ETHERNET => "Ethernet (10Mb)",
            EXPERIMENTAL_ETHERNET => "Experimental Ethernet (3Mb)",
            AX25 => "AX.25",
            PRONET_TOKEN_RING => "Proteon ProNET Token Ring",
            CHAOS => "Chaos",
            IEEE802 => "IEEE 802 Networks",
            ARCNET => "ARCNET",
            HYPERCHANNEL => "Hyperchannel",
            LANSTAR => "Lanstar",
            AUTONET => "Autonet Short Address",
            LOCALTALK => "LocalTalk",
            LOCALNET => "LocalNet",
            ULTRA_LINK => "Ultra link",
            SMDS => "SMDS",
            FRAME_RELAY => "Frame relay",
            ATM | ATM_2 | ATM_3 => "ATM",
            HDLC => "HDLC",
            FIBRE_CHANNEL => "Fibre Channel",
            SERIAL_LINE => "Serial Line",
            _ => "Unknown",
        }
    }

    #[inline]
    pub const fn is_ethernet_like(t: u16) -> bool {
        matches!(t, ETHERNET | EXPERIMENTAL_ETHERNET | IEEE802)
    }
}

/// Protocol types (EtherType values).
pub mod protocol_type {
    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86DD;
    pub const ARP: u16 = 0x0806;

    #[inline]
    pub const fn is_ipv4(t: u16) -> bool {
        t == IPV4
    }
    #[inline]
    pub const fn is_ipv6(t: u16) -> bool {
        t == IPV6
    }
}

/// ARP operation codes.
pub mod opcode {
    pub const REQUEST: u16 = 1;
    pub const REPLY: u16 = 2;
    pub const RARP_REQUEST: u16 = 3;
    pub const RARP_REPLY: u16 = 4;
    pub const DRARP_REQUEST: u16 = 5;
    pub const DRARP_REPLY: u16 = 6;
    pub const DRARP_ERROR: u16 = 7;
    pub const INARP_REQUEST: u16 = 8;
    pub const INARP_REPLY: u16 = 9;

    pub fn name(op: u16) -> &'static str {
        match op {
            REQUEST => "who-has",
            REPLY => "is-at",
            RARP_REQUEST => "RARP-req",
            RARP_REPLY => "RARP-rep",
            DRARP_REQUEST => "Dyn-RARP-req",
            DRARP_REPLY => "Dyn-RARP-rep",
            DRARP_ERROR => "Dyn-RARP-err",
            INARP_REQUEST => "InARP-req",
            INARP_REPLY => "InARP-rep",
            _ => "unknown",
        }
    }

    pub fn from_name(name: &str) -> Option<u16> {
        match name.to_lowercase().as_str() {
            "who-has" | "request" | "1" => Some(REQUEST),
            "is-at" | "reply" | "2" => Some(REPLY),
            "rarp-req" | "3" => Some(RARP_REQUEST),
            "rarp-rep" | "4" => Some(RARP_REPLY),
            "dyn-rarp-req" | "5" => Some(DRARP_REQUEST),
            "dyn-rarp-rep" | "6" => Some(DRARP_REPLY),
            "dyn-rarp-err" | "7" => Some(DRARP_ERROR),
            "inarp-req" | "8" => Some(INARP_REQUEST),
            "inarp-rep" | "9" => Some(INARP_REPLY),
            _ => None,
        }
    }

    #[inline]
    pub const fn is_request(op: u16) -> bool {
        op % 2 == 1
    }
    #[inline]
    pub const fn is_reply(op: u16) -> bool {
        op % 2 == 0 && op > 0
    }
    #[inline]
    pub const fn reply_for(request_op: u16) -> u16 {
        request_op + 1
    }
}

/// Field offsets within ARP fixed header.
pub mod offsets {
    pub const HWTYPE: usize = 0;
    pub const PTYPE: usize = 2;
    pub const HWLEN: usize = 4;
    pub const PLEN: usize = 5;
    pub const OP: usize = 6;
    pub const VAR_START: usize = 8;
}

pub static FIXED_FIELDS: &[FieldDesc] = &[
    FieldDesc::new("hwtype", offsets::HWTYPE, 2, FieldType::U16),
    FieldDesc::new("ptype", offsets::PTYPE, 2, FieldType::U16),
    FieldDesc::new("hwlen", offsets::HWLEN, 1, FieldType::U8),
    FieldDesc::new("plen", offsets::PLEN, 1, FieldType::U8),
    FieldDesc::new("op", offsets::OP, 2, FieldType::U16),
];

/// Hardware address (variable length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardwareAddr {
    Mac(MacAddress),
    Raw(Vec<u8>),
}

impl HardwareAddr {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() == 6 {
            Self::Mac(MacAddress::new([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            ]))
        } else {
            Self::Raw(bytes.to_vec())
        }
    }

    pub fn as_mac(&self) -> Option<MacAddress> {
        match self {
            Self::Mac(mac) => Some(*mac),
            Self::Raw(bytes) if bytes.len() == 6 => Some(MacAddress::new([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            ])),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Mac(mac) => mac.as_bytes(),
            Self::Raw(bytes) => bytes,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Mac(_) => 6,
            Self::Raw(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn is_zero(&self) -> bool {
        self.as_bytes().iter().all(|&b| b == 0)
    }
    pub fn is_broadcast(&self) -> bool {
        self.as_bytes().iter().all(|&b| b == 0xff)
    }
}

impl std::fmt::Display for HardwareAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mac(mac) => write!(f, "{}", mac),
            Self::Raw(bytes) => {
                for (i, b) in bytes.iter().enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            },
        }
    }
}

impl From<MacAddress> for HardwareAddr {
    fn from(mac: MacAddress) -> Self {
        Self::Mac(mac)
    }
}

impl From<Vec<u8>> for HardwareAddr {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(&bytes)
    }
}

/// Protocol address (variable length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolAddr {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Raw(Vec<u8>),
}

impl ProtocolAddr {
    pub fn from_bytes(bytes: &[u8], ptype: u16) -> Self {
        match (bytes.len(), ptype) {
            (4, protocol_type::IPV4) | (4, _) => {
                Self::Ipv4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            },
            (16, protocol_type::IPV6) => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                Self::Ipv6(Ipv6Addr::from(arr))
            },
            _ => Self::Raw(bytes.to_vec()),
        }
    }

    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Ipv4(ip) => Some(*ip),
            Self::Raw(bytes) if bytes.len() == 4 => {
                Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            },
            _ => None,
        }
    }

    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            Self::Ipv6(ip) => Some(*ip),
            Self::Raw(bytes) if bytes.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                Some(Ipv6Addr::from(arr))
            },
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ipv4(ip) => ip.octets().to_vec(),
            Self::Ipv6(ip) => ip.octets().to_vec(),
            Self::Raw(bytes) => bytes.clone(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Ipv4(_) => 4,
            Self::Ipv6(_) => 16,
            Self::Raw(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Display for ProtocolAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4(ip) => write!(f, "{}", ip),
            Self::Ipv6(ip) => write!(f, "{}", ip),
            Self::Raw(bytes) => {
                write!(f, "0x")?;
                for b in bytes {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            },
        }
    }
}

impl From<Ipv4Addr> for ProtocolAddr {
    fn from(ip: Ipv4Addr) -> Self {
        Self::Ipv4(ip)
    }
}
impl From<Ipv6Addr> for ProtocolAddr {
    fn from(ip: Ipv6Addr) -> Self {
        Self::Ipv6(ip)
    }
}
impl From<Vec<u8>> for ProtocolAddr {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Raw(bytes)
    }
}

/// Routing information for ARP layer
#[derive(Debug, Clone)]
pub struct ArpRoute {
    /// Outgoing interface name
    pub interface: Option<String>,
    /// Source IP to use
    pub source_ip: Option<String>,
    /// Gateway IP if needed
    pub gateway: Option<String>,
}

impl Default for ArpRoute {
    fn default() -> Self {
        Self {
            interface: None,
            source_ip: None,
            gateway: None,
        }
    }
}

/// A view into an ARP packet.
#[derive(Debug, Clone)]
pub struct ArpLayer {
    pub index: LayerIndex,
}

impl ArpLayer {
    #[inline]
    pub const fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Arp, start, end),
        }
    }

    #[inline]
    pub const fn at_offset(offset: usize) -> Self {
        Self::new(offset, offset + ARP_HEADER_LEN)
    }

    pub fn at_offset_dynamic(buf: &[u8], offset: usize) -> Result<Self, FieldError> {
        Self::validate(buf, offset)?;
        let hwlen = buf[offset + offsets::HWLEN] as usize;
        let plen = buf[offset + offsets::PLEN] as usize;
        let total_len = ARP_FIXED_HEADER_LEN + 2 * hwlen + 2 * plen;
        Ok(Self::new(offset, offset + total_len))
    }

    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + ARP_FIXED_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: ARP_FIXED_HEADER_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }
        let hwlen = buf[offset + offsets::HWLEN] as usize;
        let plen = buf[offset + offsets::PLEN] as usize;
        let total_len = ARP_FIXED_HEADER_LEN + 2 * hwlen + 2 * plen;
        if buf.len() < offset + total_len {
            return Err(FieldError::BufferTooShort {
                offset,
                need: total_len,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    pub fn calculate_len(&self, buf: &[u8]) -> usize {
        let hwlen = self.hwlen(buf).unwrap_or(6) as usize;
        let plen = self.plen(buf).unwrap_or(4) as usize;
        ARP_FIXED_HEADER_LEN + 2 * hwlen + 2 * plen
    }

    // ========== Fixed Header Field Readers ==========
    #[inline]
    pub fn hwtype(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::HWTYPE)
    }

    #[inline]
    pub fn ptype(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::PTYPE)
    }

    #[inline]
    pub fn hwlen(&self, buf: &[u8]) -> Result<u8, FieldError> {
        u8::read(buf, self.index.start + offsets::HWLEN)
    }

    #[inline]
    pub fn plen(&self, buf: &[u8]) -> Result<u8, FieldError> {
        u8::read(buf, self.index.start + offsets::PLEN)
    }

    #[inline]
    pub fn op(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::OP)
    }

    // ========== Fixed Header Field Writers ==========
    #[inline]
    pub fn set_hwtype(&self, buf: &mut [u8], val: u16) -> Result<(), FieldError> {
        val.write(buf, self.index.start + offsets::HWTYPE)
    }

    #[inline]
    pub fn set_ptype(&self, buf: &mut [u8], val: u16) -> Result<(), FieldError> {
        val.write(buf, self.index.start + offsets::PTYPE)
    }

    #[inline]
    pub fn set_hwlen(&self, buf: &mut [u8], val: u8) -> Result<(), FieldError> {
        val.write(buf, self.index.start + offsets::HWLEN)
    }

    #[inline]
    pub fn set_plen(&self, buf: &mut [u8], val: u8) -> Result<(), FieldError> {
        val.write(buf, self.index.start + offsets::PLEN)
    }

    #[inline]
    pub fn set_op(&self, buf: &mut [u8], val: u16) -> Result<(), FieldError> {
        val.write(buf, self.index.start + offsets::OP)
    }

    // ========== Variable Address Offset Calculations ==========
    #[inline]
    fn hwsrc_offset(&self) -> usize {
        self.index.start + offsets::VAR_START
    }

    fn psrc_offset(&self, buf: &[u8]) -> Result<usize, FieldError> {
        Ok(self.hwsrc_offset() + self.hwlen(buf)? as usize)
    }

    fn hwdst_offset(&self, buf: &[u8]) -> Result<usize, FieldError> {
        let hwlen = self.hwlen(buf)? as usize;
        let plen = self.plen(buf)? as usize;
        Ok(self.hwsrc_offset() + hwlen + plen)
    }

    fn pdst_offset(&self, buf: &[u8]) -> Result<usize, FieldError> {
        let hwlen = self.hwlen(buf)? as usize;
        let plen = self.plen(buf)? as usize;
        Ok(self.hwsrc_offset() + 2 * hwlen + plen)
    }

    // ========== Variable Address Readers ==========
    pub fn hwsrc_raw(&self, buf: &[u8]) -> Result<HardwareAddr, FieldError> {
        let hwlen = self.hwlen(buf)? as usize;
        let offset = self.hwsrc_offset();
        if buf.len() < offset + hwlen {
            return Err(FieldError::BufferTooShort {
                offset,
                need: hwlen,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(HardwareAddr::from_bytes(&buf[offset..offset + hwlen]))
    }

    pub fn hwsrc(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        let hwlen = self.hwlen(buf)?;
        if hwlen != 6 {
            return Err(FieldError::BufferTooShort {
                offset: self.hwsrc_offset(),
                need: 6,
                have: hwlen as usize,
            });
        }
        MacAddress::read(buf, self.hwsrc_offset())
    }

    pub fn psrc_raw(&self, buf: &[u8]) -> Result<ProtocolAddr, FieldError> {
        let plen = self.plen(buf)? as usize;
        let ptype = self.ptype(buf)?;
        let offset = self.psrc_offset(buf)?;
        if buf.len() < offset + plen {
            return Err(FieldError::BufferTooShort {
                offset,
                need: plen,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(ProtocolAddr::from_bytes(&buf[offset..offset + plen], ptype))
    }

    pub fn psrc(&self, buf: &[u8]) -> Result<Ipv4Addr, FieldError> {
        Ipv4Addr::read(buf, self.psrc_offset(buf)?)
    }

    pub fn psrc_v6(&self, buf: &[u8]) -> Result<Ipv6Addr, FieldError> {
        Ipv6Addr::read(buf, self.psrc_offset(buf)?)
    }

    pub fn hwdst_raw(&self, buf: &[u8]) -> Result<HardwareAddr, FieldError> {
        let hwlen = self.hwlen(buf)? as usize;
        let offset = self.hwdst_offset(buf)?;
        if buf.len() < offset + hwlen {
            return Err(FieldError::BufferTooShort {
                offset,
                need: hwlen,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(HardwareAddr::from_bytes(&buf[offset..offset + hwlen]))
    }

    pub fn hwdst(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        MacAddress::read(buf, self.hwdst_offset(buf)?)
    }

    pub fn pdst_raw(&self, buf: &[u8]) -> Result<ProtocolAddr, FieldError> {
        let plen = self.plen(buf)? as usize;
        let ptype = self.ptype(buf)?;
        let offset = self.pdst_offset(buf)?;
        if buf.len() < offset + plen {
            return Err(FieldError::BufferTooShort {
                offset,
                need: plen,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(ProtocolAddr::from_bytes(&buf[offset..offset + plen], ptype))
    }

    pub fn pdst(&self, buf: &[u8]) -> Result<Ipv4Addr, FieldError> {
        Ipv4Addr::read(buf, self.pdst_offset(buf)?)
    }

    pub fn pdst_v6(&self, buf: &[u8]) -> Result<Ipv6Addr, FieldError> {
        Ipv6Addr::read(buf, self.pdst_offset(buf)?)
    }

    // ========== Variable Address Writers ==========
    pub fn set_hwsrc(&self, buf: &mut [u8], mac: MacAddress) -> Result<(), FieldError> {
        mac.write(buf, self.hwsrc_offset())
    }

    pub fn set_hwsrc_raw(&self, buf: &mut [u8], addr: &HardwareAddr) -> Result<(), FieldError> {
        let offset = self.hwsrc_offset();
        let bytes = addr.as_bytes();
        if buf.len() < offset + bytes.len() {
            return Err(FieldError::BufferTooShort {
                offset,
                need: bytes.len(),
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    pub fn set_psrc(&self, buf: &mut [u8], ip: Ipv4Addr) -> Result<(), FieldError> {
        ip.write(buf, self.psrc_offset(buf)?)
    }

    pub fn set_psrc_v6(&self, buf: &mut [u8], ip: Ipv6Addr) -> Result<(), FieldError> {
        ip.write(buf, self.psrc_offset(buf)?)
    }

    pub fn set_psrc_raw(&self, buf: &mut [u8], addr: &ProtocolAddr) -> Result<(), FieldError> {
        let offset = self.psrc_offset(buf)?;
        let bytes = addr.as_bytes();
        if buf.len() < offset + bytes.len() {
            return Err(FieldError::BufferTooShort {
                offset,
                need: bytes.len(),
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset..offset + bytes.len()].copy_from_slice(&bytes);
        Ok(())
    }

    pub fn set_hwdst(&self, buf: &mut [u8], mac: MacAddress) -> Result<(), FieldError> {
        mac.write(buf, self.hwdst_offset(buf)?)
    }

    pub fn set_hwdst_raw(&self, buf: &mut [u8], addr: &HardwareAddr) -> Result<(), FieldError> {
        let offset = self.hwdst_offset(buf)?;
        let bytes = addr.as_bytes();
        if buf.len() < offset + bytes.len() {
            return Err(FieldError::BufferTooShort {
                offset,
                need: bytes.len(),
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    pub fn set_pdst(&self, buf: &mut [u8], ip: Ipv4Addr) -> Result<(), FieldError> {
        ip.write(buf, self.pdst_offset(buf)?)
    }

    pub fn set_pdst_v6(&self, buf: &mut [u8], ip: Ipv6Addr) -> Result<(), FieldError> {
        ip.write(buf, self.pdst_offset(buf)?)
    }

    pub fn set_pdst_raw(&self, buf: &mut [u8], addr: &ProtocolAddr) -> Result<(), FieldError> {
        let offset = self.pdst_offset(buf)?;
        let bytes = addr.as_bytes();
        if buf.len() < offset + bytes.len() {
            return Err(FieldError::BufferTooShort {
                offset,
                need: bytes.len(),
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset..offset + bytes.len()].copy_from_slice(&bytes);
        Ok(())
    }

    // ========== Dynamic Field Access ==========
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "hwtype" => Some(self.hwtype(buf).map(FieldValue::U16)),
            "ptype" => Some(self.ptype(buf).map(FieldValue::U16)),
            "hwlen" => Some(self.hwlen(buf).map(FieldValue::U8)),
            "plen" => Some(self.plen(buf).map(FieldValue::U8)),
            "op" => Some(self.op(buf).map(FieldValue::U16)),
            "hwsrc" => Some(self.hwsrc(buf).map(FieldValue::Mac)),
            "psrc" => Some(self.psrc(buf).map(FieldValue::Ipv4)),
            "hwdst" => Some(self.hwdst(buf).map(FieldValue::Mac)),
            "pdst" => Some(self.pdst(buf).map(FieldValue::Ipv4)),
            _ => None,
        }
    }

    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match (name, value) {
            ("hwtype", FieldValue::U16(v)) => Some(self.set_hwtype(buf, v)),
            ("ptype", FieldValue::U16(v)) => Some(self.set_ptype(buf, v)),
            ("hwlen", FieldValue::U8(v)) => Some(self.set_hwlen(buf, v)),
            ("plen", FieldValue::U8(v)) => Some(self.set_plen(buf, v)),
            ("op", FieldValue::U16(v)) => Some(self.set_op(buf, v)),
            ("hwsrc", FieldValue::Mac(v)) => Some(self.set_hwsrc(buf, v)),
            ("psrc", FieldValue::Ipv4(v)) => Some(self.set_psrc(buf, v)),
            ("psrc", FieldValue::Ipv6(v)) => Some(self.set_psrc_v6(buf, v)),
            ("hwdst", FieldValue::Mac(v)) => Some(self.set_hwdst(buf, v)),
            ("pdst", FieldValue::Ipv4(v)) => Some(self.set_pdst(buf, v)),
            ("pdst", FieldValue::Ipv6(v)) => Some(self.set_pdst_v6(buf, v)),
            _ => None,
        }
    }

    pub fn field_names() -> &'static [&'static str] {
        &[
            "hwtype", "ptype", "hwlen", "plen", "op", "hwsrc", "psrc", "hwdst", "pdst",
        ]
    }

    #[inline]
    pub fn is_request(&self, buf: &[u8]) -> bool {
        self.op(buf).map(opcode::is_request).unwrap_or(false)
    }

    #[inline]
    pub fn is_reply(&self, buf: &[u8]) -> bool {
        self.op(buf).map(opcode::is_reply).unwrap_or(false)
    }

    #[inline]
    pub fn is_who_has(&self, buf: &[u8]) -> bool {
        self.op(buf)
            .map(|op| op == opcode::REQUEST)
            .unwrap_or(false)
    }

    #[inline]
    pub fn is_is_at(&self, buf: &[u8]) -> bool {
        self.op(buf).map(|op| op == opcode::REPLY).unwrap_or(false)
    }

    /// Compute hash for packet matching.
    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        let hwtype = self.hwtype(buf).unwrap_or(0);
        let ptype = self.ptype(buf).unwrap_or(0);
        let op = self.op(buf).unwrap_or(0);
        let op_group = (op + 1) / 2;

        let mut result = Vec::with_capacity(6);
        result.extend_from_slice(&hwtype.to_be_bytes());
        result.extend_from_slice(&ptype.to_be_bytes());
        result.extend_from_slice(&op_group.to_be_bytes());
        result
    }

    /// Check if this packet answers another (for sr() matching).
    pub fn answers(&self, buf: &[u8], other: &ArpLayer, other_buf: &[u8]) -> bool {
        let self_op = match self.op(buf) {
            Ok(op) => op,
            Err(_) => return false,
        };
        let other_op = match other.op(other_buf) {
            Ok(op) => op,
            Err(_) => return false,
        };

        if self_op != other_op + 1 {
            return false;
        }

        let self_psrc = match self.psrc_raw(buf) {
            Ok(addr) => addr.as_bytes(),
            Err(_) => return false,
        };
        let other_pdst = match other.pdst_raw(other_buf) {
            Ok(addr) => addr.as_bytes(),
            Err(_) => return false,
        };

        let cmp_len = self_psrc.len().min(other_pdst.len());
        self_psrc[..cmp_len] == other_pdst[..cmp_len]
    }

    /// Extract padding: ARP has no payload, remaining bytes are padding.
    pub fn extract_padding<'a>(&self, buf: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        let end = self.index.end.min(buf.len());
        (&[], &buf[end..])
    }

    /// Get routing information for this ARP packet.
    pub fn route(&self, buf: &[u8]) -> ArpRoute {
        let pdst_ip = match self.pdst_raw(buf) {
            Ok(ProtocolAddr::Ipv4(ip)) => IpAddr::V4(ip),
            Ok(ProtocolAddr::Ipv6(ip)) => IpAddr::V6(ip),
            _ => return ArpRoute::default(),
        };

        let interfaces = pnet_datalink::interfaces();

        for iface in &interfaces {
            if !iface.is_up() || iface.is_loopback() {
                continue;
            }

            for ip_net in &iface.ips {
                if ip_net.contains(pdst_ip) {
                    return ArpRoute {
                        interface: Some(iface.name.clone()),
                        source_ip: Some(ip_net.ip().to_string()),
                        gateway: None,
                    };
                }
            }
        }

        if let Ok(default_iface) = default_net::get_default_interface() {
            if let Some(iface) = interfaces.iter().find(|i| i.name == default_iface.name) {
                let src_ip = iface
                    .ips
                    .iter()
                    .find(|ip| ip.is_ipv4())
                    .map(|ip| ip.ip().to_string());
                let gw_ip = default_iface.gateway.map(|gw| gw.ip_addr.to_string());

                return ArpRoute {
                    interface: Some(iface.name.clone()),
                    source_ip: src_ip,
                    gateway: gw_ip,
                };
            }
        }

        ArpRoute::default()
    }

    /// Resolve the destination MAC for this ARP packet.
    pub fn resolve_dst_mac(&self, buf: &[u8]) -> Option<MacAddress> {
        let op = self.op(buf).ok()?;
        match op {
            opcode::REQUEST => Some(MacAddress::BROADCAST), // who-has uses broadcast
            opcode::REPLY => None,                          // is-at should have explicit dst
            _ => None,
        }
    }

    #[inline]
    pub fn header_bytes<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.index.start..self.index.end.min(buf.len())]
    }

    #[inline]
    pub fn header_copy(&self, buf: &[u8]) -> Vec<u8> {
        self.header_bytes(buf).to_vec()
    }

    pub fn op_name(&self, buf: &[u8]) -> &'static str {
        self.op(buf).map(opcode::name).unwrap_or("unknown")
    }

    pub fn hwtype_name(&self, buf: &[u8]) -> &'static str {
        self.hwtype(buf)
            .map(hardware_type::name)
            .unwrap_or("unknown")
    }
}

impl Layer for ArpLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Arp
    }

    fn summary(&self, buf: &[u8]) -> String {
        let op = self.op(buf).unwrap_or(0);
        let psrc = self
            .psrc_raw(buf)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into());
        let pdst = self
            .pdst_raw(buf)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into());

        match op {
            opcode::REQUEST => format!("ARP who has {} says {}", pdst, psrc),
            opcode::REPLY => {
                let hwsrc = self
                    .hwsrc_raw(buf)
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into());
                format!("ARP {} is at {}", psrc, hwsrc)
            },
            _ => format!("ARP {} {} > {}", opcode::name(op), psrc, pdst),
        }
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        self.calculate_len(buf)
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        self.hashret(buf)
    }

    fn answers(&self, buf: &[u8], other: &Self, other_buf: &[u8]) -> bool {
        self.answers(buf, other, other_buf)
    }

    fn extract_padding<'a>(&self, buf: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        self.extract_padding(buf)
    }
}

// ============================================================================
// ArpBuilder
// ============================================================================

#[derive(Debug, Clone)]
pub struct ArpBuilder {
    hwtype: u16,
    ptype: u16,
    hwlen: Option<u8>,
    plen: Option<u8>,
    op: u16,
    hwsrc: HardwareAddr,
    psrc: ProtocolAddr,
    hwdst: HardwareAddr,
    pdst: ProtocolAddr,
}

/// Get the default interface's MAC address and IPv4 address.
fn get_local_mac_and_ip() -> (MacAddress, Ipv4Addr) {
    let default_mac = MacAddress::ZERO;
    let default_ip = Ipv4Addr::new(0, 0, 0, 0);

    let default_iface = match default_net::get_default_interface() {
        Ok(iface) => iface,
        Err(_) => return (default_mac, default_ip),
    };

    let interfaces = pnet_datalink::interfaces();
    let iface = match interfaces.iter().find(|i| i.name == default_iface.name) {
        Some(i) => i,
        None => return (default_mac, default_ip),
    };

    let mac = iface
        .mac
        .map(|m| MacAddress::new(m.octets()))
        .unwrap_or(default_mac);

    let ip = iface
        .ips
        .iter()
        .find_map(|ip_net| {
            if let IpAddr::V4(v4) = ip_net.ip() {
                Some(v4)
            } else {
                None
            }
        })
        .unwrap_or(default_ip);

    (mac, ip)
}

impl Default for ArpBuilder {
    fn default() -> Self {
        let (local_mac, local_ip) = get_local_mac_and_ip();
        Self {
            hwtype: hardware_type::ETHERNET,
            ptype: protocol_type::IPV4,
            hwlen: None,
            plen: None,
            op: opcode::REQUEST,
            hwsrc: HardwareAddr::Mac(local_mac),
            psrc: ProtocolAddr::Ipv4(local_ip),
            hwdst: HardwareAddr::Mac(MacAddress::ZERO),
            pdst: ProtocolAddr::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }
}

impl ArpBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn who_has(pdst: Ipv4Addr) -> Self {
        Self::default().op(opcode::REQUEST).pdst(pdst)
    }

    pub fn is_at(psrc: Ipv4Addr, hwsrc: MacAddress) -> Self {
        Self::default().op(opcode::REPLY).psrc(psrc).hwsrc(hwsrc)
    }

    pub fn hwtype(mut self, v: u16) -> Self {
        self.hwtype = v;
        self
    }
    pub fn ptype(mut self, v: u16) -> Self {
        self.ptype = v;
        self
    }
    pub fn hwlen(mut self, v: u8) -> Self {
        self.hwlen = Some(v);
        self
    }
    pub fn plen(mut self, v: u8) -> Self {
        self.plen = Some(v);
        self
    }
    pub fn op(mut self, v: u16) -> Self {
        self.op = v;
        self
    }

    pub fn op_name(mut self, name: &str) -> Self {
        if let Some(op) = opcode::from_name(name) {
            self.op = op;
        }
        self
    }

    pub fn hwsrc(mut self, v: MacAddress) -> Self {
        self.hwsrc = HardwareAddr::Mac(v);
        self
    }
    pub fn hwsrc_raw(mut self, v: HardwareAddr) -> Self {
        self.hwsrc = v;
        self
    }
    pub fn psrc(mut self, v: Ipv4Addr) -> Self {
        self.psrc = ProtocolAddr::Ipv4(v);
        self
    }
    pub fn psrc_v6(mut self, v: Ipv6Addr) -> Self {
        self.psrc = ProtocolAddr::Ipv6(v);
        self.ptype = protocol_type::IPV6;
        self
    }
    pub fn psrc_raw(mut self, v: ProtocolAddr) -> Self {
        self.psrc = v;
        self
    }
    pub fn hwdst(mut self, v: MacAddress) -> Self {
        self.hwdst = HardwareAddr::Mac(v);
        self
    }
    pub fn hwdst_raw(mut self, v: HardwareAddr) -> Self {
        self.hwdst = v;
        self
    }
    pub fn pdst(mut self, v: Ipv4Addr) -> Self {
        self.pdst = ProtocolAddr::Ipv4(v);
        self
    }
    pub fn pdst_v6(mut self, v: Ipv6Addr) -> Self {
        self.pdst = ProtocolAddr::Ipv6(v);
        self.ptype = protocol_type::IPV6;
        self
    }
    pub fn pdst_raw(mut self, v: ProtocolAddr) -> Self {
        self.pdst = v;
        self
    }

    pub fn size(&self) -> usize {
        let hwlen = self.hwlen.unwrap_or(self.hwsrc.len() as u8) as usize;
        let plen = self.plen.unwrap_or(self.psrc.len() as u8) as usize;
        ARP_FIXED_HEADER_LEN + 2 * hwlen + 2 * plen
    }

    pub fn build(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.size()];
        self.build_into(&mut buf)
            .expect("buffer is correctly sized");
        buf
    }

    pub fn build_into(&self, buf: &mut [u8]) -> Result<(), FieldError> {
        let hwlen = self.hwlen.unwrap_or(self.hwsrc.len() as u8);
        let plen = self.plen.unwrap_or(self.psrc.len() as u8);
        let size = ARP_FIXED_HEADER_LEN + 2 * (hwlen as usize) + 2 * (plen as usize);

        if buf.len() < size {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: size,
                have: buf.len(),
            });
        }

        self.hwtype.write(buf, offsets::HWTYPE)?;
        self.ptype.write(buf, offsets::PTYPE)?;
        hwlen.write(buf, offsets::HWLEN)?;
        plen.write(buf, offsets::PLEN)?;
        self.op.write(buf, offsets::OP)?;

        let mut offset = offsets::VAR_START;

        let hwsrc_bytes = self.hwsrc.as_bytes();
        let hwsrc_copy_len = hwsrc_bytes.len().min(hwlen as usize);
        buf[offset..offset + hwsrc_copy_len].copy_from_slice(&hwsrc_bytes[..hwsrc_copy_len]);
        offset += hwlen as usize;

        let psrc_bytes = self.psrc.as_bytes();
        let psrc_copy_len = psrc_bytes.len().min(plen as usize);
        buf[offset..offset + psrc_copy_len].copy_from_slice(&psrc_bytes[..psrc_copy_len]);
        offset += plen as usize;

        let hwdst_bytes = self.hwdst.as_bytes();
        let hwdst_copy_len = hwdst_bytes.len().min(hwlen as usize);
        buf[offset..offset + hwdst_copy_len].copy_from_slice(&hwdst_bytes[..hwdst_copy_len]);
        offset += hwlen as usize;

        let pdst_bytes = self.pdst.as_bytes();
        let pdst_copy_len = pdst_bytes.len().min(plen as usize);
        buf[offset..offset + pdst_copy_len].copy_from_slice(&pdst_bytes[..pdst_copy_len]);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_ipv6_fields() {
        let mut buf = vec![0u8; 52]; // 8 fixed + 2*(6+16) for IPv6
        let arp = ArpLayer::at_offset(0);

        arp.set_hwtype(&mut buf, hardware_type::ETHERNET).unwrap();
        arp.set_ptype(&mut buf, protocol_type::IPV6).unwrap();
        arp.set_hwlen(&mut buf, 6).unwrap();
        arp.set_plen(&mut buf, 16).unwrap();
        arp.set_op(&mut buf, opcode::REQUEST).unwrap();

        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        arp.set_psrc_v6(&mut buf, ipv6).unwrap();
        assert_eq!(arp.psrc_v6(&buf).unwrap(), ipv6);
    }

    #[test]
    fn test_extract_padding() {
        let mut buf = vec![0u8; 60]; // Ethernet minimum with padding
        buf[..28].copy_from_slice(&sample_arp_request());

        let arp = ArpLayer::at_offset(0);
        let (payload, padding) = arp.extract_padding(&buf);

        assert!(payload.is_empty());
        assert_eq!(padding.len(), 32); // 60 - 28 = 32 bytes padding
    }

    #[test]
    fn test_route() {
        let buf = sample_arp_request();
        let arp = ArpLayer::at_offset(0);
        let route = arp.route(&buf);

        assert!(route.source_ip.is_some());
    }

    #[test]
    fn test_resolve_dst_mac() {
        let buf = sample_arp_request();
        let arp = ArpLayer::at_offset(0);

        assert_eq!(arp.resolve_dst_mac(&buf), Some(MacAddress::BROADCAST));
    }

    fn sample_arp_request() -> Vec<u8> {
        vec![
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0xc0, 0xa8, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x02,
        ]
    }
}
