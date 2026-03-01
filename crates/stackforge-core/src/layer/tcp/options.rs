//! TCP options parsing and building.
//!
//! TCP options follow the header and are variable-length.
//! Maximum options length is 40 bytes (60 byte header - 20 byte minimum).
//!
//! # Option Format
//!
//! Single-byte options (EOL, NOP):
//! ```text
//! +--------+
//! |  Kind  |
//! +--------+
//! ```
//!
//! Multi-byte options:
//! ```text
//! +--------+--------+--------...
//! |  Kind  | Length | Data
//! +--------+--------+--------...
//! ```

use crate::layer::field::FieldError;

/// Maximum length of TCP options (in bytes).
pub const MAX_OPTIONS_LEN: usize = 40;

/// TCP option kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpOptionKind {
    /// End of Option List (RFC 793)
    Eol = 0,
    /// No Operation (RFC 793)
    Nop = 1,
    /// Maximum Segment Size (RFC 793)
    Mss = 2,
    /// Window Scale (RFC 7323)
    WScale = 3,
    /// SACK Permitted (RFC 2018)
    SackOk = 4,
    /// SACK (RFC 2018)
    Sack = 5,
    /// Timestamps (RFC 7323)
    Timestamp = 8,
    /// Alternate Checksum Request (RFC 1146)
    AltChkSum = 14,
    /// Alternate Checksum Data (RFC 1146)
    AltChkSumOpt = 15,
    /// MD5 Signature (RFC 2385)
    Md5 = 19,
    /// Mood (RFC 5841) - April Fools
    Mood = 25,
    /// User Timeout Option (RFC 5482)
    Uto = 28,
    /// Authentication Option (RFC 5925)
    Ao = 29,
    /// TCP Fast Open (RFC 7413)
    Tfo = 34,
    /// Unknown option
    Unknown(u8),
}

impl TcpOptionKind {
    /// Create from raw option kind byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Eol,
            1 => Self::Nop,
            2 => Self::Mss,
            3 => Self::WScale,
            4 => Self::SackOk,
            5 => Self::Sack,
            8 => Self::Timestamp,
            14 => Self::AltChkSum,
            15 => Self::AltChkSumOpt,
            19 => Self::Md5,
            25 => Self::Mood,
            28 => Self::Uto,
            29 => Self::Ao,
            34 => Self::Tfo,
            x => Self::Unknown(x),
        }
    }

    /// Convert to raw option kind byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Eol => 0,
            Self::Nop => 1,
            Self::Mss => 2,
            Self::WScale => 3,
            Self::SackOk => 4,
            Self::Sack => 5,
            Self::Timestamp => 8,
            Self::AltChkSum => 14,
            Self::AltChkSumOpt => 15,
            Self::Md5 => 19,
            Self::Mood => 25,
            Self::Uto => 28,
            Self::Ao => 29,
            Self::Tfo => 34,
            Self::Unknown(x) => x,
        }
    }

    /// Get the name of the option.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Eol => "EOL",
            Self::Nop => "NOP",
            Self::Mss => "MSS",
            Self::WScale => "WScale",
            Self::SackOk => "SAckOK",
            Self::Sack => "SAck",
            Self::Timestamp => "Timestamp",
            Self::AltChkSum => "AltChkSum",
            Self::AltChkSumOpt => "AltChkSumOpt",
            Self::Md5 => "MD5",
            Self::Mood => "Mood",
            Self::Uto => "UTO",
            Self::Ao => "AO",
            Self::Tfo => "TFO",
            Self::Unknown(_) => "Unknown",
        }
    }

    /// Check if this is a single-byte option (no length/data).
    #[inline]
    pub fn is_single_byte(&self) -> bool {
        matches!(self, Self::Eol | Self::Nop)
    }

    /// Get the expected fixed length for this option (if any).
    /// Returns None for variable-length options.
    pub fn expected_len(&self) -> Option<usize> {
        match self {
            Self::Eol | Self::Nop => Some(1),
            Self::Mss => Some(4),
            Self::WScale => Some(3),
            Self::SackOk => Some(2),
            Self::Timestamp => Some(10),
            Self::AltChkSum => Some(4), // Variable but typical
            Self::AltChkSumOpt => Some(2),
            Self::Md5 => Some(18),
            Self::Uto => Some(4),
            Self::Tfo => Some(10), // Can vary (2-18)
            Self::Sack | Self::Ao | Self::Mood | Self::Unknown(_) => None,
        }
    }
}

impl std::fmt::Display for TcpOptionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(x) => write!(f, "Unknown({})", x),
            _ => write!(f, "{}", self.name()),
        }
    }
}

/// TCP SACK block (pair of sequence numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSackBlock {
    /// Left edge of block
    pub left: u32,
    /// Right edge of block
    pub right: u32,
}

impl TcpSackBlock {
    /// Create a new SACK block.
    pub fn new(left: u32, right: u32) -> Self {
        Self { left, right }
    }
}

/// TCP Timestamp option data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpTimestamp {
    /// Timestamp value
    pub ts_val: u32,
    /// Timestamp echo reply
    pub ts_ecr: u32,
}

impl TcpTimestamp {
    /// Create a new timestamp.
    pub fn new(ts_val: u32, ts_ecr: u32) -> Self {
        Self { ts_val, ts_ecr }
    }
}

/// TCP Authentication Option (AO) value per RFC 5925.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpAoValue {
    /// Key ID
    pub key_id: u8,
    /// Receive next key ID
    pub rnext_key_id: u8,
    /// MAC (Message Authentication Code)
    pub mac: Vec<u8>,
}

impl TcpAoValue {
    /// Create a new AO value.
    pub fn new(key_id: u8, rnext_key_id: u8, mac: Vec<u8>) -> Self {
        Self {
            key_id,
            rnext_key_id,
            mac,
        }
    }
}

/// A parsed TCP option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOption {
    /// End of Option List (kind 0)
    Eol,

    /// No Operation / Padding (kind 1)
    Nop,

    /// Maximum Segment Size (kind 2)
    Mss(u16),

    /// Window Scale (kind 3)
    WScale(u8),

    /// SACK Permitted (kind 4)
    SackOk,

    /// Selective Acknowledgment (kind 5)
    Sack(Vec<TcpSackBlock>),

    /// Timestamps (kind 8)
    Timestamp(TcpTimestamp),

    /// Alternate Checksum Request (kind 14)
    AltChkSum { algorithm: u8, checksum: u16 },

    /// Alternate Checksum Data (kind 15)
    AltChkSumOpt,

    /// MD5 Signature (kind 19)
    Md5([u8; 16]),

    /// Mood (kind 25) - RFC 5841
    Mood(String),

    /// User Timeout Option (kind 28)
    Uto(u16),

    /// Authentication Option (kind 29)
    Ao(TcpAoValue),

    /// TCP Fast Open (kind 34)
    Tfo {
        /// TFO cookie (optional)
        cookie: Option<Vec<u8>>,
    },

    /// Unknown or unimplemented option
    Unknown { kind: u8, data: Vec<u8> },
}

impl TcpOption {
    /// Get the option kind.
    pub fn kind(&self) -> TcpOptionKind {
        match self {
            Self::Eol => TcpOptionKind::Eol,
            Self::Nop => TcpOptionKind::Nop,
            Self::Mss(_) => TcpOptionKind::Mss,
            Self::WScale(_) => TcpOptionKind::WScale,
            Self::SackOk => TcpOptionKind::SackOk,
            Self::Sack(_) => TcpOptionKind::Sack,
            Self::Timestamp(_) => TcpOptionKind::Timestamp,
            Self::AltChkSum { .. } => TcpOptionKind::AltChkSum,
            Self::AltChkSumOpt => TcpOptionKind::AltChkSumOpt,
            Self::Md5(_) => TcpOptionKind::Md5,
            Self::Mood(_) => TcpOptionKind::Mood,
            Self::Uto(_) => TcpOptionKind::Uto,
            Self::Ao(_) => TcpOptionKind::Ao,
            Self::Tfo { .. } => TcpOptionKind::Tfo,
            Self::Unknown { kind, .. } => TcpOptionKind::Unknown(*kind),
        }
    }

    /// Get the serialized length of this option.
    pub fn len(&self) -> usize {
        match self {
            Self::Eol => 1,
            Self::Nop => 1,
            Self::Mss(_) => 4,
            Self::WScale(_) => 3,
            Self::SackOk => 2,
            Self::Sack(blocks) => 2 + blocks.len() * 8,
            Self::Timestamp(_) => 10,
            Self::AltChkSum { .. } => 4,
            Self::AltChkSumOpt => 2,
            Self::Md5(_) => 18,
            Self::Mood(s) => 2 + s.len(),
            Self::Uto(_) => 4,
            Self::Ao(ao) => 4 + ao.mac.len(),
            Self::Tfo { cookie: None } => 2,
            Self::Tfo { cookie: Some(c) } => 2 + c.len(),
            Self::Unknown { data, .. } => 2 + data.len(),
        }
    }

    /// Check if the option has data (for variants with data).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Serialize the option to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Eol => vec![0],
            Self::Nop => vec![1],

            Self::Mss(mss) => {
                let mut buf = vec![2, 4];
                buf.extend_from_slice(&mss.to_be_bytes());
                buf
            },

            Self::WScale(scale) => vec![3, 3, *scale],

            Self::SackOk => vec![4, 2],

            Self::Sack(blocks) => {
                let mut buf = vec![5, (2 + blocks.len() * 8) as u8];
                for block in blocks {
                    buf.extend_from_slice(&block.left.to_be_bytes());
                    buf.extend_from_slice(&block.right.to_be_bytes());
                }
                buf
            },

            Self::Timestamp(ts) => {
                let mut buf = vec![8, 10];
                buf.extend_from_slice(&ts.ts_val.to_be_bytes());
                buf.extend_from_slice(&ts.ts_ecr.to_be_bytes());
                buf
            },

            Self::AltChkSum {
                algorithm,
                checksum,
            } => {
                let mut buf = vec![14, 4, *algorithm];
                buf.extend_from_slice(&checksum.to_be_bytes());
                buf
            },

            Self::AltChkSumOpt => vec![15, 2],

            Self::Md5(sig) => {
                let mut buf = vec![19, 18];
                buf.extend_from_slice(sig);
                buf
            },

            Self::Mood(mood) => {
                let mut buf = vec![25, (2 + mood.len()) as u8];
                buf.extend_from_slice(mood.as_bytes());
                buf
            },

            Self::Uto(timeout) => {
                let mut buf = vec![28, 4];
                buf.extend_from_slice(&timeout.to_be_bytes());
                buf
            },

            Self::Ao(ao) => {
                let len = 4 + ao.mac.len();
                let mut buf = vec![29, len as u8, ao.key_id, ao.rnext_key_id];
                buf.extend_from_slice(&ao.mac);
                buf
            },

            Self::Tfo { cookie: None } => vec![34, 2],

            Self::Tfo { cookie: Some(c) } => {
                let mut buf = vec![34, (2 + c.len()) as u8];
                buf.extend_from_slice(c);
                buf
            },

            Self::Unknown { kind, data } => {
                let mut buf = vec![*kind, (2 + data.len()) as u8];
                buf.extend_from_slice(data);
                buf
            },
        }
    }

    /// Create an MSS option.
    pub fn mss(mss: u16) -> Self {
        Self::Mss(mss)
    }

    /// Create a Window Scale option.
    pub fn wscale(scale: u8) -> Self {
        Self::WScale(scale)
    }

    /// Create a Timestamp option.
    pub fn timestamp(ts_val: u32, ts_ecr: u32) -> Self {
        Self::Timestamp(TcpTimestamp::new(ts_val, ts_ecr))
    }

    /// Create a SACK option.
    pub fn sack(blocks: Vec<TcpSackBlock>) -> Self {
        Self::Sack(blocks)
    }
}

/// Collection of TCP options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpOptions {
    pub options: Vec<TcpOption>,
}

impl TcpOptions {
    /// Create empty options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from a list of options.
    pub fn from_vec(options: Vec<TcpOption>) -> Self {
        Self { options }
    }

    /// Check if there are no options.
    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }

    /// Get the number of options.
    pub fn len(&self) -> usize {
        self.options.len()
    }

    /// Get the total serialized length.
    pub fn byte_len(&self) -> usize {
        self.options.iter().map(|o| o.len()).sum()
    }

    /// Get the padded length (aligned to 4 bytes).
    pub fn padded_len(&self) -> usize {
        let len = self.byte_len();
        (len + 3) & !3
    }

    /// Add an option.
    pub fn push(&mut self, option: TcpOption) {
        self.options.push(option);
    }

    /// Get an option by kind.
    pub fn get(&self, kind: TcpOptionKind) -> Option<&TcpOption> {
        self.options.iter().find(|o| o.kind() == kind)
    }

    /// Get the MSS value if present.
    pub fn mss(&self) -> Option<u16> {
        self.options.iter().find_map(|o| match o {
            TcpOption::Mss(mss) => Some(*mss),
            _ => None,
        })
    }

    /// Get the Window Scale value if present.
    pub fn wscale(&self) -> Option<u8> {
        self.options.iter().find_map(|o| match o {
            TcpOption::WScale(scale) => Some(*scale),
            _ => None,
        })
    }

    /// Get the Timestamp if present.
    pub fn timestamp(&self) -> Option<TcpTimestamp> {
        self.options.iter().find_map(|o| match o {
            TcpOption::Timestamp(ts) => Some(*ts),
            _ => None,
        })
    }

    /// Check if SACK is permitted.
    pub fn sack_permitted(&self) -> bool {
        self.options.iter().any(|o| matches!(o, TcpOption::SackOk))
    }

    /// Get the SACK blocks if present.
    pub fn sack_blocks(&self) -> Option<&[TcpSackBlock]> {
        self.options.iter().find_map(|o| match o {
            TcpOption::Sack(blocks) => Some(blocks.as_slice()),
            _ => None,
        })
    }

    /// Get the Authentication Option if present.
    pub fn ao(&self) -> Option<&TcpAoValue> {
        self.options.iter().find_map(|o| match o {
            TcpOption::Ao(ao) => Some(ao),
            _ => None,
        })
    }

    /// Get the TFO cookie if present.
    pub fn tfo_cookie(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|o| match o {
            TcpOption::Tfo { cookie: Some(c) } => Some(c.as_slice()),
            _ => None,
        })
    }

    /// Serialize all options to bytes (with padding).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for opt in &self.options {
            buf.extend_from_slice(&opt.to_bytes());
        }

        // Pad to 4-byte boundary
        let pad = (4 - (buf.len() % 4)) % 4;
        buf.extend(std::iter::repeat(0u8).take(pad));

        buf
    }

    /// Serialize to bytes without padding.
    pub fn to_bytes_unpadded(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for opt in &self.options {
            buf.extend_from_slice(&opt.to_bytes());
        }
        buf
    }
}

impl IntoIterator for TcpOptions {
    type Item = TcpOption;
    type IntoIter = std::vec::IntoIter<TcpOption>;

    fn into_iter(self) -> Self::IntoIter {
        self.options.into_iter()
    }
}

impl<'a> IntoIterator for &'a TcpOptions {
    type Item = &'a TcpOption;
    type IntoIter = std::slice::Iter<'a, TcpOption>;

    fn into_iter(self) -> Self::IntoIter {
        self.options.iter()
    }
}

/// Parse TCP options from bytes.
pub fn parse_options(data: &[u8]) -> Result<TcpOptions, FieldError> {
    let mut options = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let kind = data[offset];

        match kind {
            // End of Option List
            0 => {
                options.push(TcpOption::Eol);
                break;
            },

            // NOP
            1 => {
                options.push(TcpOption::Nop);
                offset += 1;
            },

            // Multi-byte options
            _ => {
                if offset + 1 >= data.len() {
                    return Err(FieldError::InvalidValue(
                        "option length field missing".to_string(),
                    ));
                }

                let length = data[offset + 1] as usize;
                if length < 2 {
                    return Err(FieldError::InvalidValue(format!(
                        "option length {} is less than minimum (2)",
                        length
                    )));
                }

                if offset + length > data.len() {
                    return Err(FieldError::BufferTooShort {
                        offset,
                        need: length,
                        have: data.len() - offset,
                    });
                }

                let opt_data = &data[offset..offset + length];
                let opt = parse_single_option(kind, opt_data)?;
                options.push(opt);

                offset += length;
            },
        }
    }

    Ok(TcpOptions { options })
}

/// Parse a single multi-byte option.
fn parse_single_option(kind: u8, data: &[u8]) -> Result<TcpOption, FieldError> {
    let length = data[1] as usize;
    let value = &data[2..length];

    match kind {
        // MSS
        2 => {
            if length != 4 {
                return Err(FieldError::InvalidValue(format!(
                    "MSS option length {} != 4",
                    length
                )));
            }
            let mss = u16::from_be_bytes([value[0], value[1]]);
            Ok(TcpOption::Mss(mss))
        },

        // Window Scale
        3 => {
            if length != 3 {
                return Err(FieldError::InvalidValue(format!(
                    "WScale option length {} != 3",
                    length
                )));
            }
            Ok(TcpOption::WScale(value[0]))
        },

        // SACK Permitted
        4 => {
            if length != 2 {
                return Err(FieldError::InvalidValue(format!(
                    "SAckOK option length {} != 2",
                    length
                )));
            }
            Ok(TcpOption::SackOk)
        },

        // SACK
        5 => {
            let block_count = value.len() / 8;
            let mut blocks = Vec::with_capacity(block_count);

            for chunk in value.chunks_exact(8) {
                let left = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let right = u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                blocks.push(TcpSackBlock::new(left, right));
            }

            Ok(TcpOption::Sack(blocks))
        },

        // Timestamps
        8 => {
            if length != 10 {
                return Err(FieldError::InvalidValue(format!(
                    "Timestamp option length {} != 10",
                    length
                )));
            }
            let ts_val = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            let ts_ecr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            Ok(TcpOption::Timestamp(TcpTimestamp::new(ts_val, ts_ecr)))
        },

        // Alternate Checksum Request
        14 => {
            if length < 3 {
                return Err(FieldError::InvalidValue(format!(
                    "AltChkSum option length {} < 3",
                    length
                )));
            }
            let algorithm = value[0];
            let checksum = if value.len() >= 3 {
                u16::from_be_bytes([value[1], value[2]])
            } else {
                0
            };
            Ok(TcpOption::AltChkSum {
                algorithm,
                checksum,
            })
        },

        // Alternate Checksum Data
        15 => Ok(TcpOption::AltChkSumOpt),

        // MD5 Signature
        19 => {
            if length != 18 {
                return Err(FieldError::InvalidValue(format!(
                    "MD5 option length {} != 18",
                    length
                )));
            }
            let mut sig = [0u8; 16];
            sig.copy_from_slice(value);
            Ok(TcpOption::Md5(sig))
        },

        // Mood
        25 => {
            let mood = String::from_utf8_lossy(value).to_string();
            Ok(TcpOption::Mood(mood))
        },

        // User Timeout Option
        28 => {
            if length != 4 {
                return Err(FieldError::InvalidValue(format!(
                    "UTO option length {} != 4",
                    length
                )));
            }
            let timeout = u16::from_be_bytes([value[0], value[1]]);
            Ok(TcpOption::Uto(timeout))
        },

        // Authentication Option
        29 => {
            if length < 4 {
                return Err(FieldError::InvalidValue(format!(
                    "AO option length {} < 4",
                    length
                )));
            }
            let key_id = value[0];
            let rnext_key_id = value[1];
            let mac = value[2..].to_vec();
            Ok(TcpOption::Ao(TcpAoValue::new(key_id, rnext_key_id, mac)))
        },

        // TCP Fast Open
        34 => {
            let cookie = if value.is_empty() {
                None
            } else {
                Some(value.to_vec())
            };
            Ok(TcpOption::Tfo { cookie })
        },

        // Unknown option
        _ => Ok(TcpOption::Unknown {
            kind,
            data: value.to_vec(),
        }),
    }
}

/// Builder for TCP options.
#[derive(Debug, Clone, Default)]
pub struct TcpOptionsBuilder {
    options: Vec<TcpOption>,
}

impl TcpOptionsBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a NOP (padding).
    pub fn nop(mut self) -> Self {
        self.options.push(TcpOption::Nop);
        self
    }

    /// Add an End of Option List marker.
    pub fn eol(mut self) -> Self {
        self.options.push(TcpOption::Eol);
        self
    }

    /// Add an MSS option.
    pub fn mss(mut self, mss: u16) -> Self {
        self.options.push(TcpOption::Mss(mss));
        self
    }

    /// Add a Window Scale option.
    pub fn wscale(mut self, scale: u8) -> Self {
        self.options.push(TcpOption::WScale(scale));
        self
    }

    /// Add SACK Permitted option.
    pub fn sack_ok(mut self) -> Self {
        self.options.push(TcpOption::SackOk);
        self
    }

    /// Add a SACK option.
    pub fn sack(mut self, blocks: Vec<TcpSackBlock>) -> Self {
        self.options.push(TcpOption::Sack(blocks));
        self
    }

    /// Add a Timestamp option.
    pub fn timestamp(mut self, ts_val: u32, ts_ecr: u32) -> Self {
        self.options
            .push(TcpOption::Timestamp(TcpTimestamp::new(ts_val, ts_ecr)));
        self
    }

    /// Add a TFO (TCP Fast Open) option with cookie.
    pub fn tfo(mut self, cookie: Option<Vec<u8>>) -> Self {
        self.options.push(TcpOption::Tfo { cookie });
        self
    }

    /// Add an Authentication Option.
    pub fn ao(mut self, key_id: u8, rnext_key_id: u8, mac: Vec<u8>) -> Self {
        self.options
            .push(TcpOption::Ao(TcpAoValue::new(key_id, rnext_key_id, mac)));
        self
    }

    /// Add an MD5 signature option.
    pub fn md5(mut self, signature: [u8; 16]) -> Self {
        self.options.push(TcpOption::Md5(signature));
        self
    }

    /// Add a custom option.
    pub fn option(mut self, option: TcpOption) -> Self {
        self.options.push(option);
        self
    }

    /// Build the options.
    pub fn build(self) -> TcpOptions {
        TcpOptions {
            options: self.options,
        }
    }
}

/// Get the TCP-AO (Authentication Option) from a parsed options list.
pub fn get_tcp_ao(options: &TcpOptions) -> Option<&TcpAoValue> {
    options.ao()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nop_eol() {
        let data = [1, 1, 1, 0]; // 3 NOPs + EOL
        let opts = parse_options(&data).unwrap();

        assert_eq!(opts.len(), 4);
        assert!(matches!(opts.options[0], TcpOption::Nop));
        assert!(matches!(opts.options[1], TcpOption::Nop));
        assert!(matches!(opts.options[2], TcpOption::Nop));
        assert!(matches!(opts.options[3], TcpOption::Eol));
    }

    #[test]
    fn test_parse_mss() {
        let data = [
            2, 4, // MSS option, length 4
            0x05, 0xB4, // MSS = 1460
        ];

        let opts = parse_options(&data).unwrap();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts.mss(), Some(1460));
    }

    #[test]
    fn test_parse_wscale() {
        let data = [
            3, 3, // WScale option, length 3
            7, // scale = 7
        ];

        let opts = parse_options(&data).unwrap();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts.wscale(), Some(7));
    }

    #[test]
    fn test_parse_timestamp() {
        let data = [
            8, 10, // Timestamp option, length 10
            0x00, 0x00, 0x10, 0x00, // ts_val
            0x00, 0x00, 0x20, 0x00, // ts_ecr
        ];

        let opts = parse_options(&data).unwrap();
        assert_eq!(opts.len(), 1);

        let ts = opts.timestamp().unwrap();
        assert_eq!(ts.ts_val, 0x1000);
        assert_eq!(ts.ts_ecr, 0x2000);
    }

    #[test]
    fn test_parse_sack() {
        let data = [
            5, 18, // SACK option, length 18 (2 blocks)
            0x00, 0x00, 0x10, 0x00, // left1
            0x00, 0x00, 0x20, 0x00, // right1
            0x00, 0x00, 0x30, 0x00, // left2
            0x00, 0x00, 0x40, 0x00, // right2
        ];

        let opts = parse_options(&data).unwrap();
        assert_eq!(opts.len(), 1);

        let blocks = opts.sack_blocks().unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].left, 0x1000);
        assert_eq!(blocks[0].right, 0x2000);
        assert_eq!(blocks[1].left, 0x3000);
        assert_eq!(blocks[1].right, 0x4000);
    }

    #[test]
    fn test_parse_sack_ok() {
        let data = [4, 2]; // SACK Permitted

        let opts = parse_options(&data).unwrap();
        assert_eq!(opts.len(), 1);
        assert!(opts.sack_permitted());
    }

    #[test]
    fn test_parse_ao() {
        let data = [
            29, 6, // AO option, length 6
            1, // key_id
            2, // rnext_key_id
            0xAB, 0xCD, // MAC (2 bytes)
        ];

        let opts = parse_options(&data).unwrap();
        assert_eq!(opts.len(), 1);

        let ao = opts.ao().unwrap();
        assert_eq!(ao.key_id, 1);
        assert_eq!(ao.rnext_key_id, 2);
        assert_eq!(ao.mac, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_serialize_options() {
        let opts = TcpOptionsBuilder::new()
            .mss(1460)
            .wscale(7)
            .sack_ok()
            .timestamp(1000, 2000)
            .build();

        let bytes = opts.to_bytes();

        // Should be padded to 4-byte boundary
        assert_eq!(bytes.len() % 4, 0);

        // Parse back
        let parsed = parse_options(&bytes).unwrap();
        assert_eq!(parsed.mss(), Some(1460));
        assert_eq!(parsed.wscale(), Some(7));
        assert!(parsed.sack_permitted());

        let ts = parsed.timestamp().unwrap();
        assert_eq!(ts.ts_val, 1000);
        assert_eq!(ts.ts_ecr, 2000);
    }

    #[test]
    fn test_option_kind_properties() {
        assert!(TcpOptionKind::Eol.is_single_byte());
        assert!(TcpOptionKind::Nop.is_single_byte());
        assert!(!TcpOptionKind::Mss.is_single_byte());

        assert_eq!(TcpOptionKind::Mss.expected_len(), Some(4));
        assert_eq!(TcpOptionKind::Timestamp.expected_len(), Some(10));
        assert_eq!(TcpOptionKind::Sack.expected_len(), None);
    }

    #[test]
    fn test_typical_syn_options() {
        // Typical SYN packet options: MSS, SACK Permitted, Timestamp, NOP, Window Scale
        let opts = TcpOptionsBuilder::new()
            .mss(1460)
            .sack_ok()
            .timestamp(12345, 0)
            .nop()
            .wscale(7)
            .build();

        let bytes = opts.to_bytes();

        // Parse back and verify
        let parsed = parse_options(&bytes).unwrap();
        assert_eq!(parsed.mss(), Some(1460));
        assert!(parsed.sack_permitted());
        assert_eq!(parsed.wscale(), Some(7));

        let ts = parsed.timestamp().unwrap();
        assert_eq!(ts.ts_val, 12345);
        assert_eq!(ts.ts_ecr, 0);
    }

    #[test]
    fn test_tfo_option() {
        let cookie = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let opts = TcpOptionsBuilder::new().tfo(Some(cookie.clone())).build();

        let bytes = opts.to_bytes();
        let parsed = parse_options(&bytes).unwrap();

        assert_eq!(parsed.tfo_cookie(), Some(cookie.as_slice()));
    }

    #[test]
    fn test_md5_option() {
        let sig = [1u8; 16];
        let opts = TcpOptionsBuilder::new().md5(sig).build();

        let bytes = opts.to_bytes();
        let parsed = parse_options(&bytes).unwrap();

        if let Some(TcpOption::Md5(parsed_sig)) = parsed.get(TcpOptionKind::Md5) {
            assert_eq!(*parsed_sig, sig);
        } else {
            panic!("Expected MD5 option");
        }
    }
}
