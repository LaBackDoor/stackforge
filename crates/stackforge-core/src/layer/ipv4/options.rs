//! IPv4 options parsing and building.
//!
//! IP options follow the header and are variable-length.
//! Maximum options length is 40 bytes (60 byte header - 20 byte minimum).

use std::net::Ipv4Addr;

use crate::layer::field::FieldError;

/// Maximum length of IP options (in bytes).
pub const MAX_OPTIONS_LEN: usize = 40;

/// IP option class (bits 6-7 of option type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ipv4OptionClass {
    /// Control options
    Control = 0,
    /// Reserved (1)
    Reserved1 = 1,
    /// Debugging and measurement
    DebuggingMeasurement = 2,
    /// Reserved (3)
    Reserved3 = 3,
}

impl Ipv4OptionClass {
    #[inline]
    pub fn from_type(opt_type: u8) -> Self {
        match (opt_type >> 5) & 0x03 {
            0 => Self::Control,
            1 => Self::Reserved1,
            2 => Self::DebuggingMeasurement,
            3 => Self::Reserved3,
            _ => unreachable!(),
        }
    }
}

/// Well-known IP option types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ipv4OptionType {
    /// End of Option List
    EndOfList = 0,
    /// No Operation (padding)
    Nop = 1,
    /// Security (RFC 1108)
    Security = 130,
    /// Loose Source and Record Route
    Lsrr = 131,
    /// Internet Timestamp
    Timestamp = 68,
    /// Extended Security (RFC 1108)
    ExtendedSecurity = 133,
    /// Commercial Security
    CommercialSecurity = 134,
    /// Record Route
    RecordRoute = 7,
    /// Stream ID
    StreamId = 136,
    /// Strict Source and Record Route
    Ssrr = 137,
    /// Experimental Measurement
    ExperimentalMeasurement = 10,
    /// MTU Probe
    MtuProbe = 11,
    /// MTU Reply
    MtuReply = 12,
    /// Traceroute
    Traceroute = 82,
    /// Address Extension
    AddressExtension = 147,
    /// Router Alert
    RouterAlert = 148,
    /// Selective Directed Broadcast
    SelectiveDirectedBroadcast = 149,
    /// Unknown option
    Unknown(u8),
}

impl Ipv4OptionType {
    /// Create from raw option type byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::EndOfList,
            1 => Self::Nop,
            7 => Self::RecordRoute,
            10 => Self::ExperimentalMeasurement,
            11 => Self::MtuProbe,
            12 => Self::MtuReply,
            68 => Self::Timestamp,
            82 => Self::Traceroute,
            130 => Self::Security,
            131 => Self::Lsrr,
            133 => Self::ExtendedSecurity,
            134 => Self::CommercialSecurity,
            136 => Self::StreamId,
            137 => Self::Ssrr,
            147 => Self::AddressExtension,
            148 => Self::RouterAlert,
            149 => Self::SelectiveDirectedBroadcast,
            x => Self::Unknown(x),
        }
    }

    /// Convert to raw option type byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::EndOfList => 0,
            Self::Nop => 1,
            Self::RecordRoute => 7,
            Self::ExperimentalMeasurement => 10,
            Self::MtuProbe => 11,
            Self::MtuReply => 12,
            Self::Timestamp => 68,
            Self::Traceroute => 82,
            Self::Security => 130,
            Self::Lsrr => 131,
            Self::ExtendedSecurity => 133,
            Self::CommercialSecurity => 134,
            Self::StreamId => 136,
            Self::Ssrr => 137,
            Self::AddressExtension => 147,
            Self::RouterAlert => 148,
            Self::SelectiveDirectedBroadcast => 149,
            Self::Unknown(x) => x,
        }
    }

    /// Get the name of the option.
    pub fn name(&self) -> &'static str {
        match self {
            Self::EndOfList => "EOL",
            Self::Nop => "NOP",
            Self::Security => "Security",
            Self::Lsrr => "LSRR",
            Self::Timestamp => "Timestamp",
            Self::ExtendedSecurity => "Extended Security",
            Self::CommercialSecurity => "Commercial Security",
            Self::RecordRoute => "Record Route",
            Self::StreamId => "Stream ID",
            Self::Ssrr => "SSRR",
            Self::ExperimentalMeasurement => "Experimental Measurement",
            Self::MtuProbe => "MTU Probe",
            Self::MtuReply => "MTU Reply",
            Self::Traceroute => "Traceroute",
            Self::AddressExtension => "Address Extension",
            Self::RouterAlert => "Router Alert",
            Self::SelectiveDirectedBroadcast => "Selective Directed Broadcast",
            Self::Unknown(_) => "Unknown",
        }
    }

    /// Check if this option should be copied on fragmentation.
    #[inline]
    pub fn is_copied(&self) -> bool {
        (self.to_byte() & 0x80) != 0
    }

    /// Check if this is a single-byte option (no length/value).
    #[inline]
    pub fn is_single_byte(&self) -> bool {
        matches!(self, Self::EndOfList | Self::Nop)
    }
}

impl std::fmt::Display for Ipv4OptionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(x) => write!(f, "Unknown({})", x),
            _ => write!(f, "{}", self.name()),
        }
    }
}

/// A parsed IP option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4Option {
    /// End of Option List (type 0)
    EndOfList,

    /// No Operation / Padding (type 1)
    Nop,

    /// Record Route (type 7)
    RecordRoute { pointer: u8, route: Vec<Ipv4Addr> },

    /// Loose Source and Record Route (type 131)
    Lsrr { pointer: u8, route: Vec<Ipv4Addr> },

    /// Strict Source and Record Route (type 137)
    Ssrr { pointer: u8, route: Vec<Ipv4Addr> },

    /// Internet Timestamp (type 68)
    Timestamp {
        pointer: u8,
        overflow: u8,
        flag: u8,
        data: Vec<(Option<Ipv4Addr>, u32)>,
    },

    /// Security (type 130)
    Security {
        security: u16,
        compartment: u16,
        handling_restrictions: u16,
        transmission_control_code: [u8; 3],
    },

    /// Stream ID (type 136)
    StreamId { id: u16 },

    /// MTU Probe (type 11)
    MtuProbe { mtu: u16 },

    /// MTU Reply (type 12)
    MtuReply { mtu: u16 },

    /// Traceroute (type 82)
    Traceroute {
        id: u16,
        outbound_hops: u16,
        return_hops: u16,
        originator: Ipv4Addr,
    },

    /// Router Alert (type 148)
    RouterAlert { value: u16 },

    /// Address Extension (type 147)
    AddressExtension {
        src_ext: Ipv4Addr,
        dst_ext: Ipv4Addr,
    },

    /// Unknown or unimplemented option
    Unknown { option_type: u8, data: Vec<u8> },
}

impl Ipv4Option {
    /// Get the option type.
    pub fn option_type(&self) -> Ipv4OptionType {
        match self {
            Self::EndOfList => Ipv4OptionType::EndOfList,
            Self::Nop => Ipv4OptionType::Nop,
            Self::RecordRoute { .. } => Ipv4OptionType::RecordRoute,
            Self::Lsrr { .. } => Ipv4OptionType::Lsrr,
            Self::Ssrr { .. } => Ipv4OptionType::Ssrr,
            Self::Timestamp { .. } => Ipv4OptionType::Timestamp,
            Self::Security { .. } => Ipv4OptionType::Security,
            Self::StreamId { .. } => Ipv4OptionType::StreamId,
            Self::MtuProbe { .. } => Ipv4OptionType::MtuProbe,
            Self::MtuReply { .. } => Ipv4OptionType::MtuReply,
            Self::Traceroute { .. } => Ipv4OptionType::Traceroute,
            Self::RouterAlert { .. } => Ipv4OptionType::RouterAlert,
            Self::AddressExtension { .. } => Ipv4OptionType::AddressExtension,
            Self::Unknown { option_type, .. } => Ipv4OptionType::Unknown(*option_type),
        }
    }

    /// Get the serialized length of this option.
    pub fn len(&self) -> usize {
        match self {
            Self::EndOfList => 1,
            Self::Nop => 1,
            Self::RecordRoute { route, .. }
            | Self::Lsrr { route, .. }
            | Self::Ssrr { route, .. } => 3 + route.len() * 4,
            Self::Timestamp { data, flag, .. } => 4 + data.len() * if *flag == 0 { 4 } else { 8 },
            Self::Security { .. } => 11,
            Self::StreamId { .. } => 4,
            Self::MtuProbe { .. } | Self::MtuReply { .. } => 4,
            Self::Traceroute { .. } => 12,
            Self::RouterAlert { .. } => 4,
            Self::AddressExtension { .. } => 10,
            Self::Unknown { data, .. } => 2 + data.len(),
        }
    }

    /// Check if the option is empty (for variants with data).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Serialize the option to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::EndOfList => vec![0],
            Self::Nop => vec![1],

            Self::RecordRoute { pointer, route } => {
                let mut buf = vec![7, (3 + route.len() * 4) as u8, *pointer];
                for ip in route {
                    buf.extend_from_slice(&ip.octets());
                }
                buf
            },

            Self::Lsrr { pointer, route } => {
                let mut buf = vec![131, (3 + route.len() * 4) as u8, *pointer];
                for ip in route {
                    buf.extend_from_slice(&ip.octets());
                }
                buf
            },

            Self::Ssrr { pointer, route } => {
                let mut buf = vec![137, (3 + route.len() * 4) as u8, *pointer];
                for ip in route {
                    buf.extend_from_slice(&ip.octets());
                }
                buf
            },

            Self::Timestamp {
                pointer,
                overflow,
                flag,
                data,
            } => {
                let entry_size = if *flag == 0 { 4 } else { 8 };
                let mut buf = vec![
                    68,
                    (4 + data.len() * entry_size) as u8,
                    *pointer,
                    (*overflow << 4) | (*flag & 0x0F),
                ];
                for (ip, ts) in data {
                    if let Some(addr) = ip {
                        buf.extend_from_slice(&addr.octets());
                    }
                    buf.extend_from_slice(&ts.to_be_bytes());
                }
                buf
            },

            Self::Security {
                security,
                compartment,
                handling_restrictions,
                transmission_control_code,
            } => {
                let mut buf = vec![130, 11];
                buf.extend_from_slice(&security.to_be_bytes());
                buf.extend_from_slice(&compartment.to_be_bytes());
                buf.extend_from_slice(&handling_restrictions.to_be_bytes());
                buf.extend_from_slice(transmission_control_code);
                buf
            },

            Self::StreamId { id } => {
                let mut buf = vec![136, 4];
                buf.extend_from_slice(&id.to_be_bytes());
                buf
            },

            Self::MtuProbe { mtu } => {
                let mut buf = vec![11, 4];
                buf.extend_from_slice(&mtu.to_be_bytes());
                buf
            },

            Self::MtuReply { mtu } => {
                let mut buf = vec![12, 4];
                buf.extend_from_slice(&mtu.to_be_bytes());
                buf
            },

            Self::Traceroute {
                id,
                outbound_hops,
                return_hops,
                originator,
            } => {
                let mut buf = vec![82, 12];
                buf.extend_from_slice(&id.to_be_bytes());
                buf.extend_from_slice(&outbound_hops.to_be_bytes());
                buf.extend_from_slice(&return_hops.to_be_bytes());
                buf.extend_from_slice(&originator.octets());
                buf
            },

            Self::RouterAlert { value } => {
                let mut buf = vec![148, 4];
                buf.extend_from_slice(&value.to_be_bytes());
                buf
            },

            Self::AddressExtension { src_ext, dst_ext } => {
                let mut buf = vec![147, 10];
                buf.extend_from_slice(&src_ext.octets());
                buf.extend_from_slice(&dst_ext.octets());
                buf
            },

            Self::Unknown { option_type, data } => {
                let mut buf = vec![*option_type, (2 + data.len()) as u8];
                buf.extend_from_slice(data);
                buf
            },
        }
    }
}

/// Collection of IP options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ipv4Options {
    pub options: Vec<Ipv4Option>,
}

impl Ipv4Options {
    /// Create empty options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from a list of options.
    pub fn from_vec(options: Vec<Ipv4Option>) -> Self {
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
    pub fn push(&mut self, option: Ipv4Option) {
        self.options.push(option);
    }

    /// Get source route options (LSRR or SSRR).
    pub fn source_route(&self) -> Option<&Ipv4Option> {
        self.options
            .iter()
            .find(|o| matches!(o, Ipv4Option::Lsrr { .. } | Ipv4Option::Ssrr { .. }))
    }

    /// Get the final destination from source route options.
    pub fn final_destination(&self) -> Option<Ipv4Addr> {
        self.source_route().and_then(|opt| match opt {
            Ipv4Option::Lsrr { route, .. } | Ipv4Option::Ssrr { route, .. } => {
                route.last().copied()
            },
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

    /// Filter options that should be copied on fragmentation.
    pub fn copied_options(&self) -> Self {
        Self {
            options: self
                .options
                .iter()
                .filter(|o| o.option_type().is_copied())
                .cloned()
                .collect(),
        }
    }
}

impl IntoIterator for Ipv4Options {
    type Item = Ipv4Option;
    type IntoIter = std::vec::IntoIter<Ipv4Option>;

    fn into_iter(self) -> Self::IntoIter {
        self.options.into_iter()
    }
}

impl<'a> IntoIterator for &'a Ipv4Options {
    type Item = &'a Ipv4Option;
    type IntoIter = std::slice::Iter<'a, Ipv4Option>;

    fn into_iter(self) -> Self::IntoIter {
        self.options.iter()
    }
}

/// Parse IP options from bytes.
pub fn parse_options(data: &[u8]) -> Result<Ipv4Options, FieldError> {
    let mut options = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let opt_type = data[offset];

        match opt_type {
            // End of Option List
            0 => {
                options.push(Ipv4Option::EndOfList);
                break;
            },

            // NOP
            1 => {
                options.push(Ipv4Option::Nop);
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
                let opt = parse_single_option(opt_type, opt_data)?;
                options.push(opt);

                offset += length;
            },
        }
    }

    Ok(Ipv4Options { options })
}

/// Parse a single multi-byte option.
fn parse_single_option(opt_type: u8, data: &[u8]) -> Result<Ipv4Option, FieldError> {
    let length = data[1] as usize;

    match opt_type {
        // Record Route
        7 => {
            if length < 3 {
                return Err(FieldError::InvalidValue(
                    "Record Route option too short".to_string(),
                ));
            }
            let pointer = data[2];
            let route = parse_ip_list(&data[3..length]);
            Ok(Ipv4Option::RecordRoute { pointer, route })
        },

        // LSRR
        131 => {
            if length < 3 {
                return Err(FieldError::InvalidValue(
                    "LSRR option too short".to_string(),
                ));
            }
            let pointer = data[2];
            let route = parse_ip_list(&data[3..length]);
            Ok(Ipv4Option::Lsrr { pointer, route })
        },

        // SSRR
        137 => {
            if length < 3 {
                return Err(FieldError::InvalidValue(
                    "SSRR option too short".to_string(),
                ));
            }
            let pointer = data[2];
            let route = parse_ip_list(&data[3..length]);
            Ok(Ipv4Option::Ssrr { pointer, route })
        },

        // Timestamp
        68 => {
            if length < 4 {
                return Err(FieldError::InvalidValue(
                    "Timestamp option too short".to_string(),
                ));
            }
            let pointer = data[2];
            let oflw_flag = data[3];
            let overflow = oflw_flag >> 4;
            let flag = oflw_flag & 0x0F;

            let timestamps = parse_timestamps(&data[4..length], flag)?;
            Ok(Ipv4Option::Timestamp {
                pointer,
                overflow,
                flag,
                data: timestamps,
            })
        },

        // Security
        130 => {
            if length != 11 {
                return Err(FieldError::InvalidValue(format!(
                    "Security option length {} != 11",
                    length
                )));
            }
            let security = u16::from_be_bytes([data[2], data[3]]);
            let compartment = u16::from_be_bytes([data[4], data[5]]);
            let handling_restrictions = u16::from_be_bytes([data[6], data[7]]);
            let mut tcc = [0u8; 3];
            tcc.copy_from_slice(&data[8..11]);

            Ok(Ipv4Option::Security {
                security,
                compartment,
                handling_restrictions,
                transmission_control_code: tcc,
            })
        },

        // Stream ID
        136 => {
            if length != 4 {
                return Err(FieldError::InvalidValue(format!(
                    "Stream ID option length {} != 4",
                    length
                )));
            }
            let id = u16::from_be_bytes([data[2], data[3]]);
            Ok(Ipv4Option::StreamId { id })
        },

        // MTU Probe
        11 => {
            if length != 4 {
                return Err(FieldError::InvalidValue(format!(
                    "MTU Probe option length {} != 4",
                    length
                )));
            }
            let mtu = u16::from_be_bytes([data[2], data[3]]);
            Ok(Ipv4Option::MtuProbe { mtu })
        },

        // MTU Reply
        12 => {
            if length != 4 {
                return Err(FieldError::InvalidValue(format!(
                    "MTU Reply option length {} != 4",
                    length
                )));
            }
            let mtu = u16::from_be_bytes([data[2], data[3]]);
            Ok(Ipv4Option::MtuReply { mtu })
        },

        // Traceroute
        82 => {
            if length != 12 {
                return Err(FieldError::InvalidValue(format!(
                    "Traceroute option length {} != 12",
                    length
                )));
            }
            let id = u16::from_be_bytes([data[2], data[3]]);
            let outbound_hops = u16::from_be_bytes([data[4], data[5]]);
            let return_hops = u16::from_be_bytes([data[6], data[7]]);
            let originator = Ipv4Addr::new(data[8], data[9], data[10], data[11]);

            Ok(Ipv4Option::Traceroute {
                id,
                outbound_hops,
                return_hops,
                originator,
            })
        },

        // Router Alert
        148 => {
            if length != 4 {
                return Err(FieldError::InvalidValue(format!(
                    "Router Alert option length {} != 4",
                    length
                )));
            }
            let value = u16::from_be_bytes([data[2], data[3]]);
            Ok(Ipv4Option::RouterAlert { value })
        },

        // Address Extension
        147 => {
            if length != 10 {
                return Err(FieldError::InvalidValue(format!(
                    "Address Extension option length {} != 10",
                    length
                )));
            }
            let src_ext = Ipv4Addr::new(data[2], data[3], data[4], data[5]);
            let dst_ext = Ipv4Addr::new(data[6], data[7], data[8], data[9]);
            Ok(Ipv4Option::AddressExtension { src_ext, dst_ext })
        },

        // Unknown option
        _ => Ok(Ipv4Option::Unknown {
            option_type: opt_type,
            data: data[2..length].to_vec(),
        }),
    }
}

/// Parse a list of IP addresses from option data.
fn parse_ip_list(data: &[u8]) -> Vec<Ipv4Addr> {
    data.chunks_exact(4)
        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
        .collect()
}

/// Parse timestamp data based on flag.
fn parse_timestamps(data: &[u8], flag: u8) -> Result<Vec<(Option<Ipv4Addr>, u32)>, FieldError> {
    match flag {
        // Timestamps only
        0 => {
            let timestamps: Vec<_> = data
                .chunks_exact(4)
                .map(|c| {
                    let ts = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
                    (None, ts)
                })
                .collect();
            Ok(timestamps)
        },

        // IP + Timestamp pairs
        1 | 3 => {
            if data.len() % 8 != 0 {
                return Err(FieldError::InvalidValue(
                    "Timestamp data not aligned to 8 bytes".to_string(),
                ));
            }
            let timestamps: Vec<_> = data
                .chunks_exact(8)
                .map(|c| {
                    let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
                    let ts = u32::from_be_bytes([c[4], c[5], c[6], c[7]]);
                    (Some(ip), ts)
                })
                .collect();
            Ok(timestamps)
        },

        _ => Err(FieldError::InvalidValue(format!(
            "Unknown timestamp flag: {}",
            flag
        ))),
    }
}

/// Builder for IP options.
#[derive(Debug, Clone, Default)]
pub struct Ipv4OptionsBuilder {
    options: Vec<Ipv4Option>,
}

impl Ipv4OptionsBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an End of Option List marker.
    pub fn eol(mut self) -> Self {
        self.options.push(Ipv4Option::EndOfList);
        self
    }

    /// Add a NOP (padding).
    pub fn nop(mut self) -> Self {
        self.options.push(Ipv4Option::Nop);
        self
    }

    /// Add a Record Route option.
    pub fn record_route(mut self, route: Vec<Ipv4Addr>) -> Self {
        self.options.push(Ipv4Option::RecordRoute {
            pointer: 4, // First slot
            route,
        });
        self
    }

    /// Add a Loose Source Route option.
    pub fn lsrr(mut self, route: Vec<Ipv4Addr>) -> Self {
        self.options.push(Ipv4Option::Lsrr { pointer: 4, route });
        self
    }

    /// Add a Strict Source Route option.
    pub fn ssrr(mut self, route: Vec<Ipv4Addr>) -> Self {
        self.options.push(Ipv4Option::Ssrr { pointer: 4, route });
        self
    }

    /// Add a Timestamp option (timestamps only).
    pub fn timestamp(mut self) -> Self {
        self.options.push(Ipv4Option::Timestamp {
            pointer: 5,
            overflow: 0,
            flag: 0,
            data: vec![],
        });
        self
    }

    /// Add a Timestamp option with IP addresses.
    pub fn timestamp_with_addresses(mut self, prespecified: bool) -> Self {
        self.options.push(Ipv4Option::Timestamp {
            pointer: 9,
            overflow: 0,
            flag: if prespecified { 3 } else { 1 },
            data: vec![],
        });
        self
    }

    /// Add a Router Alert option.
    pub fn router_alert(mut self, value: u16) -> Self {
        self.options.push(Ipv4Option::RouterAlert { value });
        self
    }

    /// Add a custom option.
    pub fn option(mut self, option: Ipv4Option) -> Self {
        self.options.push(option);
        self
    }

    /// Build the options.
    pub fn build(self) -> Ipv4Options {
        Ipv4Options {
            options: self.options,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nop_eol() {
        let data = [1, 1, 1, 0]; // 3 NOPs + EOL
        let opts = parse_options(&data).unwrap();

        assert_eq!(opts.len(), 4);
        assert!(matches!(opts.options[0], Ipv4Option::Nop));
        assert!(matches!(opts.options[1], Ipv4Option::Nop));
        assert!(matches!(opts.options[2], Ipv4Option::Nop));
        assert!(matches!(opts.options[3], Ipv4Option::EndOfList));
    }

    #[test]
    fn test_parse_record_route() {
        let data = [
            7,  // Type: Record Route
            11, // Length: 11 bytes
            4,  // Pointer: first slot
            192, 168, 1, 1, // First IP
            192, 168, 1, 2, // Second IP
        ];

        let opts = parse_options(&data).unwrap();
        assert_eq!(opts.len(), 1);

        if let Ipv4Option::RecordRoute { pointer, route } = &opts.options[0] {
            assert_eq!(*pointer, 4);
            assert_eq!(route.len(), 2);
            assert_eq!(route[0], Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(route[1], Ipv4Addr::new(192, 168, 1, 2));
        } else {
            panic!("Expected RecordRoute option");
        }
    }

    #[test]
    fn test_parse_timestamp() {
        let data = [
            68,   // Type: Timestamp
            12,   // Length: 12 bytes
            5,    // Pointer
            0x01, // Overflow=0, Flag=1 (IP + timestamp)
            192, 168, 1, 1, // IP
            0x00, 0x00, 0x10, 0x00, // Timestamp
        ];

        let opts = parse_options(&data).unwrap();
        assert_eq!(opts.len(), 1);

        if let Ipv4Option::Timestamp {
            pointer,
            overflow,
            flag,
            data: ts_data,
        } = &opts.options[0]
        {
            assert_eq!(*pointer, 5);
            assert_eq!(*overflow, 0);
            assert_eq!(*flag, 1);

            assert_eq!(ts_data.len(), 1);
            assert_eq!(ts_data[0].0, Some(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(ts_data[0].1, 0x1000);
        }
    }

    #[test]
    fn test_parse_router_alert() {
        let data = [
            148,  // Type: Router Alert
            4,    // Length
            0x00, // Value high
            0x00, // Value low
        ];

        let opts = parse_options(&data).unwrap();
        assert_eq!(opts.len(), 1);

        if let Ipv4Option::RouterAlert { value } = opts.options[0] {
            assert_eq!(value, 0);
        } else {
            panic!("Expected RouterAlert option");
        }
    }

    #[test]
    fn test_serialize_options() {
        let opts = Ipv4OptionsBuilder::new()
            .nop()
            .router_alert(0)
            .nop()
            .build();

        let bytes = opts.to_bytes();

        // Should be padded to 4-byte boundary
        assert_eq!(bytes.len() % 4, 0);

        // Parse back
        let parsed = parse_options(&bytes).unwrap();
        assert!(matches!(parsed.options[0], Ipv4Option::Nop));
        assert!(matches!(
            parsed.options[1],
            Ipv4Option::RouterAlert { value: 0 }
        ));
    }

    #[test]
    fn test_option_type_properties() {
        // LSRR should be copied
        assert!(Ipv4OptionType::Lsrr.is_copied());
        // Record Route should not be copied
        assert!(!Ipv4OptionType::RecordRoute.is_copied());
        // NOP is single byte
        assert!(Ipv4OptionType::Nop.is_single_byte());
        // Timestamp is not single byte
        assert!(!Ipv4OptionType::Timestamp.is_single_byte());
    }

    #[test]
    fn test_final_destination() {
        let opts = Ipv4OptionsBuilder::new()
            .lsrr(vec![
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
            ])
            .build();

        assert_eq!(opts.final_destination(), Some(Ipv4Addr::new(10, 0, 0, 3)));
    }

    #[test]
    fn test_copied_options() {
        let opts = Ipv4OptionsBuilder::new()
            .record_route(vec![]) // Not copied
            .lsrr(vec![Ipv4Addr::new(10, 0, 0, 1)]) // Copied
            .nop() // Not copied
            .build();

        let copied = opts.copied_options();
        assert_eq!(copied.len(), 1);
        assert!(matches!(copied.options[0], Ipv4Option::Lsrr { .. }));
    }
}
