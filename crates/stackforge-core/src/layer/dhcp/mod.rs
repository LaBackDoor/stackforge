pub mod builder;
pub mod options;

use std::net::Ipv4Addr;

use crate::layer::field::{FieldError, FieldValue, MacAddress};
use crate::layer::{Layer, LayerIndex, LayerKind};

use self::options::{DhcpOption, code, parse_options};

pub use builder::DhcpBuilder;

/// DHCP magic cookie bytes.
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Minimum DHCP packet size: 240 (BOOTP header) + 4 (magic cookie) + 3 (minimum option).
pub const DHCP_MIN_HEADER_LEN: usize = 240;

/// DHCP uses UDP ports 67 (server) and 68 (client).
pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;

/// Field names for Python field access.
pub const DHCP_FIELD_NAMES: &[&str] = &[
    "op", "htype", "hlen", "hops", "xid", "secs", "flags",
    "ciaddr", "yiaddr", "siaddr", "giaddr", "chaddr",
    "msg_type", "server_id", "requested_ip", "lease_time",
    "subnet_mask", "router", "dns",
];

fn short(need: usize, have: usize) -> FieldError {
    FieldError::BufferTooShort {
        offset: 0,
        need,
        have,
    }
}

/// DHCP layer — a zero-copy view into a parsed DHCP packet.
#[derive(Debug, Clone)]
pub struct DhcpLayer {
    pub index: LayerIndex,
}

impl DhcpLayer {
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    fn data<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.index.start..self.index.end]
    }

    fn check<'a>(&self, buf: &'a [u8], need: usize) -> Result<&'a [u8], FieldError> {
        let d = self.data(buf);
        if d.len() < need {
            Err(short(need, d.len()))
        } else {
            Ok(d)
        }
    }

    /// BOOTP op code: 1 = request, 2 = reply.
    pub fn op(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok(self.check(buf, 1)?[0])
    }

    /// Hardware type (1 = Ethernet).
    pub fn htype(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok(self.check(buf, 2)?[1])
    }

    /// Hardware address length.
    pub fn hlen(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok(self.check(buf, 3)?[2])
    }

    /// Hops.
    pub fn hops(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok(self.check(buf, 4)?[3])
    }

    /// Transaction ID.
    pub fn xid(&self, buf: &[u8]) -> Result<u32, FieldError> {
        let d = self.check(buf, 8)?;
        Ok(u32::from_be_bytes([d[4], d[5], d[6], d[7]]))
    }

    /// Seconds elapsed.
    pub fn secs(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let d = self.check(buf, 10)?;
        Ok(u16::from_be_bytes([d[8], d[9]]))
    }

    /// Flags.
    pub fn flags(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let d = self.check(buf, 12)?;
        Ok(u16::from_be_bytes([d[10], d[11]]))
    }

    /// Client IP address.
    pub fn ciaddr(&self, buf: &[u8]) -> Result<Ipv4Addr, FieldError> {
        let d = self.check(buf, 16)?;
        Ok(Ipv4Addr::new(d[12], d[13], d[14], d[15]))
    }

    /// Your (client) IP address.
    pub fn yiaddr(&self, buf: &[u8]) -> Result<Ipv4Addr, FieldError> {
        let d = self.check(buf, 20)?;
        Ok(Ipv4Addr::new(d[16], d[17], d[18], d[19]))
    }

    /// Server IP address.
    pub fn siaddr(&self, buf: &[u8]) -> Result<Ipv4Addr, FieldError> {
        let d = self.check(buf, 24)?;
        Ok(Ipv4Addr::new(d[20], d[21], d[22], d[23]))
    }

    /// Gateway IP address.
    pub fn giaddr(&self, buf: &[u8]) -> Result<Ipv4Addr, FieldError> {
        let d = self.check(buf, 28)?;
        Ok(Ipv4Addr::new(d[24], d[25], d[26], d[27]))
    }

    /// Client hardware address (first 6 bytes for Ethernet).
    pub fn chaddr(&self, buf: &[u8]) -> Result<[u8; 6], FieldError> {
        let d = self.check(buf, 34)?;
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&d[28..34]);
        Ok(mac)
    }

    /// Parse all DHCP options.
    pub fn options(&self, buf: &[u8]) -> Vec<DhcpOption> {
        let d = self.data(buf);
        if d.len() < 240 {
            return Vec::new();
        }
        if d[236..240] != MAGIC_COOKIE {
            return Vec::new();
        }
        parse_options(&d[240..])
    }

    /// Get a specific option by code.
    pub fn get_option(&self, buf: &[u8], opt_code: u8) -> Option<DhcpOption> {
        self.options(buf).into_iter().find(|o| o.code == opt_code)
    }

    /// Get the DHCP message type.
    pub fn msg_type(&self, buf: &[u8]) -> Option<u8> {
        self.get_option(buf, code::MESSAGE_TYPE)
            .and_then(|o| o.as_message_type())
    }

    /// Get the server identifier.
    pub fn server_id(&self, buf: &[u8]) -> Option<Ipv4Addr> {
        self.get_option(buf, code::SERVER_ID)
            .and_then(|o| o.as_ipv4())
    }

    /// Get the requested IP address.
    pub fn requested_ip(&self, buf: &[u8]) -> Option<Ipv4Addr> {
        self.get_option(buf, code::REQUESTED_IP)
            .and_then(|o| o.as_ipv4())
    }

    /// Get the lease time option value.
    pub fn lease_time(&self, buf: &[u8]) -> Option<u32> {
        self.get_option(buf, code::LEASE_TIME).and_then(|o| {
            if o.data.len() >= 4 {
                Some(u32::from_be_bytes([o.data[0], o.data[1], o.data[2], o.data[3]]))
            } else {
                None
            }
        })
    }

    /// Get the subnet mask option.
    pub fn subnet_mask(&self, buf: &[u8]) -> Option<Ipv4Addr> {
        self.get_option(buf, code::SUBNET_MASK).and_then(|o| o.as_ipv4())
    }

    /// Get the router option.
    pub fn router(&self, buf: &[u8]) -> Option<Ipv4Addr> {
        self.get_option(buf, code::ROUTER).and_then(|o| o.as_ipv4())
    }

    /// Get the DNS servers option.
    pub fn dns(&self, buf: &[u8]) -> Vec<Ipv4Addr> {
        self.get_option(buf, code::DNS)
            .map(|o| {
                o.data
                    .chunks_exact(4)
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if this is a DHCP request (BOOTP op=1).
    pub fn is_request(&self, buf: &[u8]) -> bool {
        self.op(buf).is_ok_and(|op| op == 1)
    }

    /// Check if this is a DHCP reply (BOOTP op=2).
    pub fn is_reply(&self, buf: &[u8]) -> bool {
        self.op(buf).is_ok_and(|op| op == 2)
    }

    /// Set the op field.
    pub fn set_op(&self, buf: &mut [u8], val: u8) -> Result<(), FieldError> {
        let start = self.index.start;
        let d = &mut buf[start..self.index.end];
        if d.is_empty() { return Err(short(1, 0)); }
        d[0] = val;
        Ok(())
    }

    /// Set the xid field.
    pub fn set_xid(&self, buf: &mut [u8], val: u32) -> Result<(), FieldError> {
        let start = self.index.start;
        let d = &mut buf[start..self.index.end];
        if d.len() < 8 { return Err(short(8, d.len())); }
        d[4..8].copy_from_slice(&val.to_be_bytes());
        Ok(())
    }

    /// Set the flags field.
    pub fn set_flags(&self, buf: &mut [u8], val: u16) -> Result<(), FieldError> {
        let start = self.index.start;
        let d = &mut buf[start..self.index.end];
        if d.len() < 12 { return Err(short(12, d.len())); }
        d[10..12].copy_from_slice(&val.to_be_bytes());
        Ok(())
    }

    /// Get field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "op" => Some(self.op(buf).map(|v| FieldValue::U8(v))),
            "htype" => Some(self.htype(buf).map(|v| FieldValue::U8(v))),
            "hlen" => Some(self.hlen(buf).map(|v| FieldValue::U8(v))),
            "hops" => Some(self.hops(buf).map(|v| FieldValue::U8(v))),
            "xid" => Some(self.xid(buf).map(|v| FieldValue::U32(v))),
            "secs" => Some(self.secs(buf).map(|v| FieldValue::U16(v))),
            "flags" => Some(self.flags(buf).map(|v| FieldValue::U16(v))),
            "ciaddr" => Some(self.ciaddr(buf).map(|v| FieldValue::Ipv4(v))),
            "yiaddr" => Some(self.yiaddr(buf).map(|v| FieldValue::Ipv4(v))),
            "siaddr" => Some(self.siaddr(buf).map(|v| FieldValue::Ipv4(v))),
            "giaddr" => Some(self.giaddr(buf).map(|v| FieldValue::Ipv4(v))),
            "chaddr" => Some(self.chaddr(buf).map(|mac| FieldValue::Mac(MacAddress::new(mac)))),
            "msg_type" => Some(Ok(match self.msg_type(buf) {
                Some(v) => FieldValue::U8(v),
                None => FieldValue::U8(0),
            })),
            "server_id" => Some(Ok(match self.server_id(buf) {
                Some(v) => FieldValue::Ipv4(v),
                None => FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED),
            })),
            "requested_ip" => Some(Ok(match self.requested_ip(buf) {
                Some(v) => FieldValue::Ipv4(v),
                None => FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED),
            })),
            "lease_time" => Some(Ok(FieldValue::U32(self.lease_time(buf).unwrap_or(0)))),
            "subnet_mask" => Some(Ok(match self.subnet_mask(buf) {
                Some(v) => FieldValue::Ipv4(v),
                None => FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED),
            })),
            "router" => Some(Ok(match self.router(buf) {
                Some(v) => FieldValue::Ipv4(v),
                None => FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED),
            })),
            "dns" => {
                let servers = self.dns(buf);
                if servers.is_empty() {
                    Some(Ok(FieldValue::Str(String::new())))
                } else {
                    let s = servers.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",");
                    Some(Ok(FieldValue::Str(s)))
                }
            }
            _ => None,
        }
    }

    /// Set field value by name.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match name {
            "op" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_op(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!("op: expected U8, got {value:?}"))))
                }
            }
            "xid" => {
                if let FieldValue::U32(v) = value {
                    Some(self.set_xid(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!("xid: expected U32, got {value:?}"))))
                }
            }
            "flags" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_flags(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!("flags: expected U16, got {value:?}"))))
                }
            }
            _ => None,
        }
    }

    /// Field names for this layer.
    pub fn field_names(&self) -> &'static [&'static str] {
        DHCP_FIELD_NAMES
    }
}

impl Layer for DhcpLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Dhcp
    }

    fn summary(&self, buf: &[u8]) -> String {
        let msg = match self.msg_type(buf) {
            Some(1) => "Discover",
            Some(2) => "Offer",
            Some(3) => "Request",
            Some(4) => "Decline",
            Some(5) => "ACK",
            Some(6) => "NAK",
            Some(7) => "Release",
            Some(8) => "Inform",
            _ => "Unknown",
        };
        format!("DHCP {msg}")
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        let d = self.data(buf);
        d.len()
    }
}

/// Check if a UDP payload looks like a DHCP packet.
#[must_use]
pub fn is_dhcp_payload(data: &[u8]) -> bool {
    if data.len() < 240 {
        return false;
    }
    data[236..240] == MAGIC_COOKIE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::field::MacAddress;

    #[test]
    fn test_parse_discover() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let data = DhcpBuilder::discover(mac, 0xaabbccdd).build();

        let layer = DhcpLayer::new(LayerIndex {
            kind: LayerKind::Dhcp,
            start: 0,
            end: data.len(),
        });

        assert_eq!(layer.op(&data).unwrap(), 1);
        assert_eq!(layer.xid(&data).unwrap(), 0xaabbccdd);
        assert_eq!(layer.chaddr(&data).unwrap(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(layer.msg_type(&data), Some(options::msg_type::DISCOVER));
        assert_eq!(layer.summary(&data), "DHCP Discover");
    }

    #[test]
    fn test_parse_offer() {
        let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let data = DhcpBuilder::offer(
            0x12345678,
            mac,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
        )
        .lease_time(7200)
        .subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
        .router(Ipv4Addr::new(192, 168, 1, 1))
        .dns(&[Ipv4Addr::new(8, 8, 8, 8)])
        .build();

        let layer = DhcpLayer::new(LayerIndex {
            kind: LayerKind::Dhcp,
            start: 0,
            end: data.len(),
        });

        assert_eq!(layer.op(&data).unwrap(), 2);
        assert_eq!(layer.yiaddr(&data).unwrap(), Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(layer.siaddr(&data).unwrap(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(layer.msg_type(&data), Some(options::msg_type::OFFER));
        assert_eq!(layer.server_id(&data), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(layer.summary(&data), "DHCP Offer");
    }

    #[test]
    fn test_is_dhcp_payload() {
        let mac = MacAddress::new([0x00; 6]);
        let data = DhcpBuilder::discover(mac, 1).build();
        assert!(is_dhcp_payload(&data));
        assert!(!is_dhcp_payload(&[0u8; 10]));
    }
}
