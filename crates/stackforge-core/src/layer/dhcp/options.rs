/// DHCP message types (option 53).
pub mod msg_type {
    pub const DISCOVER: u8 = 1;
    pub const OFFER: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const DECLINE: u8 = 4;
    pub const ACK: u8 = 5;
    pub const NAK: u8 = 6;
    pub const RELEASE: u8 = 7;
    pub const INFORM: u8 = 8;
}

/// DHCP option codes.
pub mod code {
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS: u8 = 6;
    pub const HOSTNAME: u8 = 12;
    pub const DOMAIN_NAME: u8 = 15;
    pub const BROADCAST_ADDR: u8 = 28;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAM_REQUEST_LIST: u8 = 55;
    pub const MAX_MSG_SIZE: u8 = 57;
    pub const RENEWAL_TIME: u8 = 58;
    pub const REBINDING_TIME: u8 = 59;
    pub const CLIENT_ID: u8 = 61;
    pub const END: u8 = 255;
    pub const PAD: u8 = 0;
}

/// A parsed DHCP option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOption {
    pub code: u8,
    pub data: Vec<u8>,
}

impl DhcpOption {
    #[must_use]
    pub fn new(code: u8, data: Vec<u8>) -> Self {
        Self { code, data }
    }

    /// Create a message type option.
    #[must_use]
    pub fn message_type(msg_type: u8) -> Self {
        Self::new(code::MESSAGE_TYPE, vec![msg_type])
    }

    /// Create a server identifier option.
    #[must_use]
    pub fn server_id(ip: std::net::Ipv4Addr) -> Self {
        Self::new(code::SERVER_ID, ip.octets().to_vec())
    }

    /// Create a lease time option.
    #[must_use]
    pub fn lease_time(seconds: u32) -> Self {
        Self::new(code::LEASE_TIME, seconds.to_be_bytes().to_vec())
    }

    /// Create a subnet mask option.
    #[must_use]
    pub fn subnet_mask(mask: std::net::Ipv4Addr) -> Self {
        Self::new(code::SUBNET_MASK, mask.octets().to_vec())
    }

    /// Create a router option.
    #[must_use]
    pub fn router(ip: std::net::Ipv4Addr) -> Self {
        Self::new(code::ROUTER, ip.octets().to_vec())
    }

    /// Create a DNS servers option.
    #[must_use]
    pub fn dns(servers: &[std::net::Ipv4Addr]) -> Self {
        let mut data = Vec::with_capacity(servers.len() * 4);
        for s in servers {
            data.extend_from_slice(&s.octets());
        }
        Self::new(code::DNS, data)
    }

    /// Create a domain name option.
    #[must_use]
    pub fn domain_name(name: &str) -> Self {
        Self::new(code::DOMAIN_NAME, name.as_bytes().to_vec())
    }

    /// Serialize this option to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.code == code::PAD || self.code == code::END {
            return vec![self.code];
        }
        let mut out = Vec::with_capacity(2 + self.data.len());
        out.push(self.code);
        out.push(self.data.len() as u8);
        out.extend_from_slice(&self.data);
        out
    }

    /// Get the message type value (if this is a message type option).
    #[must_use]
    pub fn as_message_type(&self) -> Option<u8> {
        if self.code == code::MESSAGE_TYPE && !self.data.is_empty() {
            Some(self.data[0])
        } else {
            None
        }
    }

    /// Get an IPv4 address value (for 4-byte options like subnet mask, router, etc).
    #[must_use]
    pub fn as_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        if self.data.len() >= 4 {
            Some(std::net::Ipv4Addr::new(
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ))
        } else {
            None
        }
    }
}

/// Parse DHCP options from a byte slice (starting after the magic cookie).
pub fn parse_options(data: &[u8]) -> Vec<DhcpOption> {
    let mut opts = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let code = data[i];
        if code == code::END {
            break;
        }
        if code == code::PAD {
            i += 1;
            continue;
        }
        i += 1;
        if i >= data.len() {
            break;
        }
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            break;
        }
        opts.push(DhcpOption::new(code, data[i..i + len].to_vec()));
        i += len;
    }

    opts
}

/// Serialize a list of DHCP options to bytes (including END marker).
pub fn serialize_options(opts: &[DhcpOption]) -> Vec<u8> {
    let mut out = Vec::new();
    for opt in opts {
        out.extend_from_slice(&opt.to_bytes());
    }
    out.push(code::END);
    out
}
