//! IPv6 Extension Header types and parser.
//!
//! IPv6 extension headers form a chain: each header contains a "Next Header"
//! field pointing to the next header type. The chain terminates at a
//! transport-layer protocol (TCP, UDP, ICMPv6) or "No Next Header" (59).
//!
//! # Extension Header Length Encoding
//!
//! For Hop-by-Hop Options (NH=0), Routing (NH=43), and Destination Options (NH=60):
//! - Offset 0: Next Header
//! - Offset 1: Hdr Ext Len (in units of 8 bytes, NOT counting the first 8 bytes)
//!   - Total length = (Hdr Ext Len + 1) * 8
//!
//! For Fragment Header (NH=44): always exactly 8 bytes.

/// Types of IPv6 extension headers and next-layer protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtHeaderKind {
    /// Hop-by-Hop Options (must be first if present)
    HopByHop = 0,
    /// Transmission Control Protocol
    Tcp = 6,
    /// User Datagram Protocol
    Udp = 17,
    /// Routing Header
    Routing = 43,
    /// Fragment Header
    Fragment = 44,
    /// ICMPv6
    Icmpv6 = 58,
    /// No Next Header
    NoNextHeader = 59,
    /// Destination Options
    DestinationOptions = 60,
}

impl ExtHeaderKind {
    /// Convert a raw next-header byte to an ExtHeaderKind.
    pub fn from_nh(nh: u8) -> Option<Self> {
        match nh {
            0 => Some(Self::HopByHop),
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            43 => Some(Self::Routing),
            44 => Some(Self::Fragment),
            58 => Some(Self::Icmpv6),
            59 => Some(Self::NoNextHeader),
            60 => Some(Self::DestinationOptions),
            _ => None,
        }
    }

    /// Returns true if this is a terminal protocol (not an extension header).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Tcp | Self::Udp | Self::Icmpv6 | Self::NoNextHeader
        )
    }

    /// Returns the protocol number (next-header value) for this kind.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Represents a parsed extension header within a packet buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtHeader {
    /// The type of this extension header.
    pub kind: ExtHeaderKind,
    /// Byte offset (in the buffer) where this header starts.
    pub start: usize,
    /// Byte offset (exclusive) where this header ends.
    pub end: usize,
}

impl ExtHeader {
    /// Create a new ExtHeader.
    pub const fn new(kind: ExtHeaderKind, start: usize, end: usize) -> Self {
        Self { kind, start, end }
    }

    /// Get the length of this extension header in bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Check if this extension header is empty (zero length).
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Parse the IPv6 extension header chain.
///
/// Starting at `start` in `buf` with `first_nh` as the initial "Next Header"
/// value, walks the chain of extension headers and returns a list of all
/// extension headers found. Stops when a terminal protocol is encountered
/// (TCP, UDP, ICMPv6, NoNextHeader) or the buffer runs out.
///
/// # Arguments
///
/// * `buf` - The full packet buffer
/// * `start` - Byte offset of the first extension header (after IPv6 fixed header)
/// * `first_nh` - The Next Header value from the IPv6 fixed header
///
/// # Returns
///
/// A `Vec<ExtHeader>` containing each extension header (and terminal protocol)
/// found in the chain. The last entry in the vec is the terminal header
/// (TCP/UDP/ICMPv6/NoNextHeader) if the buffer is large enough.
pub fn parse_ext_headers(buf: &[u8], start: usize, first_nh: u8) -> Vec<ExtHeader> {
    let mut headers = Vec::new();
    let mut current_nh = first_nh;
    let mut offset = start;

    loop {
        if offset >= buf.len() {
            break;
        }

        let kind = match ExtHeaderKind::from_nh(current_nh) {
            Some(k) => k,
            None => {
                // Unknown next header — stop parsing
                break;
            },
        };

        if kind.is_terminal() {
            // Terminal protocol: include it as a marker and stop
            headers.push(ExtHeader::new(kind, offset, buf.len()));
            break;
        }

        // Extension header: need at least 2 bytes to read next_nh and length
        if offset + 2 > buf.len() {
            break;
        }

        let next_nh = buf[offset];
        let hdr_len_bytes = match kind {
            ExtHeaderKind::Fragment => {
                // Fragment header is always exactly 8 bytes
                8usize
            },
            ExtHeaderKind::HopByHop
            | ExtHeaderKind::Routing
            | ExtHeaderKind::DestinationOptions => {
                // Length field at offset 1: (len + 1) * 8
                let len_field = buf[offset + 1] as usize;
                (len_field + 1) * 8
            },
            _ => {
                // Should not reach here since we checked is_terminal above
                break;
            },
        };

        let hdr_end = offset + hdr_len_bytes;
        if hdr_end > buf.len() {
            // Truncated header
            break;
        }

        headers.push(ExtHeader::new(kind, offset, hdr_end));

        // Advance to next header
        current_nh = next_nh;
        offset = hdr_end;
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ext_header_kind_from_nh() {
        assert_eq!(ExtHeaderKind::from_nh(0), Some(ExtHeaderKind::HopByHop));
        assert_eq!(ExtHeaderKind::from_nh(6), Some(ExtHeaderKind::Tcp));
        assert_eq!(ExtHeaderKind::from_nh(17), Some(ExtHeaderKind::Udp));
        assert_eq!(ExtHeaderKind::from_nh(43), Some(ExtHeaderKind::Routing));
        assert_eq!(ExtHeaderKind::from_nh(44), Some(ExtHeaderKind::Fragment));
        assert_eq!(ExtHeaderKind::from_nh(58), Some(ExtHeaderKind::Icmpv6));
        assert_eq!(
            ExtHeaderKind::from_nh(59),
            Some(ExtHeaderKind::NoNextHeader)
        );
        assert_eq!(
            ExtHeaderKind::from_nh(60),
            Some(ExtHeaderKind::DestinationOptions)
        );
        assert_eq!(ExtHeaderKind::from_nh(99), None);
    }

    #[test]
    fn test_ext_header_kind_is_terminal() {
        assert!(ExtHeaderKind::Tcp.is_terminal());
        assert!(ExtHeaderKind::Udp.is_terminal());
        assert!(ExtHeaderKind::Icmpv6.is_terminal());
        assert!(ExtHeaderKind::NoNextHeader.is_terminal());
        assert!(!ExtHeaderKind::HopByHop.is_terminal());
        assert!(!ExtHeaderKind::Routing.is_terminal());
        assert!(!ExtHeaderKind::Fragment.is_terminal());
        assert!(!ExtHeaderKind::DestinationOptions.is_terminal());
    }

    #[test]
    fn test_parse_no_ext_headers_tcp() {
        // Buffer starting after IPv6 header with NH=6 (TCP), some dummy TCP bytes
        let buf = vec![0u8; 20]; // 20 bytes of "TCP"
        let headers = parse_ext_headers(&buf, 0, 6);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].kind, ExtHeaderKind::Tcp);
        assert_eq!(headers[0].start, 0);
    }

    #[test]
    fn test_parse_no_ext_headers_icmpv6() {
        let buf = vec![0u8; 8]; // 8 bytes of "ICMPv6"
        let headers = parse_ext_headers(&buf, 0, 58);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].kind, ExtHeaderKind::Icmpv6);
    }

    #[test]
    fn test_parse_hop_by_hop_then_tcp() {
        // Hop-by-hop header (8 bytes): next_nh=6, len=0 (meaning 8 bytes total)
        // Then 20 bytes of "TCP"
        let mut buf = vec![0u8; 28];
        buf[0] = 6; // next header = TCP
        buf[1] = 0; // length = 0, meaning (0+1)*8 = 8 bytes total
        // buf[2..8] = padding/options (zeros)
        // buf[8..28] = TCP header (zeros)

        let headers = parse_ext_headers(&buf, 0, 0); // start with HopByHop
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].kind, ExtHeaderKind::HopByHop);
        assert_eq!(headers[0].start, 0);
        assert_eq!(headers[0].end, 8);
        assert_eq!(headers[1].kind, ExtHeaderKind::Tcp);
        assert_eq!(headers[1].start, 8);
    }

    #[test]
    fn test_parse_fragment_header() {
        // Fragment header (8 bytes): next_nh=17 (UDP)
        // Then 8 bytes of "UDP"
        let mut buf = vec![0u8; 16];
        buf[0] = 17; // next header = UDP
        // buf[1..8] = fragment offset etc (zeros)
        // buf[8..16] = UDP header (zeros)

        let headers = parse_ext_headers(&buf, 0, 44); // start with Fragment
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].kind, ExtHeaderKind::Fragment);
        assert_eq!(headers[0].start, 0);
        assert_eq!(headers[0].end, 8);
        assert_eq!(headers[1].kind, ExtHeaderKind::Udp);
        assert_eq!(headers[1].start, 8);
    }

    #[test]
    fn test_parse_routing_header_with_length_1() {
        // Routing header (16 bytes): next_nh=6 (TCP), len=1 => (1+1)*8 = 16 bytes
        let mut buf = vec![0u8; 36];
        buf[0] = 6; // next header = TCP
        buf[1] = 1; // length = 1, meaning (1+1)*8 = 16 bytes total
        // buf[2..16] = routing header data (zeros)
        // buf[16..36] = TCP header (zeros)

        let headers = parse_ext_headers(&buf, 0, 43); // Routing
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].kind, ExtHeaderKind::Routing);
        assert_eq!(headers[0].len(), 16);
        assert_eq!(headers[1].kind, ExtHeaderKind::Tcp);
        assert_eq!(headers[1].start, 16);
    }

    #[test]
    fn test_parse_no_next_header() {
        let buf = vec![0u8; 4];
        let headers = parse_ext_headers(&buf, 0, 59); // NoNextHeader
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].kind, ExtHeaderKind::NoNextHeader);
    }

    #[test]
    fn test_parse_empty_buffer() {
        let buf: Vec<u8> = vec![];
        let headers = parse_ext_headers(&buf, 0, 58);
        assert!(headers.is_empty());
    }
}
