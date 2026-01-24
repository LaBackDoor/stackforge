//! TCP flags implementation.
//!
//! TCP flags are a 9-bit field in the TCP header (including NS, CWR, ECE).
//! This module provides a structured representation matching Scapy's FlagsField.

use std::fmt;

/// TCP flags structure (9 bits).
///
/// Bit layout (from MSB to LSB in the 16-bit flags/reserved field):
/// - NS (Nonce Sum) - ECN nonce concealment
/// - CWR (Congestion Window Reduced)
/// - ECE (ECN-Echo)
/// - URG (Urgent)
/// - ACK (Acknowledgment)
/// - PSH (Push)
/// - RST (Reset)
/// - SYN (Synchronize)
/// - FIN (Finish)
///
/// Scapy uses the string "FSRPAUECN" for flags (reversed order).
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct TcpFlags {
    /// FIN - No more data from sender
    pub fin: bool,
    /// SYN - Synchronize sequence numbers
    pub syn: bool,
    /// RST - Reset the connection
    pub rst: bool,
    /// PSH - Push function
    pub psh: bool,
    /// ACK - Acknowledgment field significant
    pub ack: bool,
    /// URG - Urgent pointer field significant
    pub urg: bool,
    /// ECE - ECN-Echo (RFC 3168)
    pub ece: bool,
    /// CWR - Congestion Window Reduced (RFC 3168)
    pub cwr: bool,
    /// NS - ECN-nonce concealment protection (RFC 3540)
    pub ns: bool,
}

impl TcpFlags {
    /// No flags set
    pub const NONE: Self = Self {
        fin: false,
        syn: false,
        rst: false,
        psh: false,
        ack: false,
        urg: false,
        ece: false,
        cwr: false,
        ns: false,
    };

    /// SYN flag only (connection initiation)
    pub const S: Self = Self {
        fin: false,
        syn: true,
        rst: false,
        psh: false,
        ack: false,
        urg: false,
        ece: false,
        cwr: false,
        ns: false,
    };

    /// SYN+ACK flags (connection acknowledgment)
    pub const SA: Self = Self {
        fin: false,
        syn: true,
        rst: false,
        psh: false,
        ack: true,
        urg: false,
        ece: false,
        cwr: false,
        ns: false,
    };

    /// ACK flag only
    pub const A: Self = Self {
        fin: false,
        syn: false,
        rst: false,
        psh: false,
        ack: true,
        urg: false,
        ece: false,
        cwr: false,
        ns: false,
    };

    /// FIN+ACK flags (connection termination)
    pub const FA: Self = Self {
        fin: true,
        syn: false,
        rst: false,
        psh: false,
        ack: true,
        urg: false,
        ece: false,
        cwr: false,
        ns: false,
    };

    /// RST flag only (connection reset)
    pub const R: Self = Self {
        fin: false,
        syn: false,
        rst: true,
        psh: false,
        ack: false,
        urg: false,
        ece: false,
        cwr: false,
        ns: false,
    };

    /// RST+ACK flags
    pub const RA: Self = Self {
        fin: false,
        syn: false,
        rst: true,
        psh: false,
        ack: true,
        urg: false,
        ece: false,
        cwr: false,
        ns: false,
    };

    /// PSH+ACK flags (data push)
    pub const PA: Self = Self {
        fin: false,
        syn: false,
        rst: false,
        psh: true,
        ack: true,
        urg: false,
        ece: false,
        cwr: false,
        ns: false,
    };

    /// Flag bit positions (in the 9-bit flags field)
    pub const FIN_BIT: u16 = 0x001;
    pub const SYN_BIT: u16 = 0x002;
    pub const RST_BIT: u16 = 0x004;
    pub const PSH_BIT: u16 = 0x008;
    pub const ACK_BIT: u16 = 0x010;
    pub const URG_BIT: u16 = 0x020;
    pub const ECE_BIT: u16 = 0x040;
    pub const CWR_BIT: u16 = 0x080;
    pub const NS_BIT: u16 = 0x100;

    /// Create flags from a raw 16-bit value (data offset + reserved + flags).
    ///
    /// The flags are in the lower 9 bits (with NS in bit 8 of the high byte).
    #[inline]
    pub fn from_u16(value: u16) -> Self {
        Self {
            fin: (value & Self::FIN_BIT) != 0,
            syn: (value & Self::SYN_BIT) != 0,
            rst: (value & Self::RST_BIT) != 0,
            psh: (value & Self::PSH_BIT) != 0,
            ack: (value & Self::ACK_BIT) != 0,
            urg: (value & Self::URG_BIT) != 0,
            ece: (value & Self::ECE_BIT) != 0,
            cwr: (value & Self::CWR_BIT) != 0,
            ns: (value & Self::NS_BIT) != 0,
        }
    }

    /// Create flags from just the flags byte (lower 8 bits).
    #[inline]
    pub fn from_byte(byte: u8) -> Self {
        Self::from_u16(byte as u16)
    }

    /// Create flags from two bytes (data_offset_reserved + flags).
    #[inline]
    pub fn from_bytes(hi: u8, lo: u8) -> Self {
        let ns = (hi & 0x01) != 0;
        let mut flags = Self::from_byte(lo);
        flags.ns = ns;
        flags
    }

    /// Convert to a raw 9-bit value.
    #[inline]
    pub fn to_u16(self) -> u16 {
        let mut value = 0u16;
        if self.fin {
            value |= Self::FIN_BIT;
        }
        if self.syn {
            value |= Self::SYN_BIT;
        }
        if self.rst {
            value |= Self::RST_BIT;
        }
        if self.psh {
            value |= Self::PSH_BIT;
        }
        if self.ack {
            value |= Self::ACK_BIT;
        }
        if self.urg {
            value |= Self::URG_BIT;
        }
        if self.ece {
            value |= Self::ECE_BIT;
        }
        if self.cwr {
            value |= Self::CWR_BIT;
        }
        if self.ns {
            value |= Self::NS_BIT;
        }
        value
    }

    /// Convert to the lower flags byte (without NS).
    #[inline]
    pub fn to_byte(self) -> u8 {
        (self.to_u16() & 0xFF) as u8
    }

    /// Get the NS bit for the high byte.
    #[inline]
    pub fn ns_bit(self) -> u8 {
        if self.ns { 0x01 } else { 0x00 }
    }

    /// Create flags from a string like "S", "SA", "FA", "PA", "R", etc.
    /// Uses Scapy's "FSRPAUECN" convention.
    pub fn from_str(s: &str) -> Self {
        let mut flags = Self::NONE;
        for c in s.chars() {
            match c {
                'F' | 'f' => flags.fin = true,
                'S' | 's' => flags.syn = true,
                'R' | 'r' => flags.rst = true,
                'P' | 'p' => flags.psh = true,
                'A' | 'a' => flags.ack = true,
                'U' | 'u' => flags.urg = true,
                'E' | 'e' => flags.ece = true,
                'C' | 'c' => flags.cwr = true,
                'N' | 'n' => flags.ns = true,
                _ => {} // Ignore unknown characters
            }
        }
        flags
    }

    /// Check if this is a SYN packet (SYN set, ACK not set).
    #[inline]
    pub fn is_syn(&self) -> bool {
        self.syn && !self.ack
    }

    /// Check if this is a SYN-ACK packet.
    #[inline]
    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack
    }

    /// Check if this is a pure ACK packet.
    #[inline]
    pub fn is_ack(&self) -> bool {
        self.ack && !self.syn && !self.fin && !self.rst
    }

    /// Check if this is a FIN packet.
    #[inline]
    pub fn is_fin(&self) -> bool {
        self.fin
    }

    /// Check if this is a RST packet.
    #[inline]
    pub fn is_rst(&self) -> bool {
        self.rst
    }

    /// Check if ECN is enabled (ECE or CWR set).
    #[inline]
    pub fn has_ecn(&self) -> bool {
        self.ece || self.cwr
    }

    /// Check if any flag is set.
    #[inline]
    pub fn is_empty(&self) -> bool {
        !self.fin
            && !self.syn
            && !self.rst
            && !self.psh
            && !self.ack
            && !self.urg
            && !self.ece
            && !self.cwr
            && !self.ns
    }

    /// Count how many flags are set.
    #[inline]
    pub fn count(&self) -> u8 {
        let mut count = 0;
        if self.fin {
            count += 1;
        }
        if self.syn {
            count += 1;
        }
        if self.rst {
            count += 1;
        }
        if self.psh {
            count += 1;
        }
        if self.ack {
            count += 1;
        }
        if self.urg {
            count += 1;
        }
        if self.ece {
            count += 1;
        }
        if self.cwr {
            count += 1;
        }
        if self.ns {
            count += 1;
        }
        count
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Scapy order: FSRPAUECN
        let mut s = String::with_capacity(9);
        if self.fin {
            s.push('F');
        }
        if self.syn {
            s.push('S');
        }
        if self.rst {
            s.push('R');
        }
        if self.psh {
            s.push('P');
        }
        if self.ack {
            s.push('A');
        }
        if self.urg {
            s.push('U');
        }
        if self.ece {
            s.push('E');
        }
        if self.cwr {
            s.push('C');
        }
        if self.ns {
            s.push('N');
        }

        if s.is_empty() {
            write!(f, "-")
        } else {
            write!(f, "{}", s)
        }
    }
}

impl fmt::Debug for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TcpFlags({})", self)
    }
}

impl From<u16> for TcpFlags {
    fn from(value: u16) -> Self {
        Self::from_u16(value)
    }
}

impl From<u8> for TcpFlags {
    fn from(value: u8) -> Self {
        Self::from_byte(value)
    }
}

impl From<TcpFlags> for u16 {
    fn from(flags: TcpFlags) -> Self {
        flags.to_u16()
    }
}

impl From<TcpFlags> for u8 {
    fn from(flags: TcpFlags) -> Self {
        flags.to_byte()
    }
}

impl From<&str> for TcpFlags {
    fn from(s: &str) -> Self {
        Self::from_str(s)
    }
}

impl std::ops::BitOr for TcpFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            fin: self.fin || rhs.fin,
            syn: self.syn || rhs.syn,
            rst: self.rst || rhs.rst,
            psh: self.psh || rhs.psh,
            ack: self.ack || rhs.ack,
            urg: self.urg || rhs.urg,
            ece: self.ece || rhs.ece,
            cwr: self.cwr || rhs.cwr,
            ns: self.ns || rhs.ns,
        }
    }
}

impl std::ops::BitAnd for TcpFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self {
            fin: self.fin && rhs.fin,
            syn: self.syn && rhs.syn,
            rst: self.rst && rhs.rst,
            psh: self.psh && rhs.psh,
            ack: self.ack && rhs.ack,
            urg: self.urg && rhs.urg,
            ece: self.ece && rhs.ece,
            cwr: self.cwr && rhs.cwr,
            ns: self.ns && rhs.ns,
        }
    }
}

impl std::ops::BitOrAssign for TcpFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl std::ops::BitAndAssign for TcpFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u16() {
        let flags = TcpFlags::from_u16(0x02); // SYN
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(!flags.fin);

        let flags = TcpFlags::from_u16(0x12); // SYN+ACK
        assert!(flags.syn);
        assert!(flags.ack);

        let flags = TcpFlags::from_u16(0x10); // ACK
        assert!(!flags.syn);
        assert!(flags.ack);

        let flags = TcpFlags::from_u16(0x11); // FIN+ACK
        assert!(flags.fin);
        assert!(flags.ack);

        let flags = TcpFlags::from_u16(0x04); // RST
        assert!(flags.rst);

        let flags = TcpFlags::from_u16(0x100); // NS
        assert!(flags.ns);
    }

    #[test]
    fn test_to_u16() {
        assert_eq!(TcpFlags::S.to_u16(), 0x02);
        assert_eq!(TcpFlags::SA.to_u16(), 0x12);
        assert_eq!(TcpFlags::A.to_u16(), 0x10);
        assert_eq!(TcpFlags::FA.to_u16(), 0x11);
        assert_eq!(TcpFlags::R.to_u16(), 0x04);
    }

    #[test]
    fn test_from_str() {
        let flags = TcpFlags::from_str("S");
        assert!(flags.syn);
        assert!(!flags.ack);

        let flags = TcpFlags::from_str("SA");
        assert!(flags.syn);
        assert!(flags.ack);

        let flags = TcpFlags::from_str("FSRPAUECN");
        assert!(flags.fin);
        assert!(flags.syn);
        assert!(flags.rst);
        assert!(flags.psh);
        assert!(flags.ack);
        assert!(flags.urg);
        assert!(flags.ece);
        assert!(flags.cwr);
        assert!(flags.ns);
    }

    #[test]
    fn test_display() {
        assert_eq!(TcpFlags::S.to_string(), "S");
        assert_eq!(TcpFlags::SA.to_string(), "SA");
        assert_eq!(TcpFlags::FA.to_string(), "FA");
        assert_eq!(TcpFlags::PA.to_string(), "PA");
        assert_eq!(TcpFlags::NONE.to_string(), "-");
    }

    #[test]
    fn test_is_methods() {
        assert!(TcpFlags::S.is_syn());
        assert!(!TcpFlags::SA.is_syn()); // SYN-ACK is not "just SYN"
        assert!(TcpFlags::SA.is_syn_ack());
        assert!(TcpFlags::A.is_ack());
        assert!(TcpFlags::FA.is_fin());
        assert!(TcpFlags::R.is_rst());
    }

    #[test]
    fn test_bit_ops() {
        let flags = TcpFlags::S | TcpFlags::A;
        assert!(flags.syn);
        assert!(flags.ack);

        let flags = TcpFlags::SA & TcpFlags::S;
        assert!(flags.syn);
        assert!(!flags.ack);
    }

    #[test]
    fn test_from_bytes() {
        // Data offset (5) + reserved (000) + NS (0) + flags (0x12 = SYN+ACK)
        // Byte 12: 0101_0000 = 0x50 (data offset 5, NS=0)
        // Byte 13: 0001_0010 = 0x12 (SYN+ACK)
        let flags = TcpFlags::from_bytes(0x50, 0x12);
        assert!(flags.syn);
        assert!(flags.ack);
        assert!(!flags.ns);

        // With NS bit set (bit 0 of byte 12)
        let flags = TcpFlags::from_bytes(0x51, 0x12);
        assert!(flags.syn);
        assert!(flags.ack);
        assert!(flags.ns);
    }

    #[test]
    fn test_constants() {
        assert_eq!(TcpFlags::NONE.to_u16(), 0);
        assert_eq!(TcpFlags::S.to_u16(), 0x002);
        assert_eq!(TcpFlags::SA.to_u16(), 0x012);
        assert_eq!(TcpFlags::A.to_u16(), 0x010);
        assert_eq!(TcpFlags::FA.to_u16(), 0x011);
        assert_eq!(TcpFlags::R.to_u16(), 0x004);
        assert_eq!(TcpFlags::RA.to_u16(), 0x014);
        assert_eq!(TcpFlags::PA.to_u16(), 0x018);
    }
}
