//! DNS header parsing (RFC 1035 Section 4.1.1).
//!
//! The DNS header is 12 bytes:
//! ```text
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                      ID                         |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    QDCOUNT                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    ANCOUNT                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    NSCOUNT                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    ARCOUNT                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```

use crate::layer::field::{Field, FieldError};

/// DNS header size in bytes.
pub const DNS_HEADER_LEN: usize = 12;

// Byte offsets within the header
const ID_OFFSET: usize = 0;
const FLAGS_OFFSET: usize = 2;
const QDCOUNT_OFFSET: usize = 4;
const ANCOUNT_OFFSET: usize = 6;
const NSCOUNT_OFFSET: usize = 8;
const ARCOUNT_OFFSET: usize = 10;

// Flag bit positions within the 16-bit flags field
const FLAG_QR: u16 = 0x8000;
const FLAG_OPCODE_MASK: u16 = 0x7800;
const FLAG_OPCODE_SHIFT: u16 = 11;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const FLAG_Z: u16 = 0x0040;
const FLAG_AD: u16 = 0x0020;
const FLAG_CD: u16 = 0x0010;
const FLAG_RCODE_MASK: u16 = 0x000F;

/// Read the DNS transaction ID.
#[inline]
pub fn read_id(buf: &[u8], base: usize) -> Result<u16, FieldError> {
    u16::read(buf, base + ID_OFFSET)
}

/// Write the DNS transaction ID.
#[inline]
pub fn write_id(buf: &mut [u8], base: usize, id: u16) -> Result<(), FieldError> {
    id.write(buf, base + ID_OFFSET)
}

/// Read the 16-bit flags field.
#[inline]
fn read_flags(buf: &[u8], base: usize) -> Result<u16, FieldError> {
    u16::read(buf, base + FLAGS_OFFSET)
}

/// Write the 16-bit flags field.
#[inline]
fn write_flags(buf: &mut [u8], base: usize, flags: u16) -> Result<(), FieldError> {
    flags.write(buf, base + FLAGS_OFFSET)
}

/// QR flag: 0 = query, 1 = response.
#[inline]
pub fn read_qr(buf: &[u8], base: usize) -> Result<bool, FieldError> {
    Ok(read_flags(buf, base)? & FLAG_QR != 0)
}

pub fn write_qr(buf: &mut [u8], base: usize, qr: bool) -> Result<(), FieldError> {
    let mut flags = read_flags(buf, base)?;
    if qr {
        flags |= FLAG_QR;
    } else {
        flags &= !FLAG_QR;
    }
    write_flags(buf, base, flags)
}

/// Opcode (4 bits).
#[inline]
pub fn read_opcode(buf: &[u8], base: usize) -> Result<u8, FieldError> {
    let flags = read_flags(buf, base)?;
    Ok(((flags & FLAG_OPCODE_MASK) >> FLAG_OPCODE_SHIFT) as u8)
}

pub fn write_opcode(buf: &mut [u8], base: usize, opcode: u8) -> Result<(), FieldError> {
    let mut flags = read_flags(buf, base)?;
    flags &= !FLAG_OPCODE_MASK;
    flags |= ((opcode as u16) << FLAG_OPCODE_SHIFT) & FLAG_OPCODE_MASK;
    write_flags(buf, base, flags)
}

/// AA flag: Authoritative Answer.
#[inline]
pub fn read_aa(buf: &[u8], base: usize) -> Result<bool, FieldError> {
    Ok(read_flags(buf, base)? & FLAG_AA != 0)
}

pub fn write_aa(buf: &mut [u8], base: usize, aa: bool) -> Result<(), FieldError> {
    let mut flags = read_flags(buf, base)?;
    if aa {
        flags |= FLAG_AA;
    } else {
        flags &= !FLAG_AA;
    }
    write_flags(buf, base, flags)
}

/// TC flag: Truncation.
#[inline]
pub fn read_tc(buf: &[u8], base: usize) -> Result<bool, FieldError> {
    Ok(read_flags(buf, base)? & FLAG_TC != 0)
}

pub fn write_tc(buf: &mut [u8], base: usize, tc: bool) -> Result<(), FieldError> {
    let mut flags = read_flags(buf, base)?;
    if tc {
        flags |= FLAG_TC;
    } else {
        flags &= !FLAG_TC;
    }
    write_flags(buf, base, flags)
}

/// RD flag: Recursion Desired.
#[inline]
pub fn read_rd(buf: &[u8], base: usize) -> Result<bool, FieldError> {
    Ok(read_flags(buf, base)? & FLAG_RD != 0)
}

pub fn write_rd(buf: &mut [u8], base: usize, rd: bool) -> Result<(), FieldError> {
    let mut flags = read_flags(buf, base)?;
    if rd {
        flags |= FLAG_RD;
    } else {
        flags &= !FLAG_RD;
    }
    write_flags(buf, base, flags)
}

/// RA flag: Recursion Available.
#[inline]
pub fn read_ra(buf: &[u8], base: usize) -> Result<bool, FieldError> {
    Ok(read_flags(buf, base)? & FLAG_RA != 0)
}

pub fn write_ra(buf: &mut [u8], base: usize, ra: bool) -> Result<(), FieldError> {
    let mut flags = read_flags(buf, base)?;
    if ra {
        flags |= FLAG_RA;
    } else {
        flags &= !FLAG_RA;
    }
    write_flags(buf, base, flags)
}

/// Z flag (reserved).
#[inline]
pub fn read_z(buf: &[u8], base: usize) -> Result<bool, FieldError> {
    Ok(read_flags(buf, base)? & FLAG_Z != 0)
}

pub fn write_z(buf: &mut [u8], base: usize, z: bool) -> Result<(), FieldError> {
    let mut flags = read_flags(buf, base)?;
    if z {
        flags |= FLAG_Z;
    } else {
        flags &= !FLAG_Z;
    }
    write_flags(buf, base, flags)
}

/// AD flag: Authenticated Data (DNSSEC).
#[inline]
pub fn read_ad(buf: &[u8], base: usize) -> Result<bool, FieldError> {
    Ok(read_flags(buf, base)? & FLAG_AD != 0)
}

pub fn write_ad(buf: &mut [u8], base: usize, ad: bool) -> Result<(), FieldError> {
    let mut flags = read_flags(buf, base)?;
    if ad {
        flags |= FLAG_AD;
    } else {
        flags &= !FLAG_AD;
    }
    write_flags(buf, base, flags)
}

/// CD flag: Checking Disabled (DNSSEC).
#[inline]
pub fn read_cd(buf: &[u8], base: usize) -> Result<bool, FieldError> {
    Ok(read_flags(buf, base)? & FLAG_CD != 0)
}

pub fn write_cd(buf: &mut [u8], base: usize, cd: bool) -> Result<(), FieldError> {
    let mut flags = read_flags(buf, base)?;
    if cd {
        flags |= FLAG_CD;
    } else {
        flags &= !FLAG_CD;
    }
    write_flags(buf, base, flags)
}

/// RCODE (4 bits): Response code.
#[inline]
pub fn read_rcode(buf: &[u8], base: usize) -> Result<u8, FieldError> {
    let flags = read_flags(buf, base)?;
    Ok((flags & FLAG_RCODE_MASK) as u8)
}

pub fn write_rcode(buf: &mut [u8], base: usize, rcode: u8) -> Result<(), FieldError> {
    let mut flags = read_flags(buf, base)?;
    flags &= !FLAG_RCODE_MASK;
    flags |= (rcode as u16) & FLAG_RCODE_MASK;
    write_flags(buf, base, flags)
}

/// Question count.
#[inline]
pub fn read_qdcount(buf: &[u8], base: usize) -> Result<u16, FieldError> {
    u16::read(buf, base + QDCOUNT_OFFSET)
}

#[inline]
pub fn write_qdcount(buf: &mut [u8], base: usize, count: u16) -> Result<(), FieldError> {
    count.write(buf, base + QDCOUNT_OFFSET)
}

/// Answer count.
#[inline]
pub fn read_ancount(buf: &[u8], base: usize) -> Result<u16, FieldError> {
    u16::read(buf, base + ANCOUNT_OFFSET)
}

#[inline]
pub fn write_ancount(buf: &mut [u8], base: usize, count: u16) -> Result<(), FieldError> {
    count.write(buf, base + ANCOUNT_OFFSET)
}

/// Authority count.
#[inline]
pub fn read_nscount(buf: &[u8], base: usize) -> Result<u16, FieldError> {
    u16::read(buf, base + NSCOUNT_OFFSET)
}

#[inline]
pub fn write_nscount(buf: &mut [u8], base: usize, count: u16) -> Result<(), FieldError> {
    count.write(buf, base + NSCOUNT_OFFSET)
}

/// Additional count.
#[inline]
pub fn read_arcount(buf: &[u8], base: usize) -> Result<u16, FieldError> {
    u16::read(buf, base + ARCOUNT_OFFSET)
}

#[inline]
pub fn write_arcount(buf: &mut [u8], base: usize, count: u16) -> Result<(), FieldError> {
    count.write(buf, base + ARCOUNT_OFFSET)
}

/// Build a raw 16-bit flags value from individual components.
pub fn build_flags(
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: bool,
    ad: bool,
    cd: bool,
    rcode: u8,
) -> u16 {
    let mut flags: u16 = 0;
    if qr {
        flags |= FLAG_QR;
    }
    flags |= ((opcode as u16) << FLAG_OPCODE_SHIFT) & FLAG_OPCODE_MASK;
    if aa {
        flags |= FLAG_AA;
    }
    if tc {
        flags |= FLAG_TC;
    }
    if rd {
        flags |= FLAG_RD;
    }
    if ra {
        flags |= FLAG_RA;
    }
    if z {
        flags |= FLAG_Z;
    }
    if ad {
        flags |= FLAG_AD;
    }
    if cd {
        flags |= FLAG_CD;
    }
    flags |= (rcode as u16) & FLAG_RCODE_MASK;
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(
        id: u16,
        qr: bool,
        opcode: u8,
        aa: bool,
        tc: bool,
        rd: bool,
        ra: bool,
        z: bool,
        ad: bool,
        cd: bool,
        rcode: u8,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
    ) -> Vec<u8> {
        let flags = build_flags(qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode);
        let mut buf = vec![0u8; DNS_HEADER_LEN];
        buf[0..2].copy_from_slice(&id.to_be_bytes());
        buf[2..4].copy_from_slice(&flags.to_be_bytes());
        buf[4..6].copy_from_slice(&qdcount.to_be_bytes());
        buf[6..8].copy_from_slice(&ancount.to_be_bytes());
        buf[8..10].copy_from_slice(&nscount.to_be_bytes());
        buf[10..12].copy_from_slice(&arcount.to_be_bytes());
        buf
    }

    #[test]
    fn test_read_query_header() {
        let buf = make_header(
            0x1234, false, 0, false, false, true, false, false, false, false, 0, 1, 0, 0, 0,
        );
        assert_eq!(read_id(&buf, 0).unwrap(), 0x1234);
        assert!(!read_qr(&buf, 0).unwrap());
        assert_eq!(read_opcode(&buf, 0).unwrap(), 0);
        assert!(!read_aa(&buf, 0).unwrap());
        assert!(!read_tc(&buf, 0).unwrap());
        assert!(read_rd(&buf, 0).unwrap());
        assert!(!read_ra(&buf, 0).unwrap());
        assert_eq!(read_rcode(&buf, 0).unwrap(), 0);
        assert_eq!(read_qdcount(&buf, 0).unwrap(), 1);
        assert_eq!(read_ancount(&buf, 0).unwrap(), 0);
    }

    #[test]
    fn test_read_response_header() {
        let buf = make_header(
            0xABCD, true, 0, true, false, true, true, false, true, false, 0, 1, 2, 0, 1,
        );
        assert_eq!(read_id(&buf, 0).unwrap(), 0xABCD);
        assert!(read_qr(&buf, 0).unwrap());
        assert!(read_aa(&buf, 0).unwrap());
        assert!(read_rd(&buf, 0).unwrap());
        assert!(read_ra(&buf, 0).unwrap());
        assert!(read_ad(&buf, 0).unwrap());
        assert!(!read_cd(&buf, 0).unwrap());
        assert_eq!(read_qdcount(&buf, 0).unwrap(), 1);
        assert_eq!(read_ancount(&buf, 0).unwrap(), 2);
        assert_eq!(read_arcount(&buf, 0).unwrap(), 1);
    }

    #[test]
    fn test_write_flags() {
        let mut buf = vec![0u8; DNS_HEADER_LEN];
        write_id(&mut buf, 0, 0x5678).unwrap();
        write_qr(&mut buf, 0, true).unwrap();
        write_opcode(&mut buf, 0, 0).unwrap();
        write_aa(&mut buf, 0, true).unwrap();
        write_rd(&mut buf, 0, true).unwrap();
        write_ra(&mut buf, 0, true).unwrap();
        write_rcode(&mut buf, 0, 3).unwrap(); // NXDOMAIN
        write_qdcount(&mut buf, 0, 1).unwrap();
        write_ancount(&mut buf, 0, 0).unwrap();

        assert_eq!(read_id(&buf, 0).unwrap(), 0x5678);
        assert!(read_qr(&buf, 0).unwrap());
        assert!(read_aa(&buf, 0).unwrap());
        assert!(read_rd(&buf, 0).unwrap());
        assert!(read_ra(&buf, 0).unwrap());
        assert_eq!(read_rcode(&buf, 0).unwrap(), 3);
    }

    #[test]
    fn test_build_flags() {
        let flags = build_flags(true, 0, true, false, true, true, false, true, false, 3);
        assert_eq!(flags & FLAG_QR, FLAG_QR);
        assert_eq!(flags & FLAG_AA, FLAG_AA);
        assert_eq!(flags & FLAG_RD, FLAG_RD);
        assert_eq!(flags & FLAG_RA, FLAG_RA);
        assert_eq!(flags & FLAG_AD, FLAG_AD);
        assert_eq!(flags & FLAG_RCODE_MASK, 3);
    }

    #[test]
    fn test_opcode_values() {
        let mut buf = vec![0u8; DNS_HEADER_LEN];
        for opcode in 0..=15 {
            write_opcode(&mut buf, 0, opcode).unwrap();
            assert_eq!(read_opcode(&buf, 0).unwrap(), opcode);
        }
    }

    #[test]
    fn test_rcode_values() {
        let mut buf = vec![0u8; DNS_HEADER_LEN];
        for rcode in 0..=15 {
            write_rcode(&mut buf, 0, rcode).unwrap();
            assert_eq!(read_rcode(&buf, 0).unwrap(), rcode);
        }
    }

    #[test]
    fn test_header_at_offset() {
        // Simulate DNS header not at position 0 (e.g., after UDP)
        let mut buf = vec![0xAA; 20 + DNS_HEADER_LEN];
        let base = 20;
        write_id(&mut buf, base, 0x9999).unwrap();
        write_qdcount(&mut buf, base, 5).unwrap();
        assert_eq!(read_id(&buf, base).unwrap(), 0x9999);
        assert_eq!(read_qdcount(&buf, base).unwrap(), 5);
    }
}
