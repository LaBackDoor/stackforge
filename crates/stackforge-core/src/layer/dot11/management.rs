//! IEEE 802.11 management frame subtypes.
//!
//! Management frames are used for establishing and maintaining communications.
//! This module provides parsers for all major management frame subtypes
//! including Beacon, Probe Request/Response, Authentication, Association, etc.

use crate::layer::field::{FieldError, MacAddress};

// ============================================================================
// Dot11Beacon
// ============================================================================

/// 802.11 Beacon frame body.
///
/// Fixed fields: timestamp(8B) + beacon_interval(2B) + capability(2B) = 12 bytes.
/// Followed by an IE chain (parsed separately by the ie module).
#[derive(Debug, Clone)]
pub struct Dot11Beacon {
    pub offset: usize,
}

/// Beacon fixed fields length.
pub const BEACON_FIXED_LEN: usize = 12;

impl Dot11Beacon {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Validate the buffer contains enough data.
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + BEACON_FIXED_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: BEACON_FIXED_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    /// Timestamp (8 bytes, little-endian).
    pub fn timestamp(&self, buf: &[u8]) -> Result<u64, FieldError> {
        let off = self.offset;
        if buf.len() < off + 8 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 8,
                have: buf.len(),
            });
        }
        Ok(u64::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]))
    }

    /// Beacon interval in TUs (1 TU = 1024 microseconds), little-endian u16.
    pub fn beacon_interval(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 8;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Capability information (2 bytes, little-endian).
    pub fn capability(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 10;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Offset where the IE chain starts.
    pub fn ie_offset(&self) -> usize {
        self.offset + BEACON_FIXED_LEN
    }

    /// Header length (fixed fields only).
    pub fn header_len(&self) -> usize {
        BEACON_FIXED_LEN
    }

    /// Build beacon fixed fields.
    pub fn build(timestamp: u64, beacon_interval: u16, capability: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(BEACON_FIXED_LEN);
        out.extend_from_slice(&timestamp.to_le_bytes());
        out.extend_from_slice(&beacon_interval.to_le_bytes());
        out.extend_from_slice(&capability.to_le_bytes());
        out
    }
}

// ============================================================================
// Dot11ProbeReq
// ============================================================================

/// 802.11 Probe Request frame body.
///
/// Has no fixed fields; just an IE chain.
#[derive(Debug, Clone)]
pub struct Dot11ProbeReq {
    pub offset: usize,
}

impl Dot11ProbeReq {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Offset where the IE chain starts (immediately).
    pub fn ie_offset(&self) -> usize {
        self.offset
    }

    /// Header length (no fixed fields).
    pub fn header_len(&self) -> usize {
        0
    }
}

// ============================================================================
// Dot11ProbeResp
// ============================================================================

/// 802.11 Probe Response frame body.
///
/// Same fixed fields as Beacon: timestamp(8B) + beacon_interval(2B) + capability(2B).
#[derive(Debug, Clone)]
pub struct Dot11ProbeResp {
    pub offset: usize,
}

impl Dot11ProbeResp {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Timestamp (8 bytes, little-endian).
    pub fn timestamp(&self, buf: &[u8]) -> Result<u64, FieldError> {
        let off = self.offset;
        if buf.len() < off + 8 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 8,
                have: buf.len(),
            });
        }
        Ok(u64::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]))
    }

    /// Beacon interval in TUs, little-endian.
    pub fn beacon_interval(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 8;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Capability information (2 bytes, little-endian).
    pub fn capability(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 10;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Offset where the IE chain starts.
    pub fn ie_offset(&self) -> usize {
        self.offset + BEACON_FIXED_LEN
    }

    /// Header length (fixed fields only).
    pub fn header_len(&self) -> usize {
        BEACON_FIXED_LEN
    }

    /// Build probe response fixed fields.
    pub fn build(timestamp: u64, beacon_interval: u16, capability: u16) -> Vec<u8> {
        Dot11Beacon::build(timestamp, beacon_interval, capability)
    }
}

// ============================================================================
// Dot11Auth
// ============================================================================

/// 802.11 Authentication frame body.
///
/// Fixed fields: auth_algo(2B) + auth_seq(2B) + status_code(2B) = 6 bytes.
/// May be followed by IEs (e.g., challenge text for shared key auth).
#[derive(Debug, Clone)]
pub struct Dot11Auth {
    pub offset: usize,
}

pub const AUTH_FIXED_LEN: usize = 6;

impl Dot11Auth {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Validate buffer.
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + AUTH_FIXED_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: AUTH_FIXED_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    /// Authentication algorithm number (little-endian u16).
    pub fn algo(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Authentication sequence number (little-endian u16).
    pub fn seqnum(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 2;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Status code (little-endian u16).
    pub fn status_code(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 4;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Offset where the IE chain starts.
    pub fn ie_offset(&self) -> usize {
        self.offset + AUTH_FIXED_LEN
    }

    /// Header length.
    pub fn header_len(&self) -> usize {
        AUTH_FIXED_LEN
    }

    /// Check if this auth frame answers another.
    pub fn answers(&self, buf: &[u8], other: &Dot11Auth, other_buf: &[u8]) -> bool {
        let self_algo = self.algo(buf).unwrap_or(0);
        let other_algo = other.algo(other_buf).unwrap_or(0);
        if self_algo != other_algo {
            return false;
        }
        let self_seq = self.seqnum(buf).unwrap_or(0);
        let other_seq = other.seqnum(other_buf).unwrap_or(0);
        self_seq == other_seq + 1 || (self_algo == 3 && self_seq == other_seq)
    }

    /// Build authentication fixed fields.
    pub fn build(algo: u16, seqnum: u16, status_code: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(AUTH_FIXED_LEN);
        out.extend_from_slice(&algo.to_le_bytes());
        out.extend_from_slice(&seqnum.to_le_bytes());
        out.extend_from_slice(&status_code.to_le_bytes());
        out
    }
}

// ============================================================================
// Dot11Deauth
// ============================================================================

/// 802.11 Deauthentication frame body.
///
/// Fixed fields: reason_code(2B).
#[derive(Debug, Clone)]
pub struct Dot11Deauth {
    pub offset: usize,
}

pub const DEAUTH_FIXED_LEN: usize = 2;

impl Dot11Deauth {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Reason code (little-endian u16).
    pub fn reason_code(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Header length.
    pub fn header_len(&self) -> usize {
        DEAUTH_FIXED_LEN
    }

    /// Build deauthentication body.
    pub fn build(reason_code: u16) -> Vec<u8> {
        reason_code.to_le_bytes().to_vec()
    }
}

// ============================================================================
// Dot11Disas (Disassociation)
// ============================================================================

/// 802.11 Disassociation frame body.
///
/// Fixed fields: reason_code(2B).
#[derive(Debug, Clone)]
pub struct Dot11Disas {
    pub offset: usize,
}

pub const DISAS_FIXED_LEN: usize = 2;

impl Dot11Disas {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Reason code (little-endian u16).
    pub fn reason_code(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Header length.
    pub fn header_len(&self) -> usize {
        DISAS_FIXED_LEN
    }

    /// Build disassociation body.
    pub fn build(reason_code: u16) -> Vec<u8> {
        reason_code.to_le_bytes().to_vec()
    }
}

// ============================================================================
// Dot11AssocReq (Association Request)
// ============================================================================

/// 802.11 Association Request frame body.
///
/// Fixed fields: capability(2B) + listen_interval(2B) = 4 bytes.
/// Followed by an IE chain.
#[derive(Debug, Clone)]
pub struct Dot11AssocReq {
    pub offset: usize,
}

pub const ASSOC_REQ_FIXED_LEN: usize = 4;

impl Dot11AssocReq {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Capability information (little-endian u16).
    pub fn capability(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Listen interval (little-endian u16).
    pub fn listen_interval(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 2;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Offset where the IE chain starts.
    pub fn ie_offset(&self) -> usize {
        self.offset + ASSOC_REQ_FIXED_LEN
    }

    /// Header length.
    pub fn header_len(&self) -> usize {
        ASSOC_REQ_FIXED_LEN
    }

    /// Build association request fixed fields.
    pub fn build(capability: u16, listen_interval: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(ASSOC_REQ_FIXED_LEN);
        out.extend_from_slice(&capability.to_le_bytes());
        out.extend_from_slice(&listen_interval.to_le_bytes());
        out
    }
}

// ============================================================================
// Dot11AssocResp (Association Response)
// ============================================================================

/// 802.11 Association Response frame body.
///
/// Fixed fields: capability(2B) + status_code(2B) + AID(2B) = 6 bytes.
/// Followed by an IE chain.
#[derive(Debug, Clone)]
pub struct Dot11AssocResp {
    pub offset: usize,
}

pub const ASSOC_RESP_FIXED_LEN: usize = 6;

impl Dot11AssocResp {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Capability information (little-endian u16).
    pub fn capability(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Status code (little-endian u16).
    pub fn status_code(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 2;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Association ID (little-endian u16).
    pub fn aid(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 4;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Offset where the IE chain starts.
    pub fn ie_offset(&self) -> usize {
        self.offset + ASSOC_RESP_FIXED_LEN
    }

    /// Header length.
    pub fn header_len(&self) -> usize {
        ASSOC_RESP_FIXED_LEN
    }

    /// Build association response fixed fields.
    pub fn build(capability: u16, status_code: u16, aid: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(ASSOC_RESP_FIXED_LEN);
        out.extend_from_slice(&capability.to_le_bytes());
        out.extend_from_slice(&status_code.to_le_bytes());
        out.extend_from_slice(&aid.to_le_bytes());
        out
    }
}

// ============================================================================
// Dot11ReassocReq (Reassociation Request)
// ============================================================================

/// 802.11 Reassociation Request frame body.
///
/// Fixed fields: capability(2B) + listen_interval(2B) + current_ap(6B) = 10 bytes.
/// Followed by an IE chain.
#[derive(Debug, Clone)]
pub struct Dot11ReassocReq {
    pub offset: usize,
}

pub const REASSOC_REQ_FIXED_LEN: usize = 10;

impl Dot11ReassocReq {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Capability information (little-endian u16).
    pub fn capability(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Listen interval (little-endian u16).
    pub fn listen_interval(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 2;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Current AP MAC address (6 bytes).
    pub fn current_ap(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        let off = self.offset + 4;
        if buf.len() < off + 6 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 6,
                have: buf.len(),
            });
        }
        Ok(MacAddress::new([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
        ]))
    }

    /// Offset where the IE chain starts.
    pub fn ie_offset(&self) -> usize {
        self.offset + REASSOC_REQ_FIXED_LEN
    }

    /// Header length.
    pub fn header_len(&self) -> usize {
        REASSOC_REQ_FIXED_LEN
    }

    /// Build reassociation request fixed fields.
    pub fn build(capability: u16, listen_interval: u16, current_ap: MacAddress) -> Vec<u8> {
        let mut out = Vec::with_capacity(REASSOC_REQ_FIXED_LEN);
        out.extend_from_slice(&capability.to_le_bytes());
        out.extend_from_slice(&listen_interval.to_le_bytes());
        out.extend_from_slice(current_ap.as_bytes());
        out
    }
}

// ============================================================================
// Dot11ReassocResp (Reassociation Response)
// ============================================================================

/// 802.11 Reassociation Response frame body (same as Association Response).
#[derive(Debug, Clone)]
pub struct Dot11ReassocResp {
    pub offset: usize,
}

impl Dot11ReassocResp {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Capability information (little-endian u16).
    pub fn capability(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Status code (little-endian u16).
    pub fn status_code(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 2;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Association ID (little-endian u16).
    pub fn aid(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 4;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Offset where the IE chain starts.
    pub fn ie_offset(&self) -> usize {
        self.offset + ASSOC_RESP_FIXED_LEN
    }

    /// Header length.
    pub fn header_len(&self) -> usize {
        ASSOC_RESP_FIXED_LEN
    }

    /// Build reassociation response fixed fields (same as assoc resp).
    pub fn build(capability: u16, status_code: u16, aid: u16) -> Vec<u8> {
        Dot11AssocResp::build(capability, status_code, aid)
    }
}

// ============================================================================
// Dot11Action
// ============================================================================

/// 802.11 Action frame body.
///
/// Fixed fields: category(1B) + variable action data.
#[derive(Debug, Clone)]
pub struct Dot11Action {
    pub offset: usize,
}

pub const ACTION_MIN_LEN: usize = 1;

impl Dot11Action {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Action category (1 byte).
    pub fn category(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.offset;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len(),
            });
        }
        Ok(buf[off])
    }

    /// Action code (1 byte, second byte of action frame body).
    pub fn action_code(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.offset + 1;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len(),
            });
        }
        Ok(buf[off])
    }

    /// Payload offset (after category byte).
    pub fn payload_offset(&self) -> usize {
        self.offset + ACTION_MIN_LEN
    }

    /// Header length (just the category byte).
    pub fn header_len(&self) -> usize {
        ACTION_MIN_LEN
    }

    /// Build action frame body.
    pub fn build(category: u8) -> Vec<u8> {
        vec![category]
    }
}

// ============================================================================
// Dot11ATIM
// ============================================================================

/// 802.11 ATIM (Announcement Traffic Indication Message) frame body.
///
/// Has no body fields.
#[derive(Debug, Clone)]
pub struct Dot11ATIM {
    pub offset: usize,
}

impl Dot11ATIM {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    pub fn header_len(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beacon_parse() {
        let mut buf = vec![0u8; 12];
        // timestamp = 0x0102030405060708 (LE)
        buf[0..8].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
        // beacon_interval = 100 (0x0064)
        buf[8..10].copy_from_slice(&100u16.to_le_bytes());
        // capability = 0x0411 (ESS + privacy + short-slot)
        buf[10..12].copy_from_slice(&0x0411u16.to_le_bytes());

        let beacon = Dot11Beacon::new(0);
        assert_eq!(beacon.timestamp(&buf).unwrap(), 0x0102030405060708);
        assert_eq!(beacon.beacon_interval(&buf).unwrap(), 100);
        assert_eq!(beacon.capability(&buf).unwrap(), 0x0411);
        assert_eq!(beacon.ie_offset(), 12);
    }

    #[test]
    fn test_beacon_build_roundtrip() {
        let data = Dot11Beacon::build(0x1234567890ABCDEF, 100, 0x0411);
        assert_eq!(data.len(), BEACON_FIXED_LEN);

        let beacon = Dot11Beacon::new(0);
        assert_eq!(beacon.timestamp(&data).unwrap(), 0x1234567890ABCDEF);
        assert_eq!(beacon.beacon_interval(&data).unwrap(), 100);
        assert_eq!(beacon.capability(&data).unwrap(), 0x0411);
    }

    #[test]
    fn test_auth_parse() {
        let mut buf = vec![0u8; 6];
        // algo = 0 (open)
        buf[0..2].copy_from_slice(&0u16.to_le_bytes());
        // seqnum = 1
        buf[2..4].copy_from_slice(&1u16.to_le_bytes());
        // status = 0 (success)
        buf[4..6].copy_from_slice(&0u16.to_le_bytes());

        let auth = Dot11Auth::new(0);
        assert_eq!(auth.algo(&buf).unwrap(), 0);
        assert_eq!(auth.seqnum(&buf).unwrap(), 1);
        assert_eq!(auth.status_code(&buf).unwrap(), 0);
    }

    #[test]
    fn test_auth_build_roundtrip() {
        let data = Dot11Auth::build(0, 1, 0);
        assert_eq!(data.len(), AUTH_FIXED_LEN);

        let auth = Dot11Auth::new(0);
        assert_eq!(auth.algo(&data).unwrap(), 0);
        assert_eq!(auth.seqnum(&data).unwrap(), 1);
        assert_eq!(auth.status_code(&data).unwrap(), 0);
    }

    #[test]
    fn test_auth_answers() {
        let req = Dot11Auth::build(0, 1, 0);
        let resp = Dot11Auth::build(0, 2, 0);

        let req_auth = Dot11Auth::new(0);
        let resp_auth = Dot11Auth::new(0);

        assert!(resp_auth.answers(&resp, &req_auth, &req));
        assert!(!req_auth.answers(&req, &resp_auth, &resp));
    }

    #[test]
    fn test_deauth_parse() {
        let buf = 1u16.to_le_bytes().to_vec();
        let deauth = Dot11Deauth::new(0);
        assert_eq!(deauth.reason_code(&buf).unwrap(), 1);
    }

    #[test]
    fn test_deauth_build_roundtrip() {
        let data = Dot11Deauth::build(4);
        let deauth = Dot11Deauth::new(0);
        assert_eq!(deauth.reason_code(&data).unwrap(), 4);
    }

    #[test]
    fn test_disas_parse() {
        let buf = 5u16.to_le_bytes().to_vec();
        let disas = Dot11Disas::new(0);
        assert_eq!(disas.reason_code(&buf).unwrap(), 5);
    }

    #[test]
    fn test_assoc_req_parse() {
        let mut buf = vec![0u8; 4];
        buf[0..2].copy_from_slice(&0x0411u16.to_le_bytes()); // cap
        buf[2..4].copy_from_slice(&200u16.to_le_bytes()); // listen interval

        let assoc = Dot11AssocReq::new(0);
        assert_eq!(assoc.capability(&buf).unwrap(), 0x0411);
        assert_eq!(assoc.listen_interval(&buf).unwrap(), 200);
    }

    #[test]
    fn test_assoc_req_build_roundtrip() {
        let data = Dot11AssocReq::build(0x0411, 200);
        let assoc = Dot11AssocReq::new(0);
        assert_eq!(assoc.capability(&data).unwrap(), 0x0411);
        assert_eq!(assoc.listen_interval(&data).unwrap(), 200);
    }

    #[test]
    fn test_assoc_resp_parse() {
        let mut buf = vec![0u8; 6];
        buf[0..2].copy_from_slice(&0x0411u16.to_le_bytes());
        buf[2..4].copy_from_slice(&0u16.to_le_bytes());
        buf[4..6].copy_from_slice(&1u16.to_le_bytes());

        let assoc = Dot11AssocResp::new(0);
        assert_eq!(assoc.capability(&buf).unwrap(), 0x0411);
        assert_eq!(assoc.status_code(&buf).unwrap(), 0);
        assert_eq!(assoc.aid(&buf).unwrap(), 1);
    }

    #[test]
    fn test_reassoc_req_parse() {
        let mut buf = vec![0u8; 10];
        buf[0..2].copy_from_slice(&0x0411u16.to_le_bytes());
        buf[2..4].copy_from_slice(&200u16.to_le_bytes());
        buf[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let reassoc = Dot11ReassocReq::new(0);
        assert_eq!(reassoc.capability(&buf).unwrap(), 0x0411);
        assert_eq!(reassoc.listen_interval(&buf).unwrap(), 200);
        assert_eq!(
            reassoc.current_ap(&buf).unwrap(),
            MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        );
    }

    #[test]
    fn test_reassoc_req_build_roundtrip() {
        let ap = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let data = Dot11ReassocReq::build(0x0411, 200, ap);
        assert_eq!(data.len(), REASSOC_REQ_FIXED_LEN);

        let reassoc = Dot11ReassocReq::new(0);
        assert_eq!(reassoc.current_ap(&data).unwrap(), ap);
    }

    #[test]
    fn test_action_parse() {
        let buf = vec![0x00u8, 0x04]; // category=spectrum_mgmt, action=CSA
        let action = Dot11Action::new(0);
        assert_eq!(action.category(&buf).unwrap(), 0x00);
        assert_eq!(action.action_code(&buf).unwrap(), 0x04);
    }

    #[test]
    fn test_action_build() {
        let data = Dot11Action::build(0x0A); // WNM category
        assert_eq!(data.len(), 1);
        assert_eq!(data[0], 0x0A);
    }

    #[test]
    fn test_probe_req() {
        let req = Dot11ProbeReq::new(0);
        assert_eq!(req.header_len(), 0);
        assert_eq!(req.ie_offset(), 0);
    }

    #[test]
    fn test_probe_resp_parse() {
        let mut buf = vec![0u8; 12];
        buf[0..8].copy_from_slice(&1000u64.to_le_bytes());
        buf[8..10].copy_from_slice(&100u16.to_le_bytes());
        buf[10..12].copy_from_slice(&0x0001u16.to_le_bytes());

        let resp = Dot11ProbeResp::new(0);
        assert_eq!(resp.timestamp(&buf).unwrap(), 1000);
        assert_eq!(resp.beacon_interval(&buf).unwrap(), 100);
        assert_eq!(resp.capability(&buf).unwrap(), 0x0001);
    }

    #[test]
    fn test_reassoc_resp() {
        let data = Dot11ReassocResp::build(0x0411, 0, 1);
        let resp = Dot11ReassocResp::new(0);
        assert_eq!(resp.capability(&data).unwrap(), 0x0411);
        assert_eq!(resp.status_code(&data).unwrap(), 0);
        assert_eq!(resp.aid(&data).unwrap(), 1);
    }
}
