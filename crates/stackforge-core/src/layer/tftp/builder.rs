//! TFTP packet builder.
//!
//! Provides a fluent API for constructing TFTP packets (RFC 1350).
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::tftp::builder::TftpBuilder;
//!
//! // Build a Read Request
//! let pkt = TftpBuilder::new().rrq("file.txt", "octet").build();
//!
//! // Build a DATA packet (block 1)
//! let pkt = TftpBuilder::new().data(1, b"hello world").build();
//!
//! // Build an ACK for block 1
//! let pkt = TftpBuilder::new().ack(1).build();
//! ```

use super::{OPCODE_ACK, OPCODE_DATA, OPCODE_ERROR, OPCODE_RRQ, OPCODE_WRQ};

/// Builder for TFTP packets.
#[must_use]
#[derive(Debug, Clone)]
pub struct TftpBuilder {
    opcode: u16,
    filename: Vec<u8>,
    mode: Vec<u8>,
    block_num: u16,
    payload: Vec<u8>,
    error_code: u16,
    error_msg: Vec<u8>,
}

impl Default for TftpBuilder {
    fn default() -> Self {
        Self {
            opcode: OPCODE_RRQ,
            filename: b"file.bin".to_vec(),
            mode: b"octet".to_vec(),
            block_num: 0,
            payload: Vec::new(),
            error_code: 0,
            error_msg: Vec::new(),
        }
    }
}

impl TftpBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // Request builders
    // ========================================================================

    /// Build a Read Request (RRQ) packet.
    ///
    /// Mode is typically "netascii", "octet", or "mail".
    pub fn rrq(mut self, filename: impl Into<Vec<u8>>, mode: impl Into<Vec<u8>>) -> Self {
        self.opcode = OPCODE_RRQ;
        self.filename = filename.into();
        self.mode = mode.into();
        self
    }

    /// Build a Write Request (WRQ) packet.
    pub fn wrq(mut self, filename: impl Into<Vec<u8>>, mode: impl Into<Vec<u8>>) -> Self {
        self.opcode = OPCODE_WRQ;
        self.filename = filename.into();
        self.mode = mode.into();
        self
    }

    // ========================================================================
    // Data / ACK builders
    // ========================================================================

    /// Build a DATA packet with the given block number and payload.
    pub fn data(mut self, block_num: u16, payload: impl Into<Vec<u8>>) -> Self {
        self.opcode = OPCODE_DATA;
        self.block_num = block_num;
        self.payload = payload.into();
        self
    }

    /// Build an ACK packet for the given block number.
    pub fn ack(mut self, block_num: u16) -> Self {
        self.opcode = OPCODE_ACK;
        self.block_num = block_num;
        self
    }

    // ========================================================================
    // Error builder
    // ========================================================================

    /// Build an ERROR packet.
    pub fn error(mut self, error_code: u16, msg: impl Into<Vec<u8>>) -> Self {
        self.opcode = OPCODE_ERROR;
        self.error_code = error_code;
        self.error_msg = msg.into();
        self
    }

    /// Build "File not found" error (code 1).
    pub fn error_file_not_found(self) -> Self {
        self.error(1, b"File not found".as_ref())
    }

    /// Build "Access violation" error (code 2).
    pub fn error_access_violation(self) -> Self {
        self.error(2, b"Access violation".as_ref())
    }

    /// Build "Disk full" error (code 3).
    pub fn error_disk_full(self) -> Self {
        self.error(3, b"Disk full or allocation exceeded".as_ref())
    }

    /// Build "Illegal operation" error (code 4).
    pub fn error_illegal_op(self) -> Self {
        self.error(4, b"Illegal TFTP operation".as_ref())
    }

    /// Build "File already exists" error (code 6).
    pub fn error_file_exists(self) -> Self {
        self.error(6, b"File already exists".as_ref())
    }

    // ========================================================================
    // Build
    // ========================================================================

    /// Serialize this TFTP packet to bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        match self.opcode {
            OPCODE_RRQ | OPCODE_WRQ => self.build_request(),
            OPCODE_DATA => self.build_data(),
            OPCODE_ACK => self.build_ack(),
            OPCODE_ERROR => self.build_error(),
            _ => vec![],
        }
    }

    fn build_request(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.opcode.to_be_bytes());
        out.extend_from_slice(&self.filename);
        out.push(0); // null terminator
        out.extend_from_slice(&self.mode);
        out.push(0); // null terminator
        out
    }

    fn build_data(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.payload.len());
        out.extend_from_slice(&self.opcode.to_be_bytes());
        out.extend_from_slice(&self.block_num.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    fn build_ack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        out.extend_from_slice(&self.opcode.to_be_bytes());
        out.extend_from_slice(&self.block_num.to_be_bytes());
        out
    }

    fn build_error(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.opcode.to_be_bytes());
        out.extend_from_slice(&self.error_code.to_be_bytes());
        out.extend_from_slice(&self.error_msg);
        out.push(0); // null terminator
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::LayerIndex;
    use crate::layer::LayerKind;
    use crate::layer::tftp::{
        OPCODE_ACK, OPCODE_DATA, OPCODE_ERROR, OPCODE_RRQ, OPCODE_WRQ, TftpLayer,
    };

    fn parse(data: Vec<u8>) -> (TftpLayer, Vec<u8>) {
        let len = data.len();
        let layer = TftpLayer::new(LayerIndex::new(LayerKind::Tftp, 0, len));
        (layer, data)
    }

    #[test]
    fn test_build_rrq() {
        let pkt = TftpBuilder::new().rrq("test.txt", "octet").build();
        let (layer, buf) = parse(pkt);
        assert_eq!(layer.opcode(&buf).unwrap(), OPCODE_RRQ);
        assert_eq!(layer.filename(&buf).unwrap(), "test.txt");
        assert_eq!(layer.mode(&buf).unwrap(), "octet");
    }

    #[test]
    fn test_build_wrq() {
        let pkt = TftpBuilder::new().wrq("upload.txt", "netascii").build();
        let (layer, buf) = parse(pkt);
        assert_eq!(layer.opcode(&buf).unwrap(), OPCODE_WRQ);
        assert_eq!(layer.filename(&buf).unwrap(), "upload.txt");
        assert_eq!(layer.mode(&buf).unwrap(), "netascii");
    }

    #[test]
    fn test_build_data() {
        let payload = b"Hello TFTP world!";
        let pkt = TftpBuilder::new().data(1, payload.as_ref()).build();
        let (layer, buf) = parse(pkt);
        assert_eq!(layer.opcode(&buf).unwrap(), OPCODE_DATA);
        assert_eq!(layer.block_num(&buf).unwrap(), 1);
        assert_eq!(layer.data(&buf).unwrap(), payload);
    }

    #[test]
    fn test_build_ack() {
        let pkt = TftpBuilder::new().ack(3).build();
        let (layer, buf) = parse(pkt);
        assert_eq!(layer.opcode(&buf).unwrap(), OPCODE_ACK);
        assert_eq!(layer.block_num(&buf).unwrap(), 3);
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn test_build_error() {
        let pkt = TftpBuilder::new().error_file_not_found().build();
        let (layer, buf) = parse(pkt);
        assert_eq!(layer.opcode(&buf).unwrap(), OPCODE_ERROR);
        assert_eq!(layer.error_code(&buf).unwrap(), 1);
        assert_eq!(layer.error_msg(&buf).unwrap(), "File not found");
    }

    #[test]
    fn test_build_custom_error() {
        let pkt = TftpBuilder::new()
            .error(0, b"Custom error message".as_ref())
            .build();
        let (layer, buf) = parse(pkt);
        assert_eq!(layer.error_code(&buf).unwrap(), 0);
        assert_eq!(layer.error_msg(&buf).unwrap(), "Custom error message");
    }

    #[test]
    fn test_data_roundtrip() {
        let large_data: Vec<u8> = (0u8..=255u8).collect();
        let pkt = TftpBuilder::new().data(42, large_data.clone()).build();
        let (layer, buf) = parse(pkt);
        assert_eq!(layer.block_num(&buf).unwrap(), 42);
        assert_eq!(layer.data(&buf).unwrap(), large_data);
    }
}
