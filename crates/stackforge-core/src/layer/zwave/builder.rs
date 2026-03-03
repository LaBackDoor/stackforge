//! Z-Wave packet builder.
//!
//! Provides a fluent API for constructing Z-Wave frames.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::zwave::builder::ZWaveBuilder;
//!
//! // ACK frame
//! let pkt = ZWaveBuilder::new().home_id(0x0161f498).src(1).dst(2).ack().build();
//! assert_eq!(pkt.len(), 10);
//!
//! // REQ frame with SWITCH_BINARY command class
//! let pkt = ZWaveBuilder::new()
//!     .home_id(0x0161f498)
//!     .src(1)
//!     .dst(2)
//!     .cmd_class(0x25)
//!     .cmd(0x01)
//!     .cmd_data(vec![0xFF])
//!     .build();
//! assert!(pkt.len() > 10);
//! ```

use super::zwave_crc;

/// Builder for Z-Wave frames.
///
/// Produces either ACK frames (10 bytes, no payload) or REQ frames
/// (10 + payload bytes) with auto-computed CRC.
///
/// Frame layout:
///   homeId(4) + src(1) + frameCtrl(1) + beamSeqn(1) + length(1) + dst(1) + [payload] + crc(1)
#[derive(Debug, Clone)]
pub struct ZWaveBuilder {
    home_id: u32,
    src: u8,
    dst: u8,
    routed: bool,
    ackreq: bool,
    lowpower: bool,
    speedmodified: bool,
    headertype: u8,
    beam_control: u8,
    seqn: u8,
    cmd_class_val: Option<u8>,
    cmd_val: Option<u8>,
    cmd_data_val: Vec<u8>,
}

impl Default for ZWaveBuilder {
    fn default() -> Self {
        Self {
            home_id: 0,
            src: 1,
            dst: 2,
            routed: false,
            ackreq: true,
            lowpower: false,
            speedmodified: false,
            headertype: 0,
            beam_control: 0,
            seqn: 0,
            cmd_class_val: None,
            cmd_val: None,
            cmd_data_val: Vec::new(),
        }
    }
}

impl ZWaveBuilder {
    /// Create a new Z-Wave builder with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ========== Field setters (fluent API) ==========

    /// Set the 4-byte Home ID.
    #[must_use]
    pub fn home_id(mut self, id: u32) -> Self {
        self.home_id = id;
        self
    }

    /// Set the source node ID.
    #[must_use]
    pub fn src(mut self, src: u8) -> Self {
        self.src = src;
        self
    }

    /// Set the destination node ID.
    #[must_use]
    pub fn dst(mut self, dst: u8) -> Self {
        self.dst = dst;
        self
    }

    /// Set the routed flag (bit 7 of frame control).
    #[must_use]
    pub fn routed(mut self, v: bool) -> Self {
        self.routed = v;
        self
    }

    /// Set the ack request flag (bit 6 of frame control).
    #[must_use]
    pub fn ackreq(mut self, v: bool) -> Self {
        self.ackreq = v;
        self
    }

    /// Set the low power flag (bit 5 of frame control).
    #[must_use]
    pub fn lowpower(mut self, v: bool) -> Self {
        self.lowpower = v;
        self
    }

    /// Set the speed modified flag (bit 4 of frame control).
    #[must_use]
    pub fn speedmodified(mut self, v: bool) -> Self {
        self.speedmodified = v;
        self
    }

    /// Set the header type (bits 3-0 of frame control).
    #[must_use]
    pub fn headertype(mut self, v: u8) -> Self {
        self.headertype = v & 0x0F;
        self
    }

    /// Set the beam control field (bits 6-5 of beam/sequence byte).
    #[must_use]
    pub fn beam_control(mut self, v: u8) -> Self {
        self.beam_control = v & 0x03;
        self
    }

    /// Set the sequence number (bits 3-0 of beam/sequence byte).
    #[must_use]
    pub fn seqn(mut self, v: u8) -> Self {
        self.seqn = v & 0x0F;
        self
    }

    /// Set the command class byte. Setting this makes the frame a REQ.
    #[must_use]
    pub fn cmd_class(mut self, cc: u8) -> Self {
        self.cmd_class_val = Some(cc);
        self
    }

    /// Set the command byte.
    #[must_use]
    pub fn cmd(mut self, c: u8) -> Self {
        self.cmd_val = Some(c);
        self
    }

    /// Set the command data bytes.
    #[must_use]
    pub fn cmd_data(mut self, data: Vec<u8>) -> Self {
        self.cmd_data_val = data;
        self
    }

    /// Configure this builder for an ACK frame (clears any payload fields).
    #[must_use]
    pub fn ack(mut self) -> Self {
        self.cmd_class_val = None;
        self.cmd_val = None;
        self.cmd_data_val = Vec::new();
        self
    }

    // ========== Build ==========

    /// Compute the frame control byte from the individual flags.
    fn build_frame_ctrl(&self) -> u8 {
        let mut fc: u8 = self.headertype & 0x0F;
        if self.routed {
            fc |= 0x80;
        }
        if self.ackreq {
            fc |= 0x40;
        }
        if self.lowpower {
            fc |= 0x20;
        }
        if self.speedmodified {
            fc |= 0x10;
        }
        fc
    }

    /// Compute the beam/sequence byte.
    fn build_beam_seqn(&self) -> u8 {
        ((self.beam_control & 0x03) << 5) | (self.seqn & 0x0F)
    }

    /// Serialize the Z-Wave frame into bytes.
    ///
    /// If `cmd_class_val` is `None`, builds a 10-byte ACK frame.
    /// Otherwise builds a REQ frame with `cmd_class` + cmd + data.
    /// The CRC is computed automatically as XOR of all preceding bytes starting from 0xFF.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let is_ack = self.cmd_class_val.is_none();

        // Compute payload size
        let payload_len = if is_ack {
            0
        } else {
            // cmd_class(1) + cmd(1) + data
            1 + usize::from(self.cmd_val.is_some()) + self.cmd_data_val.len()
        };

        let total_len = 10 + payload_len; // header(9) + crc(1) + payload
        let mut buf = Vec::with_capacity(total_len);

        // Home ID (4 bytes, big-endian)
        buf.extend_from_slice(&self.home_id.to_be_bytes());

        // Source node ID (1 byte)
        buf.push(self.src);

        // Frame control byte (1 byte)
        buf.push(self.build_frame_ctrl());

        // Beam/sequence byte (1 byte)
        buf.push(self.build_beam_seqn());

        // Length field (1 byte) - total frame length
        buf.push(total_len as u8);

        // Destination node ID (1 byte)
        buf.push(self.dst);

        // Payload (only for REQ frames)
        if let Some(cc) = self.cmd_class_val {
            buf.push(cc);
            if let Some(cmd) = self.cmd_val {
                buf.push(cmd);
            }
            buf.extend_from_slice(&self.cmd_data_val);
        }

        // CRC: XOR of all preceding bytes starting from 0xFF
        let crc = zwave_crc(&buf);
        buf.push(crc);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::zwave::{ZWAVE_MIN_HEADER_LEN, ZWaveLayer, cmd_class};
    use crate::layer::{LayerIndex, LayerKind};

    #[test]
    fn test_build_ack_frame() {
        let pkt = ZWaveBuilder::new()
            .home_id(0x0161f498)
            .src(1)
            .dst(2)
            .ack()
            .build();
        assert_eq!(pkt.len(), ZWAVE_MIN_HEADER_LEN);
        // Verify fields
        let idx = LayerIndex::new(LayerKind::ZWave, 0, pkt.len());
        let zw = ZWaveLayer::new(idx);
        assert_eq!(zw.home_id(&pkt).unwrap(), 0x0161f498);
        assert_eq!(zw.src(&pkt).unwrap(), 1);
        assert_eq!(zw.dst(&pkt).unwrap(), 2);
        assert!(zw.is_ack(&pkt));
        assert!(zw.verify_crc(&pkt));
    }

    #[test]
    fn test_build_req_frame() {
        let pkt = ZWaveBuilder::new()
            .home_id(0xDEADBEEF)
            .src(3)
            .dst(5)
            .cmd_class(cmd_class::SWITCH_BINARY)
            .cmd(0x01)
            .cmd_data(vec![0xFF])
            .build();

        // 10 (header + crc) + 3 (cmd_class + cmd + data) = 13
        assert_eq!(pkt.len(), 13);

        let idx = LayerIndex::new(LayerKind::ZWave, 0, pkt.len());
        let zw = ZWaveLayer::new(idx);
        assert!(!zw.is_ack(&pkt));
        assert_eq!(zw.home_id(&pkt).unwrap(), 0xDEADBEEF);
        assert_eq!(zw.src(&pkt).unwrap(), 3);
        assert_eq!(zw.dst(&pkt).unwrap(), 5);
        assert_eq!(zw.cmd_class(&pkt).unwrap(), cmd_class::SWITCH_BINARY);
        assert_eq!(zw.cmd(&pkt).unwrap(), 0x01);
        assert_eq!(zw.cmd_data(&pkt).unwrap(), &[0xFF]);
        assert!(zw.verify_crc(&pkt));
    }

    #[test]
    fn test_crc_verification() {
        let pkt = ZWaveBuilder::new()
            .home_id(0x01020304)
            .src(10)
            .dst(20)
            .cmd_class(cmd_class::BASIC)
            .cmd(0x01)
            .build();

        let idx = LayerIndex::new(LayerKind::ZWave, 0, pkt.len());
        let zw = ZWaveLayer::new(idx);
        assert!(zw.verify_crc(&pkt));

        // Corrupt a byte and verify CRC fails
        let mut bad = pkt.clone();
        bad[4] ^= 0x01;
        assert!(!zw.verify_crc(&bad));
    }

    #[test]
    fn test_frame_ctrl_flags() {
        let pkt = ZWaveBuilder::new()
            .routed(true)
            .ackreq(true)
            .lowpower(true)
            .speedmodified(true)
            .headertype(0x03)
            .ack()
            .build();

        let idx = LayerIndex::new(LayerKind::ZWave, 0, pkt.len());
        let zw = ZWaveLayer::new(idx);
        assert!(zw.routed(&pkt).unwrap());
        assert!(zw.ackreq(&pkt).unwrap());
        assert!(zw.lowpower(&pkt).unwrap());
        assert!(zw.speedmodified(&pkt).unwrap());
        assert_eq!(zw.headertype(&pkt).unwrap(), 0x03);
    }

    #[test]
    fn test_beam_seqn() {
        let pkt = ZWaveBuilder::new().beam_control(2).seqn(0x0A).ack().build();

        let idx = LayerIndex::new(LayerKind::ZWave, 0, pkt.len());
        let zw = ZWaveLayer::new(idx);
        assert_eq!(zw.beam_control(&pkt).unwrap(), 2);
        assert_eq!(zw.seqn(&pkt).unwrap(), 0x0A);
    }

    #[test]
    fn test_defaults() {
        let b = ZWaveBuilder::new();
        let pkt = b.build();
        // Default: home_id=0, src=1, dst=2, ackreq=true, no cmd_class -> ACK
        assert_eq!(pkt.len(), 10);
        let idx = LayerIndex::new(LayerKind::ZWave, 0, pkt.len());
        let zw = ZWaveLayer::new(idx);
        assert_eq!(zw.home_id(&pkt).unwrap(), 0);
        assert_eq!(zw.src(&pkt).unwrap(), 1);
        assert_eq!(zw.dst(&pkt).unwrap(), 2);
        assert!(zw.ackreq(&pkt).unwrap());
        assert!(!zw.routed(&pkt).unwrap());
        assert!(zw.is_ack(&pkt));
    }

    #[test]
    fn test_large_payload_round_trip() {
        let data: Vec<u8> = (0..200).map(|i| (i & 0xFF) as u8).collect();
        let pkt = ZWaveBuilder::new()
            .home_id(0xCAFEBABE)
            .src(10)
            .dst(20)
            .cmd_class(cmd_class::MANUFACTURER_PROPRIETARY)
            .cmd(0x42)
            .cmd_data(data.clone())
            .build();

        let idx = LayerIndex::new(LayerKind::ZWave, 0, pkt.len());
        let zw = ZWaveLayer::new(idx);
        assert_eq!(zw.home_id(&pkt).unwrap(), 0xCAFEBABE);
        assert_eq!(zw.src(&pkt).unwrap(), 10);
        assert_eq!(zw.dst(&pkt).unwrap(), 20);
        assert_eq!(
            zw.cmd_class(&pkt).unwrap(),
            cmd_class::MANUFACTURER_PROPRIETARY
        );
        assert_eq!(zw.cmd(&pkt).unwrap(), 0x42);
        assert_eq!(zw.cmd_data(&pkt).unwrap(), &data[..]);
        assert!(zw.verify_crc(&pkt));
    }

    #[test]
    fn test_length_field_correct() {
        // ACK: length = 10
        let ack = ZWaveBuilder::new().ack().build();
        let idx = LayerIndex::new(LayerKind::ZWave, 0, ack.len());
        let zw = ZWaveLayer::new(idx);
        assert_eq!(zw.length(&ack).unwrap(), 10);

        // REQ with 1 byte data: 10 + 3 = 13
        let req = ZWaveBuilder::new()
            .cmd_class(cmd_class::BASIC)
            .cmd(0x01)
            .cmd_data(vec![0xAA])
            .build();
        let idx2 = LayerIndex::new(LayerKind::ZWave, 0, req.len());
        let zw2 = ZWaveLayer::new(idx2);
        assert_eq!(zw2.length(&req).unwrap(), 13);
        assert_eq!(req.len(), 13);
    }
}
