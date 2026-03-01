//! IEEE 802.15.4 MAC Command frame parsing and building.
//!
//! MAC command frames carry the Command Frame Identifier (1 byte)
//! followed by command-specific payloads:
//! - Association Request (1 byte capability info)
//! - Association Response (2 bytes short addr + 1 byte status)
//! - Disassociation Notification (1 byte reason)
//! - Data Request (no payload)
//! - PAN ID Conflict Notification (no payload)
//! - Orphan Notification (no payload)
//! - Beacon Request (no payload)
//! - Coordinator Realignment (7 bytes)
//! - GTS Request (1 byte characteristics)

use crate::layer::field::{FieldError, read_u16_le};

use super::types;

/// Parsed MAC command frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandFrame {
    /// Command Frame Identifier (1 byte).
    pub cmd_id: u8,
    /// Command-specific payload.
    pub payload: CommandPayload,
}

/// Command-specific payload variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandPayload {
    /// Association Request: Capability Information (1 byte).
    AssocReq(AssocReqPayload),
    /// Association Response: Short Address (2 bytes) + Status (1 byte).
    AssocResp(AssocRespPayload),
    /// Disassociation Notification: Reason (1 byte).
    DisassocNotify(DisassocNotifyPayload),
    /// Data Request: no payload.
    DataReq,
    /// PAN ID Conflict Notification: no payload.
    PanIdConflict,
    /// Orphan Notification: no payload.
    OrphanNotify,
    /// Beacon Request: no payload.
    BeaconReq,
    /// Coordinator Realignment.
    CoordRealign(CoordRealignPayload),
    /// GTS Request: Characteristics (1 byte).
    GtsReq(GtsReqPayload),
    /// Unknown command with raw bytes.
    Unknown(Vec<u8>),
}

/// Association Request capability information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssocReqPayload {
    /// Alternate PAN Coordinator (bit 0).
    pub alternate_pan_coordinator: bool,
    /// Device Type (bit 1): 1=FFD, 0=RFD.
    pub device_type: bool,
    /// Power Source (bit 2): 1=mains, 0=battery.
    pub power_source: bool,
    /// Receiver On When Idle (bit 3).
    pub receiver_on_when_idle: bool,
    /// Security Capability (bit 6).
    pub security_capability: bool,
    /// Allocate Address (bit 7).
    pub allocate_address: bool,
}

/// Association Response payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssocRespPayload {
    /// Short address assigned by coordinator (0xFFFF = none).
    pub short_address: u16,
    /// Association status.
    pub association_status: u8,
}

/// Disassociation Notification payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisassocNotifyPayload {
    /// Disassociation reason.
    pub reason: u8,
}

/// Coordinator Realignment payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordRealignPayload {
    /// PAN Identifier (2 bytes, LE).
    pub panid: u16,
    /// Coordinator Short Address (2 bytes, LE).
    pub coord_address: u16,
    /// Logical Channel (1 byte).
    pub channel: u8,
    /// Short Address assigned to device (2 bytes, LE).
    pub dev_address: u16,
}

/// GTS Request payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtsReqPayload {
    /// GTS Length (4 bits).
    pub gts_len: u8,
    /// GTS Direction (1 bit).
    pub gts_dir: bool,
    /// Characteristics Type (1 bit).
    pub charact_type: bool,
}

impl CommandFrame {
    /// Parse a command frame from the buffer at the given offset.
    /// Returns the parsed frame and the number of bytes consumed.
    pub fn parse(buf: &[u8], offset: usize) -> Result<(Self, usize), FieldError> {
        if buf.len() < offset + 1 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 1,
                have: buf.len().saturating_sub(offset),
            });
        }

        let cmd_id = buf[offset];
        let payload_start = offset + 1;
        let remaining = &buf[payload_start..];

        let (payload, payload_len) = match cmd_id {
            types::cmd_id::ASSOC_REQ => {
                if remaining.is_empty() {
                    return Err(FieldError::BufferTooShort {
                        offset: payload_start,
                        need: 1,
                        have: 0,
                    });
                }
                let cap = remaining[0];
                let payload = AssocReqPayload {
                    alternate_pan_coordinator: (cap & 0x01) != 0,
                    device_type: (cap & 0x02) != 0,
                    power_source: (cap & 0x04) != 0,
                    receiver_on_when_idle: (cap & 0x08) != 0,
                    security_capability: (cap & 0x40) != 0,
                    allocate_address: (cap & 0x80) != 0,
                };
                (CommandPayload::AssocReq(payload), 1)
            }
            types::cmd_id::ASSOC_RESP => {
                if remaining.len() < 3 {
                    return Err(FieldError::BufferTooShort {
                        offset: payload_start,
                        need: 3,
                        have: remaining.len(),
                    });
                }
                let short_address = read_u16_le(remaining, 0)?;
                let association_status = remaining[2];
                let payload = AssocRespPayload {
                    short_address,
                    association_status,
                };
                (CommandPayload::AssocResp(payload), 3)
            }
            types::cmd_id::DISASSOC_NOTIFY => {
                if remaining.is_empty() {
                    return Err(FieldError::BufferTooShort {
                        offset: payload_start,
                        need: 1,
                        have: 0,
                    });
                }
                let payload = DisassocNotifyPayload {
                    reason: remaining[0],
                };
                (CommandPayload::DisassocNotify(payload), 1)
            }
            types::cmd_id::DATA_REQ => (CommandPayload::DataReq, 0),
            types::cmd_id::PAN_ID_CONFLICT => (CommandPayload::PanIdConflict, 0),
            types::cmd_id::ORPHAN_NOTIFY => (CommandPayload::OrphanNotify, 0),
            types::cmd_id::BEACON_REQ => (CommandPayload::BeaconReq, 0),
            types::cmd_id::COORD_REALIGN => {
                if remaining.len() < 7 {
                    return Err(FieldError::BufferTooShort {
                        offset: payload_start,
                        need: 7,
                        have: remaining.len(),
                    });
                }
                let panid = read_u16_le(remaining, 0)?;
                let coord_address = read_u16_le(remaining, 2)?;
                let channel = remaining[4];
                let dev_address = read_u16_le(remaining, 5)?;
                let payload = CoordRealignPayload {
                    panid,
                    coord_address,
                    channel,
                    dev_address,
                };
                (CommandPayload::CoordRealign(payload), 7)
            }
            types::cmd_id::GTS_REQ => {
                if remaining.is_empty() {
                    return Err(FieldError::BufferTooShort {
                        offset: payload_start,
                        need: 1,
                        have: 0,
                    });
                }
                let charact = remaining[0];
                let payload = GtsReqPayload {
                    gts_len: charact & 0x0F,
                    gts_dir: (charact & 0x10) != 0,
                    charact_type: (charact & 0x20) != 0,
                };
                (CommandPayload::GtsReq(payload), 1)
            }
            _ => {
                let payload = CommandPayload::Unknown(remaining.to_vec());
                let len = remaining.len();
                (payload, len)
            }
        };

        let consumed = 1 + payload_len;
        Ok((CommandFrame { cmd_id, payload }, consumed))
    }

    /// Build the command frame bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.cmd_id);

        match &self.payload {
            CommandPayload::AssocReq(p) => {
                let mut cap: u8 = 0;
                if p.alternate_pan_coordinator {
                    cap |= 0x01;
                }
                if p.device_type {
                    cap |= 0x02;
                }
                if p.power_source {
                    cap |= 0x04;
                }
                if p.receiver_on_when_idle {
                    cap |= 0x08;
                }
                if p.security_capability {
                    cap |= 0x40;
                }
                if p.allocate_address {
                    cap |= 0x80;
                }
                out.push(cap);
            }
            CommandPayload::AssocResp(p) => {
                out.extend_from_slice(&p.short_address.to_le_bytes());
                out.push(p.association_status);
            }
            CommandPayload::DisassocNotify(p) => {
                out.push(p.reason);
            }
            CommandPayload::DataReq
            | CommandPayload::PanIdConflict
            | CommandPayload::OrphanNotify
            | CommandPayload::BeaconReq => {}
            CommandPayload::CoordRealign(p) => {
                out.extend_from_slice(&p.panid.to_le_bytes());
                out.extend_from_slice(&p.coord_address.to_le_bytes());
                out.push(p.channel);
                out.extend_from_slice(&p.dev_address.to_le_bytes());
            }
            CommandPayload::GtsReq(p) => {
                let mut charact: u8 = p.gts_len & 0x0F;
                if p.gts_dir {
                    charact |= 0x10;
                }
                if p.charact_type {
                    charact |= 0x20;
                }
                out.push(charact);
            }
            CommandPayload::Unknown(data) => {
                out.extend_from_slice(data);
            }
        }

        out
    }

    /// Get a human-readable summary of this command.
    pub fn summary(&self) -> String {
        format!("802.15.4 Command {}", types::cmd_id_name(self.cmd_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_assoc_req() {
        let buf = [0x01, 0x83];
        let (cmd, consumed) = CommandFrame::parse(&buf, 0).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(cmd.cmd_id, 1);
        if let CommandPayload::AssocReq(p) = &cmd.payload {
            assert!(p.allocate_address);
            assert!(p.device_type);
            assert!(p.alternate_pan_coordinator);
            assert!(!p.power_source);
            assert!(!p.receiver_on_when_idle);
            assert!(!p.security_capability);
        } else {
            panic!("Expected AssocReq payload");
        }
    }

    #[test]
    fn test_parse_assoc_resp() {
        let buf = [0x02, 0x34, 0x12, 0x00];
        let (cmd, consumed) = CommandFrame::parse(&buf, 0).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(cmd.cmd_id, 2);
        if let CommandPayload::AssocResp(p) = &cmd.payload {
            assert_eq!(p.short_address, 0x1234);
            assert_eq!(p.association_status, 0);
        } else {
            panic!("Expected AssocResp payload");
        }
    }

    #[test]
    fn test_parse_disassoc_notify() {
        let buf = [0x03, 0x02];
        let (cmd, consumed) = CommandFrame::parse(&buf, 0).unwrap();
        assert_eq!(consumed, 2);
        if let CommandPayload::DisassocNotify(p) = &cmd.payload {
            assert_eq!(p.reason, 2);
        } else {
            panic!("Expected DisassocNotify payload");
        }
    }

    #[test]
    fn test_parse_data_req() {
        let buf = [0x04];
        let (cmd, consumed) = CommandFrame::parse(&buf, 0).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(cmd.payload, CommandPayload::DataReq);
    }

    #[test]
    fn test_parse_panid_conflict() {
        let buf = [0x05];
        let (cmd, consumed) = CommandFrame::parse(&buf, 0).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(cmd.payload, CommandPayload::PanIdConflict);
    }

    #[test]
    fn test_parse_orphan_notify() {
        let buf = [0x06];
        let (cmd, consumed) = CommandFrame::parse(&buf, 0).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(cmd.payload, CommandPayload::OrphanNotify);
    }

    #[test]
    fn test_parse_beacon_req() {
        let buf = [0x07];
        let (cmd, consumed) = CommandFrame::parse(&buf, 0).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(cmd.payload, CommandPayload::BeaconReq);
    }

    #[test]
    fn test_parse_coord_realign() {
        let buf = [0x08, 0xFF, 0xFF, 0x00, 0x00, 0x0B, 0xCD, 0xAB];
        let (cmd, consumed) = CommandFrame::parse(&buf, 0).unwrap();
        assert_eq!(consumed, 8);
        if let CommandPayload::CoordRealign(p) = &cmd.payload {
            assert_eq!(p.panid, 0xFFFF);
            assert_eq!(p.coord_address, 0x0000);
            assert_eq!(p.channel, 11);
            assert_eq!(p.dev_address, 0xABCD);
        } else {
            panic!("Expected CoordRealign payload");
        }
    }

    #[test]
    fn test_parse_gts_req() {
        let buf = [0x09, 0x15];
        let (cmd, consumed) = CommandFrame::parse(&buf, 0).unwrap();
        assert_eq!(consumed, 2);
        if let CommandPayload::GtsReq(p) = &cmd.payload {
            assert_eq!(p.gts_len, 5);
            assert!(p.gts_dir);
            assert!(!p.charact_type);
        } else {
            panic!("Expected GtsReq payload");
        }
    }

    #[test]
    fn test_build_roundtrip_assoc_req() {
        let cmd = CommandFrame {
            cmd_id: types::cmd_id::ASSOC_REQ,
            payload: CommandPayload::AssocReq(AssocReqPayload {
                alternate_pan_coordinator: false,
                device_type: true,
                power_source: true,
                receiver_on_when_idle: true,
                security_capability: false,
                allocate_address: true,
            }),
        };
        let bytes = cmd.build();
        let (parsed, _) = CommandFrame::parse(&bytes, 0).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn test_build_roundtrip_assoc_resp() {
        let cmd = CommandFrame {
            cmd_id: types::cmd_id::ASSOC_RESP,
            payload: CommandPayload::AssocResp(AssocRespPayload {
                short_address: 0x5678,
                association_status: types::assoc_status::PAN_AT_CAPACITY,
            }),
        };
        let bytes = cmd.build();
        let (parsed, _) = CommandFrame::parse(&bytes, 0).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn test_build_roundtrip_disassoc() {
        let cmd = CommandFrame {
            cmd_id: types::cmd_id::DISASSOC_NOTIFY,
            payload: CommandPayload::DisassocNotify(DisassocNotifyPayload {
                reason: types::disassoc_reason::DEVICE_WISHES_TO_LEAVE,
            }),
        };
        let bytes = cmd.build();
        let (parsed, _) = CommandFrame::parse(&bytes, 0).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn test_build_roundtrip_data_req() {
        let cmd = CommandFrame {
            cmd_id: types::cmd_id::DATA_REQ,
            payload: CommandPayload::DataReq,
        };
        let bytes = cmd.build();
        assert_eq!(bytes, vec![0x04]);
        let (parsed, _) = CommandFrame::parse(&bytes, 0).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn test_build_roundtrip_coord_realign() {
        let cmd = CommandFrame {
            cmd_id: types::cmd_id::COORD_REALIGN,
            payload: CommandPayload::CoordRealign(CoordRealignPayload {
                panid: 0x1234,
                coord_address: 0x0000,
                channel: 15,
                dev_address: 0xFFFF,
            }),
        };
        let bytes = cmd.build();
        let (parsed, _) = CommandFrame::parse(&bytes, 0).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn test_build_roundtrip_gts_req() {
        let cmd = CommandFrame {
            cmd_id: types::cmd_id::GTS_REQ,
            payload: CommandPayload::GtsReq(GtsReqPayload {
                gts_len: 7,
                gts_dir: true,
                charact_type: true,
            }),
        };
        let bytes = cmd.build();
        let (parsed, _) = CommandFrame::parse(&bytes, 0).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn test_parse_with_offset() {
        let mut buf = vec![0xAA, 0xBB];
        buf.push(0x04);
        let (cmd, consumed) = CommandFrame::parse(&buf, 2).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(cmd.cmd_id, types::cmd_id::DATA_REQ);
    }

    #[test]
    fn test_parse_buffer_too_short() {
        let buf: [u8; 0] = [];
        let result = CommandFrame::parse(&buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_summary() {
        let cmd = CommandFrame {
            cmd_id: types::cmd_id::ASSOC_REQ,
            payload: CommandPayload::AssocReq(AssocReqPayload {
                alternate_pan_coordinator: false,
                device_type: true,
                power_source: false,
                receiver_on_when_idle: false,
                security_capability: false,
                allocate_address: true,
            }),
        };
        let summary = cmd.summary();
        assert!(summary.contains("AssocReq"));
    }
}
