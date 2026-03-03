//! Z-Wave wireless protocol layer implementation.
//!
//! Implements the Z-Wave home automation wireless protocol.
//!
//! ## Frame Format
//!
//! ```text
//! Offset  Size  Field
//! 0       4     Home ID (big-endian)
//! 4       1     Source node ID
//! 5       1     Frame control byte
//!                 bit 7: routed
//!                 bit 6: ack request
//!                 bit 5: low power
//!                 bit 4: speed modified
//!                 bits 3-0: header type
//! 6       1     Beam/Sequence byte
//!                 bit 7: reserved
//!                 bits 6-5: beam control
//!                 bit 4: reserved
//!                 bits 3-0: sequence number
//! 7       1     Length (total frame length)
//! 8       1     Destination node ID
//! 9..N-1  var   Payload (cmd_class + cmd + data) -- only for Req frames
//! N       1     CRC (XOR checksum)
//! ```
//!
//! An ACK frame is exactly 10 bytes (no payload between dst and CRC).
//! A REQ frame is 10 + `payload_len` bytes.

pub mod builder;

pub use builder::ZWaveBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum Z-Wave header length: homeId(4) + src(1) + frameCtrl(1) + beamSeqn(1) + length(1) + dst(1) + crc(1).
pub const ZWAVE_MIN_HEADER_LEN: usize = 10;

/// Fixed header size for an ACK frame (no payload).
pub const ZWAVE_HEADER_LEN: usize = 10;

/// Z-Wave command class constants.
pub mod cmd_class {
    pub const NO_OPERATION: u8 = 0x00;
    pub const BASIC: u8 = 0x20;
    pub const CONTROLLER_REPLICATION: u8 = 0x21;
    pub const APPLICATION_STATUS: u8 = 0x22;
    pub const ZIP_SERVICES: u8 = 0x23;
    pub const ZIP_SERVER: u8 = 0x24;
    pub const SWITCH_BINARY: u8 = 0x25;
    pub const SWITCH_MULTILEVEL: u8 = 0x26;
    pub const SWITCH_ALL: u8 = 0x27;
    pub const SWITCH_TOGGLE_BINARY: u8 = 0x28;
    pub const SWITCH_TOGGLE_MULTILEVEL: u8 = 0x29;
    pub const CHIMNEY_FAN: u8 = 0x2A;
    pub const SCENE_ACTIVATION: u8 = 0x2B;
    pub const SCENE_ACTUATOR_CONF: u8 = 0x2C;
    pub const SCENE_CONTROLLER_CONF: u8 = 0x2D;
    pub const ZIP_CLIENT: u8 = 0x2E;
    pub const ZIP_ADV_SERVICES: u8 = 0x2F;
    pub const SENSOR_BINARY: u8 = 0x30;
    pub const SENSOR_MULTILEVEL: u8 = 0x31;
    pub const METER: u8 = 0x32;
    pub const ZIP_ADV_SERVER: u8 = 0x33;
    pub const ZIP_ADV_CLIENT: u8 = 0x34;
    pub const METER_PULSE: u8 = 0x35;
    pub const THERMOSTAT_HEATING: u8 = 0x38;
    pub const METER_TBL_CONFIG: u8 = 0x3C;
    pub const METER_TBL_MONITOR: u8 = 0x3D;
    pub const METER_TBL_PUSH: u8 = 0x3E;
    pub const THERMOSTAT_MODE: u8 = 0x40;
    pub const THERMOSTAT_OPERATING_STATE: u8 = 0x42;
    pub const THERMOSTAT_SETPOINT: u8 = 0x43;
    pub const THERMOSTAT_FAN_MODE: u8 = 0x44;
    pub const THERMOSTAT_FAN_STATE: u8 = 0x45;
    pub const CLIMATE_CONTROL_SCHEDULE: u8 = 0x46;
    pub const THERMOSTAT_SETBACK: u8 = 0x47;
    pub const DOOR_LOCK_LOGGING: u8 = 0x4C;
    pub const SCHEDULE_ENTRY_LOCK: u8 = 0x4E;
    pub const BASIC_WINDOW_COVERING: u8 = 0x50;
    pub const MTP_WINDOW_COVERING: u8 = 0x51;
    pub const MULTI_CHANNEL_V2: u8 = 0x60;
    pub const MULTI_INSTANCE: u8 = 0x61;
    pub const DOOR_LOCK: u8 = 0x62;
    pub const USER_CODE: u8 = 0x63;
    pub const CONFIGURATION: u8 = 0x70;
    pub const ALARM: u8 = 0x71;
    pub const MANUFACTURER_SPECIFIC: u8 = 0x72;
    pub const POWERLEVEL: u8 = 0x73;
    pub const PROTECTION: u8 = 0x75;
    pub const LOCK: u8 = 0x76;
    pub const NODE_NAMING: u8 = 0x77;
    pub const FIRMWARE_UPDATE_MD: u8 = 0x7A;
    pub const GROUPING_NAME: u8 = 0x7B;
    pub const REMOTE_ASSOCIATION_ACTIVATE: u8 = 0x7C;
    pub const REMOTE_ASSOCIATION: u8 = 0x7D;
    pub const BATTERY: u8 = 0x80;
    pub const CLOCK: u8 = 0x81;
    pub const HAIL: u8 = 0x82;
    pub const WAKE_UP: u8 = 0x84;
    pub const ASSOCIATION: u8 = 0x85;
    pub const VERSION: u8 = 0x86;
    pub const INDICATOR: u8 = 0x87;
    pub const PROPRIETARY: u8 = 0x88;
    pub const LANGUAGE: u8 = 0x89;
    pub const TIME: u8 = 0x8A;
    pub const TIME_PARAMETERS: u8 = 0x8B;
    pub const GEOGRAPHIC_LOCATION: u8 = 0x8C;
    pub const COMPOSITE: u8 = 0x8D;
    pub const MULTI_INSTANCE_ASSOCIATION: u8 = 0x8E;
    pub const MULTI_CMD: u8 = 0x8F;
    pub const ENERGY_PRODUCTION: u8 = 0x90;
    pub const MANUFACTURER_PROPRIETARY: u8 = 0x91;
    pub const SCREEN_MD: u8 = 0x92;
    pub const SCREEN_ATTRIBUTES: u8 = 0x93;
    pub const SIMPLE_AV_CONTROL: u8 = 0x94;
    pub const AV_CONTENT_DIRECTORY_MD: u8 = 0x95;
    pub const AV_RENDERER_STATUS: u8 = 0x96;
    pub const AV_CONTENT_SEARCH_MD: u8 = 0x97;
    pub const SECURITY: u8 = 0x98;
    pub const AV_TAGGING_MD: u8 = 0x99;
    pub const SIP_CONFIGURATION: u8 = 0x9A;
    pub const ASSOCIATION_COMMAND_CONFIGURATION: u8 = 0x9B;
    pub const SENSOR_ALARM: u8 = 0x9C;
    pub const SILENCE_ALARM: u8 = 0x9D;
    pub const MARK: u8 = 0x9E;
    pub const NON_INTEROPERABLE: u8 = 0xF0;
}

/// Return a human-readable name for a command class byte value.
#[must_use]
pub fn cmd_class_name(cc: u8) -> &'static str {
    match cc {
        cmd_class::NO_OPERATION => "NO_OPERATION",
        cmd_class::BASIC => "BASIC",
        cmd_class::CONTROLLER_REPLICATION => "CONTROLLER_REPLICATION",
        cmd_class::APPLICATION_STATUS => "APPLICATION_STATUS",
        cmd_class::ZIP_SERVICES => "ZIP_SERVICES",
        cmd_class::ZIP_SERVER => "ZIP_SERVER",
        cmd_class::SWITCH_BINARY => "SWITCH_BINARY",
        cmd_class::SWITCH_MULTILEVEL => "SWITCH_MULTILEVEL",
        cmd_class::SWITCH_ALL => "SWITCH_ALL",
        cmd_class::SWITCH_TOGGLE_BINARY => "SWITCH_TOGGLE_BINARY",
        cmd_class::SWITCH_TOGGLE_MULTILEVEL => "SWITCH_TOGGLE_MULTILEVEL",
        cmd_class::CHIMNEY_FAN => "CHIMNEY_FAN",
        cmd_class::SCENE_ACTIVATION => "SCENE_ACTIVATION",
        cmd_class::SCENE_ACTUATOR_CONF => "SCENE_ACTUATOR_CONF",
        cmd_class::SCENE_CONTROLLER_CONF => "SCENE_CONTROLLER_CONF",
        cmd_class::ZIP_CLIENT => "ZIP_CLIENT",
        cmd_class::ZIP_ADV_SERVICES => "ZIP_ADV_SERVICES",
        cmd_class::SENSOR_BINARY => "SENSOR_BINARY",
        cmd_class::SENSOR_MULTILEVEL => "SENSOR_MULTILEVEL",
        cmd_class::METER => "METER",
        cmd_class::ZIP_ADV_SERVER => "ZIP_ADV_SERVER",
        cmd_class::ZIP_ADV_CLIENT => "ZIP_ADV_CLIENT",
        cmd_class::METER_PULSE => "METER_PULSE",
        cmd_class::THERMOSTAT_HEATING => "THERMOSTAT_HEATING",
        cmd_class::METER_TBL_CONFIG => "METER_TBL_CONFIG",
        cmd_class::METER_TBL_MONITOR => "METER_TBL_MONITOR",
        cmd_class::METER_TBL_PUSH => "METER_TBL_PUSH",
        cmd_class::THERMOSTAT_MODE => "THERMOSTAT_MODE",
        cmd_class::THERMOSTAT_OPERATING_STATE => "THERMOSTAT_OPERATING_STATE",
        cmd_class::THERMOSTAT_SETPOINT => "THERMOSTAT_SETPOINT",
        cmd_class::THERMOSTAT_FAN_MODE => "THERMOSTAT_FAN_MODE",
        cmd_class::THERMOSTAT_FAN_STATE => "THERMOSTAT_FAN_STATE",
        cmd_class::CLIMATE_CONTROL_SCHEDULE => "CLIMATE_CONTROL_SCHEDULE",
        cmd_class::THERMOSTAT_SETBACK => "THERMOSTAT_SETBACK",
        cmd_class::DOOR_LOCK_LOGGING => "DOOR_LOCK_LOGGING",
        cmd_class::SCHEDULE_ENTRY_LOCK => "SCHEDULE_ENTRY_LOCK",
        cmd_class::BASIC_WINDOW_COVERING => "BASIC_WINDOW_COVERING",
        cmd_class::MTP_WINDOW_COVERING => "MTP_WINDOW_COVERING",
        cmd_class::MULTI_CHANNEL_V2 => "MULTI_CHANNEL_V2",
        cmd_class::MULTI_INSTANCE => "MULTI_INSTANCE",
        cmd_class::DOOR_LOCK => "DOOR_LOCK",
        cmd_class::USER_CODE => "USER_CODE",
        cmd_class::CONFIGURATION => "CONFIGURATION",
        cmd_class::ALARM => "ALARM",
        cmd_class::MANUFACTURER_SPECIFIC => "MANUFACTURER_SPECIFIC",
        cmd_class::POWERLEVEL => "POWERLEVEL",
        cmd_class::PROTECTION => "PROTECTION",
        cmd_class::LOCK => "LOCK",
        cmd_class::NODE_NAMING => "NODE_NAMING",
        cmd_class::FIRMWARE_UPDATE_MD => "FIRMWARE_UPDATE_MD",
        cmd_class::GROUPING_NAME => "GROUPING_NAME",
        cmd_class::REMOTE_ASSOCIATION_ACTIVATE => "REMOTE_ASSOCIATION_ACTIVATE",
        cmd_class::REMOTE_ASSOCIATION => "REMOTE_ASSOCIATION",
        cmd_class::BATTERY => "BATTERY",
        cmd_class::CLOCK => "CLOCK",
        cmd_class::HAIL => "HAIL",
        cmd_class::WAKE_UP => "WAKE_UP",
        cmd_class::ASSOCIATION => "ASSOCIATION",
        cmd_class::VERSION => "VERSION",
        cmd_class::INDICATOR => "INDICATOR",
        cmd_class::PROPRIETARY => "PROPRIETARY",
        cmd_class::LANGUAGE => "LANGUAGE",
        cmd_class::TIME => "TIME",
        cmd_class::TIME_PARAMETERS => "TIME_PARAMETERS",
        cmd_class::GEOGRAPHIC_LOCATION => "GEOGRAPHIC_LOCATION",
        cmd_class::COMPOSITE => "COMPOSITE",
        cmd_class::MULTI_INSTANCE_ASSOCIATION => "MULTI_INSTANCE_ASSOCIATION",
        cmd_class::MULTI_CMD => "MULTI_CMD",
        cmd_class::ENERGY_PRODUCTION => "ENERGY_PRODUCTION",
        cmd_class::MANUFACTURER_PROPRIETARY => "MANUFACTURER_PROPRIETARY",
        cmd_class::SCREEN_MD => "SCREEN_MD",
        cmd_class::SCREEN_ATTRIBUTES => "SCREEN_ATTRIBUTES",
        cmd_class::SIMPLE_AV_CONTROL => "SIMPLE_AV_CONTROL",
        cmd_class::AV_CONTENT_DIRECTORY_MD => "AV_CONTENT_DIRECTORY_MD",
        cmd_class::AV_RENDERER_STATUS => "AV_RENDERER_STATUS",
        cmd_class::AV_CONTENT_SEARCH_MD => "AV_CONTENT_SEARCH_MD",
        cmd_class::SECURITY => "SECURITY",
        cmd_class::AV_TAGGING_MD => "AV_TAGGING_MD",
        cmd_class::SIP_CONFIGURATION => "SIP_CONFIGURATION",
        cmd_class::ASSOCIATION_COMMAND_CONFIGURATION => "ASSOCIATION_COMMAND_CONFIGURATION",
        cmd_class::SENSOR_ALARM => "SENSOR_ALARM",
        cmd_class::SILENCE_ALARM => "SILENCE_ALARM",
        cmd_class::MARK => "MARK",
        cmd_class::NON_INTEROPERABLE => "NON_INTEROPERABLE",
        _ => "UNKNOWN",
    }
}

/// Field names exported for Python/generic access.
pub static ZWAVE_FIELD_NAMES: &[&str] = &[
    "home_id",
    "src",
    "dst",
    "routed",
    "ackreq",
    "lowpower",
    "speedmodified",
    "headertype",
    "beam_control",
    "seqn",
    "length",
    "cmd_class",
    "cmd",
    "crc",
];

/// Compute the Z-Wave CRC: XOR all bytes starting from an initial value of 0xFF.
#[must_use]
pub fn zwave_crc(data: &[u8]) -> u8 {
    data.iter().fold(0xFFu8, |acc, &b| acc ^ b)
}

/// Check if a buffer looks like a valid Z-Wave frame.
///
/// Z-Wave is a wireless protocol (not carried over TCP/UDP), so this is used
/// for detecting Z-Wave frames in raw captures.
#[must_use]
pub fn is_zwave_frame(buf: &[u8]) -> bool {
    if buf.len() < 10 {
        return false;
    }
    let length = buf[7] as usize;
    length >= 10 && length <= buf.len()
}

/// Z-Wave layer -- a zero-copy view into a packet buffer.
#[derive(Debug, Clone)]
pub struct ZWaveLayer {
    pub index: LayerIndex,
}

impl ZWaveLayer {
    /// Create a new Z-Wave layer from a layer index.
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Create a Z-Wave layer starting at offset 0 (for standalone parsing).
    #[must_use]
    pub fn at_start(end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::ZWave, 0, end),
        }
    }

    /// Return a reference to the slice of the buffer corresponding to this layer.
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    // ========================================================================
    // Field accessors (fixed offsets from index.start)
    // ========================================================================

    /// Read the 4-byte Home ID (big-endian u32) at offset 0.
    pub fn home_id(&self, buf: &[u8]) -> Result<u32, FieldError> {
        let s = self.slice(buf);
        if s.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 4,
                have: s.len(),
            });
        }
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Set the Home ID (big-endian u32) at offset 0.
    pub fn set_home_id(&self, buf: &mut [u8], value: u32) -> Result<(), FieldError> {
        let off = self.index.start;
        if buf.len() < off + 4 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 4,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off..off + 4].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Read the source node ID at offset 4.
    pub fn src(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 5 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 4,
                need: 1,
                have: s.len().saturating_sub(4),
            });
        }
        Ok(s[4])
    }

    /// Set the source node ID at offset 4.
    pub fn set_src(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 4;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Read the raw frame control byte at offset 5.
    pub fn frame_ctrl(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 6 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 5,
                need: 1,
                have: s.len().saturating_sub(5),
            });
        }
        Ok(s[5])
    }

    /// Set the raw frame control byte at offset 5.
    pub fn set_frame_ctrl(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 5;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Get the routed flag (bit 7 of frame control).
    pub fn routed(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let fc = self.frame_ctrl(buf)?;
        Ok((fc >> 7) & 0x01 == 1)
    }

    /// Set the routed flag (bit 7 of frame control).
    pub fn set_routed(&self, buf: &mut [u8], value: bool) -> Result<(), FieldError> {
        let fc = self.frame_ctrl(buf)?;
        let fc = if value { fc | 0x80 } else { fc & !0x80 };
        self.set_frame_ctrl(buf, fc)
    }

    /// Get the ack request flag (bit 6 of frame control).
    pub fn ackreq(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let fc = self.frame_ctrl(buf)?;
        Ok((fc >> 6) & 0x01 == 1)
    }

    /// Set the ack request flag (bit 6 of frame control).
    pub fn set_ackreq(&self, buf: &mut [u8], value: bool) -> Result<(), FieldError> {
        let fc = self.frame_ctrl(buf)?;
        let fc = if value { fc | 0x40 } else { fc & !0x40 };
        self.set_frame_ctrl(buf, fc)
    }

    /// Get the low power flag (bit 5 of frame control).
    pub fn lowpower(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let fc = self.frame_ctrl(buf)?;
        Ok((fc >> 5) & 0x01 == 1)
    }

    /// Set the low power flag (bit 5 of frame control).
    pub fn set_lowpower(&self, buf: &mut [u8], value: bool) -> Result<(), FieldError> {
        let fc = self.frame_ctrl(buf)?;
        let fc = if value { fc | 0x20 } else { fc & !0x20 };
        self.set_frame_ctrl(buf, fc)
    }

    /// Get the speed modified flag (bit 4 of frame control).
    pub fn speedmodified(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let fc = self.frame_ctrl(buf)?;
        Ok((fc >> 4) & 0x01 == 1)
    }

    /// Set the speed modified flag (bit 4 of frame control).
    pub fn set_speedmodified(&self, buf: &mut [u8], value: bool) -> Result<(), FieldError> {
        let fc = self.frame_ctrl(buf)?;
        let fc = if value { fc | 0x10 } else { fc & !0x10 };
        self.set_frame_ctrl(buf, fc)
    }

    /// Get the header type (bits 3-0 of frame control).
    pub fn headertype(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let fc = self.frame_ctrl(buf)?;
        Ok(fc & 0x0F)
    }

    /// Set the header type (bits 3-0 of frame control).
    pub fn set_headertype(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let fc = self.frame_ctrl(buf)?;
        let fc = (fc & 0xF0) | (value & 0x0F);
        self.set_frame_ctrl(buf, fc)
    }

    /// Read the raw beam/sequence byte at offset 6.
    pub fn beam_seqn(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 7 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 6,
                need: 1,
                have: s.len().saturating_sub(6),
            });
        }
        Ok(s[6])
    }

    /// Set the raw beam/sequence byte at offset 6.
    pub fn set_beam_seqn(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 6;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Get the beam control field (bits 6-5 of beam/sequence byte).
    pub fn beam_control(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let bs = self.beam_seqn(buf)?;
        Ok((bs >> 5) & 0x03)
    }

    /// Set the beam control field (bits 6-5 of beam/sequence byte).
    pub fn set_beam_control(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let bs = self.beam_seqn(buf)?;
        let bs = (bs & !0x60) | ((value & 0x03) << 5);
        self.set_beam_seqn(buf, bs)
    }

    /// Get the sequence number (bits 3-0 of beam/sequence byte).
    pub fn seqn(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let bs = self.beam_seqn(buf)?;
        Ok(bs & 0x0F)
    }

    /// Set the sequence number (bits 3-0 of beam/sequence byte).
    pub fn set_seqn(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let bs = self.beam_seqn(buf)?;
        let bs = (bs & 0xF0) | (value & 0x0F);
        self.set_beam_seqn(buf, bs)
    }

    /// Read the length field at offset 7.
    pub fn length(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 8 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 7,
                need: 1,
                have: s.len().saturating_sub(7),
            });
        }
        Ok(s[7])
    }

    /// Set the length field at offset 7.
    pub fn set_length(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 7;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Read the destination node ID at offset 8.
    pub fn dst(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 9 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 8,
                need: 1,
                have: s.len().saturating_sub(8),
            });
        }
        Ok(s[8])
    }

    /// Set the destination node ID at offset 8.
    pub fn set_dst(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 8;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Read the CRC byte. For ACK frames it is at offset 9.
    /// For REQ frames it is the last byte of the frame.
    pub fn crc(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < ZWAVE_MIN_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 9,
                need: 1,
                have: s.len().saturating_sub(9),
            });
        }
        // CRC is always the last byte of the frame
        Ok(s[s.len() - 1])
    }

    /// Set the CRC byte (last byte of the frame).
    pub fn set_crc(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let end = self.index.end;
        if end == 0 || buf.len() < end {
            return Err(FieldError::BufferTooShort {
                offset: end.saturating_sub(1),
                need: 1,
                have: 0,
            });
        }
        buf[end - 1] = value;
        Ok(())
    }

    // ========================================================================
    // Payload field accessors (only present in Req frames)
    // ========================================================================

    /// Returns true if this frame is an ACK (no payload -- total length is 10).
    #[must_use]
    pub fn is_ack(&self, buf: &[u8]) -> bool {
        let s = self.slice(buf);
        s.len() <= ZWAVE_MIN_HEADER_LEN
    }

    /// Read the command class byte at offset 9 (only valid for Req frames).
    /// In the wire format, the payload starts at offset 9 (between dst and crc).
    /// Layout for Req: [homeId(4), src(1), fc(1), bs(1), len(1), dst(1), cmdClass(1), cmd(1), ...data, crc(1)]
    pub fn cmd_class(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() <= ZWAVE_MIN_HEADER_LEN {
            return Err(FieldError::InvalidValue(
                "ACK frame has no cmd_class field".into(),
            ));
        }
        // Payload starts at offset 9: cmdClass is at index 9
        Ok(s[9])
    }

    /// Set the command class byte at offset 9.
    pub fn set_cmd_class(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 9;
        if self.is_ack(buf) {
            return Err(FieldError::InvalidValue(
                "ACK frame has no cmd_class field".into(),
            ));
        }
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Read the command byte at offset 10 (only valid for Req frames with sufficient payload).
    pub fn cmd(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() <= ZWAVE_MIN_HEADER_LEN + 1 {
            return Err(FieldError::InvalidValue("frame has no cmd field".into()));
        }
        Ok(s[10])
    }

    /// Set the command byte at offset 10.
    pub fn set_cmd(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 10;
        let s = self.slice(buf);
        if s.len() <= ZWAVE_MIN_HEADER_LEN + 1 {
            return Err(FieldError::InvalidValue("frame has no cmd field".into()));
        }
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Read the command data bytes (everything after cmd and before CRC).
    pub fn cmd_data<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8], FieldError> {
        let s = self.slice(buf);
        if s.len() <= ZWAVE_MIN_HEADER_LEN + 2 {
            // No data after cmd_class + cmd (or it's an ACK)
            return Ok(&[]);
        }
        // Data is from offset 11 to len-1 (last byte is CRC)
        Ok(&s[11..s.len() - 1])
    }

    // ========================================================================
    // CRC verification
    // ========================================================================

    /// Verify the CRC of this frame. Computes XOR of all bytes except the last
    /// (starting from 0xFF) and compares with the stored CRC.
    #[must_use]
    pub fn verify_crc(&self, buf: &[u8]) -> bool {
        let s = self.slice(buf);
        if s.len() < ZWAVE_MIN_HEADER_LEN {
            return false;
        }
        let computed = zwave_crc(&s[..s.len() - 1]);
        computed == s[s.len() - 1]
    }

    // ========================================================================
    // Summary / display
    // ========================================================================

    /// Generate a one-line summary of this Z-Wave frame.
    #[must_use]
    pub fn summary(&self, buf: &[u8]) -> String {
        let s = self.slice(buf);
        if s.len() < ZWAVE_MIN_HEADER_LEN {
            return "Z-Wave".to_string();
        }

        let home = self.home_id(buf).unwrap_or(0);
        let src_id = self.src(buf).unwrap_or(0);
        let dst_id = self.dst(buf).unwrap_or(0);

        if self.is_ack(buf) {
            format!("Z-Wave ACK {home:#010x} {src_id}->{dst_id}")
        } else {
            let cc = self
                .cmd_class(buf)
                .map_or_else(|_| "?".to_string(), |c| cmd_class_name(c).to_string());
            format!("Z-Wave {home:#010x} {src_id}->{dst_id}  {cc}")
        }
    }

    /// Compute the header length. For ACK frames this is the full 10 bytes.
    /// For REQ frames this is the entire frame (header + payload + CRC).
    fn compute_header_len(&self, buf: &[u8]) -> usize {
        let s = self.slice(buf);
        // The entire Z-Wave frame is this layer (no sub-layers to chain)
        s.len()
    }

    // ========================================================================
    // Field access API
    // ========================================================================

    /// Get the field names for this layer.
    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        ZWAVE_FIELD_NAMES
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "home_id" => Some(self.home_id(buf).map(FieldValue::U32)),
            "src" => Some(self.src(buf).map(FieldValue::U8)),
            "dst" => Some(self.dst(buf).map(FieldValue::U8)),
            "routed" => Some(self.routed(buf).map(FieldValue::Bool)),
            "ackreq" => Some(self.ackreq(buf).map(FieldValue::Bool)),
            "lowpower" => Some(self.lowpower(buf).map(FieldValue::Bool)),
            "speedmodified" => Some(self.speedmodified(buf).map(FieldValue::Bool)),
            "headertype" => Some(self.headertype(buf).map(FieldValue::U8)),
            "beam_control" => Some(self.beam_control(buf).map(FieldValue::U8)),
            "seqn" => Some(self.seqn(buf).map(FieldValue::U8)),
            "length" => Some(self.length(buf).map(FieldValue::U8)),
            "cmd_class" => {
                if self.is_ack(buf) {
                    Some(Ok(FieldValue::U8(0)))
                } else {
                    Some(self.cmd_class(buf).map(FieldValue::U8))
                }
            },
            "cmd" => {
                if self.is_ack(buf) {
                    Some(Ok(FieldValue::U8(0)))
                } else {
                    Some(self.cmd(buf).map(FieldValue::U8))
                }
            },
            "crc" => Some(self.crc(buf).map(FieldValue::U8)),
            _ => None,
        }
    }

    /// Set a field value by name.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match name {
            "home_id" => {
                if let FieldValue::U32(v) = value {
                    Some(self.set_home_id(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "home_id: expected U32, got {value:?}"
                    ))))
                }
            },
            "src" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_src(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "src: expected U8, got {value:?}"
                    ))))
                }
            },
            "dst" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_dst(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "dst: expected U8, got {value:?}"
                    ))))
                }
            },
            "routed" => {
                if let FieldValue::Bool(v) = value {
                    Some(self.set_routed(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "routed: expected Bool, got {value:?}"
                    ))))
                }
            },
            "ackreq" => {
                if let FieldValue::Bool(v) = value {
                    Some(self.set_ackreq(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "ackreq: expected Bool, got {value:?}"
                    ))))
                }
            },
            "lowpower" => {
                if let FieldValue::Bool(v) = value {
                    Some(self.set_lowpower(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "lowpower: expected Bool, got {value:?}"
                    ))))
                }
            },
            "speedmodified" => {
                if let FieldValue::Bool(v) = value {
                    Some(self.set_speedmodified(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "speedmodified: expected Bool, got {value:?}"
                    ))))
                }
            },
            "headertype" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_headertype(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "headertype: expected U8, got {value:?}"
                    ))))
                }
            },
            "beam_control" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_beam_control(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "beam_control: expected U8, got {value:?}"
                    ))))
                }
            },
            "seqn" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_seqn(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "seqn: expected U8, got {value:?}"
                    ))))
                }
            },
            "length" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_length(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "length: expected U8, got {value:?}"
                    ))))
                }
            },
            "cmd_class" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_cmd_class(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "cmd_class: expected U8, got {value:?}"
                    ))))
                }
            },
            "cmd" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_cmd(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "cmd: expected U8, got {value:?}"
                    ))))
                }
            },
            "crc" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_crc(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "crc: expected U8, got {value:?}"
                    ))))
                }
            },
            _ => None,
        }
    }
}

impl Layer for ZWaveLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::ZWave
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.compute_header_len(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        ZWAVE_FIELD_NAMES
    }

    fn hashret(&self, data: &[u8]) -> Vec<u8> {
        // Hash on home ID for packet matching
        self.home_id(data)
            .map(|h| h.to_be_bytes().to_vec())
            .unwrap_or_default()
    }

    fn answers(&self, data: &[u8], other: &Self, other_data: &[u8]) -> bool {
        // A reply swaps src and dst within the same home ID
        let same_home = self.home_id(data) == other.home_id(other_data);
        let swapped =
            self.src(data) == other.dst(other_data) && self.dst(data) == other.src(other_data);
        same_home && swapped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an ACK frame (10 bytes): homeId(4) + src(1) + fc(1) + bs(1) + len(1) + dst(1) + crc(1)
    fn ack_frame(home_id: u32, src: u8, dst: u8) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ZWAVE_MIN_HEADER_LEN);
        buf.extend_from_slice(&home_id.to_be_bytes()); // 0-3: home_id
        buf.push(src); // 4: src
        buf.push(0x40); // 5: frame_ctrl (ackreq=1)
        buf.push(0x01); // 6: beam_seqn (seqn=1)
        buf.push(0x0A); // 7: length=10
        buf.push(dst); // 8: dst
        let crc = zwave_crc(&buf);
        buf.push(crc); // 9: CRC
        buf
    }

    /// Build a REQ frame with a command class.
    fn req_frame(home_id: u32, src: u8, dst: u8, cmd_class: u8, cmd: u8, data: &[u8]) -> Vec<u8> {
        let payload_len = 2 + data.len(); // cmd_class + cmd + data
        let total_len = ZWAVE_MIN_HEADER_LEN + payload_len;
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&home_id.to_be_bytes()); // 0-3: home_id
        buf.push(src); // 4: src
        buf.push(0x40); // 5: frame_ctrl (ackreq=1)
        buf.push(0x01); // 6: beam_seqn (seqn=1)
        buf.push(total_len as u8); // 7: length
        buf.push(dst); // 8: dst
        buf.push(cmd_class); // 9: cmd_class
        buf.push(cmd); // 10: cmd
        buf.extend_from_slice(data); // 11..: cmd_data
        let crc = zwave_crc(&buf);
        buf.push(crc); // last: CRC
        buf
    }

    #[test]
    fn test_crc_computation() {
        // XOR of all bytes starting from 0xFF
        assert_eq!(zwave_crc(&[]), 0xFF);
        assert_eq!(zwave_crc(&[0xFF]), 0x00);
        assert_eq!(zwave_crc(&[0x01, 0x02]), 0xFF ^ 0x01 ^ 0x02);
        assert_eq!(zwave_crc(&[0xAA, 0x55]), 0xFF ^ 0xAA ^ 0x55);
    }

    #[test]
    fn test_parse_ack_frame() {
        let data = ack_frame(0x0161f498, 1, 2);
        assert_eq!(data.len(), 10);

        let idx = LayerIndex::new(LayerKind::ZWave, 0, data.len());
        let zw = ZWaveLayer::new(idx);

        assert_eq!(zw.home_id(&data).unwrap(), 0x0161f498);
        assert_eq!(zw.src(&data).unwrap(), 1);
        assert_eq!(zw.dst(&data).unwrap(), 2);
        assert_eq!(zw.length(&data).unwrap(), 10);
        assert!(zw.is_ack(&data));
        assert!(zw.verify_crc(&data));
    }

    #[test]
    fn test_parse_req_switch_binary() {
        let data = req_frame(0x0161f498, 1, 2, cmd_class::SWITCH_BINARY, 0x01, &[0xFF]);
        // Total: 10 + 3 (cmd_class + cmd + one data byte) = 13
        assert_eq!(data.len(), 13);

        let idx = LayerIndex::new(LayerKind::ZWave, 0, data.len());
        let zw = ZWaveLayer::new(idx);

        assert!(!zw.is_ack(&data));
        assert_eq!(zw.cmd_class(&data).unwrap(), cmd_class::SWITCH_BINARY);
        assert_eq!(zw.cmd(&data).unwrap(), 0x01);
        assert_eq!(zw.cmd_data(&data).unwrap(), &[0xFF]);
        assert!(zw.verify_crc(&data));
    }

    #[test]
    fn test_parse_req_sensor_binary() {
        let data = req_frame(0xDEADBEEF, 3, 5, cmd_class::SENSOR_BINARY, 0x03, &[0xFF]);
        let idx = LayerIndex::new(LayerKind::ZWave, 0, data.len());
        let zw = ZWaveLayer::new(idx);

        assert!(!zw.is_ack(&data));
        assert_eq!(zw.home_id(&data).unwrap(), 0xDEADBEEF);
        assert_eq!(zw.cmd_class(&data).unwrap(), cmd_class::SENSOR_BINARY);
        assert_eq!(cmd_class_name(cmd_class::SENSOR_BINARY), "SENSOR_BINARY");
        assert!(zw.verify_crc(&data));
    }

    #[test]
    fn test_frame_ctrl_bitfields() {
        let mut data = ack_frame(0x0161f498, 1, 2);
        let idx = LayerIndex::new(LayerKind::ZWave, 0, data.len());
        let zw = ZWaveLayer::new(idx);

        // Default: ackreq=true, routed=false
        assert!(zw.ackreq(&data).unwrap());
        assert!(!zw.routed(&data).unwrap());
        assert!(!zw.lowpower(&data).unwrap());
        assert!(!zw.speedmodified(&data).unwrap());
        assert_eq!(zw.headertype(&data).unwrap(), 0);

        // Set routed
        zw.set_routed(&mut data, true).unwrap();
        assert!(zw.routed(&data).unwrap());
        assert!(zw.ackreq(&data).unwrap()); // preserved

        // Set headertype
        zw.set_headertype(&mut data, 0x05).unwrap();
        assert_eq!(zw.headertype(&data).unwrap(), 0x05);
        assert!(zw.routed(&data).unwrap()); // preserved
    }

    #[test]
    fn test_beam_seqn_bitfields() {
        let mut data = ack_frame(0x0161f498, 1, 2);
        let idx = LayerIndex::new(LayerKind::ZWave, 0, data.len());
        let zw = ZWaveLayer::new(idx);

        // Default: beam_control=0, seqn=1
        assert_eq!(zw.beam_control(&data).unwrap(), 0);
        assert_eq!(zw.seqn(&data).unwrap(), 1);

        // Set beam control
        zw.set_beam_control(&mut data, 2).unwrap();
        assert_eq!(zw.beam_control(&data).unwrap(), 2);
        assert_eq!(zw.seqn(&data).unwrap(), 1); // preserved

        // Set sequence number
        zw.set_seqn(&mut data, 0x0F).unwrap();
        assert_eq!(zw.seqn(&data).unwrap(), 0x0F);
        assert_eq!(zw.beam_control(&data).unwrap(), 2); // preserved
    }

    #[test]
    fn test_cmd_class_name_helper() {
        assert_eq!(cmd_class_name(cmd_class::NO_OPERATION), "NO_OPERATION");
        assert_eq!(cmd_class_name(cmd_class::SWITCH_BINARY), "SWITCH_BINARY");
        assert_eq!(cmd_class_name(cmd_class::SENSOR_BINARY), "SENSOR_BINARY");
        assert_eq!(cmd_class_name(cmd_class::BATTERY), "BATTERY");
        assert_eq!(cmd_class_name(cmd_class::SECURITY), "SECURITY");
        assert_eq!(
            cmd_class_name(cmd_class::NON_INTEROPERABLE),
            "NON_INTEROPERABLE"
        );
        assert_eq!(cmd_class_name(0x99), "AV_TAGGING_MD");
        assert_eq!(cmd_class_name(0xBB), "UNKNOWN");
    }

    #[test]
    fn test_is_ack_detection() {
        let ack = ack_frame(0x0161f498, 1, 2);
        let idx = LayerIndex::new(LayerKind::ZWave, 0, ack.len());
        let zw = ZWaveLayer::new(idx);
        assert!(zw.is_ack(&ack));

        let req = req_frame(0x0161f498, 1, 2, cmd_class::BASIC, 0x01, &[]);
        let idx = LayerIndex::new(LayerKind::ZWave, 0, req.len());
        let zw = ZWaveLayer::new(idx);
        assert!(!zw.is_ack(&req));
    }

    #[test]
    fn test_verify_crc_valid() {
        let data = req_frame(0x0161f498, 1, 2, cmd_class::SWITCH_BINARY, 0x01, &[0xFF]);
        let idx = LayerIndex::new(LayerKind::ZWave, 0, data.len());
        let zw = ZWaveLayer::new(idx);
        assert!(zw.verify_crc(&data));
    }

    #[test]
    fn test_verify_crc_invalid() {
        let mut data = req_frame(0x0161f498, 1, 2, cmd_class::SWITCH_BINARY, 0x01, &[0xFF]);
        // Corrupt the CRC
        let last = data.len() - 1;
        data[last] ^= 0x01;
        let idx = LayerIndex::new(LayerKind::ZWave, 0, data.len());
        let zw = ZWaveLayer::new(idx);
        assert!(!zw.verify_crc(&data));
    }

    #[test]
    fn test_summary_ack() {
        let data = ack_frame(0x0161f498, 1, 2);
        let idx = LayerIndex::new(LayerKind::ZWave, 0, data.len());
        let zw = ZWaveLayer::new(idx);
        let s = zw.summary(&data);
        assert!(s.contains("ACK"));
        assert!(s.contains("0x0161f498"));
        assert!(s.contains("1->2"));
    }

    #[test]
    fn test_summary_req() {
        let data = req_frame(0x0161f498, 1, 2, cmd_class::SWITCH_BINARY, 0x01, &[0xFF]);
        let idx = LayerIndex::new(LayerKind::ZWave, 0, data.len());
        let zw = ZWaveLayer::new(idx);
        let s = zw.summary(&data);
        assert!(s.contains("SWITCH_BINARY"));
        assert!(s.contains("0x0161f498"));
        assert!(s.contains("1->2"));
        assert!(!s.contains("ACK"));
    }

    #[test]
    fn test_get_field() {
        let data = req_frame(0x0161f498, 1, 2, cmd_class::SWITCH_BINARY, 0x01, &[0xFF]);
        let idx = LayerIndex::new(LayerKind::ZWave, 0, data.len());
        let zw = ZWaveLayer::new(idx);

        assert_eq!(
            zw.get_field(&data, "home_id").unwrap().unwrap(),
            FieldValue::U32(0x0161f498)
        );
        assert_eq!(
            zw.get_field(&data, "src").unwrap().unwrap(),
            FieldValue::U8(1)
        );
        assert_eq!(
            zw.get_field(&data, "dst").unwrap().unwrap(),
            FieldValue::U8(2)
        );
        assert_eq!(
            zw.get_field(&data, "ackreq").unwrap().unwrap(),
            FieldValue::Bool(true)
        );
        assert_eq!(
            zw.get_field(&data, "cmd_class").unwrap().unwrap(),
            FieldValue::U8(cmd_class::SWITCH_BINARY)
        );
        assert!(zw.get_field(&data, "nonexistent").is_none());
    }

    #[test]
    fn test_builder_round_trip() {
        let built = ZWaveBuilder::new()
            .home_id(0x0161f498)
            .src(1)
            .dst(2)
            .cmd_class(cmd_class::SWITCH_BINARY)
            .cmd(0x01)
            .cmd_data(vec![0xFF])
            .build();

        let idx = LayerIndex::new(LayerKind::ZWave, 0, built.len());
        let zw = ZWaveLayer::new(idx);

        assert_eq!(zw.home_id(&built).unwrap(), 0x0161f498);
        assert_eq!(zw.src(&built).unwrap(), 1);
        assert_eq!(zw.dst(&built).unwrap(), 2);
        assert_eq!(zw.cmd_class(&built).unwrap(), cmd_class::SWITCH_BINARY);
        assert_eq!(zw.cmd(&built).unwrap(), 0x01);
        assert_eq!(zw.cmd_data(&built).unwrap(), &[0xFF]);
        assert!(zw.verify_crc(&built));
    }

    #[test]
    fn test_is_zwave_frame_detection() {
        // Valid ACK frame
        let ack = ack_frame(0x0161f498, 1, 2);
        assert!(is_zwave_frame(&ack));

        // Valid REQ frame
        let req = req_frame(0x0161f498, 1, 2, cmd_class::BASIC, 0x01, &[]);
        assert!(is_zwave_frame(&req));

        // Too short
        assert!(!is_zwave_frame(&[0x00; 9]));

        // Length field too large
        let mut bad = ack.clone();
        bad[7] = 0xFF; // length=255, but buffer is only 10
        assert!(!is_zwave_frame(&bad));

        // Length field too small
        let mut bad2 = ack.clone();
        bad2[7] = 5; // length=5, less than minimum 10
        assert!(!is_zwave_frame(&bad2));
    }

    #[test]
    fn test_set_field_home_id() {
        let mut data = ack_frame(0x0161f498, 1, 2);
        let idx = LayerIndex::new(LayerKind::ZWave, 0, data.len());
        let zw = ZWaveLayer::new(idx);

        zw.set_field(&mut data, "home_id", FieldValue::U32(0xAABBCCDD))
            .unwrap()
            .unwrap();
        assert_eq!(zw.home_id(&data).unwrap(), 0xAABBCCDD);
    }

    #[test]
    fn test_hashret_and_answers() {
        let frame1 = req_frame(0x0161f498, 1, 2, cmd_class::BASIC, 0x01, &[]);
        let frame2 = req_frame(0x0161f498, 2, 1, cmd_class::BASIC, 0x03, &[]);

        let idx1 = LayerIndex::new(LayerKind::ZWave, 0, frame1.len());
        let zw1 = ZWaveLayer::new(idx1);

        let idx2 = LayerIndex::new(LayerKind::ZWave, 0, frame2.len());
        let zw2 = ZWaveLayer::new(idx2);

        // hashret should match (same home ID)
        assert_eq!(zw1.hashret(&frame1), zw2.hashret(&frame2));

        // answers should be true (swapped src/dst)
        assert!(zw1.answers(&frame1, &zw2, &frame2));
        assert!(zw2.answers(&frame2, &zw1, &frame1));

        // Different home ID should not match
        let frame3 = req_frame(0xDEADBEEF, 2, 1, cmd_class::BASIC, 0x03, &[]);
        let idx3 = LayerIndex::new(LayerKind::ZWave, 0, frame3.len());
        let zw3 = ZWaveLayer::new(idx3);
        assert!(!zw1.answers(&frame1, &zw3, &frame3));
    }
}
