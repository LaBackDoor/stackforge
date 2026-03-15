//! DNP3 Application layer definitions.
//!
//! Provides application control byte parsing, Internal Indications (IIN) flags,
//! function code definitions, and object group/variation names.

/// DNP3 Application Control byte.
///
/// ```text
/// Bit 7: FIR (first fragment)
/// Bit 6: FIN (final fragment)
/// Bit 5: CON (confirm requested)
/// Bit 4: UNS (unsolicited)
/// Bits 3-0: SEQ (sequence number, 0-15)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppControl {
    /// First fragment flag.
    pub fir: bool,
    /// Final fragment flag.
    pub fin: bool,
    /// Confirm requested flag.
    pub con: bool,
    /// Unsolicited flag.
    pub uns: bool,
    /// Sequence number (0-15).
    pub seq: u8,
}

impl AppControl {
    /// Parse an application control byte.
    #[inline]
    #[must_use]
    pub fn parse(byte: u8) -> Self {
        Self {
            fir: byte & 0x80 != 0,
            fin: byte & 0x40 != 0,
            con: byte & 0x20 != 0,
            uns: byte & 0x10 != 0,
            seq: byte & 0x0F,
        }
    }

    /// Build the application control byte.
    #[inline]
    #[must_use]
    pub fn build(&self) -> u8 {
        let mut b = self.seq & 0x0F;
        if self.fir {
            b |= 0x80;
        }
        if self.fin {
            b |= 0x40;
        }
        if self.con {
            b |= 0x20;
        }
        if self.uns {
            b |= 0x10;
        }
        b
    }
}

/// Internal Indications (IIN) flags.
///
/// Two bytes of status information included in response messages when FIR=1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Iin {
    // IIN1 (first byte)
    /// IIN1.0 - Broadcast message received.
    pub broadcast: bool,
    /// IIN1.1 - Class 1 data available.
    pub class1: bool,
    /// IIN1.2 - Class 2 data available.
    pub class2: bool,
    /// IIN1.3 - Class 3 data available.
    pub class3: bool,
    /// IIN1.4 - Need time synchronization.
    pub need_time: bool,
    /// IIN1.5 - Some outputs are in local control.
    pub local_control: bool,
    /// IIN1.6 - Device trouble.
    pub device_trouble: bool,
    /// IIN1.7 - Device restart.
    pub device_restart: bool,
    // IIN2 (second byte)
    /// IIN2.0 - Function code not supported.
    pub func_not_supported: bool,
    /// IIN2.1 - Requested objects unknown.
    pub object_unknown: bool,
    /// IIN2.2 - Parameter error.
    pub param_error: bool,
    /// IIN2.3 - Event buffer overflow.
    pub event_buffer_overflow: bool,
    /// IIN2.4 - Operation already executing.
    pub already_executing: bool,
    /// IIN2.5 - Configuration corrupt.
    pub config_corrupt: bool,
}

impl Iin {
    /// Parse IIN from two bytes.
    #[must_use]
    pub fn parse(iin1: u8, iin2: u8) -> Self {
        Self {
            broadcast: iin1 & 0x01 != 0,
            class1: iin1 & 0x02 != 0,
            class2: iin1 & 0x04 != 0,
            class3: iin1 & 0x08 != 0,
            need_time: iin1 & 0x10 != 0,
            local_control: iin1 & 0x20 != 0,
            device_trouble: iin1 & 0x40 != 0,
            device_restart: iin1 & 0x80 != 0,
            func_not_supported: iin2 & 0x01 != 0,
            object_unknown: iin2 & 0x02 != 0,
            param_error: iin2 & 0x04 != 0,
            event_buffer_overflow: iin2 & 0x08 != 0,
            already_executing: iin2 & 0x10 != 0,
            config_corrupt: iin2 & 0x20 != 0,
        }
    }

    /// Convert IIN flags to a u16 (LE: [iin1, iin2]).
    #[must_use]
    pub fn to_u16(&self) -> u16 {
        let mut iin1: u8 = 0;
        let mut iin2: u8 = 0;
        if self.broadcast {
            iin1 |= 0x01;
        }
        if self.class1 {
            iin1 |= 0x02;
        }
        if self.class2 {
            iin1 |= 0x04;
        }
        if self.class3 {
            iin1 |= 0x08;
        }
        if self.need_time {
            iin1 |= 0x10;
        }
        if self.local_control {
            iin1 |= 0x20;
        }
        if self.device_trouble {
            iin1 |= 0x40;
        }
        if self.device_restart {
            iin1 |= 0x80;
        }
        if self.func_not_supported {
            iin2 |= 0x01;
        }
        if self.object_unknown {
            iin2 |= 0x02;
        }
        if self.param_error {
            iin2 |= 0x04;
        }
        if self.event_buffer_overflow {
            iin2 |= 0x08;
        }
        if self.already_executing {
            iin2 |= 0x10;
        }
        if self.config_corrupt {
            iin2 |= 0x20;
        }
        u16::from_le_bytes([iin1, iin2])
    }
}

/// Return a human-readable name for a DNP3 application function code.
#[must_use]
pub fn app_func_name(fc: u8) -> &'static str {
    match fc {
        0x00 => "CONFIRM",
        0x01 => "READ",
        0x02 => "WRITE",
        0x03 => "SELECT",
        0x04 => "OPERATE",
        0x05 => "DIRECT_OPERATE",
        0x06 => "DIRECT_OPERATE_NR",
        0x07 => "IMMEDIATE_FREEZE",
        0x08 => "IMMEDIATE_FREEZE_NR",
        0x09 => "FREEZE_CLEAR",
        0x0A => "FREEZE_CLEAR_NR",
        0x0B => "FREEZE_AT_TIME",
        0x0C => "FREEZE_AT_TIME_NR",
        0x0D => "COLD_RESTART",
        0x0E => "WARM_RESTART",
        0x0F => "INITIALIZE_DATA",
        0x10 => "INITIALIZE_APPLICATION",
        0x11 => "START_APPLICATION",
        0x12 => "STOP_APPLICATION",
        0x13 => "SAVE_CONFIGURATION",
        0x14 => "ENABLE_UNSOLICITED",
        0x15 => "DISABLE_UNSOLICITED",
        0x16 => "ASSIGN_CLASS",
        0x17 => "DELAY_MEASURE",
        0x18 => "RECORD_CURRENT_TIME",
        0x19 => "OPEN_FILE",
        0x1A => "CLOSE_FILE",
        0x1B => "DELETE_FILE",
        0x1C => "GET_FILE_INFO",
        0x1D => "AUTHENTICATE_FILE",
        0x1E => "ABORT_FILE",
        0x81 => "RESPONSE",
        0x82 => "UNSOLICITED_RESPONSE",
        0x83 => "AUTHENTICATE_RESPONSE",
        _ => "UNKNOWN",
    }
}

/// Return whether a function code is a response type (0x81-0x83).
#[inline]
#[must_use]
pub fn is_response_func(fc: u8) -> bool {
    matches!(fc, 0x81 | 0x82 | 0x83)
}

/// Return a human-readable name for a DNP3 object group.
#[must_use]
pub fn group_name(group: u8) -> &'static str {
    match group {
        1 => "Binary Input",
        2 => "Binary Input Event",
        3 => "Double-bit Binary Input",
        4 => "Double-bit Binary Input Event",
        10 => "Binary Output",
        11 => "Binary Output Event",
        12 => "Control Relay Output Block",
        20 => "Counter",
        21 => "Frozen Counter",
        22 => "Counter Event",
        30 => "Analog Input",
        31 => "Frozen Analog Input",
        32 => "Analog Input Event",
        34 => "Analog Input Deadband",
        40 => "Analog Output Status",
        41 => "Analog Output Block",
        42 => "Analog Output Event",
        50 => "Time and Date",
        51 => "Time and Date CTO",
        52 => "Time Delay",
        60 => "Class Data",
        70 => "File Identifier",
        80 => "Internal Indications",
        110 => "Octet String",
        111 => "Octet String Event",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_control_parse() {
        let ac = AppControl::parse(0xC1);
        assert!(ac.fir);
        assert!(ac.fin);
        assert!(!ac.con);
        assert!(!ac.uns);
        assert_eq!(ac.seq, 1);
    }

    #[test]
    fn test_app_control_all_flags() {
        let ac = AppControl::parse(0xFF);
        assert!(ac.fir);
        assert!(ac.fin);
        assert!(ac.con);
        assert!(ac.uns);
        assert_eq!(ac.seq, 15);
    }

    #[test]
    fn test_app_control_build_roundtrip() {
        for byte in 0..=255u8 {
            let ac = AppControl::parse(byte);
            assert_eq!(ac.build(), byte);
        }
    }

    #[test]
    fn test_iin_default_zero() {
        let iin = Iin::default();
        assert_eq!(iin.to_u16(), 0);
    }

    #[test]
    fn test_iin_parse_device_restart() {
        let iin = Iin::parse(0x80, 0x00);
        assert!(iin.device_restart);
        assert!(!iin.broadcast);
        assert_eq!(iin.to_u16(), 0x0080);
    }

    #[test]
    fn test_iin_parse_roundtrip() {
        let iin = Iin::parse(0xAB, 0x3F);
        let val = iin.to_u16();
        let bytes = val.to_le_bytes();
        let iin2 = Iin::parse(bytes[0], bytes[1]);
        assert_eq!(iin2.to_u16(), val);
    }

    #[test]
    fn test_iin_all_flags() {
        let iin = Iin::parse(0xFF, 0x3F);
        assert!(iin.broadcast);
        assert!(iin.class1);
        assert!(iin.class2);
        assert!(iin.class3);
        assert!(iin.need_time);
        assert!(iin.local_control);
        assert!(iin.device_trouble);
        assert!(iin.device_restart);
        assert!(iin.func_not_supported);
        assert!(iin.object_unknown);
        assert!(iin.param_error);
        assert!(iin.event_buffer_overflow);
        assert!(iin.already_executing);
        assert!(iin.config_corrupt);
    }

    #[test]
    fn test_app_func_name() {
        assert_eq!(app_func_name(0x01), "READ");
        assert_eq!(app_func_name(0x02), "WRITE");
        assert_eq!(app_func_name(0x81), "RESPONSE");
        assert_eq!(app_func_name(0x82), "UNSOLICITED_RESPONSE");
        assert_eq!(app_func_name(0xFF), "UNKNOWN");
    }

    #[test]
    fn test_is_response_func() {
        assert!(is_response_func(0x81));
        assert!(is_response_func(0x82));
        assert!(is_response_func(0x83));
        assert!(!is_response_func(0x01));
        assert!(!is_response_func(0x00));
    }

    #[test]
    fn test_group_name() {
        assert_eq!(group_name(1), "Binary Input");
        assert_eq!(group_name(30), "Analog Input");
        assert_eq!(group_name(60), "Class Data");
        assert_eq!(group_name(255), "Unknown");
    }
}
