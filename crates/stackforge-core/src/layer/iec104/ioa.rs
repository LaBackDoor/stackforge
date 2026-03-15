//! Time tag parsers for IEC 60870-5-104.
//!
//! Implements CP56Time2a (7-byte) and CP24Time2a (3-byte) timestamp formats
//! used extensively in IEC 104 information objects.

// ============================================================================
// CP56Time2a — 7-byte timestamp (ms + min + hour + day/dow + month + year)
// ============================================================================

/// CP56Time2a: 7-byte timestamp used in IEC 60870-5-104 information objects.
///
/// # Wire format (7 bytes, little-endian)
///
/// | Byte(s) | Field                                   |
/// |---------|-----------------------------------------|
/// | 0-1     | Milliseconds (0-59999, LE u16)          |
/// | 2       | Minutes (bits 0-5), IV flag (bit 7)     |
/// | 3       | Hours (bits 0-4), SU flag (bit 7)       |
/// | 4       | Day of month (bits 0-4), DOW (bits 5-7) |
/// | 5       | Month (bits 0-3)                        |
/// | 6       | Year (bits 0-6, relative to 2000)       |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cp56Time2a {
    /// Milliseconds (0-59999).
    pub ms: u16,
    /// Minutes (0-59).
    pub min: u8,
    /// Invalid flag.
    pub iv: bool,
    /// Hours (0-23).
    pub hour: u8,
    /// Summer time flag.
    pub su: bool,
    /// Day of month (1-31).
    pub day: u8,
    /// Day of week (1-7, 1=Monday).
    pub dow: u8,
    /// Month (1-12).
    pub month: u8,
    /// Year (0-99, relative to 2000).
    pub year: u8,
}

impl Cp56Time2a {
    /// Parse a CP56Time2a from a 7-byte buffer.
    ///
    /// Returns `None` if the buffer is too short.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 7 {
            return None;
        }
        Some(Self {
            ms: u16::from_le_bytes([buf[0], buf[1]]),
            min: buf[2] & 0x3F,
            iv: buf[2] & 0x80 != 0,
            hour: buf[3] & 0x1F,
            su: buf[3] & 0x80 != 0,
            day: buf[4] & 0x1F,
            dow: (buf[4] >> 5) & 0x07,
            month: buf[5] & 0x0F,
            year: buf[6] & 0x7F,
        })
    }

    /// Serialize to a 7-byte array.
    #[must_use]
    pub fn build(&self) -> [u8; 7] {
        let mut buf = [0u8; 7];
        let ms_bytes = self.ms.to_le_bytes();
        buf[0] = ms_bytes[0];
        buf[1] = ms_bytes[1];
        buf[2] = (self.min & 0x3F) | if self.iv { 0x80 } else { 0 };
        buf[3] = (self.hour & 0x1F) | if self.su { 0x80 } else { 0 };
        buf[4] = (self.day & 0x1F) | ((self.dow & 0x07) << 5);
        buf[5] = self.month & 0x0F;
        buf[6] = self.year & 0x7F;
        buf
    }
}

impl std::fmt::Display for Cp56Time2a {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}{}{}",
            2000u16 + u16::from(self.year),
            self.month,
            self.day,
            self.hour,
            self.min,
            self.ms / 1000,
            self.ms % 1000,
            if self.iv { " IV" } else { "" },
            if self.su { " SU" } else { "" },
        )
    }
}

// ============================================================================
// CP24Time2a — 3-byte timestamp (ms + min)
// ============================================================================

/// CP24Time2a: 3-byte timestamp used in some IEC 60870-5 information objects.
///
/// # Wire format (3 bytes, little-endian)
///
/// | Byte(s) | Field                               |
/// |---------|-------------------------------------|
/// | 0-1     | Milliseconds (0-59999, LE u16)      |
/// | 2       | Minutes (bits 0-5), IV flag (bit 7) |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cp24Time2a {
    /// Milliseconds (0-59999).
    pub ms: u16,
    /// Minutes (0-59).
    pub min: u8,
    /// Invalid flag.
    pub iv: bool,
}

impl Cp24Time2a {
    /// Parse a CP24Time2a from a 3-byte buffer.
    ///
    /// Returns `None` if the buffer is too short.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 3 {
            return None;
        }
        Some(Self {
            ms: u16::from_le_bytes([buf[0], buf[1]]),
            min: buf[2] & 0x3F,
            iv: buf[2] & 0x80 != 0,
        })
    }

    /// Serialize to a 3-byte array.
    #[must_use]
    pub fn build(&self) -> [u8; 3] {
        let mut buf = [0u8; 3];
        let ms_bytes = self.ms.to_le_bytes();
        buf[0] = ms_bytes[0];
        buf[1] = ms_bytes[1];
        buf[2] = (self.min & 0x3F) | if self.iv { 0x80 } else { 0 };
        buf
    }
}

impl std::fmt::Display for Cp24Time2a {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02}:{:02}.{:03}{}",
            self.min,
            self.ms / 1000,
            self.ms % 1000,
            if self.iv { " IV" } else { "" },
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cp56time2a_parse_build_roundtrip() {
        let original = Cp56Time2a {
            ms: 34567,
            min: 45,
            iv: false,
            hour: 13,
            su: true,
            day: 15,
            dow: 3, // Wednesday
            month: 7,
            year: 24,
        };
        let bytes = original.build();
        assert_eq!(bytes.len(), 7);
        let parsed = Cp56Time2a::parse(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_cp56time2a_flags() {
        let t = Cp56Time2a {
            ms: 0,
            min: 0,
            iv: true,
            hour: 0,
            su: false,
            day: 1,
            dow: 1,
            month: 1,
            year: 0,
        };
        let bytes = t.build();
        assert_eq!(bytes[2] & 0x80, 0x80); // IV flag set
        assert_eq!(bytes[3] & 0x80, 0x00); // SU flag not set

        let t2 = Cp56Time2a {
            ms: 0,
            min: 0,
            iv: false,
            hour: 0,
            su: true,
            day: 1,
            dow: 1,
            month: 1,
            year: 0,
        };
        let bytes2 = t2.build();
        assert_eq!(bytes2[2] & 0x80, 0x00); // IV flag not set
        assert_eq!(bytes2[3] & 0x80, 0x80); // SU flag set
    }

    #[test]
    fn test_cp56time2a_too_short() {
        assert!(Cp56Time2a::parse(&[0; 6]).is_none());
        assert!(Cp56Time2a::parse(&[]).is_none());
    }

    #[test]
    fn test_cp56time2a_display() {
        let t = Cp56Time2a {
            ms: 12345,
            min: 30,
            iv: false,
            hour: 14,
            su: false,
            day: 20,
            dow: 5,
            month: 11,
            year: 23,
        };
        let s = t.to_string();
        assert!(s.contains("2023-11-20"));
        assert!(s.contains("14:30:12.345"));
    }

    #[test]
    fn test_cp24time2a_parse_build_roundtrip() {
        let original = Cp24Time2a {
            ms: 45678,
            min: 59,
            iv: true,
        };
        let bytes = original.build();
        assert_eq!(bytes.len(), 3);
        let parsed = Cp24Time2a::parse(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_cp24time2a_too_short() {
        assert!(Cp24Time2a::parse(&[0; 2]).is_none());
        assert!(Cp24Time2a::parse(&[]).is_none());
    }

    #[test]
    fn test_cp24time2a_display() {
        let t = Cp24Time2a {
            ms: 5000,
            min: 12,
            iv: false,
        };
        assert_eq!(t.to_string(), "12:05.000");

        let t2 = Cp24Time2a {
            ms: 1500,
            min: 0,
            iv: true,
        };
        assert_eq!(t2.to_string(), "00:01.500 IV");
    }

    #[test]
    fn test_cp56time2a_dow_encoding() {
        // DOW is stored in bits 5-7 of byte 4
        let t = Cp56Time2a {
            ms: 0,
            min: 0,
            iv: false,
            hour: 0,
            su: false,
            day: 1,
            dow: 7, // Sunday
            month: 1,
            year: 0,
        };
        let bytes = t.build();
        assert_eq!((bytes[4] >> 5) & 0x07, 7);
        assert_eq!(bytes[4] & 0x1F, 1);
    }
}
