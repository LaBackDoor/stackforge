//! ASDU (Application Service Data Unit) type definitions for IEC 60870-5-104.
//!
//! Provides information element sizes for each type ID, plus bit-field helpers
//! for SIQ (Single-point Information with Quality), DIQ (Double-point Information
//! with Quality), and QDS (Quality Descriptor) bytes.

// ============================================================================
// Information element sizes (excluding the 3-byte IOA)
// ============================================================================

/// Returns the size of the information element for a given type ID.
/// This excludes the IOA (3 bytes).
#[must_use]
pub fn ie_size(type_id: u8) -> Option<usize> {
    match type_id {
        1 => Some(1),   // M_SP_NA_1: SIQ (1 byte)
        3 => Some(1),   // M_DP_NA_1: DIQ (1 byte)
        5 => Some(2),   // M_ST_NA_1: VTI(1) + QDS(1)
        7 => Some(5),   // M_BO_NA_1: BSI(4) + QDS(1)
        9 => Some(3),   // M_ME_NA_1: NVA(2) + QDS(1)
        11 => Some(3),  // M_ME_NB_1: SVA(2) + QDS(1)
        13 => Some(5),  // M_ME_NC_1: R32(4) + QDS(1)
        15 => Some(5),  // M_IT_NA_1: BCR(5)
        30 => Some(8),  // M_SP_TB_1: SIQ(1) + CP56Time2a(7)
        31 => Some(8),  // M_DP_TB_1: DIQ(1) + CP56Time2a(7)
        34 => Some(10), // M_ME_TD_1: NVA(2) + QDS(1) + CP56Time2a(7)
        35 => Some(10), // M_ME_TE_1: SVA(2) + QDS(1) + CP56Time2a(7)
        36 => Some(12), // M_ME_TF_1: R32(4) + QDS(1) + CP56Time2a(7)
        45 => Some(1),  // C_SC_NA_1: SCO(1)
        46 => Some(1),  // C_DC_NA_1: DCO(1)
        47 => Some(1),  // C_RC_NA_1: RCO(1)
        48 => Some(3),  // C_SE_NA_1: NVA(2) + QOS(1)
        49 => Some(3),  // C_SE_NB_1: SVA(2) + QOS(1)
        50 => Some(5),  // C_SE_NC_1: R32(4) + QOS(1)
        100 => Some(1), // C_IC_NA_1: QOI(1)
        101 => Some(1), // C_CI_NA_1: QCC(1)
        102 => Some(0), // C_RD_NA_1: (no IE)
        103 => Some(7), // C_CS_NA_1: CP56Time2a(7)
        _ => None,
    }
}

// ============================================================================
// SIQ — Single-point Information with Quality descriptor
// ============================================================================

/// SPI: single-point information (bit 0). `true` = ON, `false` = OFF.
#[inline]
#[must_use]
pub fn siq_spi(val: u8) -> bool {
    val & 0x01 != 0
}

/// BL: blocked flag (bit 4).
#[inline]
#[must_use]
pub fn siq_bl(val: u8) -> bool {
    val & 0x10 != 0
}

/// SB: substituted flag (bit 5).
#[inline]
#[must_use]
pub fn siq_sb(val: u8) -> bool {
    val & 0x20 != 0
}

/// NT: not topical flag (bit 6).
#[inline]
#[must_use]
pub fn siq_nt(val: u8) -> bool {
    val & 0x40 != 0
}

/// IV: invalid flag (bit 7).
#[inline]
#[must_use]
pub fn siq_iv(val: u8) -> bool {
    val & 0x80 != 0
}

// ============================================================================
// DIQ — Double-point Information with Quality descriptor
// ============================================================================

/// DPI: double-point information (bits 0-1).
/// 0 = indeterminate/intermediate, 1 = OFF, 2 = ON, 3 = indeterminate.
#[inline]
#[must_use]
pub fn diq_dpi(val: u8) -> u8 {
    val & 0x03
}

// ============================================================================
// QDS — Quality Descriptor
// ============================================================================

/// OV: overflow flag (bit 0).
#[inline]
#[must_use]
pub fn qds_ov(val: u8) -> bool {
    val & 0x01 != 0
}

/// BL: blocked flag (bit 4).
#[inline]
#[must_use]
pub fn qds_bl(val: u8) -> bool {
    val & 0x10 != 0
}

/// SB: substituted flag (bit 5).
#[inline]
#[must_use]
pub fn qds_sb(val: u8) -> bool {
    val & 0x20 != 0
}

/// NT: not topical flag (bit 6).
#[inline]
#[must_use]
pub fn qds_nt(val: u8) -> bool {
    val & 0x40 != 0
}

/// IV: invalid flag (bit 7).
#[inline]
#[must_use]
pub fn qds_iv(val: u8) -> bool {
    val & 0x80 != 0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ie_size_known_types() {
        assert_eq!(ie_size(1), Some(1));
        assert_eq!(ie_size(13), Some(5));
        assert_eq!(ie_size(30), Some(8));
        assert_eq!(ie_size(36), Some(12));
        assert_eq!(ie_size(45), Some(1));
        assert_eq!(ie_size(100), Some(1));
        assert_eq!(ie_size(102), Some(0));
        assert_eq!(ie_size(103), Some(7));
    }

    #[test]
    fn test_ie_size_unknown() {
        assert_eq!(ie_size(0), None);
        assert_eq!(ie_size(2), None);
        assert_eq!(ie_size(200), None);
    }

    #[test]
    fn test_siq_flags() {
        // SPI=1, BL=0, SB=0, NT=0, IV=0
        assert!(siq_spi(0x01));
        assert!(!siq_bl(0x01));
        // All flags set: 0xF1
        assert!(siq_spi(0xF1));
        assert!(siq_bl(0xF1));
        assert!(siq_sb(0xF1));
        assert!(siq_nt(0xF1));
        assert!(siq_iv(0xF1));
        // No flags
        assert!(!siq_spi(0x00));
        assert!(!siq_iv(0x00));
    }

    #[test]
    fn test_diq_dpi() {
        assert_eq!(diq_dpi(0x00), 0);
        assert_eq!(diq_dpi(0x01), 1);
        assert_eq!(diq_dpi(0x02), 2);
        assert_eq!(diq_dpi(0x03), 3);
        assert_eq!(diq_dpi(0xFF), 3);
    }

    #[test]
    fn test_qds_flags() {
        // OV=1
        assert!(qds_ov(0x01));
        assert!(!qds_bl(0x01));
        // All flags: 0xF1
        assert!(qds_ov(0xF1));
        assert!(qds_bl(0xF1));
        assert!(qds_sb(0xF1));
        assert!(qds_nt(0xF1));
        assert!(qds_iv(0xF1));
        // No flags
        assert!(!qds_ov(0x00));
        assert!(!qds_iv(0x00));
    }
}
