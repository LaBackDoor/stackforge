//! IEEE 802.15.4 constants and type definitions.
//!
//! Frame types, address modes, command identifiers, security levels,
//! and key identifier modes as defined in the IEEE 802.15.4 standard.

// ============================================================================
// Frame Types (3 bits, from FCF bits 0-2)
// ============================================================================

/// Frame type constants for the Frame Control Field.
pub mod frame_type {
    pub const BEACON: u8 = 0;
    pub const DATA: u8 = 1;
    pub const ACK: u8 = 2;
    pub const MAC_CMD: u8 = 3;
    pub const LLDN: u8 = 4;
    pub const MULTIPURPOSE: u8 = 5;
}

/// Get the name of a frame type.
pub fn frame_type_name(ft: u8) -> &'static str {
    match ft {
        frame_type::BEACON => "Beacon",
        frame_type::DATA => "Data",
        frame_type::ACK => "Ack",
        frame_type::MAC_CMD => "Command",
        frame_type::LLDN => "LLDN",
        frame_type::MULTIPURPOSE => "Multipurpose",
        _ => "Reserved",
    }
}

// ============================================================================
// Address Modes (2 bits, from FCF)
// ============================================================================

/// Address mode constants for source/destination addressing.
pub mod addr_mode {
    pub const NONE: u8 = 0;
    pub const RESERVED: u8 = 1;
    pub const SHORT: u8 = 2;
    pub const LONG: u8 = 3;
}

/// Get the name of an address mode.
pub fn addr_mode_name(mode: u8) -> &'static str {
    match mode {
        addr_mode::NONE => "None",
        addr_mode::RESERVED => "Reserved",
        addr_mode::SHORT => "Short",
        addr_mode::LONG => "Long",
        _ => "Unknown",
    }
}

/// Get the byte length of an address for a given address mode.
pub fn addr_mode_len(mode: u8) -> usize {
    match mode {
        addr_mode::SHORT => 2,
        addr_mode::LONG => 8,
        _ => 0,
    }
}

// ============================================================================
// MAC Command Identifiers (1 byte)
// ============================================================================

/// MAC command frame identifier constants.
pub mod cmd_id {
    pub const ASSOC_REQ: u8 = 1;
    pub const ASSOC_RESP: u8 = 2;
    pub const DISASSOC_NOTIFY: u8 = 3;
    pub const DATA_REQ: u8 = 4;
    pub const PAN_ID_CONFLICT: u8 = 5;
    pub const ORPHAN_NOTIFY: u8 = 6;
    pub const BEACON_REQ: u8 = 7;
    pub const COORD_REALIGN: u8 = 8;
    pub const GTS_REQ: u8 = 9;
}

/// Get the name of a MAC command identifier.
pub fn cmd_id_name(id: u8) -> &'static str {
    match id {
        cmd_id::ASSOC_REQ => "AssocReq",
        cmd_id::ASSOC_RESP => "AssocResp",
        cmd_id::DISASSOC_NOTIFY => "DisassocNotify",
        cmd_id::DATA_REQ => "DataReq",
        cmd_id::PAN_ID_CONFLICT => "PANIDConflictNotify",
        cmd_id::ORPHAN_NOTIFY => "OrphanNotify",
        cmd_id::BEACON_REQ => "BeaconReq",
        cmd_id::COORD_REALIGN => "CoordRealign",
        cmd_id::GTS_REQ => "GTSReq",
        _ => "Reserved",
    }
}

// ============================================================================
// Security Levels (3 bits)
// ============================================================================

/// Security level constants for the Auxiliary Security Header.
pub mod security_level {
    pub const NONE: u8 = 0;
    pub const MIC_32: u8 = 1;
    pub const MIC_64: u8 = 2;
    pub const MIC_128: u8 = 3;
    pub const ENC: u8 = 4;
    pub const ENC_MIC_32: u8 = 5;
    pub const ENC_MIC_64: u8 = 6;
    pub const ENC_MIC_128: u8 = 7;
}

/// Get the name of a security level.
pub fn security_level_name(level: u8) -> &'static str {
    match level {
        security_level::NONE => "None",
        security_level::MIC_32 => "MIC-32",
        security_level::MIC_64 => "MIC-64",
        security_level::MIC_128 => "MIC-128",
        security_level::ENC => "ENC",
        security_level::ENC_MIC_32 => "ENC-MIC-32",
        security_level::ENC_MIC_64 => "ENC-MIC-64",
        security_level::ENC_MIC_128 => "ENC-MIC-128",
        _ => "Unknown",
    }
}

// ============================================================================
// Key Identifier Modes (2 bits)
// ============================================================================

/// Key identifier mode constants for the Auxiliary Security Header.
pub mod key_id_mode {
    pub const IMPLICIT: u8 = 0;
    pub const KEY_INDEX: u8 = 1;
    pub const KEY_SOURCE_4: u8 = 2;
    pub const KEY_SOURCE_8: u8 = 3;
}

/// Get the name of a key identifier mode.
pub fn key_id_mode_name(mode: u8) -> &'static str {
    match mode {
        key_id_mode::IMPLICIT => "Implicit",
        key_id_mode::KEY_INDEX => "1oKeyIndex",
        key_id_mode::KEY_SOURCE_4 => "4o-KeySource-1oKeyIndex",
        key_id_mode::KEY_SOURCE_8 => "8o-KeySource-1oKeyIndex",
        _ => "Unknown",
    }
}

/// Get the byte length of the Key Identifier field for a given key ID mode.
/// This includes the key source and key index bytes.
pub fn key_id_len(mode: u8) -> usize {
    match mode {
        key_id_mode::IMPLICIT => 0,
        key_id_mode::KEY_INDEX => 1,    // Key Index only
        key_id_mode::KEY_SOURCE_4 => 5, // 4-byte source + 1-byte index
        key_id_mode::KEY_SOURCE_8 => 9, // 8-byte source + 1-byte index
        _ => 0,
    }
}

// ============================================================================
// Association Status (for AssocResp command)
// ============================================================================

/// Association status constants for association response commands.
pub mod assoc_status {
    pub const SUCCESSFUL: u8 = 0;
    pub const PAN_AT_CAPACITY: u8 = 1;
    pub const PAN_ACCESS_DENIED: u8 = 2;
}

/// Get the name of an association status.
pub fn assoc_status_name(status: u8) -> &'static str {
    match status {
        assoc_status::SUCCESSFUL => "successful",
        assoc_status::PAN_AT_CAPACITY => "PAN_at_capacity",
        assoc_status::PAN_ACCESS_DENIED => "PAN_access_denied",
        _ => "Reserved",
    }
}

// ============================================================================
// Disassociation Reason (for DisassocNotify command)
// ============================================================================

/// Disassociation reason constants.
pub mod disassoc_reason {
    pub const COORD_WISHES_DEVICE_TO_LEAVE: u8 = 1;
    pub const DEVICE_WISHES_TO_LEAVE: u8 = 2;
}

/// Get the name of a disassociation reason.
pub fn disassoc_reason_name(reason: u8) -> &'static str {
    match reason {
        disassoc_reason::COORD_WISHES_DEVICE_TO_LEAVE => "coord_wishes_device_to_leave",
        disassoc_reason::DEVICE_WISHES_TO_LEAVE => "device_wishes_to_leave",
        _ => "Reserved",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_names() {
        assert_eq!(frame_type_name(frame_type::BEACON), "Beacon");
        assert_eq!(frame_type_name(frame_type::DATA), "Data");
        assert_eq!(frame_type_name(frame_type::ACK), "Ack");
        assert_eq!(frame_type_name(frame_type::MAC_CMD), "Command");
        assert_eq!(frame_type_name(frame_type::LLDN), "LLDN");
        assert_eq!(frame_type_name(frame_type::MULTIPURPOSE), "Multipurpose");
        assert_eq!(frame_type_name(6), "Reserved");
    }

    #[test]
    fn test_addr_mode_names() {
        assert_eq!(addr_mode_name(addr_mode::NONE), "None");
        assert_eq!(addr_mode_name(addr_mode::SHORT), "Short");
        assert_eq!(addr_mode_name(addr_mode::LONG), "Long");
        assert_eq!(addr_mode_name(addr_mode::RESERVED), "Reserved");
    }

    #[test]
    fn test_addr_mode_len() {
        assert_eq!(addr_mode_len(addr_mode::NONE), 0);
        assert_eq!(addr_mode_len(addr_mode::SHORT), 2);
        assert_eq!(addr_mode_len(addr_mode::LONG), 8);
        assert_eq!(addr_mode_len(addr_mode::RESERVED), 0);
    }

    #[test]
    fn test_cmd_id_names() {
        assert_eq!(cmd_id_name(cmd_id::ASSOC_REQ), "AssocReq");
        assert_eq!(cmd_id_name(cmd_id::ASSOC_RESP), "AssocResp");
        assert_eq!(cmd_id_name(cmd_id::DISASSOC_NOTIFY), "DisassocNotify");
        assert_eq!(cmd_id_name(cmd_id::DATA_REQ), "DataReq");
        assert_eq!(cmd_id_name(cmd_id::PAN_ID_CONFLICT), "PANIDConflictNotify");
        assert_eq!(cmd_id_name(cmd_id::ORPHAN_NOTIFY), "OrphanNotify");
        assert_eq!(cmd_id_name(cmd_id::BEACON_REQ), "BeaconReq");
        assert_eq!(cmd_id_name(cmd_id::COORD_REALIGN), "CoordRealign");
        assert_eq!(cmd_id_name(cmd_id::GTS_REQ), "GTSReq");
        assert_eq!(cmd_id_name(0), "Reserved");
    }

    #[test]
    fn test_security_level_names() {
        assert_eq!(security_level_name(security_level::NONE), "None");
        assert_eq!(security_level_name(security_level::MIC_32), "MIC-32");
        assert_eq!(
            security_level_name(security_level::ENC_MIC_128),
            "ENC-MIC-128"
        );
    }

    #[test]
    fn test_key_id_mode_names() {
        assert_eq!(key_id_mode_name(key_id_mode::IMPLICIT), "Implicit");
        assert_eq!(key_id_mode_name(key_id_mode::KEY_INDEX), "1oKeyIndex");
        assert_eq!(
            key_id_mode_name(key_id_mode::KEY_SOURCE_4),
            "4o-KeySource-1oKeyIndex"
        );
        assert_eq!(
            key_id_mode_name(key_id_mode::KEY_SOURCE_8),
            "8o-KeySource-1oKeyIndex"
        );
    }

    #[test]
    fn test_key_id_len() {
        assert_eq!(key_id_len(key_id_mode::IMPLICIT), 0);
        assert_eq!(key_id_len(key_id_mode::KEY_INDEX), 1);
        assert_eq!(key_id_len(key_id_mode::KEY_SOURCE_4), 5);
        assert_eq!(key_id_len(key_id_mode::KEY_SOURCE_8), 9);
    }

    #[test]
    fn test_assoc_status_names() {
        assert_eq!(assoc_status_name(assoc_status::SUCCESSFUL), "successful");
        assert_eq!(
            assoc_status_name(assoc_status::PAN_AT_CAPACITY),
            "PAN_at_capacity"
        );
        assert_eq!(
            assoc_status_name(assoc_status::PAN_ACCESS_DENIED),
            "PAN_access_denied"
        );
        assert_eq!(assoc_status_name(3), "Reserved");
    }

    #[test]
    fn test_disassoc_reason_names() {
        assert_eq!(
            disassoc_reason_name(disassoc_reason::COORD_WISHES_DEVICE_TO_LEAVE),
            "coord_wishes_device_to_leave"
        );
        assert_eq!(
            disassoc_reason_name(disassoc_reason::DEVICE_WISHES_TO_LEAVE),
            "device_wishes_to_leave"
        );
        assert_eq!(disassoc_reason_name(0), "Reserved");
    }
}
