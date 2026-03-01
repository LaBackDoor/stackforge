//! IEEE 802.11 constants, type codes, and name lookup functions.
//!
//! This module contains all the constant definitions for 802.11 frame types,
//! subtypes, reason codes, status codes, capability bits, cipher suites,
//! AKM suites, and information element IDs.

// ============================================================================
// Frame Types (802.11-2016 9.2.4.1.3)
// ============================================================================

/// Frame type constants (2-bit field in Frame Control).
pub mod frame_type {
    pub const MANAGEMENT: u8 = 0;
    pub const CONTROL: u8 = 1;
    pub const DATA: u8 = 2;
    pub const EXTENSION: u8 = 3;

    /// Get the name for a frame type value.
    pub fn name(t: u8) -> &'static str {
        match t {
            MANAGEMENT => "Management",
            CONTROL => "Control",
            DATA => "Data",
            EXTENSION => "Extension",
            _ => "Unknown",
        }
    }
}

// ============================================================================
// Management Frame Subtypes (802.11-2016 9.2.4.1.3)
// ============================================================================

/// Management frame subtype constants (4-bit field).
pub mod mgmt_subtype {
    pub const ASSOC_REQ: u8 = 0;
    pub const ASSOC_RESP: u8 = 1;
    pub const REASSOC_REQ: u8 = 2;
    pub const REASSOC_RESP: u8 = 3;
    pub const PROBE_REQ: u8 = 4;
    pub const PROBE_RESP: u8 = 5;
    pub const TIMING_ADV: u8 = 6;
    pub const BEACON: u8 = 8;
    pub const ATIM: u8 = 9;
    pub const DISASSOC: u8 = 10;
    pub const AUTH: u8 = 11;
    pub const DEAUTH: u8 = 12;
    pub const ACTION: u8 = 13;
    pub const ACTION_NOACK: u8 = 14;

    /// Get the name for a management frame subtype value.
    pub fn name(s: u8) -> &'static str {
        match s {
            ASSOC_REQ => "Association Request",
            ASSOC_RESP => "Association Response",
            REASSOC_REQ => "Reassociation Request",
            REASSOC_RESP => "Reassociation Response",
            PROBE_REQ => "Probe Request",
            PROBE_RESP => "Probe Response",
            TIMING_ADV => "Timing Advertisement",
            BEACON => "Beacon",
            ATIM => "ATIM",
            DISASSOC => "Disassociation",
            AUTH => "Authentication",
            DEAUTH => "Deauthentication",
            ACTION => "Action",
            ACTION_NOACK => "Action No Ack",
            _ => "Reserved",
        }
    }
}

// ============================================================================
// Control Frame Subtypes (802.11-2016 9.2.4.1.3)
// ============================================================================

/// Control frame subtype constants (4-bit field).
pub mod ctrl_subtype {
    pub const TRIGGER: u8 = 2;
    pub const TACK: u8 = 3;
    pub const BEAMFORMING_REPORT_POLL: u8 = 4;
    pub const VHT_HE_NDP_ANNOUNCEMENT: u8 = 5;
    pub const CONTROL_FRAME_EXT: u8 = 6;
    pub const CONTROL_WRAPPER: u8 = 7;
    pub const BAR: u8 = 8;
    pub const BA: u8 = 9;
    pub const PS_POLL: u8 = 10;
    pub const RTS: u8 = 11;
    pub const CTS: u8 = 12;
    pub const ACK: u8 = 13;
    pub const CF_END: u8 = 14;
    pub const CF_END_ACK: u8 = 15;

    /// Get the name for a control frame subtype value.
    pub fn name(s: u8) -> &'static str {
        match s {
            TRIGGER => "Trigger",
            TACK => "TACK",
            BEAMFORMING_REPORT_POLL => "Beamforming Report Poll",
            VHT_HE_NDP_ANNOUNCEMENT => "VHT/HE NDP Announcement",
            CONTROL_FRAME_EXT => "Control Frame Extension",
            CONTROL_WRAPPER => "Control Wrapper",
            BAR => "Block Ack Request",
            BA => "Block Ack",
            PS_POLL => "PS-Poll",
            RTS => "RTS",
            CTS => "CTS",
            ACK => "Ack",
            CF_END => "CF-End",
            CF_END_ACK => "CF-End+CF-Ack",
            _ => "Reserved",
        }
    }
}

// ============================================================================
// Data Frame Subtypes (802.11-2016 9.2.4.1.3)
// ============================================================================

/// Data frame subtype constants (4-bit field).
pub mod data_subtype {
    pub const DATA: u8 = 0;
    pub const DATA_CF_ACK: u8 = 1;
    pub const DATA_CF_POLL: u8 = 2;
    pub const DATA_CF_ACK_POLL: u8 = 3;
    pub const NULL: u8 = 4;
    pub const CF_ACK: u8 = 5;
    pub const CF_POLL: u8 = 6;
    pub const CF_ACK_POLL: u8 = 7;
    pub const QOS_DATA: u8 = 8;
    pub const QOS_DATA_CF_ACK: u8 = 9;
    pub const QOS_DATA_CF_POLL: u8 = 10;
    pub const QOS_DATA_CF_ACK_POLL: u8 = 11;
    pub const QOS_NULL: u8 = 12;
    pub const QOS_CF_POLL: u8 = 14;
    pub const QOS_CF_ACK_POLL: u8 = 15;

    /// Get the name for a data frame subtype value.
    pub fn name(s: u8) -> &'static str {
        match s {
            DATA => "Data",
            DATA_CF_ACK => "Data+CF-Ack",
            DATA_CF_POLL => "Data+CF-Poll",
            DATA_CF_ACK_POLL => "Data+CF-Ack+CF-Poll",
            NULL => "Null (no data)",
            CF_ACK => "CF-Ack (no data)",
            CF_POLL => "CF-Poll (no data)",
            CF_ACK_POLL => "CF-Ack+CF-Poll (no data)",
            QOS_DATA => "QoS Data",
            QOS_DATA_CF_ACK => "QoS Data+CF-Ack",
            QOS_DATA_CF_POLL => "QoS Data+CF-Poll",
            QOS_DATA_CF_ACK_POLL => "QoS Data+CF-Ack+CF-Poll",
            QOS_NULL => "QoS Null (no data)",
            QOS_CF_POLL => "QoS CF-Poll (no data)",
            QOS_CF_ACK_POLL => "QoS CF-Ack+CF-Poll (no data)",
            _ => "Reserved",
        }
    }

    /// Check if this data subtype includes QoS.
    #[inline]
    pub fn is_qos(subtype: u8) -> bool {
        subtype >= QOS_DATA
    }
}

// ============================================================================
// Extension Frame Subtypes
// ============================================================================

/// Extension frame subtype constants.
pub mod ext_subtype {
    pub const DMG_BEACON: u8 = 0;
    pub const S1G_BEACON: u8 = 1;

    /// Get the name for an extension frame subtype value.
    pub fn name(s: u8) -> &'static str {
        match s {
            DMG_BEACON => "DMG Beacon",
            S1G_BEACON => "S1G Beacon",
            _ => "Reserved",
        }
    }
}

/// Get the name for a given frame type and subtype combination.
pub fn subtype_name(frame_type: u8, subtype: u8) -> &'static str {
    match frame_type {
        frame_type::MANAGEMENT => mgmt_subtype::name(subtype),
        frame_type::CONTROL => ctrl_subtype::name(subtype),
        frame_type::DATA => data_subtype::name(subtype),
        frame_type::EXTENSION => ext_subtype::name(subtype),
        _ => "Unknown",
    }
}

// ============================================================================
// Frame Control Flags (802.11-2016 9.2.4.1)
// ============================================================================

/// Frame Control flag bits (in the flags byte, byte 1 of FC).
pub mod fc_flags {
    pub const TO_DS: u8 = 0x01;
    pub const FROM_DS: u8 = 0x02;
    pub const MORE_FRAG: u8 = 0x04;
    pub const RETRY: u8 = 0x08;
    pub const PWR_MGT: u8 = 0x10;
    pub const MORE_DATA: u8 = 0x20;
    pub const PROTECTED: u8 = 0x40;
    pub const HTC_ORDER: u8 = 0x80;

    /// Get a string representation of the flags byte.
    pub fn flags_string(flags: u8) -> String {
        let mut parts = Vec::new();
        if flags & TO_DS != 0 {
            parts.push("to_DS");
        }
        if flags & FROM_DS != 0 {
            parts.push("from_DS");
        }
        if flags & MORE_FRAG != 0 {
            parts.push("MF");
        }
        if flags & RETRY != 0 {
            parts.push("retry");
        }
        if flags & PWR_MGT != 0 {
            parts.push("pw_mgt");
        }
        if flags & MORE_DATA != 0 {
            parts.push("MD");
        }
        if flags & PROTECTED != 0 {
            parts.push("protected");
        }
        if flags & HTC_ORDER != 0 {
            parts.push("order");
        }
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join("+")
        }
    }
}

// ============================================================================
// Reason Codes (802.11-2016 9.4.1.7)
// ============================================================================

/// IEEE 802.11 reason codes for deauthentication/disassociation.
pub mod reason_code {
    pub const RESERVED: u16 = 0;
    pub const UNSPECIFIED: u16 = 1;
    pub const AUTH_EXPIRED: u16 = 2;
    pub const DEAUTH_LEAVING: u16 = 3;
    pub const INACTIVITY: u16 = 4;
    pub const AP_FULL: u16 = 5;
    pub const CLASS2_FROM_NONAUTH: u16 = 6;
    pub const CLASS3_FROM_NONASS: u16 = 7;
    pub const DISAS_LEAVING: u16 = 8;
    pub const NOT_AUTH: u16 = 9;
    pub const UNACCEPTABLE_POWER_CAP: u16 = 10;
    pub const UNACCEPTABLE_SUPPORTED_CHANNELS: u16 = 11;
    pub const BSS_TRANSITION_DISASSOC: u16 = 12;
    pub const INVALID_ELEMENT: u16 = 13;
    pub const MIC_FAILURE: u16 = 14;
    pub const FOURWAY_HANDSHAKE_TIMEOUT: u16 = 15;
    pub const GK_HANDSHAKE_TIMEOUT: u16 = 16;
    pub const ELEMENT_MISMATCH: u16 = 17;
    pub const INVALID_GROUP_CIPHER: u16 = 18;
    pub const INVALID_PAIRWISE_CIPHER: u16 = 19;
    pub const INVALID_AKMP: u16 = 20;
    pub const UNSUPPORTED_RSN_VERSION: u16 = 21;
    pub const INVALID_RSN_CAPABILITIES: u16 = 22;
    pub const IEEE_802_1X_AUTH_FAILED: u16 = 23;
    pub const CIPHER_SUITE_REJECTED: u16 = 24;
    pub const TDLS_DIRECT_LINK_TEARDOWN: u16 = 25;
    pub const TDLS_DIRECT_LINK_TEARDOWN_ALT: u16 = 26;
    pub const SSP_REQUESTED_DISASSOC: u16 = 27;
    pub const NO_SSP_ROAMING: u16 = 28;
    pub const BAD_CIPHER_OR_AKM: u16 = 29;
    pub const NOT_AUTHORIZED_LOCATION: u16 = 30;
    pub const SERVICE_CHANGE_PRECLUDES_TS: u16 = 31;
    pub const UNSPECIFIED_QOS: u16 = 32;
    pub const NOT_ENOUGH_BANDWIDTH: u16 = 33;
    pub const MISSING_ACKS: u16 = 34;
    pub const EXCEEDED_TXOP: u16 = 35;
    pub const STA_LEAVING: u16 = 36;
    pub const STA_NOT_USING: u16 = 37;
    pub const STA_REQUIRES_SETUP: u16 = 38;
    pub const TIMEOUT: u16 = 39;
    pub const PEER_INITIATED: u16 = 46;
    pub const AP_INITIATED: u16 = 47;
    pub const INVALID_FT_ACTION_FRAME_COUNT: u16 = 48;
    pub const INVALID_PMKID: u16 = 49;
    pub const INVALID_MDE: u16 = 50;
    pub const INVALID_FTE: u16 = 51;
    pub const MESH_PEERING_CANCELLED: u16 = 52;
    pub const MESH_MAX_PEERS: u16 = 53;
    pub const MESH_CONFIGURATION_POLICY: u16 = 54;
    pub const MESH_CLOSE_RCVD: u16 = 55;
    pub const MESH_MAX_RETRIES: u16 = 56;
    pub const MESH_CONFIRM_TIMEOUT: u16 = 57;
    pub const MESH_INVALID_GTK: u16 = 58;
    pub const MESH_INCONSISTENT_PARAMS: u16 = 59;
    pub const MESH_INVALID_SECURITY_CAP: u16 = 60;
    pub const MESH_PATH_ERROR_NO_PROXY_INFO: u16 = 61;
    pub const MESH_PATH_ERROR_NO_FORWARDING_INFO: u16 = 62;
    pub const MESH_PATH_ERROR_DEST_UNREACHABLE: u16 = 63;
    pub const MAC_EXISTS_IN_MBSS: u16 = 64;
    pub const MESH_CHANNEL_SWITCH_REGULATORY: u16 = 65;
    pub const MESH_CHANNEL_SWITCH_UNSPECIFIED: u16 = 66;
    pub const POOR_RSSI_CONDITIONS: u16 = 71;

    /// Get the name for a reason code.
    pub fn name(code: u16) -> &'static str {
        match code {
            RESERVED => "reserved",
            UNSPECIFIED => "unspec",
            AUTH_EXPIRED => "auth-expired",
            DEAUTH_LEAVING => "deauth-ST-leaving",
            INACTIVITY => "inactivity",
            AP_FULL => "AP-full",
            CLASS2_FROM_NONAUTH => "class2-from-nonauth",
            CLASS3_FROM_NONASS => "class3-from-nonass",
            DISAS_LEAVING => "disas-ST-leaving",
            NOT_AUTH => "ST-not-auth",
            UNACCEPTABLE_POWER_CAP => "unacceptable-power-cap",
            UNACCEPTABLE_SUPPORTED_CHANNELS => "unacceptable-sup-channels",
            BSS_TRANSITION_DISASSOC => "bss-transition-disassoc",
            INVALID_ELEMENT => "invalid-element",
            MIC_FAILURE => "mic-failure",
            FOURWAY_HANDSHAKE_TIMEOUT => "4way-handshake-timeout",
            GK_HANDSHAKE_TIMEOUT => "gk-handshake-timeout",
            ELEMENT_MISMATCH => "element-mismatch",
            INVALID_GROUP_CIPHER => "invalid-group-cipher",
            INVALID_PAIRWISE_CIPHER => "invalid-pairwise-cipher",
            INVALID_AKMP => "invalid-akmp",
            UNSUPPORTED_RSN_VERSION => "unsupported-rsn-version",
            INVALID_RSN_CAPABILITIES => "invalid-rsn-capabilities",
            IEEE_802_1X_AUTH_FAILED => "802.1x-auth-failed",
            CIPHER_SUITE_REJECTED => "cipher-suite-rejected",
            TDLS_DIRECT_LINK_TEARDOWN => "tdls-teardown-unreachable",
            TDLS_DIRECT_LINK_TEARDOWN_ALT => "tdls-teardown-unspecified",
            SSP_REQUESTED_DISASSOC => "ssp-requested-disassoc",
            NO_SSP_ROAMING => "no-ssp-roaming",
            BAD_CIPHER_OR_AKM => "bad-cipher-or-akm",
            NOT_AUTHORIZED_LOCATION => "not-authorized-location",
            SERVICE_CHANGE_PRECLUDES_TS => "service-change-precludes-ts",
            UNSPECIFIED_QOS => "unspecified-qos",
            NOT_ENOUGH_BANDWIDTH => "not-enough-bandwidth",
            MISSING_ACKS => "missing-acks",
            EXCEEDED_TXOP => "exceeded-txop",
            STA_LEAVING => "sta-leaving",
            STA_NOT_USING => "sta-not-using",
            STA_REQUIRES_SETUP => "sta-requires-setup",
            TIMEOUT => "timeout",
            PEER_INITIATED => "peer-initiated",
            AP_INITIATED => "ap-initiated",
            INVALID_FT_ACTION_FRAME_COUNT => "invalid-ft-action-frame-count",
            INVALID_PMKID => "invalid-pmkid",
            INVALID_MDE => "invalid-mde",
            INVALID_FTE => "invalid-fte",
            MESH_PEERING_CANCELLED => "mesh-peering-cancelled",
            MESH_MAX_PEERS => "mesh-max-peers",
            MESH_CONFIGURATION_POLICY => "mesh-config-policy",
            MESH_CLOSE_RCVD => "mesh-close-rcvd",
            MESH_MAX_RETRIES => "mesh-max-retries",
            MESH_CONFIRM_TIMEOUT => "mesh-confirm-timeout",
            MESH_INVALID_GTK => "mesh-invalid-gtk",
            MESH_INCONSISTENT_PARAMS => "mesh-inconsistent-params",
            MESH_INVALID_SECURITY_CAP => "mesh-invalid-security-cap",
            MESH_PATH_ERROR_NO_PROXY_INFO => "mesh-path-error-no-proxy",
            MESH_PATH_ERROR_NO_FORWARDING_INFO => "mesh-path-error-no-forward",
            MESH_PATH_ERROR_DEST_UNREACHABLE => "mesh-path-error-dest-unreach",
            MAC_EXISTS_IN_MBSS => "mac-exists-in-mbss",
            MESH_CHANNEL_SWITCH_REGULATORY => "mesh-channel-switch-regulatory",
            MESH_CHANNEL_SWITCH_UNSPECIFIED => "mesh-channel-switch-unspecified",
            POOR_RSSI_CONDITIONS => "poor-rssi",
            _ => "unknown",
        }
    }
}

// ============================================================================
// Status Codes (802.11-2016 9.4.1.9)
// ============================================================================

/// IEEE 802.11 status codes for authentication/association responses.
pub mod status_code {
    pub const SUCCESS: u16 = 0;
    pub const FAILURE: u16 = 1;
    pub const TDLS_WAKEUP_REJECT: u16 = 3;
    pub const SECURITY_DISABLED: u16 = 5;
    pub const UNACCEPTABLE_LIFETIME: u16 = 6;
    pub const NOT_IN_SAME_BSS: u16 = 7;
    pub const CANNOT_SUPPORT_ALL_CAP: u16 = 10;
    pub const REASSOC_DENIED: u16 = 11;
    pub const ASSOC_DENIED: u16 = 12;
    pub const ALGO_UNSUPPORTED: u16 = 13;
    pub const BAD_SEQ_NUM: u16 = 14;
    pub const CHALLENGE_FAILURE: u16 = 15;
    pub const TIMEOUT: u16 = 16;
    pub const AP_FULL: u16 = 17;
    pub const RATE_UNSUPPORTED: u16 = 18;
    pub const SHORT_PREAMBLE_REQUIRED: u16 = 19;
    pub const PBCC_REQUIRED: u16 = 20;
    pub const CHANNEL_AGILITY_REQUIRED: u16 = 21;
    pub const SPECTRUM_MGMT_REQUIRED: u16 = 22;
    pub const UNACCEPTABLE_POWER_CAP: u16 = 23;
    pub const UNACCEPTABLE_CHANNELS: u16 = 24;
    pub const SHORT_SLOT_REQUIRED: u16 = 25;
    pub const DSSS_OFDM_REQUIRED: u16 = 26;
    pub const NO_HT: u16 = 27;
    pub const R0KH_UNREACHABLE: u16 = 28;
    pub const NO_PCO_TRANSITION: u16 = 29;
    pub const REFUSED_TEMPORARILY: u16 = 30;
    pub const ROBUST_MGMT_POLICY_VIOLATION: u16 = 31;
    pub const UNSPECIFIED_QOS: u16 = 32;
    pub const QOS_INSUFFICIENT_BANDWIDTH: u16 = 33;
    pub const MISSING_ACKS: u16 = 34;
    pub const EXCEEDED_TXOP: u16 = 35;
    pub const REQUEST_DECLINED: u16 = 37;
    pub const INVALID_PARAMETERS: u16 = 38;
    pub const INVALID_ELEMENT: u16 = 40;
    pub const INVALID_GROUP_CIPHER: u16 = 41;
    pub const INVALID_PAIRWISE_CIPHER: u16 = 42;
    pub const INVALID_AKMP: u16 = 43;
    pub const UNSUPPORTED_RSN_VERSION: u16 = 44;
    pub const INVALID_RSN_CAPABILITIES: u16 = 45;
    pub const CIPHER_SUITE_REJECTED: u16 = 46;
    pub const ANTI_CLOG_TOKEN_REQUIRED: u16 = 76;
    pub const FINITE_CYCLIC_GROUP_NOT_SUPPORTED: u16 = 77;
    pub const SAE_HASH_TO_ELEMENT: u16 = 126;

    /// Get the name for a status code.
    pub fn name(code: u16) -> &'static str {
        match code {
            SUCCESS => "success",
            FAILURE => "failure",
            TDLS_WAKEUP_REJECT => "tdls-wakeup-reject",
            SECURITY_DISABLED => "security-disabled",
            UNACCEPTABLE_LIFETIME => "unacceptable-lifetime",
            NOT_IN_SAME_BSS => "not-in-same-bss",
            CANNOT_SUPPORT_ALL_CAP => "cannot-support-all-cap",
            REASSOC_DENIED => "inexist-asso",
            ASSOC_DENIED => "asso-denied",
            ALGO_UNSUPPORTED => "algo-unsupported",
            BAD_SEQ_NUM => "bad-seq-num",
            CHALLENGE_FAILURE => "challenge-failure",
            TIMEOUT => "timeout",
            AP_FULL => "AP-full",
            RATE_UNSUPPORTED => "rate-unsupported",
            SHORT_PREAMBLE_REQUIRED => "short-preamble-required",
            PBCC_REQUIRED => "pbcc-required",
            CHANNEL_AGILITY_REQUIRED => "channel-agility-required",
            SPECTRUM_MGMT_REQUIRED => "spectrum-mgmt-required",
            UNACCEPTABLE_POWER_CAP => "unacceptable-power-cap",
            UNACCEPTABLE_CHANNELS => "unacceptable-channels",
            SHORT_SLOT_REQUIRED => "short-slot-required",
            DSSS_OFDM_REQUIRED => "dsss-ofdm-required",
            NO_HT => "no-ht",
            R0KH_UNREACHABLE => "r0kh-unreachable",
            NO_PCO_TRANSITION => "no-pco-transition",
            REFUSED_TEMPORARILY => "refused-temporarily",
            ROBUST_MGMT_POLICY_VIOLATION => "robust-mgmt-policy-violation",
            UNSPECIFIED_QOS => "unspecified-qos",
            QOS_INSUFFICIENT_BANDWIDTH => "qos-insufficient-bandwidth",
            MISSING_ACKS => "missing-acks",
            EXCEEDED_TXOP => "exceeded-txop",
            REQUEST_DECLINED => "request-declined",
            INVALID_PARAMETERS => "invalid-parameters",
            INVALID_ELEMENT => "invalid-element",
            INVALID_GROUP_CIPHER => "invalid-group-cipher",
            INVALID_PAIRWISE_CIPHER => "invalid-pairwise-cipher",
            INVALID_AKMP => "invalid-akmp",
            UNSUPPORTED_RSN_VERSION => "unsupported-rsn-version",
            INVALID_RSN_CAPABILITIES => "invalid-rsn-capabilities",
            CIPHER_SUITE_REJECTED => "cipher-suite-rejected",
            ANTI_CLOG_TOKEN_REQUIRED => "anti-clog-token-required",
            FINITE_CYCLIC_GROUP_NOT_SUPPORTED => "finite-cyclic-group-not-supported",
            SAE_HASH_TO_ELEMENT => "sae-hash-to-element",
            _ => "unknown",
        }
    }
}

// ============================================================================
// Capability Information Bits (802.11-2016 9.4.1.4)
// ============================================================================

/// Capability information bits (16-bit field in beacons/probe responses).
pub mod capability {
    pub const ESS: u16 = 0x0001;
    pub const IBSS: u16 = 0x0002;
    pub const CF_POLLABLE: u16 = 0x0004;
    pub const CF_POLL_REQUEST: u16 = 0x0008;
    pub const PRIVACY: u16 = 0x0010;
    pub const SHORT_PREAMBLE: u16 = 0x0020;
    pub const PBCC: u16 = 0x0040;
    pub const CHANNEL_AGILITY: u16 = 0x0080;
    pub const SPECTRUM_MGMT: u16 = 0x0100;
    pub const SHORT_SLOT_TIME: u16 = 0x0400;
    pub const APSD: u16 = 0x0800;
    pub const RADIO_MEASUREMENT: u16 = 0x1000;
    pub const DSSS_OFDM: u16 = 0x2000;
    pub const DELAYED_BLOCK_ACK: u16 = 0x4000;
    pub const IMMEDIATE_BLOCK_ACK: u16 = 0x8000;

    /// Capability flag names matching Scapy's ordering (LSB first per byte).
    pub const FLAG_NAMES: &[&str] = &[
        "ESS",
        "IBSS",
        "CFP",
        "CFP-req",
        "privacy",
        "short-preamble",
        "PBCC",
        "agility",
        "res8",
        "res9",
        "short-slot",
        "res11",
        "res12",
        "DSSS-OFDM",
        "res14",
        "res15",
    ];

    /// Get a string representation of the capability bits.
    pub fn flags_string(cap: u16) -> String {
        let mut parts = Vec::new();
        for (i, name) in FLAG_NAMES.iter().enumerate() {
            if cap & (1 << i) != 0 {
                parts.push(*name);
            }
        }
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join("+")
        }
    }
}

// ============================================================================
// Information Element IDs (802.11-2016 9.4.2)
// ============================================================================

/// Information Element ID constants.
pub mod ie_id {
    pub const SSID: u8 = 0;
    pub const SUPPORTED_RATES: u8 = 1;
    pub const FH_PARAMS: u8 = 2;
    pub const DS_PARAMS: u8 = 3;
    pub const CF_PARAMS: u8 = 4;
    pub const TIM: u8 = 5;
    pub const IBSS_PARAMS: u8 = 6;
    pub const COUNTRY: u8 = 7;
    pub const HOPPING_PATTERN: u8 = 8;
    pub const HOPPING_TABLE: u8 = 9;
    pub const REQUEST: u8 = 10;
    pub const BSS_LOAD: u8 = 11;
    pub const EDCA_PARAMS: u8 = 12;
    pub const TSPEC: u8 = 13;
    pub const TCLAS: u8 = 14;
    pub const SCHEDULE: u8 = 15;
    pub const CHALLENGE_TEXT: u8 = 16;
    pub const POWER_CONSTRAINT: u8 = 32;
    pub const POWER_CAPABILITY: u8 = 33;
    pub const TPC_REQUEST: u8 = 34;
    pub const TPC_REPORT: u8 = 35;
    pub const SUPPORTED_CHANNELS: u8 = 36;
    pub const CSA: u8 = 37;
    pub const MEASUREMENT_REQUEST: u8 = 38;
    pub const MEASUREMENT_REPORT: u8 = 39;
    pub const QUIET: u8 = 40;
    pub const IBSS_DFS: u8 = 41;
    pub const ERP: u8 = 42;
    pub const TS_DELAY: u8 = 43;
    pub const TCLAS_PROCESSING: u8 = 44;
    pub const HT_CAPABILITIES: u8 = 45;
    pub const QOS_CAPABILITY: u8 = 46;
    pub const RSN: u8 = 48;
    pub const EXTENDED_SUPPORTED_RATES: u8 = 50;
    pub const AP_CHANNEL_REPORT: u8 = 51;
    pub const NEIGHBOR_REPORT: u8 = 52;
    pub const RCPI: u8 = 53;
    pub const MOBILITY_DOMAIN: u8 = 54;
    pub const FAST_BSS_TRANSITION: u8 = 55;
    pub const TIMEOUT_INTERVAL: u8 = 56;
    pub const RIC_DATA: u8 = 57;
    pub const HT_OPERATION: u8 = 61;
    pub const SECONDARY_CHANNEL_OFFSET: u8 = 62;
    pub const BSS_AVERAGE_ACCESS_DELAY: u8 = 63;
    pub const ANTENNA: u8 = 64;
    pub const RSNI: u8 = 65;
    pub const MEASUREMENT_PILOT_TRANSMISSION: u8 = 66;
    pub const BSS_AVAILABLE_ADMISSION_CAPACITY: u8 = 67;
    pub const BSS_AC_ACCESS_DELAY: u8 = 68;
    pub const TIME_ADVERTISEMENT: u8 = 69;
    pub const RM_ENABLED_CAPABILITIES: u8 = 70;
    pub const MULTIPLE_BSSID: u8 = 71;
    pub const OBSS_SCAN_PARAMS: u8 = 74;
    pub const RIC_DESCRIPTOR: u8 = 75;
    pub const MGMT_MIC: u8 = 76;
    pub const EVENT_REQUEST: u8 = 78;
    pub const EVENT_REPORT: u8 = 79;
    pub const DIAGNOSTIC_REQUEST: u8 = 80;
    pub const DIAGNOSTIC_REPORT: u8 = 81;
    pub const LOCATION_PARAMS: u8 = 82;
    pub const NONTRANSMITTED_BSSID_CAP: u8 = 83;
    pub const SSID_LIST: u8 = 84;
    pub const MULTIPLE_BSSID_INDEX: u8 = 85;
    pub const FMS_DESCRIPTOR: u8 = 86;
    pub const QOS_TRAFFIC_CAPABILITY: u8 = 89;
    pub const BSS_MAX_IDLE_PERIOD: u8 = 90;
    pub const TFS_REQUEST: u8 = 91;
    pub const TFS_RESPONSE: u8 = 92;
    pub const WNM_SLEEP_MODE: u8 = 93;
    pub const TIM_BROADCAST_REQUEST: u8 = 94;
    pub const TIM_BROADCAST_RESPONSE: u8 = 95;
    pub const CHANNEL_USAGE: u8 = 97;
    pub const TIME_ZONE: u8 = 98;
    pub const DMS_REQUEST: u8 = 99;
    pub const DMS_RESPONSE: u8 = 100;
    pub const LINK_IDENTIFIER: u8 = 101;
    pub const WAKEUP_SCHEDULE: u8 = 102;
    pub const CHANNEL_SWITCH_TIMING: u8 = 104;
    pub const PTI_CONTROL: u8 = 105;
    pub const TPU_BUFFER_STATUS: u8 = 106;
    pub const INTERWORKING: u8 = 107;
    pub const ADVERTISEMENT_PROTOCOL: u8 = 108;
    pub const EXPEDITED_BANDWIDTH_REQUEST: u8 = 109;
    pub const QOS_MAP: u8 = 110;
    pub const ROAMING_CONSORTIUM: u8 = 111;
    pub const EMERGENCY_ALERT_IDENTIFIER: u8 = 112;
    pub const MESH_CONFIGURATION: u8 = 113;
    pub const MESH_ID: u8 = 114;
    pub const EXTENDED_CAPABILITIES: u8 = 127;
    pub const VHT_CAPABILITIES: u8 = 191;
    pub const VHT_OPERATION: u8 = 192;
    pub const VHT_TRANSMIT_POWER_ENVELOPE: u8 = 195;
    pub const VENDOR_SPECIFIC: u8 = 221;
    pub const ELEMENT_ID_EXTENSION: u8 = 255;

    // Aliases used by ie.rs structured-IE parsers
    pub const RATES: u8 = SUPPORTED_RATES;
    pub const DS_PARAMETER_SET: u8 = DS_PARAMS;
    pub const CHANNEL_SWITCH_ANNOUNCEMENT: u8 = CSA;
    pub const HT_INFORMATION: u8 = HT_OPERATION;

    /// Get the name for an Information Element ID.
    pub fn name(id: u8) -> &'static str {
        match id {
            SSID => "SSID",
            SUPPORTED_RATES => "Supported Rates",
            FH_PARAMS => "FHset",
            DS_PARAMS => "DSSS Set",
            CF_PARAMS => "CF Set",
            TIM => "TIM",
            IBSS_PARAMS => "IBSS Set",
            COUNTRY => "Country",
            REQUEST => "Request",
            BSS_LOAD => "BSS Load",
            EDCA_PARAMS => "EDCA Set",
            TSPEC => "TSPEC",
            TCLAS => "TCLAS",
            SCHEDULE => "Schedule",
            CHALLENGE_TEXT => "Challenge text",
            POWER_CONSTRAINT => "Power Constraint",
            POWER_CAPABILITY => "Power Capability",
            SUPPORTED_CHANNELS => "Supported Channels",
            CSA => "Channel Switch Announcement",
            ERP => "ERP",
            HT_CAPABILITIES => "HT Capabilities",
            QOS_CAPABILITY => "QoS Capability",
            RSN => "RSN",
            EXTENDED_SUPPORTED_RATES => "Extended Supported Rates",
            NEIGHBOR_REPORT => "Neighbor Report",
            HT_OPERATION => "HT Operation",
            OBSS_SCAN_PARAMS => "Overlapping BSS Scan Parameters",
            INTERWORKING => "Interworking",
            EXTENDED_CAPABILITIES => "Extended Capabilities",
            VHT_CAPABILITIES => "VHT Capabilities",
            VHT_OPERATION => "VHT Operation",
            VENDOR_SPECIFIC => "Vendor Specific",
            _ => "Unknown",
        }
    }
}

// ============================================================================
// Cipher Suite Constants (802.11-2016 9.4.2.24.2)
// ============================================================================

/// RSN cipher suite selectors.
pub mod cipher_suite {
    /// OUI prefix for IEEE 802.11 cipher suites (00-0F-AC).
    pub const IEEE_OUI: [u8; 3] = [0x00, 0x0f, 0xac];

    pub const USE_GROUP: u8 = 0x00;
    pub const WEP_40: u8 = 0x01;
    pub const TKIP: u8 = 0x02;
    pub const OCB: u8 = 0x03;
    pub const CCMP_128: u8 = 0x04;
    pub const WEP_104: u8 = 0x05;
    pub const BIP_CMAC_128: u8 = 0x06;
    pub const GROUP_NOT_ALLOWED: u8 = 0x07;
    pub const GCMP_128: u8 = 0x08;
    pub const GCMP_256: u8 = 0x09;
    pub const CCMP_256: u8 = 0x0A;
    pub const BIP_GMAC_128: u8 = 0x0B;
    pub const BIP_GMAC_256: u8 = 0x0C;
    pub const BIP_CMAC_256: u8 = 0x0D;

    /// Get the name for a cipher suite type byte.
    pub fn name(cipher: u8) -> &'static str {
        match cipher {
            USE_GROUP => "Use group cipher suite",
            WEP_40 => "WEP-40",
            TKIP => "TKIP",
            OCB => "OCB",
            CCMP_128 => "CCMP-128",
            WEP_104 => "WEP-104",
            BIP_CMAC_128 => "BIP-CMAC-128",
            GROUP_NOT_ALLOWED => "Group addressed traffic not allowed",
            GCMP_128 => "GCMP-128",
            GCMP_256 => "GCMP-256",
            CCMP_256 => "CCMP-256",
            BIP_GMAC_128 => "BIP-GMAC-128",
            BIP_GMAC_256 => "BIP-GMAC-256",
            BIP_CMAC_256 => "BIP-CMAC-256",
            _ => "Unknown",
        }
    }
}

// ============================================================================
// AKM Suite Constants (802.11-2016 9.4.2.24.3)
// ============================================================================

/// Authentication and Key Management (AKM) suite selectors.
pub mod akm_suite {
    /// OUI prefix for IEEE 802.11 AKM suites (00-0F-AC).
    pub const IEEE_OUI: [u8; 3] = [0x00, 0x0f, 0xac];

    pub const RESERVED: u8 = 0x00;
    pub const IEEE_802_1X: u8 = 0x01;
    pub const PSK: u8 = 0x02;
    pub const FT_802_1X: u8 = 0x03;
    pub const FT_PSK: u8 = 0x04;
    pub const WPA_SHA256: u8 = 0x05;
    pub const PSK_SHA256: u8 = 0x06;
    pub const TDLS: u8 = 0x07;
    pub const SAE: u8 = 0x08;
    pub const FT_SAE: u8 = 0x09;
    pub const AP_PEER_KEY: u8 = 0x0A;
    pub const WPA_SHA256_SUITE_B: u8 = 0x0B;
    pub const WPA_SHA384_SUITE_B: u8 = 0x0C;
    pub const FT_802_1X_SHA384: u8 = 0x0D;
    pub const FILS_SHA256: u8 = 0x0E;
    pub const FILS_SHA384: u8 = 0x0F;
    pub const FT_FILS_SHA256: u8 = 0x10;
    pub const FT_FILS_SHA384: u8 = 0x11;
    pub const OWE: u8 = 0x12;

    /// Get the name for an AKM suite type byte.
    pub fn name(suite: u8) -> &'static str {
        match suite {
            RESERVED => "Reserved",
            IEEE_802_1X => "802.1X",
            PSK => "PSK",
            FT_802_1X => "FT-802.1X",
            FT_PSK => "FT-PSK",
            WPA_SHA256 => "WPA-SHA256",
            PSK_SHA256 => "PSK-SHA256",
            TDLS => "TDLS",
            SAE => "SAE",
            FT_SAE => "FT-SAE",
            AP_PEER_KEY => "AP-PEER-KEY",
            WPA_SHA256_SUITE_B => "WPA-SHA256-SUITE-B",
            WPA_SHA384_SUITE_B => "WPA-SHA384-SUITE-B",
            FT_802_1X_SHA384 => "FT-802.1X-SHA384",
            FILS_SHA256 => "FILS-SHA256",
            FILS_SHA384 => "FILS-SHA384",
            FT_FILS_SHA256 => "FT-FILS-SHA256",
            FT_FILS_SHA384 => "FT-FILS-SHA384",
            OWE => "OWE",
            _ => "Unknown",
        }
    }
}

// ============================================================================
// Action Category Codes (802.11-2016 9.4.1.11)
// ============================================================================

/// Action frame category codes.
pub mod action_category {
    pub const SPECTRUM_MANAGEMENT: u8 = 0x00;
    pub const QOS: u8 = 0x01;
    pub const DLS: u8 = 0x02;
    pub const BLOCK_ACK: u8 = 0x03;
    pub const PUBLIC: u8 = 0x04;
    pub const RADIO_MEASUREMENT: u8 = 0x05;
    pub const FAST_BSS_TRANSITION: u8 = 0x06;
    pub const HT: u8 = 0x07;
    pub const SA_QUERY: u8 = 0x08;
    pub const PROTECTED_DUAL_OF_PUBLIC: u8 = 0x09;
    pub const WNM: u8 = 0x0A;
    pub const UNPROTECTED_WNM: u8 = 0x0B;
    pub const TDLS: u8 = 0x0C;
    pub const MESH: u8 = 0x0D;
    pub const MULTIHOP: u8 = 0x0E;
    pub const SELF_PROTECTED: u8 = 0x0F;
    pub const DMG: u8 = 0x10;
    pub const WIFI_ALLIANCE: u8 = 0x11;
    pub const FAST_SESSION_TRANSFER: u8 = 0x12;
    pub const ROBUST_AV_STREAMING: u8 = 0x13;
    pub const UNPROTECTED_DMG: u8 = 0x14;
    pub const VHT: u8 = 0x15;
    pub const VENDOR_SPECIFIC: u8 = 0x7F;

    /// Get the name for an action category code.
    pub fn name(cat: u8) -> &'static str {
        match cat {
            SPECTRUM_MANAGEMENT => "Spectrum Management",
            QOS => "QoS",
            DLS => "DLS",
            BLOCK_ACK => "Block Ack",
            PUBLIC => "Public",
            RADIO_MEASUREMENT => "Radio Measurement",
            FAST_BSS_TRANSITION => "Fast BSS Transition",
            HT => "HT",
            SA_QUERY => "SA Query",
            PROTECTED_DUAL_OF_PUBLIC => "Protected Dual of Public Action",
            WNM => "WNM",
            UNPROTECTED_WNM => "Unprotected WNM",
            TDLS => "TDLS",
            MESH => "Mesh",
            MULTIHOP => "Multihop",
            SELF_PROTECTED => "Self-protected",
            DMG => "DMG",
            WIFI_ALLIANCE => "Reserved Wi-Fi Alliance",
            FAST_SESSION_TRANSFER => "Fast Session Transfer",
            ROBUST_AV_STREAMING => "Robust AV Streaming",
            UNPROTECTED_DMG => "Unprotected DMG",
            VHT => "VHT",
            VENDOR_SPECIFIC => "Vendor Specific",
            _ => "Unknown",
        }
    }
}

// ============================================================================
// Authentication Algorithm Numbers (802.11-2016 9.4.1.1)
// ============================================================================

/// Authentication algorithm numbers.
pub mod auth_algo {
    pub const OPEN: u16 = 0;
    pub const SHARED_KEY: u16 = 1;
    pub const FAST_BSS_TRANSITION: u16 = 2;
    pub const SAE: u16 = 3;
    pub const FILS_SK: u16 = 4;
    pub const FILS_SK_PFS: u16 = 5;
    pub const FILS_PK: u16 = 6;
    pub const VENDOR_SPECIFIC: u16 = 65535;

    /// Get the name for an authentication algorithm number.
    pub fn name(algo: u16) -> &'static str {
        match algo {
            OPEN => "open",
            SHARED_KEY => "sharedkey",
            FAST_BSS_TRANSITION => "FT",
            SAE => "SAE",
            FILS_SK => "FILS-SK",
            FILS_SK_PFS => "FILS-SK-PFS",
            FILS_PK => "FILS-PK",
            VENDOR_SPECIFIC => "vendor-specific",
            _ => "unknown",
        }
    }
}

// ============================================================================
// RadioTap Present Field Bit Definitions
// ============================================================================

/// RadioTap present field bit positions.
pub mod radiotap_present {
    pub const TSFT: u32 = 0;
    pub const FLAGS: u32 = 1;
    pub const RATE: u32 = 2;
    pub const CHANNEL: u32 = 3;
    pub const FHSS: u32 = 4;
    pub const DBM_ANT_SIGNAL: u32 = 5;
    pub const DBM_ANT_NOISE: u32 = 6;
    pub const LOCK_QUALITY: u32 = 7;
    pub const TX_ATTENUATION: u32 = 8;
    pub const DB_TX_ATTENUATION: u32 = 9;
    pub const DBM_TX_POWER: u32 = 10;
    pub const ANTENNA: u32 = 11;
    pub const DB_ANT_SIGNAL: u32 = 12;
    pub const DB_ANT_NOISE: u32 = 13;
    pub const RX_FLAGS: u32 = 14;
    pub const TX_FLAGS: u32 = 15;
    pub const CHANNEL_PLUS: u32 = 18;
    pub const MCS: u32 = 19;
    pub const A_MPDU: u32 = 20;
    pub const VHT: u32 = 21;
    pub const TIMESTAMP: u32 = 22;
    pub const HE: u32 = 23;
    pub const HE_MU: u32 = 24;
    pub const HE_MU_OTHER_USER: u32 = 25;
    pub const ZERO_LENGTH_PSDU: u32 = 26;
    pub const L_SIG: u32 = 27;
    pub const TLV: u32 = 28;
    pub const RADIOTAP_NS: u32 = 29;
    pub const VENDOR_NS: u32 = 30;
    pub const EXT: u32 = 31;

    /// Present field names indexed by bit position.
    pub const NAMES: &[&str] = &[
        "TSFT",
        "Flags",
        "Rate",
        "Channel",
        "FHSS",
        "dBm_AntSignal",
        "dBm_AntNoise",
        "Lock_Quality",
        "TX_Attenuation",
        "dB_TX_Attenuation",
        "dBm_TX_Power",
        "Antenna",
        "dB_AntSignal",
        "dB_AntNoise",
        "RXFlags",
        "TXFlags",
        "b16",
        "b17",
        "ChannelPlus",
        "MCS",
        "A_MPDU",
        "VHT",
        "timestamp",
        "HE",
        "HE_MU",
        "HE_MU_other_user",
        "zero_length_psdu",
        "L_SIG",
        "TLV",
        "RadiotapNS",
        "VendorNS",
        "Ext",
    ];
}

/// RadioTap Flags field bit definitions.
pub mod radiotap_flags {
    pub const CFP: u8 = 0x01;
    pub const SHORT_PREAMBLE: u8 = 0x02;
    pub const WEP: u8 = 0x04;
    pub const FRAGMENTED: u8 = 0x08;
    pub const FCS: u8 = 0x10;
    pub const PAD: u8 = 0x20;
    pub const BAD_FCS: u8 = 0x40;
    pub const SHORT_GI: u8 = 0x80;
}

// ============================================================================
// Microsoft WPA OUI
// ============================================================================

/// Microsoft OUI for WPA vendor-specific IE.
pub const MICROSOFT_WPA_OUI: [u8; 3] = [0x00, 0x50, 0xf2];
/// WPA type within Microsoft vendor-specific IE.
pub const MICROSOFT_WPA_TYPE: u8 = 0x01;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_names() {
        assert_eq!(frame_type::name(0), "Management");
        assert_eq!(frame_type::name(1), "Control");
        assert_eq!(frame_type::name(2), "Data");
        assert_eq!(frame_type::name(3), "Extension");
        assert_eq!(frame_type::name(4), "Unknown");
    }

    #[test]
    fn test_mgmt_subtype_names() {
        assert_eq!(mgmt_subtype::name(0), "Association Request");
        assert_eq!(mgmt_subtype::name(1), "Association Response");
        assert_eq!(mgmt_subtype::name(4), "Probe Request");
        assert_eq!(mgmt_subtype::name(5), "Probe Response");
        assert_eq!(mgmt_subtype::name(8), "Beacon");
        assert_eq!(mgmt_subtype::name(11), "Authentication");
        assert_eq!(mgmt_subtype::name(12), "Deauthentication");
        assert_eq!(mgmt_subtype::name(13), "Action");
    }

    #[test]
    fn test_ctrl_subtype_names() {
        assert_eq!(ctrl_subtype::name(8), "Block Ack Request");
        assert_eq!(ctrl_subtype::name(9), "Block Ack");
        assert_eq!(ctrl_subtype::name(10), "PS-Poll");
        assert_eq!(ctrl_subtype::name(11), "RTS");
        assert_eq!(ctrl_subtype::name(12), "CTS");
        assert_eq!(ctrl_subtype::name(13), "Ack");
        assert_eq!(ctrl_subtype::name(14), "CF-End");
        assert_eq!(ctrl_subtype::name(15), "CF-End+CF-Ack");
    }

    #[test]
    fn test_data_subtype_names() {
        assert_eq!(data_subtype::name(0), "Data");
        assert_eq!(data_subtype::name(8), "QoS Data");
        assert_eq!(data_subtype::name(12), "QoS Null (no data)");
        assert!(data_subtype::is_qos(8));
        assert!(!data_subtype::is_qos(0));
    }

    #[test]
    fn test_subtype_name_dispatch() {
        assert_eq!(subtype_name(0, 8), "Beacon");
        assert_eq!(subtype_name(1, 13), "Ack");
        assert_eq!(subtype_name(2, 8), "QoS Data");
        assert_eq!(subtype_name(3, 0), "DMG Beacon");
    }

    #[test]
    fn test_reason_code_names() {
        assert_eq!(reason_code::name(0), "reserved");
        assert_eq!(reason_code::name(1), "unspec");
        assert_eq!(reason_code::name(4), "inactivity");
        assert_eq!(reason_code::name(14), "mic-failure");
        assert_eq!(reason_code::name(999), "unknown");
    }

    #[test]
    fn test_status_code_names() {
        assert_eq!(status_code::name(0), "success");
        assert_eq!(status_code::name(1), "failure");
        assert_eq!(status_code::name(17), "AP-full");
        assert_eq!(status_code::name(999), "unknown");
    }

    #[test]
    fn test_capability_flags_string() {
        assert_eq!(capability::flags_string(0x0001), "ESS");
        assert_eq!(capability::flags_string(0x0011), "ESS+privacy");
        assert_eq!(capability::flags_string(0), "none");
    }

    #[test]
    fn test_fc_flags_string() {
        assert_eq!(fc_flags::flags_string(0x01), "to_DS");
        assert_eq!(fc_flags::flags_string(0x03), "to_DS+from_DS");
        assert_eq!(fc_flags::flags_string(0x40), "protected");
        assert_eq!(fc_flags::flags_string(0), "none");
    }

    #[test]
    fn test_ie_id_names() {
        assert_eq!(ie_id::name(0), "SSID");
        assert_eq!(ie_id::name(1), "Supported Rates");
        assert_eq!(ie_id::name(3), "DSSS Set");
        assert_eq!(ie_id::name(48), "RSN");
        assert_eq!(ie_id::name(221), "Vendor Specific");
    }

    #[test]
    fn test_cipher_suite_names() {
        assert_eq!(cipher_suite::name(0x04), "CCMP-128");
        assert_eq!(cipher_suite::name(0x02), "TKIP");
        assert_eq!(cipher_suite::name(0x01), "WEP-40");
    }

    #[test]
    fn test_akm_suite_names() {
        assert_eq!(akm_suite::name(0x01), "802.1X");
        assert_eq!(akm_suite::name(0x02), "PSK");
        assert_eq!(akm_suite::name(0x08), "SAE");
        assert_eq!(akm_suite::name(0x12), "OWE");
    }

    #[test]
    fn test_action_category_names() {
        assert_eq!(action_category::name(0x00), "Spectrum Management");
        assert_eq!(action_category::name(0x0A), "WNM");
        assert_eq!(action_category::name(0x15), "VHT");
    }

    #[test]
    fn test_auth_algo_names() {
        assert_eq!(auth_algo::name(0), "open");
        assert_eq!(auth_algo::name(1), "sharedkey");
        assert_eq!(auth_algo::name(3), "SAE");
    }
}
