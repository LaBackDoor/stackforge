//! ICMP type and code constants.
//!
//! Defines constants for common ICMP message types and codes,
//! plus helper functions for human-readable names.

/// ICMP message types.
pub mod types {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACH: u8 = 3;
    pub const SOURCE_QUENCH: u8 = 4;
    pub const REDIRECT: u8 = 5;
    pub const ECHO_REQUEST: u8 = 8;
    pub const ROUTER_ADVERTISEMENT: u8 = 9;
    pub const ROUTER_SOLICITATION: u8 = 10;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAM_PROBLEM: u8 = 12;
    pub const TIMESTAMP: u8 = 13;
    pub const TIMESTAMP_REPLY: u8 = 14;
    pub const INFO_REQUEST: u8 = 15;
    pub const INFO_REPLY: u8 = 16;
    pub const ADDRESS_MASK_REQUEST: u8 = 17;
    pub const ADDRESS_MASK_REPLY: u8 = 18;
}

/// ICMP destination unreachable codes.
pub mod dest_unreach_codes {
    pub const NET_UNREACH: u8 = 0;
    pub const HOST_UNREACH: u8 = 1;
    pub const PROTO_UNREACH: u8 = 2;
    pub const PORT_UNREACH: u8 = 3;
    pub const FRAG_NEEDED: u8 = 4;
    pub const SRC_ROUTE_FAILED: u8 = 5;
    pub const NET_UNKNOWN: u8 = 6;
    pub const HOST_UNKNOWN: u8 = 7;
    pub const SRC_HOST_ISOLATED: u8 = 8;
    pub const NET_PROHIBITED: u8 = 9;
    pub const HOST_PROHIBITED: u8 = 10;
    pub const NET_TOS: u8 = 11;
    pub const HOST_TOS: u8 = 12;
    pub const COMM_PROHIBITED: u8 = 13;
}

/// ICMP redirect codes.
pub mod redirect_codes {
    pub const REDIRECT_NET: u8 = 0;
    pub const REDIRECT_HOST: u8 = 1;
    pub const REDIRECT_TOS_NET: u8 = 2;
    pub const REDIRECT_TOS_HOST: u8 = 3;
}

/// ICMP time exceeded codes.
pub mod time_exceeded_codes {
    pub const TTL_EXCEEDED: u8 = 0;
    pub const FRAG_REASSEMBLY: u8 = 1;
}

/// ICMP answer pairs (request type, reply type).
pub const ICMP_ANSWERS: &[(u8, u8)] = &[
    (types::ECHO_REQUEST, types::ECHO_REPLY),
    (types::TIMESTAMP, types::TIMESTAMP_REPLY),
    (types::INFO_REQUEST, types::INFO_REPLY),
    (types::ADDRESS_MASK_REQUEST, types::ADDRESS_MASK_REPLY),
];

/// Get human-readable name for ICMP type.
pub fn type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        types::ECHO_REPLY => "echo-reply",
        types::DEST_UNREACH => "dest-unreach",
        types::SOURCE_QUENCH => "source-quench",
        types::REDIRECT => "redirect",
        types::ECHO_REQUEST => "echo-request",
        types::ROUTER_ADVERTISEMENT => "router-advertisement",
        types::ROUTER_SOLICITATION => "router-solicitation",
        types::TIME_EXCEEDED => "time-exceeded",
        types::PARAM_PROBLEM => "parameter-problem",
        types::TIMESTAMP => "timestamp-request",
        types::TIMESTAMP_REPLY => "timestamp-reply",
        types::INFO_REQUEST => "info-request",
        types::INFO_REPLY => "info-reply",
        types::ADDRESS_MASK_REQUEST => "address-mask-request",
        types::ADDRESS_MASK_REPLY => "address-mask-reply",
        _ => "unknown",
    }
}

/// Get human-readable name for ICMP code given type.
pub fn code_name(icmp_type: u8, code: u8) -> &'static str {
    match icmp_type {
        types::DEST_UNREACH => match code {
            dest_unreach_codes::NET_UNREACH => "network-unreachable",
            dest_unreach_codes::HOST_UNREACH => "host-unreachable",
            dest_unreach_codes::PROTO_UNREACH => "protocol-unreachable",
            dest_unreach_codes::PORT_UNREACH => "port-unreachable",
            dest_unreach_codes::FRAG_NEEDED => "fragmentation-needed",
            dest_unreach_codes::SRC_ROUTE_FAILED => "source-route-failed",
            _ => "unknown-code",
        },
        types::REDIRECT => match code {
            redirect_codes::REDIRECT_NET => "redirect-network",
            redirect_codes::REDIRECT_HOST => "redirect-host",
            redirect_codes::REDIRECT_TOS_NET => "redirect-tos-network",
            redirect_codes::REDIRECT_TOS_HOST => "redirect-tos-host",
            _ => "unknown-code",
        },
        types::TIME_EXCEEDED => match code {
            time_exceeded_codes::TTL_EXCEEDED => "ttl-exceeded",
            time_exceeded_codes::FRAG_REASSEMBLY => "fragment-reassembly-exceeded",
            _ => "unknown-code",
        },
        _ => "code",
    }
}
