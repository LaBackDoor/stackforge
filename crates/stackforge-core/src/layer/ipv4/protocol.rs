//! IPv4 Protocol numbers.
//!
//! Registry of common IP protocol numbers assigned by IANA.
//! These values correspond to the "Protocol" field in the IPv4 header.

/// IPv6 Hop-by-Hop Option (RFC 8200)
pub const HOPOPT: u8 = 0;

/// Internet Control Message (RFC 792)
pub const ICMP: u8 = 1;

/// Internet Group Management (RFC 1112)
pub const IGMP: u8 = 2;

/// Gateway-to-Gateway (RFC 823)
pub const GGP: u8 = 3;

/// IP in IP (encapsulation) (RFC 2003)
pub const IPIP: u8 = 4;

/// IPv4 Encapsulation (alias for IPIP)
pub const IPV4: u8 = 4;

/// Stream Internet (RFC 1190)
pub const ST: u8 = 5;

/// Transmission Control (RFC 793)
pub const TCP: u8 = 6;

/// CBT (RFC 2189)
pub const CBT: u8 = 7;

/// Exterior Gateway Protocol (RFC 888)
pub const EGP: u8 = 8;

/// IGP (any private interior gateway: used by Cisco for their IGRP)
pub const IGP: u8 = 9;

/// BBN RCC Monitoring
pub const BBN_RCC_MON: u8 = 10;

/// Network Voice Protocol (RFC 741)
pub const NVP_II: u8 = 11;

/// PUP
pub const PUP: u8 = 12;

/// ARGUS
pub const ARGUS: u8 = 13;

/// EMCON
pub const EMCON: u8 = 14;

/// Cross Net Debugger
pub const XNET: u8 = 15;

/// Chaos
pub const CHAOS: u8 = 16;

/// User Datagram (RFC 768)
pub const UDP: u8 = 17;

/// Multiplexing
pub const MUX: u8 = 18;

/// DCN Measurement Subsystems
pub const DCN_MEAS: u8 = 19;

/// Host Monitoring (RFC 869)
pub const HMP: u8 = 20;

/// Packet Radio Measurement
pub const PRM: u8 = 21;

/// XEROX NS IDP
pub const XNS_IDP: u8 = 22;

/// Trunk-1
pub const TRUNK_1: u8 = 23;

/// Trunk-2
pub const TRUNK_2: u8 = 24;

/// Leaf-1
pub const LEAF_1: u8 = 25;

/// Leaf-2
pub const LEAF_2: u8 = 26;

/// Reliable Data Protocol (RFC 908)
pub const RDP: u8 = 27;

/// Internet Reliable Transaction (RFC 938)
pub const IRTP: u8 = 28;

/// ISO Transport Class 4 (RFC 905)
pub const ISO_TP4: u8 = 29;

/// Bulk Data Transfer Protocol (RFC 969)
pub const NETBLT: u8 = 30;

/// MFE Network Services Protocol
pub const MFE_NSP: u8 = 31;

/// MERIT Internodal Protocol
pub const MERIT_INP: u8 = 32;

/// Datagram Congestion Control Protocol (RFC 4340)
pub const DCCP: u8 = 33;

/// Third Party Connect Protocol
pub const THIRD_PARTY_CONNECT: u8 = 34;

/// IDPR (RFC 1479)
pub const IDPR: u8 = 35;

/// XTP
pub const XTP: u8 = 36;

/// Datagram Delivery Protocol
pub const DDP: u8 = 37;

/// IDPR Control Message Transport Proto
pub const IDPR_CMTP: u8 = 38;

/// TP++ Transport Protocol
pub const TP_PLUS_PLUS: u8 = 39;

/// IL Transport Protocol
pub const IL: u8 = 40;

/// IPv6 Encapsulation (RFC 2473)
pub const IPV6: u8 = 41;

/// Source Demand Routing Protocol
pub const SDRP: u8 = 42;

/// Routing Header for IPv6 (RFC 8200)
pub const IPV6_ROUTE: u8 = 43;

/// Fragment Header for IPv6 (RFC 8200)
pub const IPV6_FRAG: u8 = 44;

/// Inter-Domain Policy Routing Protocol
pub const IDRP: u8 = 45;

/// Reservation Protocol (RFC 2205)
pub const RSVP: u8 = 46;

/// Generic Routing Encapsulation (RFC 2784)
pub const GRE: u8 = 47;

/// Dynamic Source Routing Protocol (RFC 4728)
pub const DSR: u8 = 48;

/// BNA
pub const BNA: u8 = 49;

/// Encap Security Payload (RFC 4303)
pub const ESP: u8 = 50;

/// Authentication Header (RFC 4302)
pub const AH: u8 = 51;

/// Integrated Net Layer Security  TUBA
pub const I_NLSP: u8 = 52;

/// IP with Encryption
pub const SWIPE: u8 = 53;

/// NBMA Address Resolution Protocol (RFC 1735)
pub const NARP: u8 = 54;

/// IP Mobility (RFC 2004)
pub const MOBILE: u8 = 55;

/// Transport Layer Security Protocol using Kryptonet key management
pub const TLSP: u8 = 56;

/// SKIP
pub const SKIP: u8 = 57;

/// ICMP for IPv6 (RFC 4443)
pub const ICMPV6: u8 = 58;

/// No Next Header for IPv6 (RFC 8200)
pub const IPV6_NONXT: u8 = 59;

/// Destination Options for IPv6 (RFC 8200)
pub const IPV6_OPTS: u8 = 60;

/// Any host internal protocol
pub const ANY_HOST_INTERNAL: u8 = 61;

/// CFTP
pub const CFTP: u8 = 62;

/// Any local network
pub const ANY_LOCAL_NETWORK: u8 = 63;

/// SATNET and Backroom EXPAK
pub const SAT_EXPAK: u8 = 64;

/// Kryptolan
pub const KRYPTOLAN: u8 = 65;

/// MIT Remote Virtual Disk Protocol
pub const RVD: u8 = 66;

/// Internet Pluribus Packet Core
pub const IPPC: u8 = 67;

/// Any distributed file system
pub const ANY_DIST_FS: u8 = 68;

/// SATNET Monitoring
pub const SAT_MON: u8 = 69;

/// VISA Protocol
pub const VISA: u8 = 70;

/// Internet Packet Core Utility
pub const IPCV: u8 = 71;

/// Computer Protocol Network Executive
pub const CPNX: u8 = 72;

/// Computer Protocol Heart Beat
pub const CPHB: u8 = 73;

/// Wang Span Network
pub const WSN: u8 = 74;

/// Packet Video Protocol
pub const PVP: u8 = 75;

/// Backroom SATNET Monitoring
pub const BR_SAT_MON: u8 = 76;

/// SUN ND PROTOCOL-Temporary
pub const SUN_ND: u8 = 77;

/// WIDEBAND Monitoring
pub const WB_MON: u8 = 78;

/// WIDEBAND EXPAK
pub const WB_EXPAK: u8 = 79;

/// ISO Internet Protocol
pub const ISO_IP: u8 = 80;

/// VMTP
pub const VMTP: u8 = 81;

/// SECURE-VMTP
pub const SECURE_VMTP: u8 = 82;

/// VINES
pub const VINES: u8 = 83;

/// Transaction Transport Protocol (IPTM)
pub const TTP: u8 = 84;

/// NSFNET-IGP
pub const NSFNET_IGP: u8 = 85;

/// Dissimilar Gateway Protocol
pub const DGP: u8 = 86;

/// TCF
pub const TCF: u8 = 87;

/// EIGRP (RFC 7868)
pub const EIGRP: u8 = 88;

/// OSPF (RFC 2328)
pub const OSPFIGP: u8 = 89;

/// Sprite RPC Protocol
pub const SPRITE_RPC: u8 = 90;

/// Locus Address Resolution Protocol
pub const LARP: u8 = 91;

/// Multicast Transport Protocol
pub const MTP: u8 = 92;

/// AX.25 Frames
pub const AX_25: u8 = 93;

/// IP-within-IP Encapsulation Protocol
pub const IPIP_ENCAP: u8 = 94;

/// Mobile Internetworking Control Pro. (RFC 2003)
pub const MICP: u8 = 95;

/// Semaphore Communications Sec. Pro.
pub const SCC_SP: u8 = 96;

/// Ethernet-within-IP Encapsulation (RFC 3378)
pub const ETHERIP: u8 = 97;

/// Encapsulation Header (RFC 1241)
pub const ENCAP: u8 = 98;

/// Any private encryption scheme
pub const ANY_ENC: u8 = 99;

/// GMTP
pub const GMTP: u8 = 100;

/// Ipsilon Flow Management Protocol
pub const IFMP: u8 = 101;

/// PNNI over IP
pub const PNNI: u8 = 102;

/// Protocol Independent Multicast (RFC 7761)
pub const PIM: u8 = 103;

/// ARIS
pub const ARIS: u8 = 104;

/// SCPS
pub const SCPS: u8 = 105;

/// QNX
pub const QNX: u8 = 106;

/// Active Networks
pub const AN: u8 = 107;

/// IP Payload Compression Protocol (RFC 2393)
pub const IPCOMP: u8 = 108;

/// Sitara Networks Protocol
pub const SNP: u8 = 109;

/// Compaq Peer Protocol
pub const COMPAQ_PEER: u8 = 110;

/// IPX in IP
pub const IPX_IN_IP: u8 = 111;

/// Virtual Router Redundancy Protocol (RFC 5798)
pub const VRRP: u8 = 112;

/// PGM Reliable Transport Protocol
pub const PGM: u8 = 113;

/// Any 0-hop protocol
pub const ANY_0_HOP: u8 = 114;

/// Layer Two Tunneling Protocol (RFC 3931)
pub const L2TP: u8 = 115;

/// D-II Data Exchange (DX)
pub const DDX: u8 = 116;

/// Interactive Agent Transfer Protocol
pub const IATP: u8 = 117;

/// Schedule Transfer Protocol
pub const STP: u8 = 118;

/// SpectraLink Radio Protocol
pub const SRP: u8 = 119;

/// UTI
pub const UTI: u8 = 120;

/// Simple Message Protocol
pub const SMP: u8 = 121;

/// Simple Multicast Protocol
pub const SM: u8 = 122;

/// Performance Transparency Protocol
pub const PTP: u8 = 123;

/// ISIS over IPv4 (RFC 1142)
pub const ISIS_OVER_IPV4: u8 = 124;

/// CRTP
pub const FIRE: u8 = 125;

/// Combat Radio Transport Protocol
pub const CRTP: u8 = 126;

/// Combat Radio User Datagram
pub const CRUDP: u8 = 127;

/// SSCOPMCE
pub const SSCOPMCE: u8 = 128;

/// IPLT
pub const IPLT: u8 = 129;

/// Secure Packet Shield
pub const SPS: u8 = 130;

/// Private IP Encapsulation within IP
pub const PIPE: u8 = 131;

/// Stream Control Transmission Protocol (RFC 4960)
pub const SCTP: u8 = 132;

/// Fibre Channel
pub const FC: u8 = 133;

/// RSVP-E2E-IGNORE (RFC 3175)
pub const RSVP_E2E_IGNORE: u8 = 134;

/// Mobility Header (RFC 6275)
pub const MOBILITY_HEADER: u8 = 135;

/// UDPLite (RFC 3828)
pub const UDPLITE: u8 = 136;

/// MPLS-in-IP (RFC 4023)
pub const MPLS_IN_IP: u8 = 137;

/// MANET Protocols (RFC 5498)
pub const MANET: u8 = 138;

/// Host Identity Protocol (RFC 7401)
pub const HIP: u8 = 139;

/// Shim6 Protocol (RFC 5533)
pub const SHIM6: u8 = 140;

/// Wrapped Encapsulating Security Payload (RFC 5840)
pub const WESP: u8 = 141;

/// RObust Header Compression (RFC 5858)
pub const ROHC: u8 = 142;

/// Ethernet (RFC 8986)
pub const ETHERNET: u8 = 143;

/// AGGFRAG encapsulation payload for ESP (RFC 9347)
pub const AGGFRAG: u8 = 144;

/// Reserved
pub const RESERVED: u8 = 255;

/// Convert a string name to a protocol number (case-insensitive).
pub fn from_name(name: &str) -> Option<u8> {
    match name.to_ascii_lowercase().as_str() {
        "ip" => Some(0), // Sometimes used as alias for HOPOPT
        "ipv4" => Some(IPV4),
        "icmp" => Some(ICMP),
        "igmp" => Some(IGMP),
        "ggp" => Some(GGP),
        "ipip" => Some(IPIP),
        "tcp" => Some(TCP),
        "egp" => Some(EGP),
        "igp" => Some(IGP),
        "pup" => Some(PUP),
        "udp" => Some(UDP),
        "hmp" => Some(HMP),
        "xns-idp" => Some(XNS_IDP),
        "rdp" => Some(RDP),
        "iso-tp4" => Some(ISO_TP4),
        "dccp" => Some(DCCP),
        "xtp" => Some(XTP),
        "ddp" => Some(DDP),
        "idpr-cmtp" => Some(IDPR_CMTP),
        "ipv6" => Some(IPV6),
        "ipv6-route" => Some(IPV6_ROUTE),
        "ipv6-frag" => Some(IPV6_FRAG),
        "idrp" => Some(IDRP),
        "rsvp" => Some(RSVP),
        "gre" => Some(GRE),
        "esp" => Some(ESP),
        "ah" => Some(AH),
        "skip" => Some(SKIP),
        "icmpv6" => Some(ICMPV6),
        "ipv6-nonxt" => Some(IPV6_NONXT),
        "ipv6-opts" => Some(IPV6_OPTS),
        "eigrp" => Some(EIGRP),
        "ospf" => Some(OSPFIGP),
        "mtp" => Some(MTP),
        "encap" => Some(ENCAP),
        "pim" => Some(PIM),
        "ipcomp" => Some(IPCOMP),
        "vrrp" => Some(VRRP),
        "l2tp" => Some(L2TP),
        "isis" => Some(ISIS_OVER_IPV4),
        "sctp" => Some(SCTP),
        "fc" => Some(FC),
        "mobility-header" => Some(MOBILITY_HEADER),
        "udplite" => Some(UDPLITE),
        "mpls-in-ip" => Some(MPLS_IN_IP),
        "manet" => Some(MANET),
        "hip" => Some(HIP),
        "shim6" => Some(SHIM6),
        "wesp" => Some(WESP),
        "rohc" => Some(ROHC),
        "ethernet" => Some(ETHERNET),
        _ => None,
    }
}

/// Get the string name for a protocol number.
pub fn to_name(proto: u8) -> &'static str {
    match proto {
        HOPOPT => "HOPOPT",
        ICMP => "ICMP",
        IGMP => "IGMP",
        GGP => "GGP",
        IPIP => "IPIP",
        ST => "ST",
        TCP => "TCP",
        CBT => "CBT",
        EGP => "EGP",
        IGP => "IGP",
        BBN_RCC_MON => "BBN_RCC_MON",
        NVP_II => "NVP_II",
        PUP => "PUP",
        ARGUS => "ARGUS",
        EMCON => "EMCON",
        XNET => "XNET",
        CHAOS => "CHAOS",
        UDP => "UDP",
        MUX => "MUX",
        DCN_MEAS => "DCN_MEAS",
        HMP => "HMP",
        PRM => "PRM",
        XNS_IDP => "XNS_IDP",
        TRUNK_1 => "TRUNK_1",
        TRUNK_2 => "TRUNK_2",
        LEAF_1 => "LEAF_1",
        LEAF_2 => "LEAF_2",
        RDP => "RDP",
        IRTP => "IRTP",
        ISO_TP4 => "ISO_TP4",
        NETBLT => "NETBLT",
        MFE_NSP => "MFE_NSP",
        MERIT_INP => "MERIT_INP",
        DCCP => "DCCP",
        THIRD_PARTY_CONNECT => "THIRD_PARTY_CONNECT",
        IDPR => "IDPR",
        XTP => "XTP",
        DDP => "DDP",
        IDPR_CMTP => "IDPR_CMTP",
        TP_PLUS_PLUS => "TP_PLUS_PLUS",
        IL => "IL",
        IPV6 => "IPV6",
        SDRP => "SDRP",
        IPV6_ROUTE => "IPV6_ROUTE",
        IPV6_FRAG => "IPV6_FRAG",
        IDRP => "IDRP",
        RSVP => "RSVP",
        GRE => "GRE",
        DSR => "DSR",
        BNA => "BNA",
        ESP => "ESP",
        AH => "AH",
        I_NLSP => "I_NLSP",
        SWIPE => "SWIPE",
        NARP => "NARP",
        MOBILE => "MOBILE",
        TLSP => "TLSP",
        SKIP => "SKIP",
        ICMPV6 => "ICMPV6",
        IPV6_NONXT => "IPV6_NONXT",
        IPV6_OPTS => "IPV6_OPTS",
        ANY_HOST_INTERNAL => "ANY_HOST_INTERNAL",
        CFTP => "CFTP",
        ANY_LOCAL_NETWORK => "ANY_LOCAL_NETWORK",
        SAT_EXPAK => "SAT_EXPAK",
        KRYPTOLAN => "KRYPTOLAN",
        RVD => "RVD",
        IPPC => "IPPC",
        ANY_DIST_FS => "ANY_DIST_FS",
        SAT_MON => "SAT_MON",
        VISA => "VISA",
        IPCV => "IPCV",
        CPNX => "CPNX",
        CPHB => "CPHB",
        WSN => "WSN",
        PVP => "PVP",
        BR_SAT_MON => "BR_SAT_MON",
        SUN_ND => "SUN_ND",
        WB_MON => "WB_MON",
        WB_EXPAK => "WB_EXPAK",
        ISO_IP => "ISO_IP",
        VMTP => "VMTP",
        SECURE_VMTP => "SECURE_VMTP",
        VINES => "VINES",
        TTP => "TTP",
        NSFNET_IGP => "NSFNET_IGP",
        DGP => "DGP",
        TCF => "TCF",
        EIGRP => "EIGRP",
        OSPFIGP => "OSPFIGP",
        SPRITE_RPC => "SPRITE_RPC",
        LARP => "LARP",
        MTP => "MTP",
        AX_25 => "AX_25",
        IPIP_ENCAP => "IPIP_ENCAP",
        MICP => "MICP",
        SCC_SP => "SCC_SP",
        ETHERIP => "ETHERIP",
        ENCAP => "ENCAP",
        ANY_ENC => "ANY_ENC",
        GMTP => "GMTP",
        IFMP => "IFMP",
        PNNI => "PNNI",
        PIM => "PIM",
        ARIS => "ARIS",
        SCPS => "SCPS",
        QNX => "QNX",
        AN => "AN",
        IPCOMP => "IPCOMP",
        SNP => "SNP",
        COMPAQ_PEER => "COMPAQ_PEER",
        IPX_IN_IP => "IPX_IN_IP",
        VRRP => "VRRP",
        PGM => "PGM",
        ANY_0_HOP => "ANY_0_HOP",
        L2TP => "L2TP",
        DDX => "DDX",
        IATP => "IATP",
        STP => "STP",
        SRP => "SRP",
        UTI => "UTI",
        SMP => "SMP",
        SM => "SM",
        PTP => "PTP",
        ISIS_OVER_IPV4 => "ISIS_OVER_IPV4",
        FIRE => "FIRE",
        CRTP => "CRTP",
        CRUDP => "CRUDP",
        SSCOPMCE => "SSCOPMCE",
        IPLT => "IPLT",
        SPS => "SPS",
        PIPE => "PIPE",
        SCTP => "SCTP",
        FC => "FC",
        RSVP_E2E_IGNORE => "RSVP_E2E_IGNORE",
        MOBILITY_HEADER => "MOBILITY_HEADER",
        UDPLITE => "UDPLITE",
        MPLS_IN_IP => "MPLS_IN_IP",
        MANET => "MANET",
        HIP => "HIP",
        SHIM6 => "SHIM6",
        WESP => "WESP",
        ROHC => "ROHC",
        ETHERNET => "ETHERNET",
        AGGFRAG => "AGGFRAG",
        RESERVED => "RESERVED",
        _ => "UNKNOWN",
    }
}
