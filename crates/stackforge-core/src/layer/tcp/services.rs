//! TCP services (port to name mapping).
//!
//! This module provides mappings between well-known TCP port numbers
//! and their service names, similar to Scapy's TCP_SERVICES.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Well-known TCP services mapping (port -> name).
pub static TCP_SERVICES: LazyLock<HashMap<u16, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    // System ports (0-1023)
    m.insert(1, "tcpmux");
    m.insert(5, "rje");
    m.insert(7, "echo");
    m.insert(9, "discard");
    m.insert(11, "systat");
    m.insert(13, "daytime");
    m.insert(17, "qotd");
    m.insert(18, "msp");
    m.insert(19, "chargen");
    m.insert(20, "ftp-data");
    m.insert(21, "ftp");
    m.insert(22, "ssh");
    m.insert(23, "telnet");
    m.insert(25, "smtp");
    m.insert(37, "time");
    m.insert(39, "rlp");
    m.insert(42, "nameserver");
    m.insert(43, "whois");
    m.insert(49, "tacacs");
    m.insert(50, "re-mail-ck");
    m.insert(53, "domain");
    m.insert(63, "whois++");
    m.insert(67, "bootps");
    m.insert(68, "bootpc");
    m.insert(69, "tftp");
    m.insert(70, "gopher");
    m.insert(71, "netrjs-1");
    m.insert(72, "netrjs-2");
    m.insert(73, "netrjs-3");
    m.insert(74, "netrjs-4");
    m.insert(79, "finger");
    m.insert(80, "http");
    m.insert(81, "hosts2-ns");
    m.insert(82, "xfer");
    m.insert(83, "mit-ml-dev");
    m.insert(84, "ctf");
    m.insert(85, "mit-ml-dev");
    m.insert(86, "mfcobol");
    m.insert(88, "kerberos");
    m.insert(89, "su-mit-tg");
    m.insert(90, "dnsix");
    m.insert(91, "mit-dov");
    m.insert(92, "npp");
    m.insert(93, "dcp");
    m.insert(94, "objcall");
    m.insert(95, "supdup");
    m.insert(96, "dixie");
    m.insert(97, "swift-rvf");
    m.insert(98, "tacnews");
    m.insert(99, "metagram");
    m.insert(101, "hostname");
    m.insert(102, "iso-tsap");
    m.insert(103, "gppitnp");
    m.insert(104, "acr-nema");
    m.insert(105, "csnet-ns");
    m.insert(106, "3com-tsmux");
    m.insert(107, "rtelnet");
    m.insert(108, "snagas");
    m.insert(109, "pop2");
    m.insert(110, "pop3");
    m.insert(111, "sunrpc");
    m.insert(112, "mcidas");
    m.insert(113, "auth");
    m.insert(115, "sftp");
    m.insert(117, "uucp-path");
    m.insert(118, "sqlserv");
    m.insert(119, "nntp");
    m.insert(120, "cfdptkt");
    m.insert(121, "erpc");
    m.insert(122, "smakynet");
    m.insert(123, "ntp");
    m.insert(124, "ansatrader");
    m.insert(125, "locus-map");
    m.insert(126, "unitary");
    m.insert(127, "locus-con");
    m.insert(128, "gss-xlicen");
    m.insert(129, "pwdgen");
    m.insert(130, "cisco-fna");
    m.insert(131, "cisco-tna");
    m.insert(132, "cisco-sys");
    m.insert(133, "statsrv");
    m.insert(134, "ingres-net");
    m.insert(135, "msrpc");
    m.insert(136, "profile");
    m.insert(137, "netbios-ns");
    m.insert(138, "netbios-dgm");
    m.insert(139, "netbios-ssn");
    m.insert(140, "emfis-data");
    m.insert(141, "emfis-cntl");
    m.insert(142, "bl-idm");
    m.insert(143, "imap");
    m.insert(144, "uma");
    m.insert(145, "uaac");
    m.insert(146, "iso-tp0");
    m.insert(147, "iso-ip");
    m.insert(148, "jargon");
    m.insert(149, "aed-512");
    m.insert(150, "sql-net");
    m.insert(151, "hems");
    m.insert(152, "bftp");
    m.insert(153, "sgmp");
    m.insert(154, "netsc-prod");
    m.insert(155, "netsc-dev");
    m.insert(156, "sqlsrv");
    m.insert(157, "knet-cmp");
    m.insert(158, "pcmail-srv");
    m.insert(159, "nss-routing");
    m.insert(160, "sgmp-traps");
    m.insert(161, "snmp");
    m.insert(162, "snmptrap");
    m.insert(163, "cmip-man");
    m.insert(164, "cmip-agent");
    m.insert(165, "xns-courier");
    m.insert(166, "s-net");
    m.insert(167, "namp");
    m.insert(168, "rsvd");
    m.insert(169, "send");
    m.insert(170, "print-srv");
    m.insert(171, "multiplex");
    m.insert(172, "cl/1");
    m.insert(173, "xyplex-mux");
    m.insert(174, "mailq");
    m.insert(175, "vmnet");
    m.insert(176, "genrad-mux");
    m.insert(177, "xdmcp");
    m.insert(178, "nextstep");
    m.insert(179, "bgp");
    m.insert(180, "ris");
    m.insert(181, "unify");
    m.insert(182, "audit");
    m.insert(183, "ocbinder");
    m.insert(184, "ocserver");
    m.insert(185, "remote-kis");
    m.insert(186, "kis");
    m.insert(187, "aci");
    m.insert(188, "mumps");
    m.insert(189, "qft");
    m.insert(190, "gacp");
    m.insert(191, "prospero");
    m.insert(192, "osu-nms");
    m.insert(193, "srmp");
    m.insert(194, "irc");
    m.insert(195, "dn6-nlm-aud");
    m.insert(196, "dn6-smm-red");
    m.insert(197, "dls");
    m.insert(198, "dls-mon");
    m.insert(199, "smux");
    m.insert(200, "src");
    m.insert(201, "at-rtmp");
    m.insert(202, "at-nbp");
    m.insert(203, "at-3");
    m.insert(204, "at-echo");
    m.insert(205, "at-5");
    m.insert(206, "at-zis");
    m.insert(207, "at-7");
    m.insert(208, "at-8");
    m.insert(209, "qmtp");
    m.insert(210, "z39.50");
    m.insert(211, "914c/g");
    m.insert(212, "anet");
    m.insert(213, "ipx");
    m.insert(214, "vmpwscs");
    m.insert(215, "softpc");
    m.insert(216, "CAIlic");
    m.insert(217, "dbase");
    m.insert(218, "mpp");
    m.insert(219, "uarps");
    m.insert(220, "imap3");
    m.insert(221, "fln-spx");
    m.insert(222, "rsh-spx");
    m.insert(223, "cdc");
    m.insert(224, "masqdialer");
    m.insert(242, "direct");
    m.insert(243, "sur-meas");
    m.insert(244, "dayna");
    m.insert(245, "link");
    m.insert(246, "dsp3270");
    m.insert(247, "subntbcst_tftp");
    m.insert(248, "bhfhs");
    m.insert(256, "rap");
    m.insert(257, "set");
    m.insert(259, "esro-gen");
    m.insert(260, "openport");
    m.insert(261, "nsiiops");
    m.insert(262, "arcisdms");
    m.insert(263, "hdap");
    m.insert(264, "bgmp");
    m.insert(280, "http-mgmt");
    m.insert(281, "personal-link");
    m.insert(282, "cableport-ax");
    m.insert(283, "rescap");
    m.insert(284, "corerjd");
    m.insert(286, "fxp-1");
    m.insert(287, "k-block");
    m.insert(308, "novastorbakcup");
    m.insert(309, "entrusttime");
    m.insert(310, "bhmds");
    m.insert(311, "asip-webadmin");
    m.insert(312, "vslmp");
    m.insert(313, "magenta-logic");
    m.insert(314, "opalis-robot");
    m.insert(315, "dpsi");
    m.insert(316, "decauth");
    m.insert(317, "zannet");
    m.insert(318, "pkix-timestamp");
    m.insert(319, "ptp-event");
    m.insert(320, "ptp-general");
    m.insert(321, "pip");
    m.insert(322, "rtsps");
    m.insert(333, "texar");
    m.insert(344, "pdap");
    m.insert(345, "pawserv");
    m.insert(346, "zserv");
    m.insert(347, "fatserv");
    m.insert(348, "csi-sgwp");
    m.insert(349, "mftp");
    m.insert(350, "matip-type-a");
    m.insert(351, "matip-type-b");
    m.insert(352, "dtag-ste-sb");
    m.insert(353, "ndsauth");
    m.insert(354, "bh611");
    m.insert(355, "datex-asn");
    m.insert(356, "cloanto-net-1");
    m.insert(357, "bhevent");
    m.insert(358, "shrinkwrap");
    m.insert(359, "nsrmp");
    m.insert(360, "scoi2odialog");
    m.insert(361, "semantix");
    m.insert(362, "srssend");
    m.insert(363, "rsvp_tunnel");
    m.insert(364, "aurora-cmgr");
    m.insert(365, "dtk");
    m.insert(366, "odmr");
    m.insert(367, "mortgageware");
    m.insert(368, "qbikgdp");
    m.insert(369, "rpc2portmap");
    m.insert(370, "codaauth2");
    m.insert(371, "clearcase");
    m.insert(372, "ulistserv");
    m.insert(373, "legent-1");
    m.insert(374, "legent-2");
    m.insert(375, "hassle");
    m.insert(376, "nip");
    m.insert(377, "tnETOS");
    m.insert(378, "dsETOS");
    m.insert(379, "is99c");
    m.insert(380, "is99s");
    m.insert(381, "hp-collector");
    m.insert(382, "hp-managed-node");
    m.insert(383, "hp-alarm-mgr");
    m.insert(384, "arns");
    m.insert(385, "ibm-app");
    m.insert(386, "asa");
    m.insert(387, "aurp");
    m.insert(388, "unidata-ldm");
    m.insert(389, "ldap");
    m.insert(390, "uis");
    m.insert(391, "synotics-relay");
    m.insert(392, "synotics-broker");
    m.insert(393, "dis");
    m.insert(394, "embl-ndt");
    m.insert(395, "netcp");
    m.insert(396, "netware-ip");
    m.insert(397, "mptn");
    m.insert(398, "kryptolan");
    m.insert(399, "iso-tsap-c2");
    m.insert(400, "work-sol");
    m.insert(401, "ups");
    m.insert(402, "genie");
    m.insert(403, "decap");
    m.insert(404, "nced");
    m.insert(405, "ncld");
    m.insert(406, "imsp");
    m.insert(407, "timbuktu");
    m.insert(408, "prm-sm");
    m.insert(409, "prm-nm");
    m.insert(410, "decladebug");
    m.insert(411, "rmt");
    m.insert(412, "synoptics-trap");
    m.insert(413, "smsp");
    m.insert(414, "infoseek");
    m.insert(415, "bnet");
    m.insert(416, "silverplatter");
    m.insert(417, "onmux");
    m.insert(418, "hyper-g");
    m.insert(419, "ariel1");
    m.insert(420, "smpte");
    m.insert(421, "ariel2");
    m.insert(422, "ariel3");
    m.insert(423, "opc-job-start");
    m.insert(424, "opc-job-track");
    m.insert(425, "icad-el");
    m.insert(426, "smartsdp");
    m.insert(427, "svrloc");
    m.insert(428, "ocs_cmu");
    m.insert(429, "ocs_amu");
    m.insert(430, "utmpsd");
    m.insert(431, "utmpcd");
    m.insert(432, "iasd");
    m.insert(433, "nnsp");
    m.insert(434, "mobileip-agent");
    m.insert(435, "mobilip-mn");
    m.insert(436, "dna-cml");
    m.insert(437, "comscm");
    m.insert(438, "dsfgw");
    m.insert(439, "dasp");
    m.insert(440, "sgcp");
    m.insert(441, "decvms-sysmgt");
    m.insert(442, "cvc_hostd");
    m.insert(443, "https");
    m.insert(444, "snpp");
    m.insert(445, "microsoft-ds");
    m.insert(446, "ddm-rdb");
    m.insert(447, "ddm-dfm");
    m.insert(448, "ddm-byte");
    m.insert(449, "as-servermap");
    m.insert(450, "tserver");
    m.insert(464, "kpasswd");
    m.insert(465, "smtps");
    m.insert(475, "cybercash");
    m.insert(487, "saft");
    m.insert(488, "gss-http");
    m.insert(489, "nest-protocol");
    m.insert(491, "go-login");
    m.insert(497, "retrospect");
    m.insert(500, "isakmp");
    m.insert(501, "stmf");
    m.insert(502, "asa-appl-proto");
    m.insert(504, "citadel");
    m.insert(510, "fcp");
    m.insert(512, "exec");
    m.insert(513, "login");
    m.insert(514, "shell");
    m.insert(515, "printer");
    m.insert(517, "talk");
    m.insert(518, "ntalk");
    m.insert(519, "utime");
    m.insert(520, "efs");
    m.insert(521, "ripng");
    m.insert(522, "ulp");
    m.insert(523, "ibm-db2");
    m.insert(524, "ncp");
    m.insert(525, "timed");
    m.insert(526, "tempo");
    m.insert(527, "stx");
    m.insert(528, "custix");
    m.insert(529, "irc-serv");
    m.insert(530, "courier");
    m.insert(531, "conference");
    m.insert(532, "netnews");
    m.insert(533, "netwall");
    m.insert(534, "mm-admin");
    m.insert(535, "iiop");
    m.insert(536, "opalis-rdv");
    m.insert(537, "nmsp");
    m.insert(538, "gdomap");
    m.insert(539, "apertus-ldp");
    m.insert(540, "uucp");
    m.insert(541, "uucp-rlogin");
    m.insert(542, "commerce");
    m.insert(543, "klogin");
    m.insert(544, "kshell");
    m.insert(545, "appleqtcsrvr");
    m.insert(546, "dhcpv6-client");
    m.insert(547, "dhcpv6-server");
    m.insert(548, "afp");
    m.insert(549, "idfp");
    m.insert(550, "new-rwho");
    m.insert(551, "cybercash");
    m.insert(552, "deviceshare");
    m.insert(553, "pirp");
    m.insert(554, "rtsp");
    m.insert(555, "dsf");
    m.insert(556, "remotefs");
    m.insert(557, "openvms-sysipc");
    m.insert(558, "sdnskmp");
    m.insert(559, "teedtap");
    m.insert(560, "rmonitor");
    m.insert(561, "monitor");
    m.insert(562, "chshell");
    m.insert(563, "nntps");
    m.insert(564, "9pfs");
    m.insert(565, "whoami");
    m.insert(566, "streettalk");
    m.insert(567, "banyan-rpc");
    m.insert(568, "ms-shuttle");
    m.insert(569, "ms-rome");
    m.insert(570, "meter");
    m.insert(571, "meter");
    m.insert(572, "sonar");
    m.insert(573, "banyan-vip");
    m.insert(574, "ftp-agent");
    m.insert(575, "vemmi");
    m.insert(576, "ipcd");
    m.insert(577, "vnas");
    m.insert(578, "ipdd");
    m.insert(579, "decbsrv");
    m.insert(580, "sntp-heartbeat");
    m.insert(581, "bdp");
    m.insert(582, "scc-security");
    m.insert(583, "philips-vc");
    m.insert(584, "keyserver");
    m.insert(585, "imap4-ssl");
    m.insert(586, "password-chg");
    m.insert(587, "submission");
    m.insert(588, "cal");
    m.insert(589, "eyelink");
    m.insert(590, "tns-cml");
    m.insert(591, "http-alt");
    m.insert(592, "eudora-set");
    m.insert(593, "http-rpc-epmap");
    m.insert(594, "tpip");
    m.insert(595, "cab-protocol");
    m.insert(596, "smsd");
    m.insert(597, "ptcnameservice");
    m.insert(598, "sco-websrvrmg3");
    m.insert(599, "acp");
    m.insert(600, "ipcserver");
    m.insert(606, "urm");
    m.insert(607, "nqs");
    m.insert(608, "sift-uft");
    m.insert(609, "npmp-trap");
    m.insert(610, "npmp-local");
    m.insert(611, "npmp-gui");
    m.insert(612, "hmmp-ind");
    m.insert(613, "hmmp-op");
    m.insert(614, "sshell");
    m.insert(615, "sco-inetmgr");
    m.insert(616, "sco-sysmgr");
    m.insert(617, "sco-dtmgr");
    m.insert(618, "dei-icda");
    m.insert(619, "digital-evm");
    m.insert(620, "sco-websrvrmgr");
    m.insert(621, "escp-ip");
    m.insert(622, "collaborator");
    m.insert(623, "asf-rmcp");
    m.insert(624, "cryptoadmin");
    m.insert(625, "dec_dlm");
    m.insert(626, "asia");
    m.insert(627, "passgo-tivoli");
    m.insert(628, "qmqp");
    m.insert(629, "3com-amp3");
    m.insert(630, "rda");
    m.insert(631, "ipp");
    m.insert(632, "bmpp");
    m.insert(633, "servstat");
    m.insert(634, "ginad");
    m.insert(635, "rlzdbase");
    m.insert(636, "ldaps");
    m.insert(637, "lanserver");
    m.insert(638, "mcns-sec");
    m.insert(639, "msdp");
    m.insert(640, "entrust-sps");
    m.insert(641, "repcmd");
    m.insert(642, "esro-emsdp");
    m.insert(643, "sanity");
    m.insert(644, "dwr");
    m.insert(645, "pssc");
    m.insert(646, "ldp");
    m.insert(647, "dhcp-failover");
    m.insert(648, "rrp");
    m.insert(649, "cadview-3d");
    m.insert(650, "obex");
    m.insert(651, "ieee-mms");
    m.insert(652, "hello-port");
    m.insert(653, "repscmd");
    m.insert(654, "aodv");
    m.insert(655, "tinc");
    m.insert(656, "spmp");
    m.insert(657, "rmc");
    m.insert(658, "tenfold");
    m.insert(660, "mac-srvr-admin");
    m.insert(661, "hap");
    m.insert(662, "pftp");
    m.insert(663, "purenoise");
    m.insert(664, "asf-secure-rmcp");
    m.insert(665, "sun-dr");
    m.insert(666, "mdqs");
    m.insert(667, "disclose");
    m.insert(668, "mecomm");
    m.insert(669, "meregister");
    m.insert(670, "vacdsm-sws");
    m.insert(671, "vacdsm-app");
    m.insert(672, "vpps-qua");
    m.insert(673, "cimplex");
    m.insert(674, "acap");
    m.insert(675, "dctp");
    m.insert(676, "vpps-via");
    m.insert(677, "vpp");
    m.insert(678, "ggf-ncp");
    m.insert(679, "mrm");
    m.insert(680, "entrust-aaas");
    m.insert(681, "entrust-aams");
    m.insert(682, "xfr");
    m.insert(683, "corba-iiop");
    m.insert(684, "corba-iiop-ssl");
    m.insert(685, "mdc-portmapper");
    m.insert(686, "hcp-wismar");
    m.insert(687, "asipregistry");
    m.insert(688, "realm-rusd");
    m.insert(689, "nmap");
    m.insert(690, "vatp");
    m.insert(691, "msexch-routing");
    m.insert(692, "hyperwave-isp");
    m.insert(693, "connendp");
    m.insert(694, "ha-cluster");
    m.insert(695, "ieee-mms-ssl");
    m.insert(696, "rushd");
    m.insert(697, "uuidgen");
    m.insert(698, "olsr");
    m.insert(699, "accessnetwork");
    m.insert(700, "epp");
    m.insert(701, "lmp");
    m.insert(702, "iris-beep");
    m.insert(704, "elcsd");
    m.insert(705, "agentx");
    m.insert(706, "silc");
    m.insert(707, "borland-dsj");
    m.insert(709, "entrust-kmsh");
    m.insert(710, "entrust-ash");
    m.insert(711, "cisco-tdp");
    m.insert(712, "tbrpf");
    m.insert(729, "netviewdm1");
    m.insert(730, "netviewdm2");
    m.insert(731, "netviewdm3");
    m.insert(741, "netgw");
    m.insert(742, "netrcs");
    m.insert(744, "flexlm");
    m.insert(747, "fujitsu-dev");
    m.insert(748, "ris-cm");
    m.insert(749, "kerberos-adm");
    m.insert(750, "rfile");
    m.insert(751, "pump");
    m.insert(752, "qrh");
    m.insert(753, "rrh");
    m.insert(754, "tell");
    m.insert(758, "nlogin");
    m.insert(759, "con");
    m.insert(760, "ns");
    m.insert(761, "rxe");
    m.insert(762, "quotad");
    m.insert(763, "cycleserv");
    m.insert(764, "omserv");
    m.insert(765, "webster");
    m.insert(767, "phonebook");
    m.insert(769, "vid");
    m.insert(770, "cadlock");
    m.insert(771, "rtip");
    m.insert(772, "cycleserv2");
    m.insert(773, "submit");
    m.insert(774, "rpasswd");
    m.insert(775, "entomb");
    m.insert(776, "wpages");
    m.insert(777, "multiling-http");
    m.insert(780, "wpgs");
    m.insert(800, "mdbs_daemon");
    m.insert(801, "device");
    m.insert(810, "fcp-udp");
    m.insert(828, "itm-mcell-s");
    m.insert(829, "pkix-3-ca-ra");
    m.insert(830, "netconf-ssh");
    m.insert(831, "netconf-beep");
    m.insert(832, "netconfsoaphttp");
    m.insert(833, "netconfsoapbeep");
    m.insert(847, "dhcp-failover2");
    m.insert(848, "gdoi");
    m.insert(860, "iscsi");
    m.insert(861, "owamp-control");
    m.insert(873, "rsync");
    m.insert(886, "iclcnet-locate");
    m.insert(887, "iclcnet_svinfo");
    m.insert(888, "accessbuilder");
    m.insert(900, "omginitialrefs");
    m.insert(901, "smpnameres");
    m.insert(902, "ideafarm-chat");
    m.insert(903, "ideafarm-catch");
    m.insert(910, "kink");
    m.insert(911, "xact-backup");
    m.insert(912, "apex-mesh");
    m.insert(913, "apex-edge");
    m.insert(989, "ftps-data");
    m.insert(990, "ftps");
    m.insert(991, "nas");
    m.insert(992, "telnets");
    m.insert(993, "imaps");
    m.insert(994, "ircs");
    m.insert(995, "pop3s");
    m.insert(996, "vsinet");
    m.insert(997, "maitrd");
    m.insert(998, "busboy");
    m.insert(999, "garcon");
    m.insert(1000, "cadlock2");
    m.insert(1001, "webpush");

    // Common registered ports (1024-49151)
    m.insert(1080, "socks");
    m.insert(1194, "openvpn");
    m.insert(1433, "ms-sql-s");
    m.insert(1434, "ms-sql-m");
    m.insert(1521, "oracle");
    m.insert(1723, "pptp");
    m.insert(1812, "radius");
    m.insert(1813, "radius-acct");
    m.insert(2049, "nfs");
    m.insert(2082, "cpanel");
    m.insert(2083, "cpanels");
    m.insert(2086, "whm");
    m.insert(2087, "whms");
    m.insert(2181, "zookeeper");
    m.insert(2222, "ssh-alt");
    m.insert(2375, "docker");
    m.insert(2376, "docker-s");
    m.insert(2379, "etcd-client");
    m.insert(2380, "etcd-server");
    m.insert(3000, "ppp");
    m.insert(3128, "squid");
    m.insert(3268, "ldap-gc");
    m.insert(3269, "ldaps-gc");
    m.insert(3306, "mysql");
    m.insert(3389, "ms-wbt-server");
    m.insert(3690, "svn");
    m.insert(4000, "terabase");
    m.insert(4369, "epmd");
    m.insert(4443, "pharos");
    m.insert(5000, "upnp");
    m.insert(5001, "commplex-link");
    m.insert(5060, "sip");
    m.insert(5061, "sips");
    m.insert(5222, "xmpp-client");
    m.insert(5223, "xmpp-client-ssl");
    m.insert(5269, "xmpp-server");
    m.insert(5432, "postgresql");
    m.insert(5672, "amqp");
    m.insert(5900, "vnc");
    m.insert(5984, "couchdb");
    m.insert(6000, "x11");
    m.insert(6379, "redis");
    m.insert(6443, "kubernetes-api");
    m.insert(6666, "irc-alt");
    m.insert(6667, "irc");
    m.insert(6668, "irc-alt");
    m.insert(6669, "irc-alt");
    m.insert(7000, "afs3-fileserver");
    m.insert(7001, "afs3-callback");
    m.insert(7002, "afs3-prserver");
    m.insert(7003, "afs3-vlserver");
    m.insert(7004, "afs3-kaserver");
    m.insert(7005, "afs3-volser");
    m.insert(7006, "afs3-errors");
    m.insert(7007, "afs3-bos");
    m.insert(7008, "afs3-update");
    m.insert(7009, "afs3-rmtsys");
    m.insert(7010, "ups-onlinet");
    m.insert(8000, "http-alt");
    m.insert(8008, "http-alt");
    m.insert(8080, "http-proxy");
    m.insert(8081, "blackice-icecap");
    m.insert(8088, "radan-http");
    m.insert(8443, "https-alt");
    m.insert(8888, "ddi-tcp-1");
    m.insert(9000, "cslistener");
    m.insert(9042, "cassandra");
    m.insert(9090, "websm");
    m.insert(9091, "xmltec-xmlmail");
    m.insert(9092, "kafka");
    m.insert(9200, "elasticsearch");
    m.insert(9300, "elasticsearch");
    m.insert(9418, "git");
    m.insert(9999, "abyss");
    m.insert(10000, "webmin");
    m.insert(11211, "memcached");
    m.insert(15672, "rabbitmq-mgmt");
    m.insert(25565, "minecraft");
    m.insert(27017, "mongodb");
    m.insert(27018, "mongodb");
    m.insert(27019, "mongodb");

    m
});

/// Reverse mapping (name -> port).
pub static TCP_SERVICES_BY_NAME: LazyLock<HashMap<&'static str, u16>> = LazyLock::new(|| {
    TCP_SERVICES
        .iter()
        .map(|(&port, &name)| (name, port))
        .collect()
});

/// Get the service name for a port.
///
/// Returns "unknown" if the port is not in the database.
pub fn service_name(port: u16) -> &'static str {
    TCP_SERVICES.get(&port).copied().unwrap_or("unknown")
}

/// Get the port number for a service name.
///
/// Returns None if the service name is not found.
pub fn service_port(name: &str) -> Option<u16> {
    TCP_SERVICES_BY_NAME.get(name).copied()
}

/// Check if a port is a well-known port (< 1024).
#[inline]
pub fn is_well_known_port(port: u16) -> bool {
    port < 1024
}

/// Check if a port is a registered port (1024-49151).
#[inline]
pub fn is_registered_port(port: u16) -> bool {
    (1024..49152).contains(&port)
}

/// Check if a port is a dynamic/private port (49152-65535).
#[inline]
pub fn is_dynamic_port(port: u16) -> bool {
    port >= 49152
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_well_known_services() {
        assert_eq!(service_name(20), "ftp-data");
        assert_eq!(service_name(21), "ftp");
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(23), "telnet");
        assert_eq!(service_name(25), "smtp");
        assert_eq!(service_name(53), "domain");
        assert_eq!(service_name(80), "http");
        assert_eq!(service_name(110), "pop3");
        assert_eq!(service_name(143), "imap");
        assert_eq!(service_name(443), "https");
        assert_eq!(service_name(993), "imaps");
        assert_eq!(service_name(995), "pop3s");
    }

    #[test]
    fn test_registered_services() {
        assert_eq!(service_name(3306), "mysql");
        assert_eq!(service_name(5432), "postgresql");
        assert_eq!(service_name(6379), "redis");
        assert_eq!(service_name(8080), "http-proxy");
        assert_eq!(service_name(27017), "mongodb");
    }

    #[test]
    fn test_unknown_port() {
        assert_eq!(service_name(12345), "unknown");
        assert_eq!(service_name(65000), "unknown");
    }

    #[test]
    fn test_service_port() {
        assert_eq!(service_port("http"), Some(80));
        assert_eq!(service_port("https"), Some(443));
        assert_eq!(service_port("ssh"), Some(22));
        assert_eq!(service_port("mysql"), Some(3306));
        assert_eq!(service_port("nonexistent"), None);
    }

    #[test]
    fn test_port_categories() {
        assert!(is_well_known_port(80));
        assert!(is_well_known_port(443));
        assert!(!is_well_known_port(8080));

        assert!(!is_registered_port(80));
        assert!(is_registered_port(8080));
        assert!(is_registered_port(3306));
        assert!(!is_registered_port(50000));

        assert!(!is_dynamic_port(80));
        assert!(!is_dynamic_port(8080));
        assert!(is_dynamic_port(50000));
        assert!(is_dynamic_port(65535));
    }
}
