//! FTP (File Transfer Protocol) layer implementation.
//!
//! Implements RFC 959 FTP packet parsing as a zero-copy view into a packet buffer.
//!
//! FTP operates over two TCP connections:
//! - **Control connection** (port 21): Commands and replies (text-based)
//! - **Data connection** (port 20 or negotiated): Actual file data
//!
//! This implementation focuses on the **control connection** protocol.
//!
//! ## Packet Format
//!
//! **Client Command:**
//! ```text
//! COMMAND [arguments]\r\n
//! ```
//!
//! **Server Reply:**
//! ```text
//! NNN<SP>text\r\n               (single-line)
//! NNN-text\r\n ... NNN<SP>text\r\n  (multi-line)
//! ```
//! Where NNN is a 3-digit reply code.
//!
//! ## Reply Code Categories
//!
//! | Range | Meaning                   |
//! |-------|---------------------------|
//! | 1xx   | Positive Preliminary      |
//! | 2xx   | Positive Completion       |
//! | 3xx   | Positive Intermediate     |
//! | 4xx   | Transient Negative        |
//! | 5xx   | Permanent Negative        |

pub mod builder;
pub use builder::FtpBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum FTP payload: at least "OK\r\n" or short command.
pub const FTP_MIN_HEADER_LEN: usize = 4;

/// FTP control port.
pub const FTP_CONTROL_PORT: u16 = 21;

/// FTP data port.
pub const FTP_DATA_PORT: u16 = 20;

// ============================================================================
// FTP Reply code constants (RFC 959 §4.2)
// ============================================================================
pub const REPLY_RESTART_MARKER: u16 = 110;
pub const REPLY_SERVICE_READY_IN: u16 = 120;
pub const REPLY_DATA_OPEN_XFER: u16 = 125;
pub const REPLY_FILE_STATUS_OK: u16 = 150;
pub const REPLY_OK: u16 = 200;
pub const REPLY_COMMAND_NOT_IMPLEMENTED: u16 = 202;
pub const REPLY_SYSTEM_STATUS: u16 = 211;
pub const REPLY_DIR_STATUS: u16 = 212;
pub const REPLY_FILE_STATUS: u16 = 213;
pub const REPLY_HELP_MSG: u16 = 214;
pub const REPLY_NAME_SYSTEM: u16 = 215;
pub const REPLY_SERVICE_READY: u16 = 220;
pub const REPLY_CLOSING_CONTROL: u16 = 221;
pub const REPLY_DATA_OPEN: u16 = 225;
pub const REPLY_CLOSING_DATA: u16 = 226;
pub const REPLY_PASSIVE: u16 = 227;
pub const REPLY_LONG_PASSIVE: u16 = 228;
pub const REPLY_EXTENDED_PASSIVE: u16 = 229;
pub const REPLY_USER_LOGGED_IN: u16 = 230;
pub const REPLY_AUTH_OK: u16 = 234;
pub const REPLY_FILE_ACTION_OK: u16 = 250;
pub const REPLY_PATHNAME_CREATED: u16 = 257;
pub const REPLY_USER_OK_NEED_PASS: u16 = 331;
pub const REPLY_NEED_ACCOUNT: u16 = 332;
pub const REPLY_PENDING_INFO: u16 = 350;
pub const REPLY_SERVICE_NOT_AVAIL: u16 = 421;
pub const REPLY_CANT_OPEN_DATA: u16 = 425;
pub const REPLY_CONN_CLOSED: u16 = 426;
pub const REPLY_INVALID_CRED: u16 = 430;
pub const REPLY_HOST_UNAVAIL: u16 = 434;
pub const REPLY_FILE_UNAVAIL_BUSY: u16 = 450;
pub const REPLY_LOCAL_ERROR: u16 = 451;
pub const REPLY_INSUFF_STORAGE: u16 = 452;
pub const REPLY_SYNTAX_ERROR: u16 = 500;
pub const REPLY_ARG_SYNTAX_ERROR: u16 = 501;
pub const REPLY_CMD_NOT_IMPL: u16 = 502;
pub const REPLY_BAD_SEQUENCE: u16 = 503;
pub const REPLY_CMD_NOT_IMPL_PARAM: u16 = 504;
pub const REPLY_NOT_LOGGED_IN: u16 = 530;
pub const REPLY_NEED_ACCOUNT_FOR_STOR: u16 = 532;
pub const REPLY_FILE_UNAVAIL: u16 = 550;
pub const REPLY_PAGE_TYPE_UNKNOWN: u16 = 551;
pub const REPLY_EXCEED_STORAGE: u16 = 552;
pub const REPLY_FILENAME_NOT_ALLOWED: u16 = 553;

// ============================================================================
// FTP command constants
// ============================================================================
pub const CMD_USER: &str = "USER";
pub const CMD_PASS: &str = "PASS";
pub const CMD_ACCT: &str = "ACCT";
pub const CMD_CWD: &str = "CWD";
pub const CMD_CDUP: &str = "CDUP";
pub const CMD_SMNT: &str = "SMNT";
pub const CMD_QUIT: &str = "QUIT";
pub const CMD_REIN: &str = "REIN";
pub const CMD_PORT: &str = "PORT";
pub const CMD_PASV: &str = "PASV";
pub const CMD_TYPE: &str = "TYPE";
pub const CMD_STRU: &str = "STRU";
pub const CMD_MODE: &str = "MODE";
pub const CMD_RETR: &str = "RETR";
pub const CMD_STOR: &str = "STOR";
pub const CMD_STOU: &str = "STOU";
pub const CMD_APPE: &str = "APPE";
pub const CMD_ALLO: &str = "ALLO";
pub const CMD_REST: &str = "REST";
pub const CMD_RNFR: &str = "RNFR";
pub const CMD_RNTO: &str = "RNTO";
pub const CMD_ABOR: &str = "ABOR";
pub const CMD_DELE: &str = "DELE";
pub const CMD_RMD: &str = "RMD";
pub const CMD_MKD: &str = "MKD";
pub const CMD_PWD: &str = "PWD";
pub const CMD_LIST: &str = "LIST";
pub const CMD_NLST: &str = "NLST";
pub const CMD_SITE: &str = "SITE";
pub const CMD_SYST: &str = "SYST";
pub const CMD_STAT: &str = "STAT";
pub const CMD_HELP: &str = "HELP";
pub const CMD_NOOP: &str = "NOOP";
// Extensions (RFC 2389, RFC 3659, RFC 2428)
pub const CMD_FEAT: &str = "FEAT";
pub const CMD_OPTS: &str = "OPTS";
pub const CMD_EPRT: &str = "EPRT";
pub const CMD_EPSV: &str = "EPSV";
pub const CMD_MDTM: &str = "MDTM";
pub const CMD_SIZE: &str = "SIZE";
pub const CMD_MLST: &str = "MLST";
pub const CMD_MLSD: &str = "MLSD";
pub const CMD_AUTH: &str = "AUTH";
pub const CMD_PROT: &str = "PROT";
pub const CMD_PBSZ: &str = "PBSZ";

/// FTP command verbs for detection.
pub static FTP_COMMANDS: &[&str] = &[
    "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN", "PORT", "PASV", "TYPE", "STRU",
    "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD",
    "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP", "NOOP", "FEAT", "OPTS", "EPRT",
    "EPSV", "MDTM", "SIZE", "MLST", "MLSD", "AUTH", "PROT", "PBSZ",
];

/// Field names for Python/generic access.
pub static FTP_FIELD_NAMES: &[&str] = &[
    "command",
    "args",
    "reply_code",
    "reply_text",
    "is_response",
    "is_multiline",
    "raw",
];

// ============================================================================
// Payload detection
// ============================================================================

/// Returns true if `buf` looks like an FTP control-connection payload.
///
/// FTP is text-based. We check for either:
/// - A 3-digit ASCII reply code followed by space, dash, or CR/LF
/// - A recognized FTP command verb followed by space or CR/LF
#[must_use]
pub fn is_ftp_payload(buf: &[u8]) -> bool {
    if buf.len() < 3 {
        return false;
    }
    // Check for FTP reply (3-digit code)
    if buf[0].is_ascii_digit() && buf[1].is_ascii_digit() && buf[2].is_ascii_digit() {
        return buf.len() >= 4 && matches!(buf[3], b' ' | b'-' | b'\r' | b'\n');
    }
    // Check for FTP command
    if let Ok(text) = std::str::from_utf8(buf) {
        let upper = text.to_ascii_uppercase();
        let first_word = upper.split_ascii_whitespace().next().unwrap_or("");
        // Strip trailing \r\n from first word if applicable
        let first_word = first_word.trim_end_matches(['\r', '\n']);
        return FTP_COMMANDS.contains(&first_word);
    }
    false
}

/// Represents an FTP message type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtpMessageKind {
    /// Client command (e.g., USER, PASS, LIST)
    Command,
    /// Server reply (e.g., 220 Service ready)
    Reply,
    /// Unknown (cannot determine direction)
    Unknown,
}

// ============================================================================
// FtpLayer - zero-copy view
// ============================================================================

/// A zero-copy view into an FTP layer within a packet buffer.
///
/// FTP is text-based, so all field access involves parsing ASCII text
/// from the buffer slice on demand.
#[must_use]
#[derive(Debug, Clone)]
pub struct FtpLayer {
    pub index: LayerIndex,
}

impl FtpLayer {
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    pub fn at_start(len: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Ftp, 0, len),
        }
    }

    /// Returns the raw bytes of this layer.
    #[inline]
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let end = self.index.end.min(buf.len());
        &buf[self.index.start..end]
    }

    /// Determine if this message is a reply (starts with 3-digit code) or command.
    #[must_use]
    pub fn message_kind(&self, buf: &[u8]) -> FtpMessageKind {
        let s = self.slice(buf);
        if s.len() >= 3 && s[0].is_ascii_digit() && s[1].is_ascii_digit() && s[2].is_ascii_digit() {
            FtpMessageKind::Reply
        } else if self.command(buf).is_ok() {
            FtpMessageKind::Command
        } else {
            FtpMessageKind::Unknown
        }
    }

    /// Returns the FTP command verb (for client messages).
    ///
    /// Returns `Err` if this is a server reply, not a command.
    ///
    /// # Errors
    ///
    /// Returns [`FieldError::InvalidValue`] if the payload is not valid UTF-8.
    pub fn command(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        let text = std::str::from_utf8(s)
            .map_err(|_| FieldError::InvalidValue("non-UTF8 FTP payload".into()))?;
        let first_word = text.split_ascii_whitespace().next().unwrap_or("");
        let upper = first_word.to_ascii_uppercase();
        // Verify it's an FTP command
        if FTP_COMMANDS.contains(&upper.as_str()) {
            Ok(upper)
        } else if !s.is_empty() && s[0].is_ascii_digit() {
            Err(FieldError::InvalidValue(
                "this is a reply, not a command".into(),
            ))
        } else {
            Ok(upper) // return whatever verb is there
        }
    }

    /// Returns the command arguments (everything after the verb on the first line).
    ///
    /// # Errors
    ///
    /// Returns [`FieldError::InvalidValue`] if the payload is not valid UTF-8.
    pub fn args(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        let text = std::str::from_utf8(s)
            .map_err(|_| FieldError::InvalidValue("non-UTF8 FTP payload".into()))?;
        let first_line = text.lines().next().unwrap_or("");
        // Skip the first word (command verb)
        let rest = first_line
            .split_once(' ')
            .map_or("", |(_, r)| r)
            .trim_end_matches(['\r', '\n']);
        Ok(rest.to_string())
    }

    /// Returns the 3-digit reply code (for server replies).
    ///
    /// # Errors
    ///
    /// Returns [`FieldError::BufferTooShort`] if fewer than 3 bytes are available,
    /// or [`FieldError::InvalidValue`] if the first 3 bytes are not ASCII digits.
    pub fn reply_code(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 3 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 3,
                have: s.len(),
            });
        }
        if s[0].is_ascii_digit() && s[1].is_ascii_digit() && s[2].is_ascii_digit() {
            let code =
                u16::from(s[0] - b'0') * 100 + u16::from(s[1] - b'0') * 10 + u16::from(s[2] - b'0');
            Ok(code)
        } else {
            Err(FieldError::InvalidValue(
                "payload does not start with a 3-digit reply code".into(),
            ))
        }
    }

    /// Returns the reply text (text following the code, stripped of CR/LF).
    ///
    /// # Errors
    ///
    /// Returns [`FieldError::InvalidValue`] if the payload is not valid UTF-8 or
    /// does not begin with a valid 3-digit reply code.
    pub fn reply_text(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        let text = std::str::from_utf8(s)
            .map_err(|_| FieldError::InvalidValue("non-UTF8 FTP payload".into()))?;
        // Get first line, skip the code prefix (NNN SP or NNN-)
        let first_line = text.lines().next().unwrap_or("");
        if first_line.len() >= 4 {
            let msg = first_line[4..].trim_end_matches(['\r', '\n']).to_string();
            Ok(msg)
        } else if first_line.len() == 3 {
            Ok(String::new())
        } else {
            Err(FieldError::InvalidValue(
                "payload too short for reply format".into(),
            ))
        }
    }

    /// Returns true if this is a server reply (starts with a 3-digit code).
    #[must_use]
    pub fn is_response(&self, buf: &[u8]) -> bool {
        let s = self.slice(buf);
        s.len() >= 3 && s[0].is_ascii_digit() && s[1].is_ascii_digit() && s[2].is_ascii_digit()
    }

    /// Returns true if this is a multi-line reply (code followed by `-`).
    #[must_use]
    pub fn is_multiline(&self, buf: &[u8]) -> bool {
        let s = self.slice(buf);
        s.len() >= 4
            && s[0].is_ascii_digit()
            && s[1].is_ascii_digit()
            && s[2].is_ascii_digit()
            && s[3] == b'-'
    }

    /// Returns the raw payload as a UTF-8 string (best effort).
    #[must_use]
    pub fn raw(&self, buf: &[u8]) -> String {
        let s = self.slice(buf);
        String::from_utf8_lossy(s).to_string()
    }

    /// Get a field by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "command" => Some(self.command(buf).map(FieldValue::Str)),
            "args" => Some(self.args(buf).map(FieldValue::Str)),
            "reply_code" => Some(self.reply_code(buf).map(FieldValue::U16)),
            "reply_text" => Some(self.reply_text(buf).map(FieldValue::Str)),
            "is_response" => Some(Ok(FieldValue::Bool(self.is_response(buf)))),
            "is_multiline" => Some(Ok(FieldValue::Bool(self.is_multiline(buf)))),
            "raw" => Some(Ok(FieldValue::Str(self.raw(buf)))),
            _ => None,
        }
    }
}

impl Layer for FtpLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Ftp
    }

    fn summary(&self, buf: &[u8]) -> String {
        let s = self.slice(buf);
        let text = String::from_utf8_lossy(s);
        let first_line = text.lines().next().unwrap_or("").trim_end_matches('\r');
        format!("FTP {first_line}")
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        self.slice(buf).len()
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        // Use reply code or command verb as hash key
        if let Ok(code) = self.reply_code(buf) {
            code.to_be_bytes().to_vec()
        } else if let Ok(cmd) = self.command(buf) {
            cmd.into_bytes()
        } else {
            vec![]
        }
    }

    fn field_names(&self) -> &'static [&'static str] {
        FTP_FIELD_NAMES
    }
}

/// Display fields for `FtpLayer` in `show()` output.
#[must_use]
pub fn ftp_show_fields(l: &FtpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    if l.is_response(buf) {
        if let Ok(code) = l.reply_code(buf) {
            fields.push(("reply_code", code.to_string()));
        }
        if let Ok(text) = l.reply_text(buf) {
            fields.push(("reply_text", text));
        }
        fields.push(("is_multiline", l.is_multiline(buf).to_string()));
    } else if let Ok(cmd) = l.command(buf) {
        fields.push(("command", cmd));
        if let Ok(args) = l.args(buf)
            && !args.is_empty()
        {
            fields.push(("args", args));
        }
    }
    fields
}

// ============================================================================
// Helper: FTP reply code description
// ============================================================================

/// Returns a human-readable description for an FTP reply code.
#[must_use]
pub fn reply_code_description(code: u16) -> &'static str {
    match code {
        110 => "Restart marker reply",
        120 => "Service ready in N minutes",
        125 => "Data connection already open; transfer starting",
        150 => "File status okay; about to open data connection",
        200 => "Command okay",
        202 => "Command not implemented, superfluous at this site",
        211 => "System status, or system help reply",
        212 => "Directory status",
        213 => "File status",
        214 => "Help message",
        215 => "NAME system type",
        220 => "Service ready for new user",
        221 => "Service closing control connection",
        225 => "Data connection open; no transfer in progress",
        226 => "Closing data connection; requested file action successful",
        227 => "Entering Passive Mode",
        228 => "Entering Long Passive Mode",
        229 => "Entering Extended Passive Mode",
        230 => "User logged in, proceed",
        234 => "Specifying protection mechanism name",
        250 => "Requested file action okay, completed",
        257 => "PATHNAME created",
        331 => "User name okay, need password",
        332 => "Need account for login",
        350 => "Requested file action pending further information",
        421 => "Service not available, closing control connection",
        425 => "Can't open data connection",
        426 => "Connection closed; transfer aborted",
        430 => "Invalid username or password",
        434 => "Requested host unavailable",
        450 => "Requested file action not taken; file unavailable",
        451 => "Requested action aborted; local error in processing",
        452 => "Requested action not taken; insufficient storage space",
        500 => "Syntax error, command unrecognized",
        501 => "Syntax error in parameters or arguments",
        502 => "Command not implemented",
        503 => "Bad sequence of commands",
        504 => "Command not implemented for that parameter",
        530 => "Not logged in",
        532 => "Need account for storing files",
        550 => "Requested action not taken; file unavailable",
        551 => "Requested action aborted; page type unknown",
        552 => "Requested file action aborted; exceeded storage allocation",
        553 => "Requested action not taken; file name not allowed",
        _ => "Unknown reply code",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::LayerIndex;

    fn make_layer(data: &[u8]) -> FtpLayer {
        FtpLayer::new(LayerIndex::new(LayerKind::Ftp, 0, data.len()))
    }

    #[test]
    fn test_ftp_detection_reply() {
        assert!(is_ftp_payload(b"220 Service ready\r\n"));
        assert!(is_ftp_payload(b"331 Password required\r\n"));
        assert!(is_ftp_payload(b"230 User logged in\r\n"));
        assert!(is_ftp_payload(b"550 File not found\r\n"));
    }

    #[test]
    fn test_ftp_detection_command() {
        assert!(is_ftp_payload(b"USER anonymous\r\n"));
        assert!(is_ftp_payload(b"PASS secret\r\n"));
        assert!(is_ftp_payload(b"LIST\r\n"));
        assert!(is_ftp_payload(b"QUIT\r\n"));
        assert!(is_ftp_payload(b"RETR file.txt\r\n"));
    }

    #[test]
    fn test_ftp_detection_negative() {
        assert!(!is_ftp_payload(b""));
        assert!(!is_ftp_payload(b"GET / HTTP/1.1\r\n"));
        assert!(!is_ftp_payload(b"\x00\x00\x00\x01"));
    }

    #[test]
    fn test_ftp_layer_reply_code() {
        let data = b"220 Service ready for new user\r\n";
        let layer = make_layer(data);
        assert_eq!(layer.reply_code(data).unwrap(), 220);
        assert_eq!(
            layer.reply_text(data).unwrap(),
            "Service ready for new user"
        );
        assert!(layer.is_response(data));
        assert!(!layer.is_multiline(data));
    }

    #[test]
    fn test_ftp_layer_multiline_reply() {
        let data = b"220-Welcome to FTP\r\n220 Ready\r\n";
        let layer = make_layer(data);
        assert_eq!(layer.reply_code(data).unwrap(), 220);
        assert!(layer.is_multiline(data));
    }

    #[test]
    fn test_ftp_layer_command() {
        let data = b"USER anonymous\r\n";
        let layer = make_layer(data);
        assert_eq!(layer.command(data).unwrap(), "USER");
        assert_eq!(layer.args(data).unwrap(), "anonymous");
        assert!(!layer.is_response(data));
        assert_eq!(layer.message_kind(data), FtpMessageKind::Command);
    }

    #[test]
    fn test_ftp_layer_command_no_args() {
        let data = b"QUIT\r\n";
        let layer = make_layer(data);
        assert_eq!(layer.command(data).unwrap(), "QUIT");
        assert_eq!(layer.args(data).unwrap(), "");
    }

    #[test]
    fn test_ftp_layer_pasv_response() {
        let data = b"227 Entering Passive Mode (192,168,1,1,200,50)\r\n";
        let layer = make_layer(data);
        assert_eq!(layer.reply_code(data).unwrap(), 227);
        assert!(layer.reply_text(data).unwrap().contains("Passive Mode"));
    }

    #[test]
    fn test_ftp_reply_code_description() {
        assert_eq!(reply_code_description(220), "Service ready for new user");
        assert_eq!(reply_code_description(331), "User name okay, need password");
        assert_eq!(
            reply_code_description(550),
            "Requested action not taken; file unavailable"
        );
    }

    #[test]
    fn test_ftp_field_access() {
        let data = b"230 User logged in, proceed\r\n";
        let layer = make_layer(data);
        assert!(matches!(
            layer.get_field(data, "reply_code"),
            Some(Ok(FieldValue::U16(230)))
        ));
        assert!(matches!(
            layer.get_field(data, "is_response"),
            Some(Ok(FieldValue::Bool(true)))
        ));
        assert!(layer.get_field(data, "unknown_field").is_none());
    }
}
