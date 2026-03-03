//! POP3 (Post Office Protocol version 3) layer implementation.
//!
//! Implements RFC 1939 POP3 packet parsing as a zero-copy view into a packet buffer.
//!
//! ## Protocol Overview
//!
//! POP3 operates over TCP port 110 (or 995 for POP3S).
//! Unlike SMTP, POP3 is used to download mail from a server.
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
//! +OK [text]\r\n         (success)
//! -ERR [text]\r\n        (error)
//! ```
//!
//! Multi-line responses (for LIST, RETR, etc.) end with a line containing only `.`.
//!
//! ## POP3 Commands (RFC 1939)
//!
//! | Command | State        | Description                          |
//! |---------|--------------|--------------------------------------|
//! | USER    | Authorization| User name                            |
//! | PASS    | Authorization| Password                             |
//! | QUIT    | Both         | Quit                                 |
//! | STAT    | Transaction  | Get mailbox status                   |
//! | LIST    | Transaction  | List messages                        |
//! | RETR    | Transaction  | Retrieve message                     |
//! | DELE    | Transaction  | Delete message                       |
//! | NOOP    | Transaction  | No-op                                |
//! | RSET    | Transaction  | Reset (undelete)                     |
//! | TOP     | Transaction  | Get message headers + N body lines   |
//! | UIDL    | Transaction  | Unique ID listing                    |
//! | APOP    | Authorization| Authenticated login (MD5)            |
//! | AUTH    | Authorization| Authenticate (RFC 1734)              |
//! | CAPA    | Both         | List capabilities (RFC 2449)         |
//! | STLS    | Authorization| Start TLS (RFC 2595)                 |

pub mod builder;
pub use builder::Pop3Builder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum POP3 payload: "+OK\r\n" = 5 bytes or "USER" = 4 bytes.
pub const POP3_MIN_HEADER_LEN: usize = 4;

/// POP3 standard port.
pub const POP3_PORT: u16 = 110;

/// POP3S (over TLS) port.
pub const POP3S_PORT: u16 = 995;

// ============================================================================
// POP3 commands
// ============================================================================
pub const CMD_USER: &str = "USER";
pub const CMD_PASS: &str = "PASS";
pub const CMD_QUIT: &str = "QUIT";
pub const CMD_STAT: &str = "STAT";
pub const CMD_LIST: &str = "LIST";
pub const CMD_RETR: &str = "RETR";
pub const CMD_DELE: &str = "DELE";
pub const CMD_NOOP: &str = "NOOP";
pub const CMD_RSET: &str = "RSET";
pub const CMD_TOP: &str = "TOP";
pub const CMD_UIDL: &str = "UIDL";
pub const CMD_APOP: &str = "APOP";
pub const CMD_AUTH: &str = "AUTH";
pub const CMD_CAPA: &str = "CAPA";
pub const CMD_STLS: &str = "STLS";

pub static POP3_COMMANDS: &[&str] = &[
    "USER", "PASS", "QUIT", "STAT", "LIST", "RETR", "DELE", "NOOP", "RSET", "TOP", "UIDL", "APOP",
    "AUTH", "CAPA", "STLS",
];

/// Field names for Python/generic access.
pub static POP3_FIELD_NAMES: &[&str] = &[
    "command",
    "args",
    "is_ok",
    "is_err",
    "response_text",
    "is_response",
    "raw",
];

// ============================================================================
// Payload detection
// ============================================================================

/// Returns true if `buf` looks like a POP3 payload.
#[must_use]
pub fn is_pop3_payload(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    // +OK or -ERR prefix (server response)
    if buf.starts_with(b"+OK") || buf.starts_with(b"-ERR") {
        return true;
    }
    // POP3 client commands
    if let Ok(text) = std::str::from_utf8(buf) {
        let upper = text.to_ascii_uppercase();
        let word = upper.split_ascii_whitespace().next().unwrap_or("");
        return POP3_COMMANDS.contains(&word);
    }
    false
}

// ============================================================================
// Pop3Layer - zero-copy view
// ============================================================================

/// A zero-copy view into a POP3 layer within a packet buffer.
#[must_use]
#[derive(Debug, Clone)]
pub struct Pop3Layer {
    pub index: LayerIndex,
}

impl Pop3Layer {
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    pub fn at_start(len: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Pop3, 0, len),
        }
    }

    #[inline]
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let end = self.index.end.min(buf.len());
        &buf[self.index.start..end]
    }

    /// Returns true if this is a server response (starts with +OK or -ERR).
    #[must_use]
    pub fn is_response(&self, buf: &[u8]) -> bool {
        let s = self.slice(buf);
        s.starts_with(b"+OK") || s.starts_with(b"-ERR")
    }

    /// Returns true if this is a positive response (+OK).
    #[must_use]
    pub fn is_ok(&self, buf: &[u8]) -> bool {
        self.slice(buf).starts_with(b"+OK")
    }

    /// Returns true if this is a negative response (-ERR).
    #[must_use]
    pub fn is_err_response(&self, buf: &[u8]) -> bool {
        self.slice(buf).starts_with(b"-ERR")
    }

    /// Returns the response text after +OK or -ERR (trimmed).
    pub fn response_text(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        let text = std::str::from_utf8(s)
            .map_err(|_| FieldError::InvalidValue("response_text: non-UTF8 payload".into()))?;
        let first_line = text.lines().next().unwrap_or("").trim_end_matches('\r');
        if first_line.starts_with("+OK") {
            let rest = first_line[3..].trim_start_matches(' ');
            Ok(rest.to_string())
        } else if first_line.starts_with("-ERR") {
            let rest = first_line[4..].trim_start_matches(' ');
            Ok(rest.to_string())
        } else {
            Err(FieldError::InvalidValue(
                "response_text: not a POP3 response".into(),
            ))
        }
    }

    /// Returns the command verb (for client commands).
    pub fn command(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        let text = std::str::from_utf8(s)
            .map_err(|_| FieldError::InvalidValue("command: non-UTF8 payload".into()))?;
        let word = text.split_ascii_whitespace().next().unwrap_or("");
        Ok(word.to_ascii_uppercase())
    }

    /// Returns the command arguments.
    pub fn args(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        let text = std::str::from_utf8(s)
            .map_err(|_| FieldError::InvalidValue("args: non-UTF8 payload".into()))?;
        let first_line = text.lines().next().unwrap_or("");
        let rest = first_line
            .split_once(' ')
            .map_or("", |(_, r)| r)
            .trim_end_matches(['\r', '\n']);
        Ok(rest.to_string())
    }

    /// Returns the raw payload.
    #[must_use]
    pub fn raw(&self, buf: &[u8]) -> String {
        String::from_utf8_lossy(self.slice(buf)).to_string()
    }

    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "command" => Some(self.command(buf).map(FieldValue::Str)),
            "args" => Some(self.args(buf).map(FieldValue::Str)),
            "is_ok" => Some(Ok(FieldValue::Bool(self.is_ok(buf)))),
            "is_err" => Some(Ok(FieldValue::Bool(self.is_err_response(buf)))),
            "response_text" => Some(self.response_text(buf).map(FieldValue::Str)),
            "is_response" => Some(Ok(FieldValue::Bool(self.is_response(buf)))),
            "raw" => Some(Ok(FieldValue::Str(self.raw(buf)))),
            _ => None,
        }
    }
}

impl Layer for Pop3Layer {
    fn kind(&self) -> LayerKind {
        LayerKind::Pop3
    }

    fn summary(&self, buf: &[u8]) -> String {
        let s = self.slice(buf);
        let text = String::from_utf8_lossy(s);
        let first_line = text.lines().next().unwrap_or("").trim_end_matches('\r');
        format!("POP3 {first_line}")
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        self.slice(buf).len()
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        if let Ok(cmd) = self.command(buf) {
            cmd.into_bytes()
        } else {
            vec![]
        }
    }

    fn field_names(&self) -> &'static [&'static str] {
        POP3_FIELD_NAMES
    }
}

/// Returns a human-readable display of POP3 layer fields.
#[must_use]
pub fn pop3_show_fields(l: &Pop3Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    if l.is_response(buf) {
        fields.push((
            if l.is_ok(buf) { "is_ok" } else { "is_err" },
            "true".to_string(),
        ));
        if let Ok(text) = l.response_text(buf) {
            fields.push(("response_text", text));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::LayerIndex;

    fn make_layer(data: &[u8]) -> Pop3Layer {
        Pop3Layer::new(LayerIndex::new(LayerKind::Pop3, 0, data.len()))
    }

    #[test]
    fn test_pop3_detection_responses() {
        assert!(is_pop3_payload(b"+OK POP3 server ready\r\n"));
        assert!(is_pop3_payload(b"-ERR Permission denied\r\n"));
        assert!(is_pop3_payload(b"+OK\r\n"));
    }

    #[test]
    fn test_pop3_detection_commands() {
        assert!(is_pop3_payload(b"USER alice\r\n"));
        assert!(is_pop3_payload(b"PASS secret\r\n"));
        assert!(is_pop3_payload(b"STAT\r\n"));
        assert!(is_pop3_payload(b"LIST\r\n"));
        assert!(is_pop3_payload(b"RETR 1\r\n"));
        assert!(is_pop3_payload(b"DELE 1\r\n"));
        assert!(is_pop3_payload(b"QUIT\r\n"));
    }

    #[test]
    fn test_pop3_detection_negative() {
        assert!(!is_pop3_payload(b""));
        assert!(!is_pop3_payload(b"HTTP/1.1 200 OK\r\n"));
        assert!(!is_pop3_payload(b"\x00\x01\x02\x03"));
    }

    #[test]
    fn test_pop3_ok_response() {
        let data = b"+OK POP3 server ready\r\n";
        let layer = make_layer(data);
        assert!(layer.is_response(data));
        assert!(layer.is_ok(data));
        assert!(!layer.is_err_response(data));
        assert_eq!(layer.response_text(data).unwrap(), "POP3 server ready");
    }

    #[test]
    fn test_pop3_err_response() {
        let data = b"-ERR Permission denied\r\n";
        let layer = make_layer(data);
        assert!(layer.is_response(data));
        assert!(!layer.is_ok(data));
        assert!(layer.is_err_response(data));
        assert_eq!(layer.response_text(data).unwrap(), "Permission denied");
    }

    #[test]
    fn test_pop3_user_command() {
        let data = b"USER alice\r\n";
        let layer = make_layer(data);
        assert!(!layer.is_response(data));
        assert_eq!(layer.command(data).unwrap(), "USER");
        assert_eq!(layer.args(data).unwrap(), "alice");
    }

    #[test]
    fn test_pop3_retr_command() {
        let data = b"RETR 5\r\n";
        let layer = make_layer(data);
        assert_eq!(layer.command(data).unwrap(), "RETR");
        assert_eq!(layer.args(data).unwrap(), "5");
    }

    #[test]
    fn test_pop3_stat_no_args() {
        let data = b"STAT\r\n";
        let layer = make_layer(data);
        assert_eq!(layer.command(data).unwrap(), "STAT");
        assert_eq!(layer.args(data).unwrap(), "");
    }

    #[test]
    fn test_pop3_field_access() {
        let data = b"+OK 5 messages\r\n";
        let layer = make_layer(data);
        assert!(matches!(
            layer.get_field(data, "is_ok"),
            Some(Ok(FieldValue::Bool(true)))
        ));
        assert!(matches!(
            layer.get_field(data, "is_err"),
            Some(Ok(FieldValue::Bool(false)))
        ));
        assert!(layer.get_field(data, "nonexistent").is_none());
    }
}
